/**
 * Copyright (C) 2017 Hans Dedecker <dedeckeh@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License v2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <errno.h>
#include <string.h>
#include <syslog.h>

#include <linux/netlink.h>
#include <linux/if_addr.h>
#include <linux/neighbour.h>
#include <linux/rtnetlink.h>

#include <netlink/msg.h>
#include <netlink/socket.h>
#include <netlink/attr.h>

#include <arpa/inet.h>
#include <libubox/list.h>

#include "odhcpd.h"

struct event_socket {
	struct odhcpd_event ev;
	struct nl_sock *sock;
	int sock_bufsize;
};

static void handle_rtnl_event(struct odhcpd_event *ev);
static int cb_rtnl_valid(struct nl_msg *msg, void *arg);
static void catch_rtnl_err(struct odhcpd_event *e, int error);
static struct nl_sock *create_socket(int protocol);

static struct nl_sock *rtnl_socket = NULL;
struct list_head netevent_handler_list = LIST_HEAD_INIT(netevent_handler_list);
static struct event_socket rtnl_event = {
	.ev = {
		.uloop = {.fd = - 1, },
		.handle_dgram = NULL,
		.handle_error = catch_rtnl_err,
		.recv_msgs = handle_rtnl_event,
	},
	.sock = NULL,
	.sock_bufsize = 133120,
};

int netlink_init(void)
{
	rtnl_socket = create_socket(NETLINK_ROUTE);
	if (!rtnl_socket) {
		syslog(LOG_ERR, "Unable to open nl socket: %s", strerror(errno));
		goto err;
	}

	rtnl_event.sock = create_socket(NETLINK_ROUTE);
	if (!rtnl_event.sock) {
		syslog(LOG_ERR, "Unable to open nl event socket: %s", strerror(errno));
		goto err;
	}

	rtnl_event.ev.uloop.fd = nl_socket_get_fd(rtnl_event.sock);

	if (nl_socket_set_buffer_size(rtnl_event.sock, rtnl_event.sock_bufsize, 0))
		goto err;

	nl_socket_disable_seq_check(rtnl_event.sock);

	nl_socket_modify_cb(rtnl_event.sock, NL_CB_VALID, NL_CB_CUSTOM,
			cb_rtnl_valid, NULL);

	// Receive IPv4 address, IPv6 address, IPv6 routes and neighbor events
	if (nl_socket_add_memberships(rtnl_event.sock, RTNLGRP_IPV4_IFADDR,
				RTNLGRP_IPV6_IFADDR, RTNLGRP_IPV6_ROUTE,
				RTNLGRP_NEIGH, RTNLGRP_LINK, 0))
		goto err;

	odhcpd_register(&rtnl_event.ev);

	return 0;

err:
	if (rtnl_socket) {
		nl_socket_free(rtnl_socket);
		rtnl_socket = NULL;
	}

	if (rtnl_event.sock) {
		nl_socket_free(rtnl_event.sock);
		rtnl_event.sock = NULL;
		rtnl_event.ev.uloop.fd = -1;
	}

	return -1;
}


int netlink_add_netevent_handler(struct netevent_handler *handler)
{
	if (!handler->cb)
		return -1;

	list_add(&handler->head, &netevent_handler_list);

	return 0;
}

static void call_netevent_handler_list(unsigned long event, struct netevent_handler_info *info)
{
	struct netevent_handler *handler;

	list_for_each_entry(handler, &netevent_handler_list, head)
		handler->cb(event, info);
}

static void handle_rtnl_event(struct odhcpd_event *e)
{
	struct event_socket *ev_sock = container_of(e, struct event_socket, ev);

	nl_recvmsgs_default(ev_sock->sock);
}

static void refresh_iface_addr4(struct netevent_handler_info *event_info)
{
	struct odhcpd_ipaddr *addr = NULL;
	struct interface *iface = event_info->iface;
	ssize_t len = netlink_get_interface_addrs(iface->ifindex, false, &addr);

	if (len < 0)
		return;

	bool change = len != (ssize_t)iface->addr4_len;
	for (ssize_t i = 0; !change && i < len; ++i)
		if (addr[i].addr.in.s_addr != iface->addr4[i].addr.in.s_addr)
			change = true;

	event_info->addrs_old.addrs = iface->addr4;
	event_info->addrs_old.len = iface->addr4_len;

	iface->addr4 = addr;
	iface->addr4_len = len;

	if (change)
		call_netevent_handler_list(NETEV_ADDRLIST_CHANGE, event_info);

	free(event_info->addrs_old.addrs);
}

static void refresh_iface_addr6(struct netevent_handler_info *event_info)
{
	struct odhcpd_ipaddr *addr = NULL;
	struct interface *iface = event_info->iface;
	ssize_t len = netlink_get_interface_addrs(iface->ifindex, true, &addr);

	if (len < 0)
		return;

	bool change = len != (ssize_t)iface->addr6_len;
	for (ssize_t i = 0; !change && i < len; ++i)
		if (!IN6_ARE_ADDR_EQUAL(&addr[i].addr.in6, &iface->addr6[i].addr.in6) ||
				(addr[i].preferred > 0) != (iface->addr6[i].preferred > 0) ||
				addr[i].valid < iface->addr6[i].valid ||
				addr[i].preferred < iface->addr6[i].preferred)
			change = true;

	event_info->addrs_old.addrs = iface->addr6;
	event_info->addrs_old.len = iface->addr6_len;

	iface->addr6 = addr;
	iface->addr6_len = len;

	if (change)
		call_netevent_handler_list(NETEV_ADDR6LIST_CHANGE, event_info);

	free(event_info->addrs_old.addrs);
}

// Handler for neighbor cache entries from the kernel. This is our source
// to learn and unlearn hosts on interfaces.
static int cb_rtnl_valid(struct nl_msg *msg, _unused void *arg)
{
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	struct netevent_handler_info event_info;
	bool add = false;
	char ipbuf[INET6_ADDRSTRLEN];

	memset(&event_info, 0, sizeof(event_info));
	switch (hdr->nlmsg_type) {
	case RTM_NEWLINK: {
		struct ifinfomsg *ifi = nlmsg_data(hdr);
		struct nlattr *nla[__IFLA_MAX];

		if (!nlmsg_valid_hdr(hdr, sizeof(*ifi)) ||
				ifi->ifi_family != AF_UNSPEC)
			return NL_SKIP;

		nlmsg_parse(hdr, sizeof(*ifi), nla, __IFLA_MAX - 1, NULL);
		if (!nla[IFLA_IFNAME])
			return NL_SKIP;

		event_info.iface = odhcpd_get_interface_by_name(nla_get_string(nla[IFLA_IFNAME]));
		if (!event_info.iface)
			return NL_SKIP;

		if (event_info.iface->ifindex != ifi->ifi_index) {
			event_info.iface->ifindex = ifi->ifi_index;
			call_netevent_handler_list(NETEV_IFINDEX_CHANGE, &event_info);
		}
		break;
	}

	case RTM_NEWROUTE:
		add = true;
		/* fall through */
	case RTM_DELROUTE: {
		struct rtmsg *rtm = nlmsg_data(hdr);
		struct nlattr *nla[__RTA_MAX];

		if (!nlmsg_valid_hdr(hdr, sizeof(*rtm)) ||
				rtm->rtm_family != AF_INET6)
			return NL_SKIP;

		nlmsg_parse(hdr, sizeof(*rtm), nla, __RTA_MAX - 1, NULL);

		event_info.rt.dst_len = rtm->rtm_dst_len;
		if (nla[RTA_DST])
			nla_memcpy(&event_info.rt.dst, nla[RTA_DST],
					sizeof(&event_info.rt.dst));

		if (nla[RTA_OIF])
			event_info.iface = odhcpd_get_interface_by_index(nla_get_u32(nla[RTA_OIF]));

		if (nla[RTA_GATEWAY])
			nla_memcpy(&event_info.rt.gateway, nla[RTA_GATEWAY],
					sizeof(&event_info.rt.gateway));

		call_netevent_handler_list(add ? NETEV_ROUTE6_ADD : NETEV_ROUTE6_DEL,
					&event_info);
		break;
	}

	case RTM_NEWADDR:
		add = true;
		/* fall through */
	case RTM_DELADDR: {
		struct ifaddrmsg *ifa = nlmsg_data(hdr);
		struct nlattr *nla[__IFA_MAX];

		if (!nlmsg_valid_hdr(hdr, sizeof(*ifa)) ||
				(ifa->ifa_family != AF_INET6 &&
				 ifa->ifa_family != AF_INET))
			return NL_SKIP;

		event_info.iface = odhcpd_get_interface_by_index(ifa->ifa_index);
		if (!event_info.iface)
			return NL_SKIP;

		nlmsg_parse(hdr, sizeof(*ifa), nla, __IFA_MAX - 1, NULL);

		if (ifa->ifa_family == AF_INET6) {
			if (!nla[IFA_ADDRESS])
				return NL_SKIP;

			nla_memcpy(&event_info.addr, nla[IFA_ADDRESS], sizeof(event_info.addr));

			if (IN6_IS_ADDR_LINKLOCAL(&event_info.addr) ||
			    IN6_IS_ADDR_MULTICAST(&event_info.addr))
				return NL_SKIP;

			inet_ntop(AF_INET6, &event_info.addr, ipbuf, sizeof(ipbuf));
			syslog(LOG_DEBUG, "Netlink %s %s%%%s", add ? "newaddr" : "deladdr",
				ipbuf, event_info.iface->ifname);

			call_netevent_handler_list(add ? NETEV_ADDR6_ADD : NETEV_ADDR6_DEL,
							&event_info);

			refresh_iface_addr6(&event_info);
		} else {
			if (!nla[IFA_LOCAL])
				return NL_SKIP;

			nla_memcpy(&event_info.addr, nla[IFA_LOCAL], sizeof(event_info.addr));

			inet_ntop(AF_INET, &event_info.addr, ipbuf, sizeof(ipbuf));
			syslog(LOG_DEBUG, "Netlink %s %s%%%s", add ? "newaddr" : "deladdr",
				ipbuf, event_info.iface->ifname);

			call_netevent_handler_list(add ? NETEV_ADDR_ADD : NETEV_ADDR_DEL,
							&event_info);

			refresh_iface_addr4(&event_info);
		}
		break;
	}

	case RTM_NEWNEIGH:
		add = true;
		/* fall through */
	case RTM_DELNEIGH: {
		struct ndmsg *ndm = nlmsg_data(hdr);
		struct nlattr *nla[__NDA_MAX];

		if (!nlmsg_valid_hdr(hdr, sizeof(*ndm)) ||
				ndm->ndm_family != AF_INET6)
			return NL_SKIP;

		event_info.iface = odhcpd_get_interface_by_index(ndm->ndm_ifindex);
		if (!event_info.iface)
			return NL_SKIP;

		nlmsg_parse(hdr, sizeof(*ndm), nla, __NDA_MAX - 1, NULL);
		if (!nla[NDA_DST])
			return NL_SKIP;

		nla_memcpy(&event_info.neigh.dst, nla[NDA_DST], sizeof(event_info.neigh.dst));

		if (IN6_IS_ADDR_LINKLOCAL(&event_info.neigh.dst) ||
		    IN6_IS_ADDR_MULTICAST(&event_info.neigh.dst))
			return NL_SKIP;

		inet_ntop(AF_INET6, &event_info.neigh.dst, ipbuf, sizeof(ipbuf));
		syslog(LOG_DEBUG, "Netlink %s %s%%%s", true ? "newneigh" : "delneigh",
			ipbuf, event_info.iface->ifname);

		event_info.neigh.state = ndm->ndm_state;
		event_info.neigh.flags = ndm->ndm_flags;

		call_netevent_handler_list(add ? NETEV_NEIGH6_ADD : NETEV_NEIGH6_DEL,
						&event_info);
		break;
	}

	default:
		return NL_SKIP;
	}

	return NL_OK;
}

static void catch_rtnl_err(struct odhcpd_event *e, int error)
{
	struct event_socket *ev_sock = container_of(e, struct event_socket, ev);

	if (error != ENOBUFS)
		goto err;

	/* Double netlink event buffer size */
	ev_sock->sock_bufsize *= 2;

	if (nl_socket_set_buffer_size(ev_sock->sock, ev_sock->sock_bufsize, 0))
		goto err;

	netlink_dump_addr_table(true);
	return;

err:
	odhcpd_deregister(e);
}

static struct nl_sock *create_socket(int protocol)
{
	struct nl_sock *nl_sock;

	nl_sock = nl_socket_alloc();
	if (!nl_sock)
		goto err;

	if (nl_connect(nl_sock, protocol) < 0)
		goto err;

	return nl_sock;

err:
	if (nl_sock)
		nl_socket_free(nl_sock);

	return NULL;
}


struct addr_info {
	int ifindex;
	int af;
	struct odhcpd_ipaddr **addrs;
	int pending;
	ssize_t ret;
};


static int cb_valid_handler(struct nl_msg *msg, void *arg)
{
	struct addr_info *ctxt = (struct addr_info *)arg;
	struct odhcpd_ipaddr *addrs = *(ctxt->addrs);
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	struct ifaddrmsg *ifa;
	struct nlattr *nla[__IFA_MAX], *nla_addr = NULL;

	if (hdr->nlmsg_type != RTM_NEWADDR)
		return NL_SKIP;

	ifa = NLMSG_DATA(hdr);
	if (ifa->ifa_scope != RT_SCOPE_UNIVERSE ||
			(ctxt->af != ifa->ifa_family) ||
			(ctxt->ifindex && ifa->ifa_index != (unsigned)ctxt->ifindex))
		return NL_SKIP;

	nlmsg_parse(hdr, sizeof(*ifa), nla, __IFA_MAX - 1, NULL);

	switch (ifa->ifa_family) {
	case AF_INET6:
		if (nla[IFA_ADDRESS])
			nla_addr = nla[IFA_ADDRESS];
		break;

	case AF_INET:
		if (nla[IFA_LOCAL])
			nla_addr = nla[IFA_LOCAL];
		break;

	default:
		break;
	}
	if (!nla_addr)
		return NL_SKIP;

	addrs = realloc(addrs, sizeof(*addrs)*(ctxt->ret + 1));
	if (!addrs)
		return NL_SKIP;

	memset(&addrs[ctxt->ret], 0, sizeof(addrs[ctxt->ret]));
	addrs[ctxt->ret].prefix = ifa->ifa_prefixlen;

	nla_memcpy(&addrs[ctxt->ret].addr, nla_addr,
			sizeof(addrs[ctxt->ret].addr));

	if (nla[IFA_BROADCAST])
		nla_memcpy(&addrs[ctxt->ret].broadcast, nla[IFA_BROADCAST],
				sizeof(addrs[ctxt->ret].broadcast));

	if (nla[IFA_CACHEINFO]) {
		struct ifa_cacheinfo *ifc = nla_data(nla[IFA_CACHEINFO]);

		addrs[ctxt->ret].preferred = ifc->ifa_prefered;
		addrs[ctxt->ret].valid = ifc->ifa_valid;
	}

	if (ifa->ifa_flags & IFA_F_DEPRECATED)
		addrs[ctxt->ret].preferred = 0;

	ctxt->ret++;
	*(ctxt->addrs) = addrs;

	return NL_OK;
}


static int cb_finish_handler(_unused struct nl_msg *msg, void *arg)
{
	struct addr_info *ctxt = (struct addr_info *)arg;

	ctxt->pending = 0;

	return NL_STOP;
}


static int cb_error_handler(_unused struct sockaddr_nl *nla, struct nlmsgerr *err,
		void *arg)
{
	struct addr_info *ctxt = (struct addr_info *)arg;

	ctxt->pending = 0;
	ctxt->ret = err->error;

	return NL_STOP;
}


static int prefix_cmp(const void *va, const void *vb)
{
	const struct odhcpd_ipaddr *a = va, *b = vb;
	int ret = 0;

	if (a->prefix == b->prefix) {
		ret = (ntohl(a->addr.in.s_addr) < ntohl(b->addr.in.s_addr)) ? 1 :
			(ntohl(a->addr.in.s_addr) > ntohl(b->addr.in.s_addr)) ? -1 : 0;
	} else
		ret = a->prefix < b->prefix ? 1 : -1;

	return ret;
}


// compare IPv6 prefixes
static int prefix6_cmp(const void *va, const void *vb)
{
	const struct odhcpd_ipaddr *a = va, *b = vb;
	uint32_t a_pref = IN6_IS_ADDR_ULA(&a->addr.in6) ? 1 : a->preferred;
	uint32_t b_pref = IN6_IS_ADDR_ULA(&b->addr.in6) ? 1 : b->preferred;
	return (a_pref < b_pref) ? 1 : (a_pref > b_pref) ? -1 : 0;
}


// Detect an IPV6-address currently assigned to the given interface
ssize_t netlink_get_interface_addrs(int ifindex, bool v6, struct odhcpd_ipaddr **addrs)
{
	struct nl_msg *msg;
	struct ifaddrmsg ifa = {
		.ifa_family = v6? AF_INET6: AF_INET,
		.ifa_prefixlen = 0,
		.ifa_flags = 0,
		.ifa_scope = 0,
		.ifa_index = ifindex, };
	struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);
	struct addr_info ctxt = {
		.ifindex = ifindex,
		.af = v6? AF_INET6: AF_INET,
		.addrs = addrs,
		.ret = 0,
		.pending = 1,
	};

	if (!cb) {
		ctxt.ret = -1;
		goto out;
	}

	msg = nlmsg_alloc_simple(RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP);

	if (!msg) {
		ctxt.ret = - 1;
		goto out;
	}

	nlmsg_append(msg, &ifa, sizeof(ifa), 0);

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, cb_valid_handler, &ctxt);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, cb_finish_handler, &ctxt);
	nl_cb_err(cb, NL_CB_CUSTOM, cb_error_handler, &ctxt);

	nl_send_auto_complete(rtnl_socket, msg);
	while (ctxt.pending > 0)
		nl_recvmsgs(rtnl_socket, cb);

	nlmsg_free(msg);

	if (ctxt.ret <= 0)
		goto out;

	time_t now = odhcpd_time();
	struct odhcpd_ipaddr *addr = *addrs;

	qsort(addr, ctxt.ret, sizeof(*addr), v6 ? prefix6_cmp : prefix_cmp);

	for (ssize_t i = 0; i < ctxt.ret; ++i) {
		if (addr[i].preferred < UINT32_MAX - now)
			addr[i].preferred += now;

		if (addr[i].valid < UINT32_MAX - now)
			addr[i].valid += now;
	}

out:
	nl_cb_put(cb);

	return ctxt.ret;
}


int netlink_setup_route(const struct in6_addr *addr, const int prefixlen,
		const int ifindex, const struct in6_addr *gw,
		const uint32_t metric, const bool add)
{
	struct nl_msg *msg;
	struct rtmsg rtm = {
		.rtm_family = AF_INET6,
		.rtm_dst_len = prefixlen,
		.rtm_src_len = 0,
		.rtm_table = RT_TABLE_MAIN,
		.rtm_protocol = (add ? RTPROT_STATIC : RTPROT_UNSPEC),
		.rtm_scope = (add ? (gw ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK) : RT_SCOPE_NOWHERE),
		.rtm_type = (add ? RTN_UNICAST : RTN_UNSPEC),
	};
	int ret = 0;

	msg = nlmsg_alloc_simple(add ? RTM_NEWROUTE : RTM_DELROUTE,
					add ? NLM_F_CREATE | NLM_F_REPLACE : 0);
	if (!msg)
		return -1;

	nlmsg_append(msg, &rtm, sizeof(rtm), 0);

	nla_put(msg, RTA_DST, sizeof(*addr), addr);
	nla_put_u32(msg, RTA_OIF, ifindex);
	nla_put_u32(msg, RTA_PRIORITY, metric);

	if (gw)
		nla_put(msg, RTA_GATEWAY, sizeof(*gw), gw);

	ret = nl_send_auto_complete(rtnl_socket, msg);
	nlmsg_free(msg);

	if (ret < 0)
		return ret;

	return nl_wait_for_ack(rtnl_socket);
}


int netlink_setup_proxy_neigh(const struct in6_addr *addr,
		const int ifindex, const bool add)
{
	struct nl_msg *msg;
	struct ndmsg ndm = {
		.ndm_family = AF_INET6,
		.ndm_flags = NTF_PROXY,
		.ndm_ifindex = ifindex,
	};
	int ret = 0, flags = NLM_F_REQUEST;

	if (add)
		flags |= NLM_F_REPLACE | NLM_F_CREATE;

	msg = nlmsg_alloc_simple(add ? RTM_NEWNEIGH : RTM_DELNEIGH, flags);
	if (!msg)
		return -1;

	nlmsg_append(msg, &ndm, sizeof(ndm), 0);

	nla_put(msg, NDA_DST, sizeof(*addr), addr);

	ret = nl_send_auto_complete(rtnl_socket, msg);
	nlmsg_free(msg);

	if (ret < 0)
		return ret;

	return nl_wait_for_ack(rtnl_socket);
}


int netlink_setup_addr(struct odhcpd_ipaddr *addr,
		const int ifindex, const bool v6, const bool add)
{
	struct nl_msg *msg;
	struct ifaddrmsg ifa = {
		.ifa_family = v6 ? AF_INET6 : AF_INET,
		.ifa_prefixlen = addr->prefix,
		.ifa_flags = 0,
		.ifa_scope = 0,
		.ifa_index = ifindex, };
	int ret = 0, flags = NLM_F_REQUEST;

	if (add)
		flags |= NLM_F_REPLACE | NLM_F_CREATE;

	msg = nlmsg_alloc_simple(add ? RTM_NEWADDR : RTM_DELADDR, 0);
	if (!msg)
		return -1;

	nlmsg_append(msg, &ifa, sizeof(ifa), flags);
	nla_put(msg, IFA_LOCAL, v6 ? 16 : 4, &addr->addr);
	if (v6) {
		struct ifa_cacheinfo cinfo = {	.ifa_prefered = 0xffffffffU,
						.ifa_valid = 0xffffffffU,
						.cstamp = 0,
						.tstamp = 0 };
		time_t now = odhcpd_time();

		if (addr->preferred) {
			int64_t preferred = addr->preferred - now;
			if (preferred < 0)
				preferred = 0;
			else if (preferred > UINT32_MAX)
				preferred = UINT32_MAX;

			cinfo.ifa_prefered = preferred;
		}

		if (addr->valid) {
			int64_t valid = addr->valid - now;
			if (valid <= 0) {
				nlmsg_free(msg);
				return -1;
			}
			else if (valid > UINT32_MAX)
				valid = UINT32_MAX;

			cinfo.ifa_valid = valid;
		}

		nla_put(msg, IFA_CACHEINFO, sizeof(cinfo), &cinfo);

		nla_put_u32(msg, IFA_FLAGS, IFA_F_NOPREFIXROUTE);
	} else {
		if (addr->broadcast.s_addr)
			nla_put_u32(msg, IFA_BROADCAST, addr->broadcast.s_addr);
	}

	ret = nl_send_auto_complete(rtnl_socket, msg);
	nlmsg_free(msg);

	if (ret < 0)
		return ret;

	return nl_wait_for_ack(rtnl_socket);
}

void netlink_dump_neigh_table(const bool proxy)
{
	struct nl_msg *msg;
	struct ndmsg ndm = {
		.ndm_family = AF_INET6,
		.ndm_flags = proxy ? NTF_PROXY : 0,
	};

	msg = nlmsg_alloc_simple(RTM_GETNEIGH, NLM_F_REQUEST | NLM_F_DUMP);
	if (!msg)
		return;

	nlmsg_append(msg, &ndm, sizeof(ndm), 0);

	nl_send_auto_complete(rtnl_event.sock, msg);

	nlmsg_free(msg);
}

void netlink_dump_addr_table(const bool v6)
{
	struct nl_msg *msg;
	struct ifaddrmsg ifa = {
		.ifa_family = v6 ? AF_INET6 : AF_INET,
	};

	msg = nlmsg_alloc_simple(RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP);
	if (!msg)
		return;

	nlmsg_append(msg, &ifa, sizeof(ifa), 0);

	nl_send_auto_complete(rtnl_event.sock, msg);

	nlmsg_free(msg);
}
