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
		syslog(LOG_ERR, "Unable to open nl socket: %m");
		goto err;
	}

	rtnl_event.sock = create_socket(NETLINK_ROUTE);
	if (!rtnl_event.sock) {
		syslog(LOG_ERR, "Unable to open nl event socket: %m");
		goto err;
	}

	rtnl_event.ev.uloop.fd = nl_socket_get_fd(rtnl_event.sock);

	if (nl_socket_set_buffer_size(rtnl_event.sock, rtnl_event.sock_bufsize, 0))
		goto err;

	nl_socket_disable_seq_check(rtnl_event.sock);

	nl_socket_modify_cb(rtnl_event.sock, NL_CB_VALID, NL_CB_CUSTOM,
			cb_rtnl_valid, NULL);

	/* Receive IPv4 address, IPv6 address, IPv6 routes and neighbor events */
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

static void refresh_iface_addr4(int ifindex)
{
	struct odhcpd_ipaddr *addr = NULL;
	struct interface *iface;
	ssize_t len = netlink_get_interface_addrs(ifindex, false, &addr);
	bool change = false;

	if (len < 0)
		return;

	avl_for_each_element(&interfaces, iface, avl) {
		struct netevent_handler_info event_info;

		if (iface->ifindex != ifindex)
			continue;

		memset(&event_info, 0, sizeof(event_info));
		event_info.iface = iface;
		event_info.addrs_old.addrs = iface->addr4;
		event_info.addrs_old.len = iface->addr4_len;

		if (!change) {
			change = len != (ssize_t)iface->addr4_len;
			for (ssize_t i = 0; !change && i < len; ++i) {
				if (addr[i].addr.in.s_addr != iface->addr4[i].addr.in.s_addr)
					change = true;
			}
		}

		iface->addr4 = addr;
		iface->addr4_len = len;

		if (change)
			call_netevent_handler_list(NETEV_ADDRLIST_CHANGE, &event_info);

		free(event_info.addrs_old.addrs);

		if (!len)
			continue;

		addr = malloc(len * sizeof(*addr));
		if (!addr)
			break;

		memcpy(addr, iface->addr4, len * sizeof(*addr));
	}

	free(addr);
}

static void refresh_iface_addr6(int ifindex)
{
	struct odhcpd_ipaddr *addr = NULL;
	struct interface *iface;
	ssize_t len = netlink_get_interface_addrs(ifindex, true, &addr);
	time_t now = odhcpd_time();
	bool change = false;

	if (len < 0)
		return;

	avl_for_each_element(&interfaces, iface, avl) {
		struct netevent_handler_info event_info;

		if (iface->ifindex != ifindex)
			continue;

		memset(&event_info, 0, sizeof(event_info));
		event_info.iface = iface;
		event_info.addrs_old.addrs = iface->addr6;
		event_info.addrs_old.len = iface->addr6_len;

		if (!change) {
			change = len != (ssize_t)iface->addr6_len;
			for (ssize_t i = 0; !change && i < len; ++i) {
				if (!IN6_ARE_ADDR_EQUAL(&addr[i].addr.in6, &iface->addr6[i].addr.in6) ||
				    addr[i].prefix != iface->addr6[i].prefix ||
				    (addr[i].preferred_lt > (uint32_t)now) != (iface->addr6[i].preferred_lt > (uint32_t)now) ||
				    addr[i].valid_lt < iface->addr6[i].valid_lt || addr[i].preferred_lt < iface->addr6[i].preferred_lt)
					change = true;
			}

			if (change) {
				/*
				 * Keep track of removed prefixes, so we could advertise them as invalid
				 * for at least a couple of times.
				 *
				 * RFC7084 § 4.3 :
				 *    L-13:  If the delegated prefix changes, i.e., the current prefix is
				 *           replaced with a new prefix without any overlapping time
				 *           period, then the IPv6 CE router MUST immediately advertise the
				 *           old prefix with a Preferred Lifetime of zero and a Valid
				 *           Lifetime of either a) zero or b) the lower of the current
				 *           Valid Lifetime and two hours (which must be decremented in
				 *           real time) in a Router Advertisement message as described in
				 *           Section 5.5.3, (e) of [RFC4862].
				 */

				for (size_t i = 0; i < iface->addr6_len; ++i) {
					bool removed = true;

					if (iface->addr6[i].valid_lt <= (uint32_t)now)
						continue;

					for (ssize_t j = 0; removed && j < len; ++j) {
						size_t plen = min(addr[j].prefix, iface->addr6[i].prefix);

						if (odhcpd_bmemcmp(&addr[j].addr.in6, &iface->addr6[i].addr.in6, plen) == 0)
							removed = false;
					}

					for (size_t j = 0; removed && j < iface->invalid_addr6_len; ++j) {
						size_t plen = min(iface->invalid_addr6[j].prefix, iface->addr6[i].prefix);

						if (odhcpd_bmemcmp(&iface->invalid_addr6[j].addr.in6, &iface->addr6[i].addr.in6, plen) == 0)
							removed = false;
					}

					if (removed) {
						size_t pos = iface->invalid_addr6_len;
						struct odhcpd_ipaddr *new_invalid_addr6 = realloc(iface->invalid_addr6,
								sizeof(*iface->invalid_addr6) * (pos + 1));

						if (!new_invalid_addr6)
							break;

						iface->invalid_addr6 = new_invalid_addr6;
						iface->invalid_addr6_len++;
						memcpy(&iface->invalid_addr6[pos], &iface->addr6[i], sizeof(*iface->invalid_addr6));
						iface->invalid_addr6[pos].valid_lt = iface->invalid_addr6[pos].preferred_lt = (uint32_t)now;

						if (iface->invalid_addr6[pos].prefix < 64)
							iface->invalid_addr6[pos].prefix = 64;
					}
				}
			}
		}

		iface->addr6 = addr;
		iface->addr6_len = len;

		if (change)
			call_netevent_handler_list(NETEV_ADDR6LIST_CHANGE, &event_info);

		free(event_info.addrs_old.addrs);

		if (!len)
			continue;

		addr = malloc(len * sizeof(*addr));
		if (!addr)
			break;

		memcpy(addr, iface->addr6, len * sizeof(*addr));
	}

	free(addr);
}

static int handle_rtm_link(struct nlmsghdr *hdr)
{
	struct ifinfomsg *ifi = nlmsg_data(hdr);
	struct nlattr *nla[__IFLA_MAX];
	struct interface *iface;
	struct netevent_handler_info event_info;
	const char *ifname;

	memset(&event_info, 0, sizeof(event_info));

	if (!nlmsg_valid_hdr(hdr, sizeof(*ifi)) || ifi->ifi_family != AF_UNSPEC)
		return NL_SKIP;

	nlmsg_parse(hdr, sizeof(*ifi), nla, __IFLA_MAX - 1, NULL);
	if (!nla[IFLA_IFNAME])
		return NL_SKIP;

	ifname = nla_get_string(nla[IFLA_IFNAME]);

	avl_for_each_element(&interfaces, iface, avl) {
		if (strcmp(iface->ifname, ifname))
			continue;

		iface->ifflags = ifi->ifi_flags;

		/*
		 * Assume for link event of the same index, that link changed
		 * and reload services to enable or disable them based on the
		 * RUNNING state of the interface.
		 */
		if (iface->ifindex == ifi->ifi_index) {
			reload_services(iface);
			continue;
		}

		iface->ifindex = ifi->ifi_index;
		event_info.iface = iface;
		call_netevent_handler_list(NETEV_IFINDEX_CHANGE, &event_info);
	}

	return NL_OK;
}

static int handle_rtm_route(struct nlmsghdr *hdr, bool add)
{
	struct rtmsg *rtm = nlmsg_data(hdr);
	struct nlattr *nla[__RTA_MAX];
	struct interface *iface;
	struct netevent_handler_info event_info;
	int ifindex = 0;

	if (!nlmsg_valid_hdr(hdr, sizeof(*rtm)) || rtm->rtm_family != AF_INET6)
		return NL_SKIP;

	nlmsg_parse(hdr, sizeof(*rtm), nla, __RTA_MAX - 1, NULL);

	memset(&event_info, 0, sizeof(event_info));
	event_info.rt.dst_len = rtm->rtm_dst_len;

	if (nla[RTA_DST])
		nla_memcpy(&event_info.rt.dst, nla[RTA_DST],
				sizeof(event_info.rt.dst));

	if (nla[RTA_OIF])
		ifindex = nla_get_u32(nla[RTA_OIF]);

	if (nla[RTA_GATEWAY])
		nla_memcpy(&event_info.rt.gateway, nla[RTA_GATEWAY],
				sizeof(event_info.rt.gateway));

	avl_for_each_element(&interfaces, iface, avl) {
		if (ifindex && iface->ifindex != ifindex)
			continue;

		event_info.iface = ifindex ? iface : NULL;
		call_netevent_handler_list(add ? NETEV_ROUTE6_ADD : NETEV_ROUTE6_DEL,
						&event_info);
	}

	return NL_OK;
}

static int handle_rtm_addr(struct nlmsghdr *hdr, bool add)
{
	struct ifaddrmsg *ifa = nlmsg_data(hdr);
	struct nlattr *nla[__IFA_MAX];
	struct interface *iface;
	struct netevent_handler_info event_info;
	char buf[INET6_ADDRSTRLEN];

	if (!nlmsg_valid_hdr(hdr, sizeof(*ifa)) ||
			(ifa->ifa_family != AF_INET6 &&
			 ifa->ifa_family != AF_INET))
		return NL_SKIP;

	memset(&event_info, 0, sizeof(event_info));

	nlmsg_parse(hdr, sizeof(*ifa), nla, __IFA_MAX - 1, NULL);

	if (ifa->ifa_family == AF_INET6) {
		if (!nla[IFA_ADDRESS])
			return NL_SKIP;

		nla_memcpy(&event_info.addr, nla[IFA_ADDRESS], sizeof(event_info.addr));

		if (IN6_IS_ADDR_MULTICAST(&event_info.addr))
			return NL_SKIP;

		inet_ntop(AF_INET6, &event_info.addr, buf, sizeof(buf));

		avl_for_each_element(&interfaces, iface, avl) {
			if (iface->ifindex != (int)ifa->ifa_index)
				continue;

			if (add && IN6_IS_ADDR_LINKLOCAL(&event_info.addr)) {
				iface->have_link_local = true;
				return NL_SKIP;
			}

			syslog(LOG_DEBUG, "Netlink %s %s on %s", add ? "newaddr" : "deladdr",
					buf, iface->name);

			event_info.iface = iface;
			call_netevent_handler_list(add ? NETEV_ADDR6_ADD : NETEV_ADDR6_DEL,
							&event_info);
		}

		refresh_iface_addr6(ifa->ifa_index);
	} else {
		if (!nla[IFA_LOCAL])
			return NL_SKIP;

		nla_memcpy(&event_info.addr, nla[IFA_LOCAL], sizeof(event_info.addr));

		inet_ntop(AF_INET, &event_info.addr, buf, sizeof(buf));

		avl_for_each_element(&interfaces, iface, avl) {
			if (iface->ifindex != (int)ifa->ifa_index)
				continue;

			syslog(LOG_DEBUG, "Netlink %s %s on %s", add ? "newaddr" : "deladdr",
					buf, iface->name);

			event_info.iface = iface;
			call_netevent_handler_list(add ? NETEV_ADDR_ADD : NETEV_ADDR_DEL,
							&event_info);
		}

		refresh_iface_addr4(ifa->ifa_index);
	}

	return NL_OK;
}

static int handle_rtm_neigh(struct nlmsghdr *hdr, bool add)
{
	struct ndmsg *ndm = nlmsg_data(hdr);
	struct nlattr *nla[__NDA_MAX];
	struct interface *iface;
	struct netevent_handler_info event_info;
	char buf[INET6_ADDRSTRLEN];

	if (!nlmsg_valid_hdr(hdr, sizeof(*ndm)) ||
			ndm->ndm_family != AF_INET6)
		return NL_SKIP;

	nlmsg_parse(hdr, sizeof(*ndm), nla, __NDA_MAX - 1, NULL);
	if (!nla[NDA_DST])
		return NL_SKIP;

	memset(&event_info, 0, sizeof(event_info));

	nla_memcpy(&event_info.neigh.dst, nla[NDA_DST], sizeof(event_info.neigh.dst));

	if (IN6_IS_ADDR_LINKLOCAL(&event_info.neigh.dst) ||
			IN6_IS_ADDR_MULTICAST(&event_info.neigh.dst))
		return NL_SKIP;

	inet_ntop(AF_INET6, &event_info.neigh.dst, buf, sizeof(buf));

	avl_for_each_element(&interfaces, iface, avl) {
		if (iface->ifindex != ndm->ndm_ifindex)
			continue;

		syslog(LOG_DEBUG, "Netlink %s %s on %s", true ? "newneigh" : "delneigh",
				buf, iface->name);

		event_info.iface = iface;
		event_info.neigh.state = ndm->ndm_state;
		event_info.neigh.flags = ndm->ndm_flags;

		call_netevent_handler_list(add ? NETEV_NEIGH6_ADD : NETEV_NEIGH6_DEL,
						&event_info);
	}

	return NL_OK;
}

/* Handler for neighbor cache entries from the kernel. This is our source
 * to learn and unlearn hosts on interfaces. */
static int cb_rtnl_valid(struct nl_msg *msg, _unused void *arg)
{
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	int ret = NL_SKIP;
	bool add = false;

	switch (hdr->nlmsg_type) {
	case RTM_NEWLINK:
		ret = handle_rtm_link(hdr);
		break;

	case RTM_NEWROUTE:
		add = true;
		/* fall through */
	case RTM_DELROUTE:
		ret = handle_rtm_route(hdr, add);
		break;

	case RTM_NEWADDR:
		add = true;
		/* fall through */
	case RTM_DELADDR:
		ret = handle_rtm_addr(hdr, add);
		break;

	case RTM_NEWNEIGH:
		add = true;
		/* fall through */
	case RTM_DELNEIGH:
		ret = handle_rtm_neigh(hdr, add);
		break;

	default:
		break;
	}

	return ret;
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


static int cb_addr_valid(struct nl_msg *msg, void *arg)
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

		addrs[ctxt->ret].preferred_lt = ifc->ifa_prefered;
		addrs[ctxt->ret].valid_lt = ifc->ifa_valid;
	}

	if (ifa->ifa_flags & IFA_F_DEPRECATED)
		addrs[ctxt->ret].preferred_lt = 0;

	if (ifa->ifa_family == AF_INET6 &&
	    ifa->ifa_flags & IFA_F_TENTATIVE)
		addrs[ctxt->ret].tentative = true;

	ctxt->ret++;
	*(ctxt->addrs) = addrs;

	return NL_OK;
}


static int cb_addr_finish(_unused struct nl_msg *msg, void *arg)
{
	struct addr_info *ctxt = (struct addr_info *)arg;

	ctxt->pending = 0;

	return NL_STOP;
}


static int cb_addr_error(_unused struct sockaddr_nl *nla, struct nlmsgerr *err,
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


/* compare IPv6 prefixes */
static int prefix6_cmp(const void *va, const void *vb)
{
	const struct odhcpd_ipaddr *a = va, *b = vb;
	uint32_t a_pref_lt = IN6_IS_ADDR_ULA(&a->addr.in6) ? 1 : a->preferred_lt;
	uint32_t b_pref_lt = IN6_IS_ADDR_ULA(&b->addr.in6) ? 1 : b->preferred_lt;
	return (a_pref_lt < b_pref_lt) ? 1 : (a_pref_lt > b_pref_lt) ? -1 : 0;
}


/* Detect an IPV6-address currently assigned to the given interface */
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

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, cb_addr_valid, &ctxt);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, cb_addr_finish, &ctxt);
	nl_cb_err(cb, NL_CB_CUSTOM, cb_addr_error, &ctxt);

	ctxt.ret = nl_send_auto_complete(rtnl_socket, msg);
	if (ctxt.ret < 0)
		goto free;

	ctxt.ret = 0;
	while (ctxt.pending > 0)
		nl_recvmsgs(rtnl_socket, cb);

	if (ctxt.ret <= 0)
		goto free;

	time_t now = odhcpd_time();
	struct odhcpd_ipaddr *addr = *addrs;

	qsort(addr, ctxt.ret, sizeof(*addr), v6 ? prefix6_cmp : prefix_cmp);

	for (ssize_t i = 0; i < ctxt.ret; ++i) {
		if (addr[i].preferred_lt < UINT32_MAX - now)
			addr[i].preferred_lt += now;

		if (addr[i].valid_lt < UINT32_MAX - now)
			addr[i].valid_lt += now;
	}

free:
	nlmsg_free(msg);
out:
	nl_cb_put(cb);

	return ctxt.ret;
}


static int cb_linklocal_valid(struct nl_msg *msg, void *arg)
{
	struct addr_info *ctxt = (struct addr_info *)arg;
	struct odhcpd_ipaddr *addrs = *(ctxt->addrs);
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	struct ifaddrmsg *ifa;
	struct nlattr *nla[__IFA_MAX], *nla_addr = NULL;
	struct in6_addr addr;

	if (hdr->nlmsg_type != RTM_NEWADDR)
		return NL_SKIP;

	ifa = NLMSG_DATA(hdr);
	if (ifa->ifa_scope != RT_SCOPE_LINK ||
			(ctxt->af != ifa->ifa_family) ||
			(ctxt->ifindex && ifa->ifa_index != (unsigned)ctxt->ifindex))
		return NL_SKIP;

	nlmsg_parse(hdr, sizeof(*ifa), nla, __IFA_MAX - 1, NULL);

	switch (ifa->ifa_family) {
	case AF_INET6:
		if (nla[IFA_ADDRESS])
			nla_addr = nla[IFA_ADDRESS];
		break;

	default:
		break;
	}
	if (!nla_addr)
		return NL_SKIP;

	nla_memcpy(&addr, nla_addr, sizeof(addr));

	if (!IN6_IS_ADDR_LINKLOCAL(&addr))
		return NL_SKIP;

	addrs = realloc(addrs, sizeof(*addrs)*(ctxt->ret + 1));
	if (!addrs)
		return NL_SKIP;

	memset(&addrs[ctxt->ret], 0, sizeof(addrs[ctxt->ret]));
	memcpy(&addrs[ctxt->ret].addr, &addr, sizeof(addrs[ctxt->ret].addr));

	if (ifa->ifa_flags & IFA_F_TENTATIVE)
		addrs[ctxt->ret].tentative = true;

	ctxt->ret++;
	*(ctxt->addrs) = addrs;

	return NL_OK;
}


static int cb_linklocal_finish(_unused struct nl_msg *msg, void *arg)
{
	struct addr_info *ctxt = (struct addr_info *)arg;

	ctxt->pending = 0;

	return NL_STOP;
}


static int cb_linklocal_error(_unused struct sockaddr_nl *nla, struct nlmsgerr *err,
		void *arg)
{
	struct addr_info *ctxt = (struct addr_info *)arg;

	ctxt->pending = 0;
	ctxt->ret = err->error;

	return NL_STOP;
}


/* Detect a link local IPV6-address currently assigned to the given interface */
ssize_t netlink_get_interface_linklocal(int ifindex, struct odhcpd_ipaddr **addrs)
{
	struct nl_msg *msg;
	struct ifaddrmsg ifa = {
		.ifa_family = AF_INET6,
		.ifa_prefixlen = 0,
		.ifa_flags = 0,
		.ifa_scope = 0,
		.ifa_index = ifindex, };
	struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);
	struct addr_info ctxt = {
		.ifindex = ifindex,
		.af = AF_INET6,
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

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, cb_linklocal_valid, &ctxt);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, cb_linklocal_finish, &ctxt);
	nl_cb_err(cb, NL_CB_CUSTOM, cb_linklocal_error, &ctxt);

	ctxt.ret = nl_send_auto_complete(rtnl_socket, msg);
	if (ctxt.ret < 0)
		goto free;

	ctxt.ret = 0;
	while (ctxt.pending > 0)
		nl_recvmsgs(rtnl_socket, cb);

	if (ctxt.ret <= 0)
		goto free;

free:
	nlmsg_free(msg);
out:
	nl_cb_put(cb);

	return ctxt.ret;
}


struct neigh_info {
	int ifindex;
	int pending;
	const struct in6_addr *addr;
	int ret;
};


static int cb_proxy_neigh_valid(struct nl_msg *msg, void *arg)
{
	struct neigh_info *ctxt = (struct neigh_info *)arg;
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	struct ndmsg *ndm;
	struct nlattr *nla_dst;

	if (hdr->nlmsg_type != RTM_NEWNEIGH)
		return NL_SKIP;

	ndm = NLMSG_DATA(hdr);
	if (ndm->ndm_family != AF_INET6 ||
			(ctxt->ifindex && ndm->ndm_ifindex != ctxt->ifindex))
		return NL_SKIP;

	if (!(ndm->ndm_flags & NTF_PROXY))
		return NL_SKIP;

	nla_dst = nlmsg_find_attr(hdr, sizeof(*ndm), NDA_DST);
	if (!nla_dst)
		return NL_SKIP;

	if (nla_memcmp(nla_dst,ctxt->addr, 16) == 0)
		ctxt->ret = 1;

	return NL_OK;
}


static int cb_proxy_neigh_finish(_unused struct nl_msg *msg, void *arg)
{
	struct neigh_info *ctxt = (struct neigh_info *)arg;

	ctxt->pending = 0;

	return NL_STOP;
}


static int cb_proxy_neigh_error(_unused struct sockaddr_nl *nla, struct nlmsgerr *err,
		void *arg)
{
	struct neigh_info *ctxt = (struct neigh_info *)arg;

	ctxt->pending = 0;
	ctxt->ret = err->error;

	return NL_STOP;
}

/* Detect an IPV6-address proxy neighbor for the given interface */
int netlink_get_interface_proxy_neigh(int ifindex, const struct in6_addr *addr)
{
	struct nl_msg *msg;
	struct ndmsg ndm = {
		.ndm_family = AF_INET6,
		.ndm_flags = NTF_PROXY,
		.ndm_ifindex = ifindex,
	};
	struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);
	struct neigh_info ctxt = {
		.ifindex = ifindex,
		.addr = addr,
		.ret = 0,
		.pending = 1,
	};

	if (!cb) {
		ctxt.ret = -1;
		goto out;
	}

	msg = nlmsg_alloc_simple(RTM_GETNEIGH, NLM_F_REQUEST | NLM_F_MATCH);

	if (!msg) {
		ctxt.ret = -1;
		goto out;
	}

	nlmsg_append(msg, &ndm, sizeof(ndm), 0);
	nla_put(msg, NDA_DST, sizeof(*addr), addr);

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, cb_proxy_neigh_valid, &ctxt);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, cb_proxy_neigh_finish, &ctxt);
	nl_cb_err(cb, NL_CB_CUSTOM, cb_proxy_neigh_error, &ctxt);

	ctxt.ret = nl_send_auto_complete(rtnl_socket, msg);
	if (ctxt.ret < 0)
		goto free;

	while (ctxt.pending > 0)
		nl_recvmsgs(rtnl_socket, cb);

free:
	nlmsg_free(msg);
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

		if (addr->preferred_lt) {
			int64_t preferred_lt = addr->preferred_lt - now;
			if (preferred_lt < 0)
				preferred_lt = 0;
			else if (preferred_lt > UINT32_MAX)
				preferred_lt = UINT32_MAX;

			cinfo.ifa_prefered = preferred_lt;
		}

		if (addr->valid_lt) {
			int64_t valid_lt = addr->valid_lt - now;
			if (valid_lt <= 0) {
				nlmsg_free(msg);
				return -1;
			}
			else if (valid_lt > UINT32_MAX)
				valid_lt = UINT32_MAX;

			cinfo.ifa_valid = valid_lt;
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
