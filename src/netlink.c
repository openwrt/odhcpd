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

#include "odhcpd.h"

static struct nl_sock *rtnl_socket = NULL;


int netlink_init(void)
{
	if (!(rtnl_socket = netlink_create_socket(NETLINK_ROUTE))) {
		syslog(LOG_ERR, "Unable to open nl socket: %s", strerror(errno));
		return -1;
	}

	return 0;
}


struct nl_sock *netlink_create_socket(int protocol)
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
		const struct interface *iface, const struct in6_addr *gw,
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
	nla_put_u32(msg, RTA_OIF, iface->ifindex);
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
		const struct interface *iface, const bool add)
{
	struct nl_msg *msg;
	struct ndmsg ndm = {
		.ndm_family = AF_INET6,
		.ndm_flags = NTF_PROXY,
		.ndm_ifindex = iface->ifindex,
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
		const struct interface *iface, const bool v6,
		const bool add)
{
	struct nl_msg *msg;
	struct ifaddrmsg ifa = {
		.ifa_family = v6 ? AF_INET6 : AF_INET,
		.ifa_prefixlen = addr->prefix,
		.ifa_flags = 0,
		.ifa_scope = 0,
		.ifa_index = iface->ifindex, };
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
