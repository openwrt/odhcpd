/**
 * Copyright (C) 2012-2013 Steven Barth <steven@midlink.org>
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

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>

#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netpacket/packet.h>

#include <linux/rtnetlink.h>
#include <linux/filter.h>

#include <netlink/msg.h>
#include <netlink/socket.h>
#include <netlink/attr.h>

#include "router.h"
#include "dhcpv6.h"
#include "ndp.h"

struct event_socket {
	struct odhcpd_event ev;
	struct nl_sock *sock;
	int sock_bufsize;
};

static void handle_solicit(void *addr, void *data, size_t len,
		struct interface *iface, void *dest);
static void handle_rtnl_event(struct odhcpd_event *ev);
static int cb_rtnl_valid(struct nl_msg *msg, void *arg);
static void catch_rtnl_err(struct odhcpd_event *e, int error);

static int ping_socket = -1;
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

// Filter ICMPv6 messages of type neighbor soliciation
static struct sock_filter bpf[] = {
	BPF_STMT(BPF_LD | BPF_B | BPF_ABS, offsetof(struct ip6_hdr, ip6_nxt)),
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_ICMPV6, 0, 3),
	BPF_STMT(BPF_LD | BPF_B | BPF_ABS, sizeof(struct ip6_hdr) +
			offsetof(struct icmp6_hdr, icmp6_type)),
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ND_NEIGHBOR_SOLICIT, 0, 1),
	BPF_STMT(BPF_RET | BPF_K, 0xffffffff),
	BPF_STMT(BPF_RET | BPF_K, 0),
};
static const struct sock_fprog bpf_prog = {sizeof(bpf) / sizeof(*bpf), bpf};


// Initialize NDP-proxy
int init_ndp(void)
{
	int val = 2;

	rtnl_event.sock = odhcpd_create_nl_socket(NETLINK_ROUTE);
	if (!rtnl_event.sock)
		goto err;

	rtnl_event.ev.uloop.fd = nl_socket_get_fd(rtnl_event.sock);

	if (nl_socket_set_buffer_size(rtnl_event.sock, rtnl_event.sock_bufsize, 0))
		goto err;

	nl_socket_disable_seq_check(rtnl_event.sock);

	nl_socket_modify_cb(rtnl_event.sock, NL_CB_VALID, NL_CB_CUSTOM,
			cb_rtnl_valid, NULL);

	// Receive IPv6 address, IPv6 routes and neighbor events
	if (nl_socket_add_memberships(rtnl_event.sock, RTNLGRP_IPV6_IFADDR,
				RTNLGRP_IPV6_ROUTE, RTNLGRP_NEIGH, 0))
		goto err;

	odhcpd_register(&rtnl_event.ev);

	// Open ICMPv6 socket
	ping_socket = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMPV6);
	if (ping_socket < 0) {
		syslog(LOG_ERR, "Unable to open raw socket: %s", strerror(errno));
			return -1;
	}

	setsockopt(ping_socket, IPPROTO_RAW, IPV6_CHECKSUM, &val, sizeof(val));

	// This is required by RFC 4861
	val = 255;
	setsockopt(ping_socket, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &val, sizeof(val));
	setsockopt(ping_socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &val, sizeof(val));

	// Filter all packages, we only want to send
	struct icmp6_filter filt;
	ICMP6_FILTER_SETBLOCKALL(&filt);
	setsockopt(ping_socket, IPPROTO_ICMPV6, ICMP6_FILTER, &filt, sizeof(filt));

	return 0;

err:
	if (rtnl_event.sock) {
		nl_socket_free(rtnl_event.sock);
		rtnl_event.sock = NULL;
		rtnl_event.ev.uloop.fd = -1;
	}

	return -1;
}

static void dump_neigh_table(const bool proxy)
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

static void dump_addr_table(void)
{
	struct nl_msg *msg;
	struct ifaddrmsg ifa = {
		.ifa_family = AF_INET6,
	};

	msg = nlmsg_alloc_simple(RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP);
	if (!msg)
		return;

	nlmsg_append(msg, &ifa, sizeof(ifa), 0);

	nl_send_auto_complete(rtnl_event.sock, msg);

	nlmsg_free(msg);
}

int setup_ndp_interface(struct interface *iface, bool enable)
{
	int ret = 0, procfd;
	bool dump_neigh = false;
	char procbuf[64];

	snprintf(procbuf, sizeof(procbuf), "/proc/sys/net/ipv6/conf/%s/proxy_ndp", iface->ifname);
	procfd = open(procbuf, O_WRONLY);

	if (procfd < 0) {
		ret = -1;
		goto out;
	}

	if (iface->ndp_event.uloop.fd > 0) {
		uloop_fd_delete(&iface->ndp_event.uloop);
		close(iface->ndp_event.uloop.fd);
		iface->ndp_event.uloop.fd = -1;

		if (!enable || iface->ndp != RELAYD_RELAY)
			if (write(procfd, "0\n", 2) < 0) {}

		dump_neigh = true;
	}

	if (enable && (iface->ra == RELAYD_SERVER ||
			iface->dhcpv6 == RELAYD_SERVER || iface->ndp == RELAYD_RELAY))
		dump_addr_table();

	if (enable && iface->ndp == RELAYD_RELAY) {
		if (write(procfd, "1\n", 2) < 0) {}

		int sock = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, htons(ETH_P_IPV6));
		if (sock < 0) {
			syslog(LOG_ERR, "Unable to open packet socket: %s",
					strerror(errno));
			ret = -1;
			goto out;
		}

#ifdef PACKET_RECV_TYPE
		int pktt = 1 << PACKET_MULTICAST;
		setsockopt(sock, SOL_PACKET, PACKET_RECV_TYPE, &pktt, sizeof(pktt));
#endif

		if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER,
				&bpf_prog, sizeof(bpf_prog))) {
			syslog(LOG_ERR, "Failed to set BPF: %s", strerror(errno));
			ret = -1;
			goto out;
		}

		struct sockaddr_ll ll = {
			.sll_family = AF_PACKET,
			.sll_ifindex = iface->ifindex,
			.sll_protocol = htons(ETH_P_IPV6),
			.sll_hatype = 0,
			.sll_pkttype = 0,
			.sll_halen = 0,
			.sll_addr = {0},
		};
		bind(sock, (struct sockaddr*)&ll, sizeof(ll));

		struct packet_mreq mreq = {iface->ifindex, PACKET_MR_ALLMULTI, ETH_ALEN, {0}};
		setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

		iface->ndp_event.uloop.fd = sock;
		iface->ndp_event.handle_dgram = handle_solicit;
		odhcpd_register(&iface->ndp_event);

		// If we already were enabled dump is unnecessary, if not do dump
		if (!dump_neigh)
			dump_neigh_table(false);
		else
			dump_neigh = false;
	}

	if (dump_neigh)
		dump_neigh_table(true);

out:
	if (procfd >= 0)
		close(procfd);

	return ret;
}


// Send an ICMP-ECHO. This is less for actually pinging but for the
// neighbor cache to be kept up-to-date.
static void ping6(struct in6_addr *addr,
		const struct interface *iface)
{
	struct sockaddr_in6 dest = { .sin6_family = AF_INET6, .sin6_addr = *addr, .sin6_scope_id = iface->ifindex, };
	struct icmp6_hdr echo = { .icmp6_type = ICMP6_ECHO_REQUEST };
	struct iovec iov = { .iov_base = &echo, .iov_len = sizeof(echo) };

	odhcpd_setup_route(addr, 128, iface, NULL, 128, true);
	odhcpd_send(ping_socket, &dest, &iov, 1, iface);
	odhcpd_setup_route(addr, 128, iface, NULL, 128, false);
}


// Handle solicitations
static void handle_solicit(void *addr, void *data, size_t len,
		struct interface *iface, _unused void *dest)
{
	struct ip6_hdr *ip6 = data;
	struct nd_neighbor_solicit *req = (struct nd_neighbor_solicit*)&ip6[1];
	struct sockaddr_ll *ll = addr;

	// Solicitation is for duplicate address detection
	bool ns_is_dad = IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src);

	// Don't process solicit messages on non relay interfaces
	// Don't forward any non-DAD solicitation for external ifaces
	// TODO: check if we should even forward DADs for them
	if (iface->ndp != RELAYD_RELAY || (iface->external && !ns_is_dad))
		return;

	if (len < sizeof(*ip6) + sizeof(*req))
		return; // Invalid reqicitation

	if (IN6_IS_ADDR_LINKLOCAL(&req->nd_ns_target) ||
			IN6_IS_ADDR_LOOPBACK(&req->nd_ns_target) ||
			IN6_IS_ADDR_MULTICAST(&req->nd_ns_target))
		return; // Invalid target

	char ipbuf[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &req->nd_ns_target, ipbuf, sizeof(ipbuf));
	syslog(LOG_DEBUG, "Got a NS for %s", ipbuf);

	uint8_t mac[6];
	odhcpd_get_mac(iface, mac);
	if (!memcmp(ll->sll_addr, mac, sizeof(mac)))
		return; // Looped back

	struct interface *c;
	list_for_each_entry(c, &interfaces, head)
		if (iface != c && c->ndp == RELAYD_RELAY &&
				(ns_is_dad || !c->external))
			ping6(&req->nd_ns_target, c);
}

// Use rtnetlink to modify kernel routes
static void setup_route(struct in6_addr *addr, struct interface *iface, bool add)
{
	char namebuf[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, addr, namebuf, sizeof(namebuf));
	syslog(LOG_NOTICE, "%s about %s on %s",
			(add) ? "Learned" : "Forgot", namebuf, iface->ifname);

	if (iface->learn_routes)
		odhcpd_setup_route(addr, 128, iface, NULL, 1024, add);
}

// compare prefixes
static int prefixcmp(const void *va, const void *vb)
{
	const struct odhcpd_ipaddr *a = va, *b = vb;
	uint32_t a_pref = ((a->addr.s6_addr[0] & 0xfe) != 0xfc) ? a->preferred : 1;
	uint32_t b_pref = ((b->addr.s6_addr[0] & 0xfe) != 0xfc) ? b->preferred : 1;
	return (a_pref < b_pref) ? 1 : (a_pref > b_pref) ? -1 : 0;
}

// Check address update
static void check_addr_updates(struct interface *iface)
{
	struct odhcpd_ipaddr addr[RELAYD_MAX_ADDRS] = {{IN6ADDR_ANY_INIT, 0, 0, 0, 0}};
	time_t now = odhcpd_time();
	ssize_t len = odhcpd_get_interface_addresses(iface->ifindex, addr, ARRAY_SIZE(addr));

	if (len < 0)
		return;

	qsort(addr, len, sizeof(*addr), prefixcmp);

	for (int i = 0; i < len; ++i) {
		addr[i].addr.s6_addr32[3] = 0;

		if (addr[i].preferred < UINT32_MAX - now)
			addr[i].preferred += now;

		if (addr[i].valid < UINT32_MAX - now)
			addr[i].valid += now;
	}

	bool change = len != (ssize_t)iface->ia_addr_len;
	for (ssize_t i = 0; !change && i < len; ++i)
		if (!IN6_ARE_ADDR_EQUAL(&addr[i].addr, &iface->ia_addr[i].addr) ||
				(addr[i].preferred > 0) != (iface->ia_addr[i].preferred > 0) ||
				addr[i].valid < iface->ia_addr[i].valid ||
				addr[i].preferred < iface->ia_addr[i].preferred)
			change = true;

	if (change)
		dhcpv6_ia_preupdate(iface);

	memcpy(iface->ia_addr, addr, len * sizeof(*addr));
	iface->ia_addr_len = len;

	if (change)
		dhcpv6_ia_postupdate(iface, now);

	if (change) {
		syslog(LOG_INFO, "Raising SIGUSR1 due to address change on %s", iface->ifname);
		raise(SIGUSR1);
	}
}

void setup_addr_for_relaying(struct in6_addr *addr, struct interface *iface, bool add)
{
	struct interface *c;

	list_for_each_entry(c, &interfaces, head) {
		if (iface == c || (c->ndp != RELAYD_RELAY && !add))
			continue;

		odhcpd_setup_proxy_neigh(addr, c, c->ndp == RELAYD_RELAY ? add : false);
	}
}

void setup_ping6(struct in6_addr *addr, struct interface *iface)
{
	struct interface *c;

	list_for_each_entry(c, &interfaces, head) {
		if (iface == c || c->ndp != RELAYD_RELAY ||
				c->external == true)
			continue;

		ping6(addr, c);
	}
}

static struct in6_addr last_solicited;

static void handle_rtnl_event(struct odhcpd_event *e)
{
	struct event_socket *ev_sock = container_of(e, struct event_socket, ev);

	nl_recvmsgs_default(ev_sock->sock);
}


// Handler for neighbor cache entries from the kernel. This is our source
// to learn and unlearn hosts on interfaces.
static int cb_rtnl_valid(struct nl_msg *msg, _unused void *arg)
{
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	struct in6_addr *addr = NULL;
	struct interface *iface = NULL;
	bool add = false;

	switch (hdr->nlmsg_type) {
	case RTM_NEWROUTE:
	case RTM_DELROUTE: {
		struct rtmsg *rtm = nlmsg_data(hdr);

		if (!nlmsg_valid_hdr(hdr, sizeof(*rtm)) ||
				rtm->rtm_family != AF_INET6)
			return NL_SKIP;

		if (rtm->rtm_dst_len == 0) {
			syslog(LOG_INFO, "Raising SIGUSR1 due to default route change");
			raise(SIGUSR1);
		}
		return NL_OK;
	}

	case RTM_NEWADDR:
		add = true;
	case RTM_DELADDR: {
		struct ifaddrmsg *ifa = nlmsg_data(hdr);
		struct nlattr *nla[__IFA_MAX];

		if (!nlmsg_valid_hdr(hdr, sizeof(*ifa)) ||
				ifa->ifa_family != AF_INET6)
			return NL_SKIP;

		iface = odhcpd_get_interface_by_index(ifa->ifa_index);
		if (!iface)
			return NL_SKIP;

		nlmsg_parse(hdr, sizeof(*ifa), nla, __IFA_MAX - 1, NULL);
		if (!nla[IFA_ADDRESS])
			return NL_SKIP;

		addr = nla_data(nla[IFA_ADDRESS]);
		if (!addr || IN6_IS_ADDR_LINKLOCAL(addr) ||
				IN6_IS_ADDR_MULTICAST(addr))
			return NL_SKIP;

		check_addr_updates(iface);

		if (iface->ndp != RELAYD_RELAY)
			break;

		/* handle the relay logic below */
		setup_addr_for_relaying(addr, iface, add);

		if (!add)
			dump_neigh_table(false);
		break;
	}

	case RTM_NEWNEIGH:
		add = true;
	case RTM_DELNEIGH: {
		struct ndmsg *ndm = nlmsg_data(hdr);
		struct nlattr *nla[__NDA_MAX];

		if (!nlmsg_valid_hdr(hdr, sizeof(*ndm)) ||
				ndm->ndm_family != AF_INET6)
			return NL_SKIP;

		iface = odhcpd_get_interface_by_index(ndm->ndm_ifindex);
		if (!iface || iface->ndp != RELAYD_RELAY)
			return (iface ? NL_OK : NL_SKIP);

		nlmsg_parse(hdr, sizeof(*ndm), nla, __NDA_MAX - 1, NULL);
		if (!nla[NDA_DST])
			return NL_SKIP;

		addr = nla_data(nla[NDA_DST]);
		if (!addr || IN6_IS_ADDR_LINKLOCAL(addr) ||
				IN6_IS_ADDR_MULTICAST(addr))
			return NL_SKIP;

		if (ndm->ndm_flags & NTF_PROXY) {
			/* Dump and flush proxy entries */
			if (hdr->nlmsg_type == RTM_NEWNEIGH) {
				odhcpd_setup_proxy_neigh(addr, iface, false);
				setup_route(addr, iface, false);
				dump_neigh_table(false);
			}

			return NL_OK;
		}

		if (add && !(ndm->ndm_state &
				(NUD_REACHABLE | NUD_STALE | NUD_DELAY | NUD_PROBE |
				 NUD_PERMANENT | NUD_NOARP))) {
			if (!IN6_ARE_ADDR_EQUAL(&last_solicited, addr)) {
				last_solicited = *addr;
				setup_ping6(addr, iface);
			}

			return NL_OK;
		}

		setup_addr_for_relaying(addr, iface, add);
		setup_route(addr, iface, add);

		if (!add)
			dump_neigh_table(false);
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

	dump_addr_table();
	return;

err:
	odhcpd_deregister(e);
}
