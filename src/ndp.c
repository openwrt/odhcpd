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

#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netpacket/packet.h>

#include <linux/rtnetlink.h>
#include <linux/filter.h>
#include "router.h"
#include "ndp.h"



static void handle_solicit(void *addr, void *data, size_t len,
		struct interface *iface);
static void handle_rtnetlink(void *addr, void *data, size_t len,
		struct interface *iface);
static struct ndp_neighbor* find_neighbor(struct in6_addr *addr, bool strict);
static void modify_neighbor(struct in6_addr *addr, struct interface *iface,
		bool add);
static ssize_t ping6(struct in6_addr *addr,
		const struct interface *iface);

static struct list_head neighbors = LIST_HEAD_INIT(neighbors);
static size_t neighbor_count = 0;
static uint32_t rtnl_seqid = 0;

static int ping_socket = -1;
static struct odhcpd_event ndp_event = {{.fd = -1}, handle_solicit};
static struct odhcpd_event rtnl_event = {{.fd = -1}, handle_rtnetlink};


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
	// Setup netlink socket
	if ((rtnl_event.uloop.fd = odhcpd_open_rtnl()) < 0)
		return -1;

	// Receive netlink neighbor and ip-address events
	uint32_t group = RTNLGRP_IPV6_IFADDR;
	setsockopt(rtnl_event.uloop.fd, SOL_NETLINK,
			NETLINK_ADD_MEMBERSHIP, &group, sizeof(group));
	group = RTNLGRP_IPV6_ROUTE;
	setsockopt(rtnl_event.uloop.fd, SOL_NETLINK,
			NETLINK_ADD_MEMBERSHIP, &group, sizeof(group));

	// Synthesize initial address events
	struct {
		struct nlmsghdr nh;
		struct ifaddrmsg ifa;
	} req2 = {
		{sizeof(req2), RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP,
				++rtnl_seqid, 0},
		{.ifa_family = AF_INET6}
	};
	send(rtnl_event.uloop.fd, &req2, sizeof(req2), MSG_DONTWAIT);
	odhcpd_register(&rtnl_event);


	// Create socket for intercepting NDP
	int sock = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
			htons(ETH_P_ALL)); // ETH_P_ALL for ingress + egress
	if (sock < 0) {
		syslog(LOG_ERR, "Unable to open packet socket: %s",
				strerror(errno));
		return -1;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER,
			&bpf_prog, sizeof(bpf_prog))) {
		syslog(LOG_ERR, "Failed to set BPF: %s", strerror(errno));
		return -1;
	}

	ndp_event.uloop.fd = sock;
	odhcpd_register(&ndp_event);

	// Open ICMPv6 socket
	ping_socket = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMPV6);

	int val = 2;
	setsockopt(ping_socket, IPPROTO_RAW, IPV6_CHECKSUM, &val, sizeof(val));

	// This is required by RFC 4861
	val = 255;
	setsockopt(ping_socket, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &val, sizeof(val));
	setsockopt(ping_socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &val, sizeof(val));

	// Filter all packages, we only want to send
	struct icmp6_filter filt;
	ICMP6_FILTER_SETBLOCKALL(&filt);
	setsockopt(ping_socket, IPPROTO_ICMPV6, ICMP6_FILTER, &filt, sizeof(filt));


	// Netlink socket, continued...
	group = RTNLGRP_NEIGH;
	setsockopt(rtnl_event.uloop.fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group));

	// Synthesize initial neighbor events
	struct {
		struct nlmsghdr nh;
		struct ndmsg ndm;
	} req = {
		{sizeof(req), RTM_GETNEIGH, NLM_F_REQUEST | NLM_F_DUMP,
				++rtnl_seqid, 0},
		{.ndm_family = AF_INET6}
	};
	send(rtnl_event.uloop.fd, &req, sizeof(req), MSG_DONTWAIT);

	return 0;
}


int setup_ndp_interface(struct interface *iface, bool enable)
{
	struct packet_mreq mreq = {iface->ifindex, PACKET_MR_ALLMULTI, ETH_ALEN, {0}};
	setsockopt(ndp_event.uloop.fd, SOL_PACKET, PACKET_DROP_MEMBERSHIP, &mreq, sizeof(mreq));

	struct ndp_neighbor *c, *n;
	list_for_each_entry_safe(c, n, &neighbors, head)
		if (c->iface == iface && (c->timeout == 0 || iface->ndp != RELAYD_RELAY || !enable))
			modify_neighbor(&c->addr, c->iface, false);

	if (enable && iface->ndp == RELAYD_RELAY) {
		setsockopt(ndp_event.uloop.fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

		if (iface->static_ndp_len) {
			char *entry = alloca(iface->static_ndp_len), *saveptr;
			if (!entry) {
				syslog(LOG_ERR, "Alloca failed for static NDP list");
				return -1;
			}
			memcpy(entry, iface->static_ndp, iface->static_ndp_len);

			for (entry = strtok_r(entry, " ", &saveptr); entry; entry = strtok_r(NULL, " ", &saveptr)) {
				char *sep;
				struct ndp_neighbor *n = malloc(sizeof(*n));
				if (!n) {
					syslog(LOG_ERR, "Malloc failed for static NDP-prefix %s", entry);
					return -1;
				}

				n->iface = iface;
				n->timeout = 0;

				sep = strchr(entry, '/');
				if (!sep) {
					free(n);
					syslog(LOG_ERR, "Invalid static NDP-prefix %s", entry);
					return -1;
				}

				*sep = 0;
				n->len = atoi(sep + 1);
				if (inet_pton(AF_INET6, entry, &n->addr) != 1 || n->len > 128) {
					free(n);
					syslog(LOG_ERR, "Invalid static NDP-prefix %s/%s", entry, sep + 1);
					return -1;
				}

				list_add(&n->head, &neighbors);
			}
		}
	}

	return 0;
}


// Send an ICMP-ECHO. This is less for actually pinging but for the
// neighbor cache to be kept up-to-date.
static ssize_t ping6(struct in6_addr *addr,
		const struct interface *iface)
{
	struct sockaddr_in6 dest = {AF_INET6, 0, 0, *addr, 0};
	struct icmp6_hdr echo = {.icmp6_type = ICMP6_ECHO_REQUEST};
	struct iovec iov = {&echo, sizeof(echo)};

	// Linux seems to not honor IPV6_PKTINFO on raw-sockets, so work around
	setsockopt(ping_socket, SOL_SOCKET, SO_BINDTODEVICE,
			iface->ifname, sizeof(iface->ifname));
	return odhcpd_send(ping_socket, &dest, &iov, 1, iface);
}


// Handle solicitations
static void handle_solicit(void *addr, void *data, size_t len,
		struct interface *iface)
{
	struct ip6_hdr *ip6 = data;
	struct nd_neighbor_solicit *req = (struct nd_neighbor_solicit*)&ip6[1];
	struct sockaddr_ll *ll = addr;

	// Solicitation is for duplicate address detection
	bool ns_is_dad = IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src);

	// Don't forward any non-DAD solicitation for external ifaces
	// TODO: check if we should even forward DADs for them
	if (iface->external && !ns_is_dad)
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
	if (!memcmp(ll->sll_addr, mac, sizeof(mac)) &&
			ll->sll_pkttype != PACKET_OUTGOING)
		return; // Looped back

	time_t now = time(NULL);

	struct ndp_neighbor *n = find_neighbor(&req->nd_ns_target, false);
	if (n && (n->iface || abs(n->timeout - now) < 5)) {
		syslog(LOG_DEBUG, "%s is on %s", ipbuf,
				(n->iface) ? n->iface->ifname : "<pending>");
		if (!n->iface || n->iface == iface)
			return;

		// Found on other interface, answer with advertisement
		struct {
			struct nd_neighbor_advert body;
			struct nd_opt_hdr opt_ll_hdr;
			uint8_t mac[6];
		} advert = {
			.body = {
				.nd_na_hdr = {ND_NEIGHBOR_ADVERT,
					0, 0, {{0}}},
				.nd_na_target = req->nd_ns_target,
			},
			.opt_ll_hdr = {ND_OPT_TARGET_LINKADDR, 1},
		};

		memcpy(advert.mac, mac, sizeof(advert.mac));
		advert.body.nd_na_flags_reserved = ND_NA_FLAG_ROUTER |
				ND_NA_FLAG_SOLICITED;

		struct sockaddr_in6 dest = {AF_INET6, 0, 0, ALL_IPV6_NODES, 0};
		if (!ns_is_dad) // If not DAD, then unicast to source
			dest.sin6_addr = ip6->ip6_src;

		// Linux seems to not honor IPV6_PKTINFO on raw-sockets, so work around
		setsockopt(ping_socket, SOL_SOCKET, SO_BINDTODEVICE,
					iface->ifname, sizeof(iface->ifname));
		struct iovec iov = {&advert, sizeof(advert)};
		odhcpd_send(ping_socket, &dest, &iov, 1, iface);
	} else {
		// Send echo to all other interfaces to see where target is on
		// This will trigger neighbor discovery which is what we want.
		// We will observe the neighbor cache to see results.

		ssize_t sent = 0;
		struct interface *c;
		list_for_each_entry(c, &interfaces, head)
			if (iface->ndp == RELAYD_RELAY && iface != c &&
					(!ns_is_dad || !c->external == false))
				sent += ping6(&req->nd_ns_target, c);

		if (sent > 0) // Sent a ping, add pending neighbor entry
			modify_neighbor(&req->nd_ns_target, NULL, true);
	}
}


void odhcpd_setup_route(const struct in6_addr *addr, int prefixlen,
		const struct interface *iface, const struct in6_addr *gw, bool add)
{
	struct req {
		struct nlmsghdr nh;
		struct rtmsg rtm;
		struct rtattr rta_dst;
		struct in6_addr dst_addr;
		struct rtattr rta_oif;
		uint32_t ifindex;
		struct rtattr rta_table;
		uint32_t table;
		struct rtattr rta_gw;
		struct in6_addr gw;
	} req = {
		{sizeof(req), 0, NLM_F_REQUEST, ++rtnl_seqid, 0},
		{AF_INET6, prefixlen, 0, 0, 0, 0, 0, 0, 0},
		{sizeof(struct rtattr) + sizeof(struct in6_addr), RTA_DST},
		*addr,
		{sizeof(struct rtattr) + sizeof(uint32_t), RTA_OIF},
		iface->ifindex,
		{sizeof(struct rtattr) + sizeof(uint32_t), RTA_TABLE},
		RT_TABLE_MAIN,
		{sizeof(struct rtattr) + sizeof(struct in6_addr), RTA_GATEWAY},
		IN6ADDR_ANY_INIT,
	};

	if (gw)
		req.gw = *gw;

	if (add) {
		req.nh.nlmsg_type = RTM_NEWROUTE;
		req.nh.nlmsg_flags |= (NLM_F_CREATE | NLM_F_REPLACE);
		req.rtm.rtm_protocol = RTPROT_BOOT;
		req.rtm.rtm_scope = (gw) ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK;
		req.rtm.rtm_type = RTN_UNICAST;
	} else {
		req.nh.nlmsg_type = RTM_DELROUTE;
		req.rtm.rtm_scope = RT_SCOPE_NOWHERE;
	}

	size_t reqlen = (gw) ? sizeof(req) : offsetof(struct req, rta_gw);
	send(rtnl_event.uloop.fd, &req, reqlen, MSG_DONTWAIT);
}

// Use rtnetlink to modify kernel routes
static void setup_route(struct in6_addr *addr, struct interface *iface,
		bool add)
{
	char namebuf[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, addr, namebuf, sizeof(namebuf));
	syslog(LOG_NOTICE, "%s about %s on %s", (add) ? "Learned" : "Forgot",
			namebuf, (iface) ? iface->ifname : "<pending>");

	if (!iface || !iface->learn_routes)
		return;

	odhcpd_setup_route(addr, 128, iface, NULL, add);
}

static void free_neighbor(struct ndp_neighbor *n)
{
	setup_route(&n->addr, n->iface, false);
	list_del(&n->head);
	free(n);
	--neighbor_count;
}

static struct ndp_neighbor* find_neighbor(struct in6_addr *addr, bool strict)
{
	time_t now = time(NULL);
	struct ndp_neighbor *n, *e;
	list_for_each_entry_safe(n, e, &neighbors, head) {
		if ((!strict && !odhcpd_bmemcmp(&n->addr, addr, n->len)) ||
				(n->len == 128 && IN6_ARE_ADDR_EQUAL(&n->addr, addr)))
			return n;

		if (!n->iface && abs(n->timeout - now) >= 5)
			free_neighbor(n);
	}
	return NULL;
}


// Modified our own neighbor-entries
static void modify_neighbor(struct in6_addr *addr,
		struct interface *iface, bool add)
{
	if (!addr || (void*)addr == (void*)iface)
		return;

	struct ndp_neighbor *n = find_neighbor(addr, true);
	if (!add) { // Delete action
		if (n && (!n->iface || n->iface == iface))
			free_neighbor(n);
	} else if (!n) { // No entry yet, add one if possible
		if (neighbor_count >= NDP_MAX_NEIGHBORS ||
				!(n = malloc(sizeof(*n))))
			return;

		n->len = 128;
		n->addr = *addr;
		n->iface = iface;
		if (!n->iface)
			time(&n->timeout);
		list_add(&n->head, &neighbors);
		++neighbor_count;
		setup_route(addr, n->iface, add);
	} else if (n->iface == iface) {
		if (!n->iface)
			time(&n->timeout);
	} else if (iface && (!n->iface ||
			(!iface->external && n->iface->external))) {
		setup_route(addr, n->iface, false);
		n->iface = iface;
		setup_route(addr, n->iface, add);
	}
	// TODO: In case a host switches interfaces we might want
	// to set its old neighbor entry to NUD_STALE and ping it
	// on the old interface to confirm if the MACs match.
}


// Handler for neighbor cache entries from the kernel. This is our source
// to learn and unlearn hosts on interfaces.
static void handle_rtnetlink(_unused void *addr, void *data, size_t len,
		_unused struct interface *iface)
{
	for (struct nlmsghdr *nh = data; NLMSG_OK(nh, len);
			nh = NLMSG_NEXT(nh, len)) {
		struct rtmsg *rtm = NLMSG_DATA(nh);
		if ((nh->nlmsg_type == RTM_NEWROUTE ||
				nh->nlmsg_type == RTM_DELROUTE) &&
				rtm->rtm_dst_len == 0)
			raise(SIGUSR1); // Inform about a change in default route

		struct ndmsg *ndm = NLMSG_DATA(nh);
		struct ifaddrmsg *ifa = NLMSG_DATA(nh);
		if (nh->nlmsg_type != RTM_NEWNEIGH
				&& nh->nlmsg_type != RTM_DELNEIGH
				&& nh->nlmsg_type != RTM_NEWADDR
				&& nh->nlmsg_type != RTM_DELADDR)
			continue; // Unrelated message type
		bool is_addr = (nh->nlmsg_type == RTM_NEWADDR
				|| nh->nlmsg_type == RTM_DELADDR);

		// Family and ifindex are on the same offset for NEIGH and ADDR
		if (NLMSG_PAYLOAD(nh, 0) < sizeof(*ndm)
				|| ndm->ndm_family != AF_INET6)
			continue; //

		// Lookup interface
		struct interface *iface;
		if (!(iface = odhcpd_get_interface_by_index(ndm->ndm_ifindex)))
			continue;

		// Data to retrieve
		size_t rta_offset = (is_addr) ? sizeof(*ifa) : sizeof(*ndm);
		uint16_t atype = (is_addr) ? IFA_ADDRESS : NDA_DST;
		ssize_t alen = NLMSG_PAYLOAD(nh, rta_offset);
		struct in6_addr *addr = NULL;

		for (struct rtattr *rta = (void*)(((uint8_t*)ndm) + rta_offset);
				RTA_OK(rta, alen); rta = RTA_NEXT(rta, alen))
			if (rta->rta_type == atype &&
					RTA_PAYLOAD(rta) >= sizeof(*addr))
				addr = RTA_DATA(rta);

		// Address not specified or unrelated
		if (!addr || IN6_IS_ADDR_LINKLOCAL(addr) ||
				IN6_IS_ADDR_MULTICAST(addr))
			continue;

		// Check for states
		bool add;
		if (is_addr)
			add = (nh->nlmsg_type == RTM_NEWADDR);
		else
			add = (nh->nlmsg_type == RTM_NEWNEIGH && (ndm->ndm_state &
				(NUD_REACHABLE | NUD_STALE | NUD_DELAY | NUD_PROBE
						| NUD_PERMANENT | NUD_NOARP)));

		if (iface->ndp == RELAYD_RELAY)
			modify_neighbor(addr, iface, add);

		if (is_addr && iface->ra == RELAYD_SERVER)
			raise(SIGUSR1); // Inform about a change in addresses

		if (is_addr && iface->dhcpv6 == RELAYD_SERVER)
			iface->ia_reconf = true;

		if (iface->ndp == RELAYD_RELAY && is_addr && iface->master) {
			// Replay address changes on all slave interfaces
			nh->nlmsg_flags = NLM_F_REQUEST;

			if (nh->nlmsg_type == RTM_NEWADDR)
				nh->nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;

			struct interface *c;
			list_for_each_entry(c, &interfaces, head) {
				if (c->ndp == RELAYD_RELAY && !c->master) {
					ifa->ifa_index = c->ifindex;
					send(rtnl_event.uloop.fd, nh, nh->nlmsg_len, MSG_DONTWAIT);
				}
			}
		}

		/* TODO: See if this is required for optimal operation
		// Keep neighbor entries alive so we don't loose routes
		 */
		if (add && (ndm->ndm_state & NUD_STALE))
			ping6(addr, iface);
	}
}
