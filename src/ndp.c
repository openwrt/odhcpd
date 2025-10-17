/**
 * Copyright (C) 2012-2013 Steven Barth <steven@midlink.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License v2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
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

#include <linux/filter.h>
#include <linux/neighbour.h>

#include "dhcpv6.h"
#include "odhcpd.h"


static void ndp_netevent_cb(unsigned long event, struct netevent_handler_info *info);
static void setup_route(struct in6_addr *addr, struct interface *iface, bool add);
static void setup_addr_for_relaying(struct in6_addr *addr, struct interface *iface, bool add);
static void handle_solicit(void *addr, void *data, size_t len,
		struct interface *iface, void *dest);

static struct netevent_handler ndp_netevent_handler = { .cb = ndp_netevent_cb, };

/* Initialize NDP-proxy */
int ndp_init(void)
{
	int ret = 0;

	if (netlink_add_netevent_handler(&ndp_netevent_handler) < 0) {
		error("Failed to add ndp netevent handler");
		ret = -1;
	}

	return ret;
}

int ndp_setup_interface(struct interface *iface, bool enable)
{
	/* Drop everything */
	static const struct sock_filter bpf_drop_filter[] = {
		BPF_STMT(BPF_RET | BPF_K, 0),
	};
	static const struct sock_fprog bpf_drop = {
		.len = ARRAY_SIZE(bpf_drop_filter),
		.filter = (struct sock_filter *)bpf_drop_filter,
	};

	/* Filter ICMPv6 messages of type neighbor solicitation */
	static const struct sock_filter bpf[] = {
		BPF_STMT(BPF_LD | BPF_B | BPF_ABS, offsetof(struct ip6_hdr, ip6_nxt)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_ICMPV6, 0, 3),
		BPF_STMT(BPF_LD | BPF_B | BPF_ABS, sizeof(struct ip6_hdr) +
			 offsetof(struct icmp6_hdr, icmp6_type)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ND_NEIGHBOR_SOLICIT, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, 0xffffffff),
		BPF_STMT(BPF_RET | BPF_K, 0),
	};
	static const struct sock_fprog bpf_prog = {
		.len = ARRAY_SIZE(bpf),
		.filter = (struct sock_filter *)bpf,
	};

	int ret = 0, procfd;
	bool dump_neigh = false;
	char procbuf[64];

	enable = enable && (iface->ndp == MODE_RELAY);

	snprintf(procbuf, sizeof(procbuf), "/proc/sys/net/ipv6/conf/%s/proxy_ndp", iface->ifname);
	procfd = open(procbuf, O_WRONLY);

	if (procfd < 0) {
		ret = -1;
		goto out;
	}

	if (iface->ndp_ping_fd >= 0) {
		close(iface->ndp_ping_fd);
		iface->ndp_ping_fd = -1;
	}

	if (iface->ndp_event.uloop.fd >= 0) {
		uloop_fd_delete(&iface->ndp_event.uloop);
		close(iface->ndp_event.uloop.fd);
		iface->ndp_event.uloop.fd = -1;

		if (!enable)
			if (write(procfd, "0\n", 2) < 0) {}

		dump_neigh = true;
	}

	if (enable) {
		struct sockaddr_ll ll;
		struct packet_mreq mreq;
		struct icmp6_filter filt;
		int val = 2;

		if (write(procfd, "1\n", 2) < 0) {}

		/* Open ICMPv6 socket */
		iface->ndp_ping_fd = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMPV6);
		if (iface->ndp_ping_fd < 0) {
			error("socket(AF_INET6): %m");
			ret = -1;
			goto out;
		}

		if (setsockopt(iface->ndp_ping_fd, SOL_SOCKET, SO_BINDTODEVICE,
			       iface->ifname, strlen(iface->ifname)) < 0) {
			error("setsockopt(SO_BINDTODEVICE): %m");
			ret = -1;
			goto out;
		}

		if (setsockopt(iface->ndp_ping_fd, IPPROTO_RAW, IPV6_CHECKSUM,
			       &val, sizeof(val)) < 0) {
			error("setsockopt(IPV6_CHECKSUM): %m");
			ret = -1;
			goto out;
		}

		/* This is required by RFC 4861 */
		val = 255;
		if (setsockopt(iface->ndp_ping_fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
			       &val, sizeof(val)) < 0) {
			error("setsockopt(IPV6_MULTICAST_HOPS): %m");
			ret = -1;
			goto out;
		}

		if (setsockopt(iface->ndp_ping_fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
			       &val, sizeof(val)) < 0) {
			error("setsockopt(IPV6_UNICAST_HOPS): %m");
			ret = -1;
			goto out;
		}

		/* Filter all packages, we only want to send */
		ICMP6_FILTER_SETBLOCKALL(&filt);
		if (setsockopt(iface->ndp_ping_fd, IPPROTO_ICMPV6, ICMP6_FILTER,
			       &filt, sizeof(filt)) < 0) {
			error("setsockopt(ICMP6_FILTER): %m");
			ret = -1;
			goto out;
		}


		iface->ndp_event.uloop.fd = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, htons(ETH_P_IPV6));
		if (iface->ndp_event.uloop.fd < 0) {
			error("socket(AF_PACKET): %m");
			ret = -1;
			goto out;
		}

#ifdef PACKET_RECV_TYPE
		int pktt = 1 << PACKET_MULTICAST;
		if (setsockopt(iface->ndp_event.uloop.fd, SOL_PACKET, PACKET_RECV_TYPE,
				&pktt, sizeof(pktt)) < 0) {
			error("setsockopt(PACKET_RECV_TYPE): %m");
			ret = -1;
			goto out;
		}
#endif

		/*
		 * AF_PACKET sockets can receive packets as soon as they are
		 * created, so make sure we don't accept anything...
		 */
		if (setsockopt(iface->ndp_event.uloop.fd, SOL_SOCKET, SO_ATTACH_FILTER,
			       &bpf_drop, sizeof(bpf_drop))) {
			error("setsockopt(SO_ATTACH_FILTER): %m");
			ret = -1;
			goto out;
		}

		/* ...and remove stray packets... */
		while (true) {
			char null[1];
			if (recv(iface->ndp_event.uloop.fd, null, sizeof(null), MSG_DONTWAIT | MSG_TRUNC) < 0)
				break;
		}

		/* ...until the real filter is installed */
		if (setsockopt(iface->ndp_event.uloop.fd, SOL_SOCKET, SO_ATTACH_FILTER,
			       &bpf_prog, sizeof(bpf_prog))) {
			error("setsockopt(SO_ATTACH_FILTER): %m");
			ret = -1;
			goto out;
		}

		memset(&ll, 0, sizeof(ll));
		ll.sll_family = AF_PACKET;
		ll.sll_ifindex = iface->ifindex;
		ll.sll_protocol = htons(ETH_P_IPV6);

		if (bind(iface->ndp_event.uloop.fd, (struct sockaddr*)&ll, sizeof(ll)) < 0) {
			error("bind(): %m");
			ret = -1;
			goto out;
		}

		memset(&mreq, 0, sizeof(mreq));
		mreq.mr_ifindex = iface->ifindex;
		mreq.mr_type = PACKET_MR_ALLMULTI;
		mreq.mr_alen = ETH_ALEN;

		if (setsockopt(iface->ndp_event.uloop.fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
				&mreq, sizeof(mreq)) < 0) {
			error("setsockopt(PACKET_ADD_MEMBERSHIP): %m");
			ret = -1;
			goto out;
		}

		iface->ndp_event.handle_dgram = handle_solicit;
		odhcpd_register(&iface->ndp_event);

		/* If we already were enabled dump is unnecessary, if not do dump */
		if (!dump_neigh)
			netlink_dump_neigh_table(false);
		else
			dump_neigh = false;
	}

	if (dump_neigh)
		netlink_dump_neigh_table(true);

 out:
	if (ret < 0) {
		if (iface->ndp_event.uloop.fd >= 0) {
			close(iface->ndp_event.uloop.fd);
			iface->ndp_event.uloop.fd = -1;
		}

		if (iface->ndp_ping_fd >= 0) {
			close(iface->ndp_ping_fd);
			iface->ndp_ping_fd = -1;
		}
	}

	if (procfd >= 0)
		close(procfd);

	return ret;
}

static void ndp_netevent_cb(unsigned long event, struct netevent_handler_info *info)
{
	struct interface *iface = info->iface;
	bool add = true;

	if (!iface || iface->ndp == MODE_DISABLED)
		return;

	switch (event) {
	case NETEV_ADDR6_DEL:
		add = false;
		netlink_dump_neigh_table(false);
		_o_fallthrough;
	case NETEV_ADDR6_ADD:
		setup_addr_for_relaying(&info->addr.in6, iface, add);
		break;
	case NETEV_NEIGH6_DEL:
		add = false;
		_o_fallthrough;
	case NETEV_NEIGH6_ADD:
		if (info->neigh.flags & NTF_PROXY) {
			if (add) {
				netlink_setup_proxy_neigh(&info->neigh.dst.in6, iface->ifindex, false);
				setup_route(&info->neigh.dst.in6, iface, false);
				netlink_dump_neigh_table(false);
			}
			break;
		}

		if (add &&
		    !(info->neigh.state &
		      (NUD_REACHABLE|NUD_STALE|NUD_DELAY|NUD_PROBE|NUD_PERMANENT|NUD_NOARP)))
			break;

		setup_addr_for_relaying(&info->neigh.dst.in6, iface, add);
		setup_route(&info->neigh.dst.in6, iface, add);

		if (!add)
			netlink_dump_neigh_table(false);
		break;
	default:
		break;
	}
}

/* Send an ICMP-ECHO. This is less for actually pinging but for the
 * neighbor cache to be kept up-to-date. */
static void ping6(struct in6_addr *addr,
		struct interface *iface)
{
	struct sockaddr_in6 dest = { .sin6_family = AF_INET6, .sin6_addr = *addr , };
	struct icmp6_hdr echo = { .icmp6_type = ICMP6_ECHO_REQUEST };
	struct iovec iov = { .iov_base = &echo, .iov_len = sizeof(echo) };
	char ipbuf[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, addr, ipbuf, sizeof(ipbuf));
	debug("Pinging for %s on %s", ipbuf, iface->name);

	netlink_setup_route(addr, 128, iface->ifindex, NULL, 128, true);

	/* Use link-local address as source for RFC 4861 compliance and macOS compatibility */
	odhcpd_try_send_with_src(iface->ndp_ping_fd, &dest, &iov, 1, iface);

	netlink_setup_route(addr, 128, iface->ifindex, NULL, 128, false);
}

/* Send a Neighbor Advertisement. */
static void send_na(struct in6_addr *to_addr,
		struct interface *iface, struct in6_addr *for_addr,
		const uint8_t *mac)
{
	struct sockaddr_in6 dest = { .sin6_family = AF_INET6, .sin6_addr = *to_addr };
	char pbuf[sizeof(struct nd_neighbor_advert) + sizeof(struct nd_opt_hdr) + 6];
	struct nd_neighbor_advert *adv = (struct nd_neighbor_advert*)pbuf;
	struct nd_opt_hdr *opt = (struct nd_opt_hdr*) &pbuf[sizeof(struct nd_neighbor_advert)];
	struct iovec iov = { .iov_base = &pbuf, .iov_len = sizeof(pbuf) };
	char ipbuf[INET6_ADDRSTRLEN];

	memset(pbuf, 0, sizeof(pbuf));
	adv->nd_na_hdr = (struct icmp6_hdr) {
		.icmp6_type = ND_NEIGHBOR_ADVERT,
		.icmp6_dataun.icmp6_un_data32 = { ND_NA_FLAG_SOLICITED }
	};
	adv->nd_na_target = *for_addr;
	*opt = (struct nd_opt_hdr) { .nd_opt_type = ND_OPT_TARGET_LINKADDR, .nd_opt_len = 1 };
	memcpy(&pbuf[sizeof(struct nd_neighbor_advert) + sizeof(struct nd_opt_hdr)], mac, 6);

	inet_ntop(AF_INET6, to_addr, ipbuf, sizeof(ipbuf));
	debug("Answering NS to %s on %s", ipbuf, iface->ifname);

	/* Use link-local address as source for RFC 4861 compliance and macOS compatibility */
	odhcpd_try_send_with_src(iface->ndp_ping_fd, &dest, &iov, 1, iface);
}

/* Handle solicitations */
static void handle_solicit(void *addr, void *data, size_t len,
		struct interface *iface, _o_unused void *dest)
{
	struct ip6_hdr *ip6 = data;
	struct nd_neighbor_solicit *req = (struct nd_neighbor_solicit*)&ip6[1];
	struct sockaddr_ll *ll = addr;
	struct interface *c;
	char ipbuf[INET6_ADDRSTRLEN];
	uint8_t mac[6];
	bool is_self_sent;

	/* Solicitation is for duplicate address detection */
	bool ns_is_dad = IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src);

	/* Don't process solicit messages on non relay interfaces
	 * Don't forward any non-DAD solicitation for external ifaces
	 * TODO: check if we should even forward DADs for them */
	if (iface->ndp != MODE_RELAY || (iface->external && !ns_is_dad))
		return;

	if (len < sizeof(*ip6) + sizeof(*req))
		return; // Invalid total length

	if (IN6_IS_ADDR_LINKLOCAL(&req->nd_ns_target) ||
			IN6_IS_ADDR_LOOPBACK(&req->nd_ns_target) ||
			IN6_IS_ADDR_MULTICAST(&req->nd_ns_target))
		return; /* Invalid target */

	inet_ntop(AF_INET6, &req->nd_ns_target, ipbuf, sizeof(ipbuf));
	debug("Got a NS for %s on %s", ipbuf, iface->name);

	odhcpd_get_mac(iface, mac);
	is_self_sent = !memcmp(ll->sll_addr, mac, sizeof(mac));
	if (is_self_sent && !iface->master)
		return; /* Looped back */

	avl_for_each_element(&interfaces, c, avl) {
		if (iface != c && c->ndp == MODE_RELAY &&
				(ns_is_dad || !c->external))
			ping6(&req->nd_ns_target, c);
	}

	/* Catch global-addressed NS and answer them manually.
	 * The kernel won't answer these and cannot route them either. */
	if (!IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst) &&
			IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_src) && !is_self_sent) {
		bool is_proxy_neigh = netlink_get_interface_proxy_neigh(iface->ifindex,
				&req->nd_ns_target) == 1;

		if (is_proxy_neigh)
			send_na(&ip6->ip6_src, iface, &req->nd_ns_target, mac);
	}
}

/* Use rtnetlink to modify kernel routes */
static void setup_route(struct in6_addr *addr, struct interface *iface, bool add)
{
	char ipbuf[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, addr, ipbuf, sizeof(ipbuf));
	debug("%s about %s%s on %s",
	      (add) ? "Learning" : "Forgetting",
	      iface->learn_routes ? "proxy routing for " : "",
	      ipbuf, iface->name);

	if (iface->learn_routes)
		netlink_setup_route(addr, 128, iface->ifindex, NULL, 1024, add);
}

static void setup_addr_for_relaying(struct in6_addr *addr, struct interface *iface, bool add)
{
	struct interface *c;
	char ipbuf[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, addr, ipbuf, sizeof(ipbuf));

	avl_for_each_element(&interfaces, c, avl) {
		if (iface == c || c->ndp != MODE_RELAY)
			continue;

		if (netlink_setup_proxy_neigh(addr, c->ifindex, add)) {
			if (add)
				error("Failed to add proxy neighbour entry %s on %s",
				      ipbuf, c->name);
		} else
			debug("%s proxy neighbour entry %s on %s",
			      add ? "Added" : "Deleted", ipbuf, c->name);
	}
}
