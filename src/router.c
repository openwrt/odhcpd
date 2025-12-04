/**
 * Copyright (C) 2012-2013 Steven Barth <steven@midlink.org>
 * Copyright (C) 2018 Hans Dedecker <dedeckeh@gmail.com>
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

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <net/route.h>

#include <libubox/utils.h>

#include "router.h"
#include "odhcpd.h"


static void forward_router_solicitation(const struct interface *iface);
static void forward_router_advertisement(const struct interface *iface, uint8_t *data, size_t len);

static void handle_icmpv6(void *addr, void *data, size_t len,
		struct interface *iface, void *dest);
static void trigger_router_advert(struct uloop_timeout *event);
static void router_netevent_cb(unsigned long event, struct netevent_handler_info *info);

static struct netevent_handler router_netevent_handler = { .cb = router_netevent_cb, };

static FILE *fp_route = NULL;


#define TIME_LEFT(t1, now) ((t1) != UINT32_MAX ? (t1) - (now) : UINT32_MAX)

int router_init(void)
{
	int ret = 0;

	if (!(fp_route = fopen("/proc/net/ipv6_route", "r"))) {
		error("fopen(/proc/net/ipv6_route): %m");
		ret = -1;
		goto out;
	}

	if (netlink_add_netevent_handler(&router_netevent_handler) < 0) {
		error("Failed to add netevent handler");
		ret = -1;
	}

out:
	if (ret < 0 && fp_route) {
		fclose(fp_route);
		fp_route = NULL;
	}

	return ret;
}


int router_setup_interface(struct interface *iface, bool enable)
{
	int ret = 0;

	enable = enable && (iface->ra != MODE_DISABLED);

	if (!fp_route) {
		ret = -1;
		goto out;
	}


	if (!enable && iface->router_event.uloop.fd >= 0) {
		if (!iface->master) {
			uloop_timeout_cancel(&iface->timer_rs);
			iface->timer_rs.cb = NULL;

			trigger_router_advert(&iface->timer_rs);
		}

		uloop_fd_delete(&iface->router_event.uloop);
		close(iface->router_event.uloop.fd);
		iface->router_event.uloop.fd = -1;
	} else if (enable) {
		struct icmp6_filter filt;
		struct ipv6_mreq mreq;
		int val = 2;

		if (iface->router_event.uloop.fd < 0) {
			/* Open ICMPv6 socket */
			iface->router_event.uloop.fd = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC,
								IPPROTO_ICMPV6);
			if (iface->router_event.uloop.fd < 0) {
				error("socket(AF_INET6): %m");
				ret = -1;
				goto out;
			}

			if (setsockopt(iface->router_event.uloop.fd, SOL_SOCKET, SO_BINDTODEVICE,
						iface->ifname, strlen(iface->ifname)) < 0) {
				error("setsockopt(SO_BINDTODEVICE): %m");
				ret = -1;
				goto out;
			}

			/* Let the kernel compute our checksums */
			if (setsockopt(iface->router_event.uloop.fd, IPPROTO_RAW, IPV6_CHECKSUM,
						&val, sizeof(val)) < 0) {
				error("setsockopt(IPV6_CHECKSUM): %m");
				ret = -1;
				goto out;
			}

			/* This is required by RFC 4861 */
			val = 255;
			if (setsockopt(iface->router_event.uloop.fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
						&val, sizeof(val)) < 0) {
				error("setsockopt(IPV6_MULTICAST_HOPS): %m");
				ret = -1;
				goto out;
			}

			if (setsockopt(iface->router_event.uloop.fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
						&val, sizeof(val)) < 0) {
				error("setsockopt(IPV6_UNICAST_HOPS): %m");
				ret = -1;
				goto out;
			}

			/* We need to know the source interface */
			val = 1;
			if (setsockopt(iface->router_event.uloop.fd, IPPROTO_IPV6, IPV6_RECVPKTINFO,
						&val, sizeof(val)) < 0) {
				error("setsockopt(IPV6_RECVPKTINFO): %m");
				ret = -1;
				goto out;
			}

			if (setsockopt(iface->router_event.uloop.fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
						&val, sizeof(val)) < 0) {
				error("setsockopt(IPV6_RECVHOPLIMIT): %m");
				ret = -1;
				goto out;
			}

			/* Don't loop back */
			val = 0;
			if (setsockopt(iface->router_event.uloop.fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
						&val, sizeof(val)) < 0) {
				error("setsockopt(IPV6_MULTICAST_LOOP): %m");
				ret = -1;
				goto out;
			}

			/* Filter ICMPv6 package types */
			ICMP6_FILTER_SETBLOCKALL(&filt);
			ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filt);
			ICMP6_FILTER_SETPASS(ND_ROUTER_SOLICIT, &filt);
			if (setsockopt(iface->router_event.uloop.fd, IPPROTO_ICMPV6, ICMP6_FILTER,
						&filt, sizeof(filt)) < 0) {
				error("setsockopt(ICMP6_FILTER): %m");
				ret = -1;
				goto out;
			}

			iface->router_event.handle_dgram = handle_icmpv6;
			iface->ra_sent = 0;
			odhcpd_register(&iface->router_event);
		} else {
			uloop_timeout_cancel(&iface->timer_rs);
			iface->timer_rs.cb = NULL;

			memset(&mreq, 0, sizeof(mreq));
			mreq.ipv6mr_interface = iface->ifindex;
			inet_pton(AF_INET6, ALL_IPV6_NODES, &mreq.ipv6mr_multiaddr);
			setsockopt(iface->router_event.uloop.fd, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP,
				   &mreq, sizeof(mreq));

			inet_pton(AF_INET6, ALL_IPV6_ROUTERS, &mreq.ipv6mr_multiaddr);
			setsockopt(iface->router_event.uloop.fd, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP,
				   &mreq, sizeof(mreq));
		}

		memset(&mreq, 0, sizeof(mreq));
		mreq.ipv6mr_interface = iface->ifindex;
		inet_pton(AF_INET6, ALL_IPV6_ROUTERS, &mreq.ipv6mr_multiaddr);

		if (iface->ra == MODE_RELAY && iface->master) {
			inet_pton(AF_INET6, ALL_IPV6_NODES, &mreq.ipv6mr_multiaddr);
			forward_router_solicitation(iface);
		} else if (iface->ra == MODE_SERVER) {
			iface->timer_rs.cb = trigger_router_advert;
			uloop_timeout_set(&iface->timer_rs, 1000);
		}

		if (setsockopt(iface->router_event.uloop.fd, IPPROTO_IPV6,
					IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
			ret = -1;
			error("setsockopt(IPV6_ADD_MEMBERSHIP): %m");
			goto out;
		}
	}
out:
	if (ret < 0 && iface->router_event.uloop.fd >= 0) {
		if (iface->router_event.uloop.registered)
			uloop_fd_delete(&iface->router_event.uloop);

		close(iface->router_event.uloop.fd);
		iface->router_event.uloop.fd = -1;
	}

	return ret;
}


static void router_netevent_cb(unsigned long event, struct netevent_handler_info *info)
{
	struct interface *iface;

	switch (event) {
	case NETEV_IFINDEX_CHANGE:
		iface = info->iface;
		if (iface && iface->router_event.uloop.fd >= 0) {
			if (iface->router_event.uloop.registered)
				uloop_fd_delete(&iface->router_event.uloop);

			close(iface->router_event.uloop.fd);
			iface->router_event.uloop.fd = -1;
		}
		break;
	case NETEV_ROUTE6_ADD:
	case NETEV_ROUTE6_DEL:
		if (info->rt.dst_len)
			break;

		avl_for_each_element(&interfaces, iface, avl) {
			if (iface->ra == MODE_SERVER && !iface->master)
				uloop_timeout_set(&iface->timer_rs, 1000);
		}
		break;
	case NETEV_ADDR6LIST_CHANGE:
		iface = info->iface;
		if (iface && iface->ra == MODE_SERVER && !iface->master)
			uloop_timeout_set(&iface->timer_rs, 1000);
		break;
	default:
		break;
	}
}


static bool router_icmpv6_valid(struct sockaddr_in6 *source, uint8_t *data, size_t len)
{
	struct icmp6_hdr *hdr = (struct icmp6_hdr *)data;
	struct icmpv6_opt *opt, *end = (struct icmpv6_opt*)&data[len];

	/* Hoplimit is already checked in odhcpd_receive_packets */
	if (len < sizeof(*hdr) || hdr->icmp6_code)
		return false;

	switch (hdr->icmp6_type) {
	case ND_ROUTER_ADVERT:
		if (!IN6_IS_ADDR_LINKLOCAL(&source->sin6_addr))
			return false;

		opt = (struct icmpv6_opt *)((struct nd_router_advert *)data + 1);
		break;

	case ND_ROUTER_SOLICIT:
		opt = (struct icmpv6_opt *)((struct nd_router_solicit *)data + 1);
		break;

	default:
		return false;
	}

	icmpv6_for_each_option(opt, opt, end)
		if (opt->type == ND_OPT_SOURCE_LINKADDR &&
				IN6_IS_ADDR_UNSPECIFIED(&source->sin6_addr) &&
				hdr->icmp6_type == ND_ROUTER_SOLICIT)
			return false;

	/* Check all options parsed successfully */
	return opt == end;
}


/* Detect whether a default route exists, also find the source prefixes */
static bool parse_routes(struct odhcpd_ipaddr *n, ssize_t len)
{
	struct odhcpd_ipaddr p = {
		.addr.in6 = IN6ADDR_ANY_INIT,
		.prefix_len = 0,
		.dprefix_len = 0,
		.preferred_lt = 0,
		.valid_lt = 0
	};
	bool found_default = false;
	char line[512], ifname[16];

	rewind(fp_route);

	while (fgets(line, sizeof(line), fp_route)) {
		uint32_t rflags;
		if (sscanf(line, "00000000000000000000000000000000 00 "
				"%*s %*s %*s %*s %*s %*s %*s %15s", ifname) &&
				strcmp(ifname, "lo")) {
			found_default = true;
		} else if (sscanf(line, "%8" SCNx32 "%8" SCNx32 "%*8" SCNx32 "%*8" SCNx32 " %hhx %*s "
				"%*s 00000000000000000000000000000000 %*s %*s %*s %" SCNx32 " lo",
				&p.addr.in6.s6_addr32[0], &p.addr.in6.s6_addr32[1], &p.prefix_len, &rflags) &&
				p.prefix_len > 0 && (rflags & RTF_NONEXTHOP) && (rflags & RTF_REJECT)) {
			// Find source prefixes by scanning through unreachable-routes
			p.addr.in6.s6_addr32[0] = htonl(p.addr.in6.s6_addr32[0]);
			p.addr.in6.s6_addr32[1] = htonl(p.addr.in6.s6_addr32[1]);

			for (ssize_t i = 0; i < len; ++i) {
				if (n[i].prefix_len <= 64 && n[i].prefix_len >= p.prefix_len &&
				    !odhcpd_bmemcmp(&p.addr.in6, &n[i].addr.in6, p.prefix_len)) {
					n[i].dprefix_len = p.prefix_len;
					break;
				}
			}
		}
	}

	return found_default;
}

static int calc_adv_interval(struct interface *iface, uint32_t lowest_found_lifetime,
				uint32_t *maxival)
{
	uint32_t minival = iface->ra_mininterval;
	int msecs;

	*maxival = iface->ra_maxinterval;

	if (*maxival > lowest_found_lifetime)
		*maxival = lowest_found_lifetime;

	odhcpd_urandom(&msecs, sizeof(msecs));
	msecs = (labs(msecs) % ((*maxival != minival) ? (*maxival - minival)*1000 : 500)) +
			minival*1000;

	/* RFC 2461 6.2.4 For the first MAX_INITIAL_RTR_ADVERTISEMENTS advertisements
	 * if the timer is bigger than MAX_INITIAL_RTR_ADVERT_INTERVAL it should be
	 * set to MAX_INITIAL_RTR_ADVERT_INTERVAL
	 * Off by one as an initial interval timer has already expired
	 */
	if ((iface->ra_sent + 1) < MaxInitialRtAdvs && msecs > MaxInitialRtrAdvInterval*1000)
		msecs = MaxInitialRtrAdvInterval*1000;

	return msecs;
}

static uint32_t calc_ra_lifetime(struct interface *iface, uint32_t maxival)
{
	uint32_t lifetime = iface->max_preferred_lifetime;

	if (iface->ra_lifetime > 0) {
		lifetime = iface->ra_lifetime;
	}

	if (lifetime > 0 && lifetime < maxival)
		lifetime = maxival;
	else if (lifetime > RouterLifetime)
		lifetime = RouterLifetime;

	return lifetime;
}

enum {
	IOV_RA_ADV=0,
	IOV_RA_PFXS,
	IOV_RA_ROUTES,
	IOV_RA_DNS,
	IOV_RA_SEARCH,
	IOV_RA_PREF64,
	IOV_RA_DNR,
	IOV_RA_ADV_INTERVAL,
	IOV_RA_CAPT_PORTAL,
	IOV_RA_TOTAL,
};

struct adv_msg {
	struct nd_router_advert h;
	struct icmpv6_opt lladdr;
	struct nd_opt_mtu mtu;
};

struct nd_opt_dns_server {
	uint8_t type;
	uint8_t len;
	uint8_t pad;
	uint8_t pad2;
	uint32_t lifetime;
	struct in6_addr addr[];
};

struct nd_opt_search_list {
	uint8_t type;
	uint8_t len;
	uint16_t reserved;
	uint32_t lifetime;
	uint8_t name[];
} _o_packed;

struct nd_opt_route_info {
	uint8_t type;
	uint8_t len;
	uint8_t prefix_len;
	uint8_t flags;
	uint32_t lifetime;
	uint32_t addr[4];
};

struct nd_opt_pref64_info {
	uint8_t type;
	uint8_t len;
	uint16_t lifetime_plc;
	uint32_t prefix[3];
};

struct nd_opt_dnr_info {
	uint8_t type;
	uint8_t len;
	uint16_t priority;
	uint32_t lifetime;
	uint16_t adn_len;
	uint8_t body[];
};

struct nd_opt_capt_portal {
	uint8_t type;
	uint8_t len;
	uint8_t data[];
};

/* IPv6 RA PIOs */
inline static int router_compare_pio_addr(const struct ra_pio *pio, const struct odhcpd_ipaddr *addr)
{
	uint8_t cmp_len = max(64, max(pio->length, addr->prefix_len));

	return odhcpd_bmemcmp(&pio->prefix, &addr->addr.in6, cmp_len);
}

static struct ra_pio *router_find_ra_pio(struct interface *iface,
	struct odhcpd_ipaddr *addr)
{
	for (size_t i = 0; i < iface->pio_cnt; i++) {
		struct ra_pio *cur_pio = &iface->pios[i];

		if (!router_compare_pio_addr(cur_pio, addr))
			return cur_pio;
	}

	return NULL;
}

static void router_add_ra_pio(struct interface *iface,
	struct odhcpd_ipaddr *addr)
{
	char ipv6_str[INET6_ADDRSTRLEN];
	struct ra_pio *new_pios, *pio;

	pio = router_find_ra_pio(iface, addr);
	if (pio) {
		if (memcmp(&pio->prefix, &addr->addr.in6, sizeof(struct in6_addr)) != 0 ||
		    pio->length != addr->prefix_len)
		{
			char new_ipv6_str[INET6_ADDRSTRLEN];

			iface->pio_update = true;
			warn("rfc9096: %s: changed %s/%u -> %s/%u",
			     iface->ifname,
			     inet_ntop(AF_INET6, &pio->prefix, ipv6_str, sizeof(ipv6_str)),
			     pio->length,
			     inet_ntop(AF_INET6, &addr->addr.in6, new_ipv6_str, sizeof(new_ipv6_str)),
			     addr->prefix_len);

			memcpy(&pio->prefix, &addr->addr.in6, sizeof(struct in6_addr));
			pio->length = addr->prefix_len;
		}

		if (pio->lifetime) {
			pio->lifetime = 0;

			iface->pio_update = true;
			warn("rfc9096: %s: renew %s/%u",
			     iface->ifname,
			     inet_ntop(AF_INET6, &pio->prefix, ipv6_str, sizeof(ipv6_str)),
			     pio->length);
		}

		return;
	}

	new_pios = realloc(iface->pios, sizeof(struct ra_pio) * (iface->pio_cnt + 1));
	if (!new_pios)
		return;

	iface->pios = new_pios;
	pio = &iface->pios[iface->pio_cnt];
	iface->pio_cnt++;

	memcpy(&pio->prefix, &addr->addr.in6, sizeof(struct in6_addr));
	pio->length = addr->prefix_len;
	pio->lifetime = 0;

	iface->pio_update = true;
	info("rfc9096: %s: add %s/%u",
	     iface->ifname,
	     inet_ntop(AF_INET6, &pio->prefix, ipv6_str, sizeof(ipv6_str)),
	     pio->length);
}

static void router_clear_duplicated_ra_pio(struct interface *iface)
{
	size_t pio_cnt = iface->pio_cnt;
	char ipv6_str[INET6_ADDRSTRLEN];

	for (size_t i = 0; i < iface->pio_cnt; i++) {
		struct ra_pio *pio_a = &iface->pios[i];
		size_t j = i + 1;

		while (j < iface->pio_cnt) {
			struct ra_pio *pio_b = &iface->pios[j];

			if (!memcmp(pio_a, pio_b, ra_pio_cmp_len)) {
				warn("rfc9096: %s: clear duplicated %s/%u",
				     iface->ifname,
				     inet_ntop(AF_INET6, &pio_a->prefix, ipv6_str, sizeof(ipv6_str)),
				     pio_a->length);

				iface->pios[j] = iface->pios[iface->pio_cnt - 1];
				iface->pio_cnt--;
			} else {
				j++;
			}
		}
	}

	if (iface->pio_cnt != pio_cnt) {
		struct ra_pio *new_pios = realloc(iface->pios, sizeof(struct ra_pio) * iface->pio_cnt);

		if (new_pios)
			iface->pios = new_pios;
	}
}

static void router_clear_expired_ra_pio(time_t now,
	struct interface *iface)
{
	size_t i = 0, pio_cnt = iface->pio_cnt;
	char ipv6_str[INET6_ADDRSTRLEN];

	while (i < iface->pio_cnt) {
		struct ra_pio *cur_pio = &iface->pios[i];

		if (ra_pio_expired(cur_pio, now)) {
			info("rfc9096: %s: clear expired %s/%u",
			     iface->ifname,
			     inet_ntop(AF_INET6, &cur_pio->prefix, ipv6_str, sizeof(ipv6_str)),
			     cur_pio->length);

			iface->pios[i] = iface->pios[iface->pio_cnt - 1];
			iface->pio_cnt--;
		} else {
			i++;
		}
	}

	if (!iface->pio_cnt) {
		free(iface->pios);
		iface->pios = NULL;
	} else if (iface->pio_cnt != pio_cnt) {
		struct ra_pio *new_pios = realloc(iface->pios, sizeof(struct ra_pio) * iface->pio_cnt);

		if (new_pios)
			iface->pios = new_pios;
	}
}

static void router_stale_ra_pio(struct interface *iface,
	struct odhcpd_ipaddr *addr,
	time_t now)
{
	struct ra_pio *pio = router_find_ra_pio(iface, addr);
	char ipv6_str[INET6_ADDRSTRLEN];

	if (!pio || pio->lifetime)
		return;

	pio->lifetime = now + iface->max_valid_lifetime;

	iface->pio_update = true;
	warn("rfc9096: %s: stale %s/%u",
	     iface->ifname,
	     inet_ntop(AF_INET6, &pio->prefix, ipv6_str, sizeof(ipv6_str)),
	     pio->length);
}

/* Router Advert server mode */
static int send_router_advert(struct interface *iface, const struct in6_addr *from)
{
	time_t now = odhcpd_time();
	struct odhcpd_ipaddr *addrs = NULL;
	struct adv_msg adv;
	struct nd_opt_prefix_info *pfxs = NULL;
	struct nd_opt_dns_server *dns = NULL;
	struct nd_opt_search_list *search = NULL;
	struct nd_opt_route_info *routes = NULL;
	struct nd_opt_pref64_info *pref64 = NULL;
	struct nd_opt_dnr_info *dnrs = NULL;
	struct nd_opt_adv_interval adv_interval;
	struct nd_opt_capt_portal *capt_portal = NULL;
	struct iovec iov[IOV_RA_TOTAL];
	struct sockaddr_in6 dest;
	size_t dns_sz = 0, search_sz = 0, pref64_sz = 0, dnrs_sz = 0;
	size_t pfxs_cnt = 0, routes_cnt = 0;
	size_t total_addr_cnt = 0, valid_addr_cnt = 0;
	size_t capt_portal_sz = 0;
	/*
	 * lowest_found_lifetime stores the lowest lifetime of all prefixes;
	 * necessary to find longest adv interval necessary
	 * for shortest lived prefix
	 */
	uint32_t lowest_found_lifetime = UINT32_MAX, highest_found_lifetime = 0, maxival, ra_lifetime;
	int msecs, hlim = iface->ra_hoplimit;
	bool default_route = false;
	bool valid_prefix = false;
	char buf[INET6_ADDRSTRLEN];

	router_clear_expired_ra_pio(now, iface);

	memset(&adv, 0, sizeof(adv));
	adv.h.nd_ra_type = ND_ROUTER_ADVERT;

	if (hlim == 0)
		hlim = odhcpd_get_interface_config(iface->ifname, "hop_limit");

	if (hlim > 0)
		adv.h.nd_ra_curhoplimit = hlim;

	adv.h.nd_ra_flags_reserved = iface->ra_flags;

	if (iface->route_preference < 0)
		adv.h.nd_ra_flags_reserved |= ND_RA_PREF_LOW;
	else if (iface->route_preference > 0)
		adv.h.nd_ra_flags_reserved |= ND_RA_PREF_HIGH;

	if (iface->dhcpv6 != MODE_DISABLED && iface->dhcpv6_pd && iface->dhcpv6_pd_preferred) {
		/* RFC9762 § 5
		 * If the network desires to delegate prefixes to devices that support
		 * DHCPv6 prefix delegation but do not support the P flag, it SHOULD
		 * also set the M or O bits in the RA to 1
		 */
		adv.h.nd_ra_flags_reserved |= ND_RA_FLAG_MANAGED;
	}

	adv.h.nd_ra_reachable = htonl(iface->ra_reachabletime);
	adv.h.nd_ra_retransmit = htonl(iface->ra_retranstime);

	adv.lladdr.type = ND_OPT_SOURCE_LINKADDR;
	adv.lladdr.len = 1;
	odhcpd_get_mac(iface, adv.lladdr.data);

	adv.mtu.nd_opt_mtu_type = ND_OPT_MTU;
	adv.mtu.nd_opt_mtu_len = 1;

	adv.mtu.nd_opt_mtu_mtu = htonl(iface->ra_mtu);

	iov[IOV_RA_ADV].iov_base = (char *)&adv;
	iov[IOV_RA_ADV].iov_len = sizeof(adv);

	valid_addr_cnt = (iface->timer_rs.cb /* if not shutdown */ ? iface->addr6_len : 0);

	// check ra_default
	if (iface->default_router) {
		default_route = true;

		if (iface->default_router > 1)
			valid_prefix = true;
	}

	if (valid_addr_cnt + iface->pio_cnt) {
		addrs = alloca(sizeof(*addrs) * (valid_addr_cnt + iface->pio_cnt));

		if (valid_addr_cnt) {
			memcpy(addrs, iface->addr6, sizeof(*addrs) * valid_addr_cnt);
			total_addr_cnt = valid_addr_cnt;

			/* Check default route */
			if (!default_route && parse_routes(addrs, valid_addr_cnt))
				default_route = true;
		}

		for (size_t i = 0; i < iface->pio_cnt; i++) {
			struct ra_pio *cur_pio = &iface->pios[i];
			bool pio_found = false;

			for (size_t j = 0; j < valid_addr_cnt; j++) {
				struct odhcpd_ipaddr *cur_addr = &addrs[j];

				if (!router_compare_pio_addr(cur_pio, cur_addr)) {
					pio_found = true;
					break;
				}
			}

			if (!pio_found) {
				struct odhcpd_ipaddr *addr = &addrs[total_addr_cnt];

				memcpy(&addr->addr.in6, &cur_pio->prefix, sizeof(addr->addr.in6));
				addr->prefix_len = cur_pio->length;
				addr->preferred_lt = 0;
				addr->valid_lt = (uint32_t) (now + ND_VALID_LIMIT);
				total_addr_cnt++;
			}
		}
	}

	/* Construct Prefix Information options */
	for (size_t i = 0; i < total_addr_cnt; ++i) {
		struct odhcpd_ipaddr *addr = &addrs[i];
		struct nd_opt_prefix_info *p = NULL;
		uint32_t preferred_lt = 0;
		uint32_t valid_lt = 0;

		if (addr->prefix_len > 96 || (i < valid_addr_cnt && addr->valid_lt <= (uint32_t)now)) {
			info("Address %s (prefix %d, valid-lifetime %u) not suitable as RA prefix on %s",
			     inet_ntop(AF_INET6, &addr->addr.in6, buf, sizeof(buf)), addr->prefix_len,
			     addr->valid_lt, iface->name);
			continue;
		}

		if (ADDR_MATCH_PIO_FILTER(addr, iface)) {
			info("Address %s filtered out as RA prefix on %s",
			     inet_ntop(AF_INET6, &addr->addr.in6, buf, sizeof(buf)),
			     iface->name);
			continue; /* PIO filtered out of this RA */
		}

		for (size_t j = 0; j < pfxs_cnt; ++j) {
			if (addr->prefix_len == pfxs[j].nd_opt_pi_prefix_len &&
			    !odhcpd_bmemcmp(&pfxs[j].nd_opt_pi_prefix,
					    &addr->addr.in6, addr->prefix_len))
				p = &pfxs[j];
		}

		if (!p) {
			struct nd_opt_prefix_info *tmp;

			tmp = realloc(pfxs, sizeof(*pfxs) * (pfxs_cnt + 1));
			if (!tmp) {
				error("Realloc failed for RA prefix option on %s", iface->name);
				continue;
			}

			pfxs = tmp;
			p = &pfxs[pfxs_cnt++];
			memset(p, 0, sizeof(*p));
		}

		if (addr->preferred_lt > (uint32_t)now) {
			preferred_lt = TIME_LEFT(addr->preferred_lt, now);

			if (iface->max_preferred_lifetime && preferred_lt > iface->max_preferred_lifetime) {
				preferred_lt = iface->max_preferred_lifetime;
			}
		}

		if (addr->valid_lt > (uint32_t)now) {
			valid_lt = TIME_LEFT(addr->valid_lt, now);

			if (iface->max_valid_lifetime && valid_lt > iface->max_valid_lifetime)
				valid_lt = iface->max_valid_lifetime;
		}

		if (preferred_lt > valid_lt) {
			/*
			 * RFC4861 § 6.2.1
			 * This value [AdvPreferredLifetime] MUST NOT be larger than
			 * AdvValidLifetime.
			 */
			preferred_lt = valid_lt;
		}

		if (lowest_found_lifetime > valid_lt)
			lowest_found_lifetime = valid_lt;

		if ((!IN6_IS_ADDR_ULA(&addr->addr.in6) || iface->default_router) && valid_lt)
			valid_prefix = true;

		if (!IN6_IS_ADDR_ULA(&addr->addr.in6) && valid_lt) {
			if (highest_found_lifetime < valid_lt)
				highest_found_lifetime = valid_lt;
		}

		odhcpd_bmemcpy(&p->nd_opt_pi_prefix, &addr->addr.in6,
				(iface->ra_advrouter) ? 128 : addr->prefix_len);
		p->nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
		p->nd_opt_pi_len = 4;
		p->nd_opt_pi_prefix_len = (addr->prefix_len < 64) ? 64 : addr->prefix_len;
		/* RFC9762 DHCPv6-PD Preferred Flag § 6:
		 * Routers SHOULD set the P flag to zero by default...
		 */
		p->nd_opt_pi_flags_reserved = 0;
		if (!iface->ra_not_onlink)
			p->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_ONLINK;
		if (iface->ra_slaac && addr->prefix_len <= 64)
			p->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_AUTO;
		if (iface->dhcpv6 != MODE_DISABLED && iface->dhcpv6_pd && iface->dhcpv6_pd_preferred)
			/* RFC9762 DHCPv6-PD Preferred Flag
			 * We can run both SLAAC and DHCPv6-PD.
			 * §6:
			 * "Routers MUST allow the P flag to be configured separately from the A flag.
			 * ...en/disabling the P flag MUST NOT trigger automatic changes in the A flag
			 * value set by the router."
			 */
			p->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_PD_PREFERRED;
		if (iface->ra_advrouter)
			// RFC6275, §7.2
			p->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_RADDR;
		if (i >= valid_addr_cnt || !preferred_lt) {
			/*
			 * RFC9096 § 3.5
			 *
			 * - Any prefixes that were previously advertised by the CE router
			 *   via PIOs in RA messages, but that have now become stale, MUST
			 *   be advertised with PIOs that have the "Valid Lifetime" and the
			 *   "Preferred Lifetime" set to 0 and the "A" and "L" bits
			 *   unchanged.
			 */
			p->nd_opt_pi_preferred_time = 0;
			p->nd_opt_pi_valid_time = 0;

			router_stale_ra_pio(iface, addr, now);
		} else {
			p->nd_opt_pi_preferred_time = htonl(preferred_lt);
			p->nd_opt_pi_valid_time = htonl(valid_lt);

			router_add_ra_pio(iface, addr);
		}
	}

	router_clear_duplicated_ra_pio(iface);

	iov[IOV_RA_PFXS].iov_base = (char *)pfxs;
	iov[IOV_RA_PFXS].iov_len = pfxs_cnt * sizeof(*pfxs);

	/* Calculate periodic transmit */
	msecs = calc_adv_interval(iface, lowest_found_lifetime, &maxival);
	ra_lifetime = calc_ra_lifetime(iface, maxival);
	if (!highest_found_lifetime)
		highest_found_lifetime = ra_lifetime;

	if (!iface->have_link_local) {
		notice("Skip sending a RA on %s as no link local address is available", iface->name);
		goto out;
	}

	if (default_route && valid_prefix) {
		adv.h.nd_ra_router_lifetime = htons(ra_lifetime < UINT16_MAX ? ra_lifetime : UINT16_MAX);
	} else {
		adv.h.nd_ra_router_lifetime = 0;

		if (default_route)
			warn("A default route is present but there is no public prefix "
			     "on %s thus we announce no default route by setting ra_lifetime to 0!", iface->name);
		else
			warn("No default route present, setting ra_lifetime to 0!");
	}

	debug("Using a RA lifetime of %d seconds on %s", ntohs(adv.h.nd_ra_router_lifetime), iface->name);

	/* DNS options */
	if (iface->ra_dns) {
		struct in6_addr *dns_addrs6 = NULL, dns_addr6;
		size_t dns_addrs6_cnt = 0, dns_search_len = iface->dns_search_len;
		uint8_t *dns_search = iface->dns_search;
		uint8_t dns_search_buf[DNS_MAX_NAME_LEN];

		/* DNS Recursive DNS aka RDNSS Type 25; RFC8106 */
		if (iface->dns_addrs6_cnt > 0) {
			dns_addrs6 = iface->dns_addrs6;
			dns_addrs6_cnt = iface->dns_addrs6_cnt;
		} else if (!odhcpd_get_interface_dns_addr6(iface, &dns_addr6)) {
			dns_addrs6 = &dns_addr6;
			dns_addrs6_cnt = 1;
		}

		if (dns_addrs6_cnt) {
			dns_sz = sizeof(*dns) + dns_addrs6_cnt * sizeof(*dns_addrs6);

			dns = alloca(dns_sz);
			memset(dns, 0, dns_sz);
			dns->type = ND_OPT_RECURSIVE_DNS;
			dns->len = 1 + (2 * dns_addrs6_cnt);
			dns->lifetime = htonl(highest_found_lifetime);
			memcpy(dns->addr, dns_addrs6, dns_addrs6_cnt * sizeof(*dns_addrs6));
		}

		/* DNS Search List option aka DNSSL Type 31; RFC8106, §5.2 */
		if (!dns_search && !res_init() && _res.dnsrch[0] && _res.dnsrch[0][0]) {
			int len = dn_comp(_res.dnsrch[0], dns_search_buf,
					sizeof(dns_search_buf), NULL, NULL);
			if (len > 0) {
				dns_search = dns_search_buf;
				dns_search_len = len;
			}
		}

		if (dns_search_len > 0) {
			search_sz = sizeof(*search) + ((dns_search_len + 7) & (~7));
			search = alloca(search_sz);
			*search = (struct nd_opt_search_list) {
				.type = ND_OPT_DNS_SEARCH,
				.len = search_sz / 8,
				.reserved = 0,
				.lifetime = htonl(highest_found_lifetime),
			};
			memcpy(search->name, dns_search, dns_search_len);
		}
	}

	iov[IOV_RA_DNS].iov_base = (char *)dns;
	iov[IOV_RA_DNS].iov_len = dns_sz;
	iov[IOV_RA_SEARCH].iov_base = (char *)search;
	iov[IOV_RA_SEARCH].iov_len = search_sz;

	if (iface->pref64_length) {
		/* RFC 8781 § 4.1 rounding up lifetime to multiple of 8 */
		uint16_t pref64_lifetime = ra_lifetime < (UINT16_MAX - 7) ? ra_lifetime + 7 : (UINT16_MAX - 7);

		pref64_sz = sizeof(*pref64);
		pref64 = alloca(pref64_sz);
		pref64->type = ND_OPT_PREF64;
		pref64->len = 2;
		pref64->lifetime_plc = htons((0xfff8 & pref64_lifetime) |
					     (0x7 & iface->pref64_plc));
		memcpy(pref64->prefix, iface->pref64_prefix, sizeof(pref64->prefix));
	}
	iov[IOV_RA_PREF64].iov_base = (char *)pref64;
	iov[IOV_RA_PREF64].iov_len = pref64_sz;

	if (iface->dnr_cnt) {
		size_t dnr_sz[iface->dnr_cnt];

		for (unsigned i = 0; i < iface->dnr_cnt; i++) {
			dnr_sz[i] = sizeof(struct nd_opt_dnr_info) + iface->dnr[i].adn_len;
			if (iface->dnr[i].addr6_cnt > 0 || iface->dnr[i].svc_len > 0) {
				dnr_sz[i] += 2 + iface->dnr[i].addr6_cnt * sizeof(struct in6_addr);
				dnr_sz[i] += 2 + iface->dnr[i].svc_len;
			}
			dnr_sz[i] = (dnr_sz[i] + 7) & ~7;
			dnrs_sz += dnr_sz[i];
		}

		/* dnrs are sized in multiples of 8, so each dnr should be aligned */
		dnrs = alloca(dnrs_sz);
		memset(dnrs, 0, dnrs_sz);

		uint8_t *pos = (uint8_t *)dnrs;
		for (unsigned i = 0; i < iface->dnr_cnt; pos += dnr_sz[i], i++) {
			struct nd_opt_dnr_info *dnr = (struct nd_opt_dnr_info *)pos;
			size_t dnr_addr6_sz = iface->dnr[i].addr6_cnt * sizeof(struct in6_addr);
			uint8_t *tmp = dnr->body;

			dnr->type = ND_OPT_DNR;
			dnr->len = dnr_sz[i] / 8;
			dnr->priority = htons(iface->dnr[i].priority);
			if (iface->dnr[i].lifetime_set)
				dnr->lifetime = htonl(iface->dnr[i].lifetime);
			else
				dnr->lifetime = htonl(highest_found_lifetime);

			dnr->adn_len = htons(iface->dnr[i].adn_len);
			memcpy(tmp, iface->dnr[i].adn, iface->dnr[i].adn_len);
			tmp += iface->dnr[i].adn_len;

			*(tmp++) = dnr_addr6_sz >> 8;
			*(tmp++) = dnr_addr6_sz & 0xff;
			memcpy(tmp, iface->dnr[i].addr6, dnr_addr6_sz);
			tmp += dnr_addr6_sz;

			*(tmp++) = iface->dnr[i].svc_len >> 8;
			*(tmp++) = iface->dnr[i].svc_len & 0xff;
			memcpy(tmp, iface->dnr[i].svc, iface->dnr[i].svc_len);
		}
	}
	iov[IOV_RA_DNR].iov_base = (char *)dnrs;
	iov[IOV_RA_DNR].iov_len = dnrs_sz;

	/*
	 * RFC7084 § 4.3 :
	 *    L-3:   An IPv6 CE router MUST advertise itself as a router for the
	 *           delegated prefix(es) (and ULA prefix if configured to provide
	 *           ULA addressing) using the "Route Information Option" specified
	 *           in Section 2.3 of [RFC4191]. This advertisement is
	 *           independent of having or not having IPv6 connectivity on the
	 *           WAN interface.
	 */

	for (size_t i = 0; i < valid_addr_cnt; ++i) {
		struct odhcpd_ipaddr *addr = &addrs[i];
		struct nd_opt_route_info *tmp;
		uint32_t valid_lt;

		if (addr->dprefix_len >= 64 || addr->dprefix_len == 0 || addr->valid_lt <= (uint32_t)now) {
			info("Address %s (dprefix %d, valid-lifetime %u) not suitable as RA route on %s",
			     inet_ntop(AF_INET6, &addr->addr.in6, buf, sizeof(buf)),
			     addr->dprefix_len, addr->valid_lt, iface->name);

			continue; /* Address not suitable */
		}

		if (ADDR_MATCH_PIO_FILTER(addr, iface)) {
			info("Address %s filtered out as RA route on %s",
			     inet_ntop(AF_INET6, &addr->addr.in6, buf, sizeof(buf)),
			     iface->name);
			continue; /* PIO filtered out of this RA */
		}

		if (addr->dprefix_len > 32) {
			addr->addr.in6.s6_addr32[1] &= htonl(~((1U << (64 - addr->dprefix_len)) - 1));
		} else if (addr->dprefix_len <= 32) {
			addr->addr.in6.s6_addr32[0] &= htonl(~((1U << (32 - addr->dprefix_len)) - 1));
			addr->addr.in6.s6_addr32[1] = 0;
		}

		tmp = realloc(routes, sizeof(*routes) * (routes_cnt + 1));
		if (!tmp) {
			error("Realloc failed for RA route option on %s", iface->name);
			continue;
		}

		routes = tmp;

		memset(&routes[routes_cnt], 0, sizeof(*routes));
		routes[routes_cnt].type = ND_OPT_ROUTE_INFO;
		routes[routes_cnt].len = sizeof(*routes) / 8;
		routes[routes_cnt].prefix_len = addr->dprefix_len;
		routes[routes_cnt].flags = 0;
		if (iface->route_preference < 0)
			routes[routes_cnt].flags |= ND_RA_PREF_LOW;
		else if (iface->route_preference > 0)
			routes[routes_cnt].flags |= ND_RA_PREF_HIGH;

		valid_lt = TIME_LEFT(addr->valid_lt, now);
		if (iface->max_valid_lifetime && valid_lt > iface->max_valid_lifetime)
			valid_lt = iface->max_valid_lifetime;
		routes[routes_cnt].lifetime = htonl(valid_lt);
		routes[routes_cnt].addr[0] = addr->addr.in6.s6_addr32[0];
		routes[routes_cnt].addr[1] = addr->addr.in6.s6_addr32[1];
		routes[routes_cnt].addr[2] = 0;
		routes[routes_cnt].addr[3] = 0;

		++routes_cnt;
	}

	iov[IOV_RA_ROUTES].iov_base = (char *)routes;
	iov[IOV_RA_ROUTES].iov_len = routes_cnt * sizeof(*routes);

	memset(&adv_interval, 0, sizeof(adv_interval));
	adv_interval.nd_opt_adv_interval_type = ND_OPT_RTR_ADV_INTERVAL;
	adv_interval.nd_opt_adv_interval_len = 1;
	adv_interval.nd_opt_adv_interval_ival = htonl(maxival*1000);

	iov[IOV_RA_ADV_INTERVAL].iov_base = (char *)&adv_interval;
	iov[IOV_RA_ADV_INTERVAL].iov_len = adv_interval.nd_opt_adv_interval_len * 8;

	/* RFC 8910 Captive Portal */
	uint8_t *captive_portal_uri = (uint8_t *)iface->captive_portal_uri;
	if (iface->captive_portal_uri_len > 0) {
		/* compute pad so that (header + data + pad) is a multiple of 8 */
		capt_portal_sz = (sizeof(struct nd_opt_capt_portal) + iface->captive_portal_uri_len + 7) & ~7;

		capt_portal = alloca(capt_portal_sz);
		memset(capt_portal, 0, capt_portal_sz);

		capt_portal->type = ND_OPT_CAPTIVE_PORTAL;
		capt_portal->len = capt_portal_sz / 8;

		memcpy(capt_portal->data, captive_portal_uri, iface->captive_portal_uri_len);
		/* remaining padding bytes already set to 0x00 */
	}

	iov[IOV_RA_CAPT_PORTAL].iov_base = capt_portal;
	iov[IOV_RA_CAPT_PORTAL].iov_len = capt_portal_sz;

	memset(&dest, 0, sizeof(dest));
	dest.sin6_family = AF_INET6;

	if (from && !IN6_IS_ADDR_UNSPECIFIED(from))
		dest.sin6_addr = *from;
	else
		inet_pton(AF_INET6, ALL_IPV6_NODES, &dest.sin6_addr);

	debug("Sending a RA on %s", iface->name);

	if (odhcpd_try_send_with_src(iface->router_event.uloop.fd, &dest, iov, ARRAY_SIZE(iov), iface) > 0) {
		iface->ra_sent++;

		config_save_ra_pio(iface);
	}

out:
	free(pfxs);
	free(routes);

	return msecs;
}


static void trigger_router_advert(struct uloop_timeout *event)
{
	struct interface *iface = container_of(event, struct interface, timer_rs);
	int msecs = send_router_advert(iface, NULL);

	/* Rearm timer if not shut down */
	if (event->cb)
		uloop_timeout_set(event, msecs);
}


/* Event handler for incoming ICMPv6 packets */
static void handle_icmpv6(void *addr, void *data, size_t len,
		struct interface *iface, _o_unused void *dest)
{
	struct icmp6_hdr *hdr = data;
	struct sockaddr_in6 *from = addr;

	if (!router_icmpv6_valid(addr, data, len))
		return;

	if ((iface->ra == MODE_SERVER && !iface->master)) { /* Server mode */
		if (hdr->icmp6_type == ND_ROUTER_SOLICIT)
			send_router_advert(iface, &from->sin6_addr);
	} else if (iface->ra == MODE_RELAY) { /* Relay mode */
		if (hdr->icmp6_type == ND_ROUTER_SOLICIT && !iface->master) {
			struct interface *c;

			avl_for_each_element(&interfaces, c, avl) {
				if (!c->master || c->ra != MODE_RELAY)
					continue;

				forward_router_solicitation(c);
			}
		} else if (hdr->icmp6_type == ND_ROUTER_ADVERT && iface->master)
			forward_router_advertisement(iface, data, len);
	}
}


/* Forward a router solicitation from slave to master interface */
static void forward_router_solicitation(const struct interface *iface)
{
	struct icmp6_hdr rs = {ND_ROUTER_SOLICIT, 0, 0, {{0}}};
	struct iovec iov = {&rs, sizeof(rs)};
	struct sockaddr_in6 all_routers;

	if (!iface)
		return;

	memset(&all_routers, 0, sizeof(all_routers));
	all_routers.sin6_family = AF_INET6;
	inet_pton(AF_INET6, ALL_IPV6_ROUTERS, &all_routers.sin6_addr);
	all_routers.sin6_scope_id = iface->ifindex;

	notice("Sending RS to %s", iface->name);
	odhcpd_send(iface->router_event.uloop.fd, &all_routers, &iov, 1, iface);
}


/* Forward a router advertisement from master to slave interfaces */
static void forward_router_advertisement(const struct interface *iface, uint8_t *data, size_t len)
{
	struct nd_router_advert *adv = (struct nd_router_advert *)data;
	struct sockaddr_in6 all_nodes;
	struct icmpv6_opt *opt;
	struct interface *c;
	struct iovec iov = { .iov_base = data, .iov_len = len };
	/* Rewrite options */
	uint8_t *end = data + len;
	uint8_t *mac_ptr = NULL;
	struct in6_addr *dns_addrs6 = NULL;
	size_t dns_addrs6_cnt = 0;
	// MTU option
	struct nd_opt_mtu *mtu_opt = NULL;
	uint32_t ingress_mtu_val = 0;
	/* PIO L flag and RA M/O Flags */
	uint8_t ra_flags;
	size_t pio_count = 0;
	struct fwd_pio_flags {
		uint8_t *ptr;
		uint8_t flags;
	} *pio_flags = NULL;

	icmpv6_for_each_option(opt, &adv[1], end) {
		/* check our packet content is not truncated */
		if (opt->len == 0 || (uint8_t *)opt + opt->len * 8 > end) {
			error("Ingress RA packet option for relaying has incorrect length");
			return;
		}

		switch(opt->type) {
		case ND_OPT_PREFIX_INFORMATION:
			pio_count++;
			break;
		}
	}

	if (pio_count > 0) {
		pio_flags = alloca(sizeof(*pio_flags) * pio_count);
		pio_count = 0;
	}

	/* Parse existing options */
	icmpv6_for_each_option(opt, &adv[1], end) {
		switch (opt->type) {
		case ND_OPT_SOURCE_LINKADDR:
			mac_ptr = opt->data;
			break;

		case ND_OPT_RECURSIVE_DNS:
			if (opt->len > 1) {
				dns_addrs6 = (struct in6_addr *)&opt->data[6];
				dns_addrs6_cnt = (opt->len - 1) / 2;
			}
			break;

		case ND_OPT_MTU:
			if (opt->len == 1 && (uint8_t *)opt + sizeof(struct nd_opt_mtu) <= end) {
				mtu_opt = (struct nd_opt_mtu *)opt;
				ingress_mtu_val = ntohl(mtu_opt->nd_opt_mtu_mtu);
			}
			break;
		case ND_OPT_PREFIX_INFORMATION:
			/* Store options for each PIO */
			pio_flags[pio_count].ptr = &opt->data[1];
			pio_flags[pio_count].flags = opt->data[1];
			pio_count++;
			break;
		}
	}

	info("Got a RA on %s", iface->name);

	/*	Indicate a proxy, however we don't follow the rest of RFC 4389 yet
	 *	store original upstream RA state 
	 */
	ra_flags = adv->nd_ra_flags_reserved | ND_RA_FLAG_PROXY;

	/* Forward advertisement to all slave interfaces */
	memset(&all_nodes, 0, sizeof(all_nodes));
	all_nodes.sin6_family = AF_INET6;
	inet_pton(AF_INET6, ALL_IPV6_NODES, &all_nodes.sin6_addr);

	avl_for_each_element(&interfaces, c, avl) {
		if (c->ra != MODE_RELAY || c->master)
			continue;

		/* Fixup source hardware address option */
		if (mac_ptr)
			odhcpd_get_mac(c, mac_ptr);

		if (pio_count > 0)
			debug("RA forward: Rewriting RA PIO flags");

		for (size_t i = 0; i < pio_count; i++) {
			/* restore the flags byte to its upstream state before applying per-interface policy */
			*pio_flags[i].ptr = pio_flags[i].flags;
			/* ensure L flag (on-link) cleared; relayed == not on-link */
			*pio_flags[i].ptr &= ~ND_OPT_PI_FLAG_ONLINK;
		}

		/* Apply per-interface modifications of upstream RA state */
		adv->nd_ra_flags_reserved = ra_flags;
		/* Rewrite M/O flags unless we relay DHCPv6 */
		if (c->dhcpv6 != MODE_RELAY) {
			/* Clear the relayed M/O bits */
			adv->nd_ra_flags_reserved &= ~(ND_RA_FLAG_MANAGED | ND_RA_FLAG_OTHER);
			/* Apply the locally configured ra_flags for M and O */
			adv->nd_ra_flags_reserved |= c->ra_flags & (ND_RA_FLAG_MANAGED | ND_RA_FLAG_OTHER);
		}

		/* If we have to rewrite DNS entries */
		if (c->always_rewrite_dns && dns_addrs6 && dns_addrs6_cnt > 0) {
			const struct in6_addr *rewrite = c->dns_addrs6;
			struct in6_addr addr;
			size_t rewrite_cnt = c->dns_addrs6_cnt;

			if (rewrite_cnt == 0) {
				if (odhcpd_get_interface_dns_addr6(c, &addr))
					continue; /* Unable to comply */

				rewrite = &addr;
				rewrite_cnt = 1;
			}

			/* Copy over any other addresses */
			for (size_t i = 0; i < dns_addrs6_cnt; ++i) {
				size_t j = (i < rewrite_cnt) ? i : rewrite_cnt - 1;
				dns_addrs6[i] = rewrite[j];
			}
		}

		/* Rewrite MTU option if local RA MTU is configured */
		if (c->ra_mtu && mtu_opt) {
			if (ingress_mtu_val != c->ra_mtu) {
				debug("Rewriting RA MTU from %u to %u on %s",
				      ingress_mtu_val, c->ra_mtu, c->name);
				mtu_opt->nd_opt_mtu_mtu = htonl(c->ra_mtu);
			}
		}

		info("Forward a RA on %s", c->name);
		odhcpd_send(c->router_event.uloop.fd, &all_nodes, &iov, 1, c);
	}
}
