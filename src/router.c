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

#include "router.h"
#include "odhcpd.h"


static void forward_router_solicitation(const struct interface *iface);
static void forward_router_advertisement(uint8_t *data, size_t len);

static void handle_icmpv6(void *addr, void *data, size_t len,
		struct interface *iface, void *dest);
static void trigger_router_advert(struct uloop_timeout *event);
static void sigusr1_refresh(int signal);

static struct odhcpd_event router_event = {.uloop = {.fd = -1}, .handle_dgram = handle_icmpv6, };

static FILE *fp_route = NULL;
#define RA_IOV_LEN 6

#define TIME_LEFT(t1, now) ((t1) != UINT32_MAX ? (t1) - (now) : UINT32_MAX)

int init_router(void)
{
	// Open ICMPv6 socket
	int sock = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMPV6);
	if (sock < 0 && errno != EAFNOSUPPORT) {
		syslog(LOG_ERR, "Failed to open RAW-socket: %s", strerror(errno));
		return -1;
	}

	// Let the kernel compute our checksums
	int val = 2;
	setsockopt(sock, IPPROTO_RAW, IPV6_CHECKSUM, &val, sizeof(val));

	// This is required by RFC 4861
	val = 255;
	setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &val, sizeof(val));
	setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &val, sizeof(val));

	// We need to know the source interface
	val = 1;
	setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &val, sizeof(val));
	setsockopt(sock, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &val, sizeof(val));

	// Don't loop back
	val = 0;
	setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &val, sizeof(val));

	// Filter ICMPv6 package types
	struct icmp6_filter filt;
	ICMP6_FILTER_SETBLOCKALL(&filt);
	ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filt);
	ICMP6_FILTER_SETPASS(ND_ROUTER_SOLICIT, &filt);
	setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, &filt, sizeof(filt));

	// Register socket
	router_event.uloop.fd = sock;
	odhcpd_register(&router_event);

	if (!(fp_route = fopen("/proc/net/ipv6_route", "r")))
		syslog(LOG_ERR, "Failed to open routing table: %s",
				strerror(errno));

	signal(SIGUSR1, sigusr1_refresh);
	return 0;
}


int setup_router_interface(struct interface *iface, bool enable)
{
	if (!fp_route || router_event.uloop.fd < 0)
		return -1;

	struct ipv6_mreq all_nodes = {ALL_IPV6_NODES, iface->ifindex};
	struct ipv6_mreq all_routers = {ALL_IPV6_ROUTERS, iface->ifindex};

	uloop_timeout_cancel(&iface->timer_rs);
	iface->timer_rs.cb = NULL;

	if (iface->ifindex <= 0)
		return -1;

	setsockopt(router_event.uloop.fd, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP,
			&all_nodes, sizeof(all_nodes));
	setsockopt(router_event.uloop.fd, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP,
			&all_routers, sizeof(all_routers));

	if (!enable) {
		if (iface->ra)
			trigger_router_advert(&iface->timer_rs);
	} else {
		void *mreq = &all_routers;

		if (iface->ra == RELAYD_RELAY && iface->master) {
			mreq = &all_nodes;
			forward_router_solicitation(iface);
		} else if (iface->ra == RELAYD_SERVER && !iface->master) {
			iface->timer_rs.cb = trigger_router_advert;
			uloop_timeout_set(&iface->timer_rs, 1000);
			ndp_rqs_addr6_dump();
		}

		if (iface->ra == RELAYD_RELAY || (iface->ra == RELAYD_SERVER && !iface->master))
			setsockopt(router_event.uloop.fd, IPPROTO_IPV6,
					IPV6_ADD_MEMBERSHIP, mreq, sizeof(all_nodes));
	}
	return 0;
}


// Signal handler to resend all RDs
static void sigusr1_refresh(_unused int signal)
{
	struct interface *iface;
	list_for_each_entry(iface, &interfaces, head)
		if (iface->ra == RELAYD_SERVER && !iface->master)
			uloop_timeout_set(&iface->timer_rs, 1000);
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

	// Check all options parsed successfully
	return opt == end;
}


// Detect whether a default route exists, also find the source prefixes
static bool parse_routes(struct odhcpd_ipaddr *n, ssize_t len)
{
	rewind(fp_route);

	char line[512], ifname[16];
	bool found_default = false;
	struct odhcpd_ipaddr p = {IN6ADDR_ANY_INIT, 0, 0, 0, 0};
	while (fgets(line, sizeof(line), fp_route)) {
		uint32_t rflags;
		if (sscanf(line, "00000000000000000000000000000000 00 "
				"%*s %*s %*s %*s %*s %*s %*s %15s", ifname) &&
				strcmp(ifname, "lo")) {
			found_default = true;
		} else if (sscanf(line, "%8" SCNx32 "%8" SCNx32 "%*8" SCNx32 "%*8" SCNx32 " %hhx %*s "
				"%*s 00000000000000000000000000000000 %*s %*s %*s %" SCNx32 " lo",
				&p.addr.s6_addr32[0], &p.addr.s6_addr32[1], &p.prefix, &rflags) &&
				p.prefix > 0 && (rflags & RTF_NONEXTHOP) && (rflags & RTF_REJECT)) {
			// Find source prefixes by scanning through unreachable-routes
			p.addr.s6_addr32[0] = htonl(p.addr.s6_addr32[0]);
			p.addr.s6_addr32[1] = htonl(p.addr.s6_addr32[1]);

			for (ssize_t i = 0; i < len; ++i) {
				if (n[i].prefix <= 64 && n[i].prefix >= p.prefix &&
						!odhcpd_bmemcmp(&p.addr, &n[i].addr, p.prefix)) {
					n[i].dprefix = p.prefix;
					break;
				}
			}

		}
	}

	return found_default;
}

static int calc_adv_interval(struct interface *iface, uint32_t minvalid,
		uint32_t *maxival)
{
	uint32_t minival = iface->ra_mininterval;
	int msecs;

	*maxival = iface->ra_maxinterval;

	if (*maxival > minvalid/3)
		*maxival = minvalid/3;

	if (*maxival > MaxRtrAdvInterval)
		*maxival = MaxRtrAdvInterval;
	else if (*maxival < 4)
		*maxival = 4;

	if (minival < MinRtrAdvInterval)
		minival = MinRtrAdvInterval;
	else if (minival > (*maxival * 3)/4)
		minival = (*maxival >= 9 ? *maxival/3 : *maxival);

	odhcpd_urandom(&msecs, sizeof(msecs));
	msecs = (labs(msecs) % ((*maxival != minival) ? (*maxival - minival)*1000 : 500)) +
			minival*1000;

	return msecs;
}

static uint16_t calc_ra_lifetime(struct interface *iface, uint32_t maxival)
{
	uint16_t lifetime = 3*maxival;

	if (iface->ra_lifetime >= 0) {
		lifetime = iface->ra_lifetime;
		if (lifetime < maxival)
			lifetime = maxival;
		else if (lifetime > 9000)
			lifetime = 9000;
	}

	return lifetime;
}

// Router Advert server mode
static uint64_t send_router_advert(struct interface *iface, const struct in6_addr *from)
{
	time_t now = odhcpd_time();
	int mtu = iface->ra_mtu;
	int hlim = iface->ra_hoplimit;

	if (mtu == 0)
		mtu = odhcpd_get_interface_config(iface->ifname, "mtu");

	if (mtu < 1280)
		mtu = 1280;

	if (hlim == 0)
		hlim = odhcpd_get_interface_config(iface->ifname, "hop_limit");

	struct {
		struct nd_router_advert h;
		struct icmpv6_opt lladdr;
		struct nd_opt_mtu mtu;
		struct nd_opt_prefix_info prefix[sizeof(iface->ia_addr) / sizeof(*iface->ia_addr)];
	} adv = {
		.h = {{.icmp6_type = ND_ROUTER_ADVERT, .icmp6_code = 0}, 0, 0},
		.lladdr = {ND_OPT_SOURCE_LINKADDR, 1, {0}},
		.mtu = {ND_OPT_MTU, 1, 0, htonl(mtu)},
	};

	if (hlim > 0)
		adv.h.nd_ra_curhoplimit = hlim;

	if (iface->dhcpv6)
		adv.h.nd_ra_flags_reserved = ND_RA_FLAG_OTHER;

	if (iface->managed >= RELAYD_MANAGED_MFLAG)
		adv.h.nd_ra_flags_reserved |= ND_RA_FLAG_MANAGED;

	if (iface->route_preference < 0)
		adv.h.nd_ra_flags_reserved |= ND_RA_PREF_LOW;
	else if (iface->route_preference > 0)
		adv.h.nd_ra_flags_reserved |= ND_RA_PREF_HIGH;

	adv.h.nd_ra_reachable = htonl(iface->ra_reachabletime);
	adv.h.nd_ra_retransmit = htonl(iface->ra_retranstime);

	odhcpd_get_mac(iface, adv.lladdr.data);

	// If not currently shutting down
	struct odhcpd_ipaddr addrs[RELAYD_MAX_ADDRS];
	ssize_t ipcnt = 0;
	uint32_t minvalid = UINT32_MAX;
	bool default_route = false;
	bool valid_prefix = false;

	// If not shutdown
	if (iface->timer_rs.cb) {
		ipcnt = iface->ia_addr_len;
		memcpy(addrs, iface->ia_addr, ipcnt * sizeof(*addrs));

		// Check default route
		if (iface->default_router) {
			default_route = true;

			if (iface->default_router > 1)
				valid_prefix = true;
		} else if (parse_routes(addrs, ipcnt))
			default_route = true;
	}

	// Construct Prefix Information options
	size_t cnt = 0;

	struct in6_addr dns_pref, *dns_addr = &dns_pref;
	size_t dns_cnt = 1;

	odhcpd_get_interface_dns_addr(iface, &dns_pref);

	for (ssize_t i = 0; i < ipcnt; ++i) {
		struct odhcpd_ipaddr *addr = &addrs[i];
		uint32_t preferred = 0;
		uint32_t valid = 0;

		if (addr->prefix > 96 || addr->valid <= (uint32_t)now) {
			char namebuf[INET6_ADDRSTRLEN];

			inet_ntop(AF_INET6, addr, namebuf, sizeof(namebuf));
			syslog(LOG_INFO, "Address %s (prefix %d, valid %u) not suitable as RA prefix on %s",
					namebuf, addr->prefix, addr->valid, iface->ifname);
			continue;
		}

		struct nd_opt_prefix_info *p = NULL;
		for (size_t i = 0; i < cnt; ++i) {
			if (addr->prefix == adv.prefix[i].nd_opt_pi_prefix_len &&
					!odhcpd_bmemcmp(&adv.prefix[i].nd_opt_pi_prefix,
					&addr->addr, addr->prefix))
				p = &adv.prefix[i];
		}

		if (!p) {
			if (cnt >= ARRAY_SIZE(adv.prefix))
				break;

			p = &adv.prefix[cnt++];
		}

		if (addr->preferred > (uint32_t)now) {
			preferred = TIME_LEFT(addr->preferred, now);

			if (iface->ra_useleasetime &&
					preferred > iface->dhcpv4_leasetime)
				preferred = iface->dhcpv4_leasetime;
		}

		valid = TIME_LEFT(addr->valid, now);
		if (iface->ra_useleasetime && valid > iface->dhcpv4_leasetime)
			valid = iface->dhcpv4_leasetime;

		if (minvalid > valid)
			minvalid = valid;

		if (!IN6_IS_ADDR_ULA(&addr->addr) || iface->default_router)
			valid_prefix = true;

		odhcpd_bmemcpy(&p->nd_opt_pi_prefix, &addr->addr,
				(iface->ra_advrouter) ? 128 : addr->prefix);
		p->nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
		p->nd_opt_pi_len = 4;
		p->nd_opt_pi_prefix_len = (addr->prefix < 64) ? 64 : addr->prefix;
		p->nd_opt_pi_flags_reserved = 0;
		if (!iface->ra_not_onlink)
			p->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_ONLINK;
		if (iface->managed < RELAYD_MANAGED_NO_AFLAG && addr->prefix <= 64)
			p->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_AUTO;
		if (iface->ra_advrouter)
			p->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_RADDR;
		p->nd_opt_pi_preferred_time = htonl(preferred);
		p->nd_opt_pi_valid_time = htonl(valid);
	}

	// Calculate periodic transmit
	uint32_t maxival;
	int msecs = calc_adv_interval(iface, minvalid, &maxival);

	if (default_route) {
		if (!valid_prefix) {
			syslog(LOG_WARNING, "A default route is present but there is no public prefix "
					"on %s thus we don't announce a default route!", iface->ifname);
			adv.h.nd_ra_router_lifetime = 0;
		} else
			adv.h.nd_ra_router_lifetime = htons(calc_ra_lifetime(iface, maxival));

	} else
		adv.h.nd_ra_router_lifetime = 0;

	syslog(LOG_INFO, "Using a RA lifetime of %d seconds on %s", ntohs(adv.h.nd_ra_router_lifetime), iface->ifname);

	// DNS Recursive DNS
	if (iface->dns_cnt > 0) {
		dns_addr = iface->dns;
		dns_cnt = iface->dns_cnt;
	}

	if (!dns_addr || IN6_IS_ADDR_UNSPECIFIED(dns_addr))
		dns_cnt = 0;

	struct {
		uint8_t type;
		uint8_t len;
		uint8_t pad;
		uint8_t pad2;
		uint32_t lifetime;
	} dns = {ND_OPT_RECURSIVE_DNS, (1 + (2 * dns_cnt)), 0, 0, 0};



	// DNS Search options
	uint8_t search_buf[256], *search_domain = iface->search;
	size_t search_len = iface->search_len, search_padded = 0;

	if (!search_domain && !res_init() && _res.dnsrch[0] && _res.dnsrch[0][0]) {
		int len = dn_comp(_res.dnsrch[0], search_buf,
				sizeof(search_buf), NULL, NULL);
		if (len > 0) {
			search_domain = search_buf;
			search_len = len;
		}
	}

	if (search_len > 0)
		search_padded = ((search_len + 7) & (~7)) + 8;

	struct {
		uint8_t type;
		uint8_t len;
		uint8_t pad;
		uint8_t pad2;
		uint32_t lifetime;
		uint8_t name[];
	} *search = alloca(sizeof(*search) + search_padded);

	search->type = ND_OPT_DNS_SEARCH;
	search->len = search_len ? ((sizeof(*search) + search_padded) / 8) : 0;
	search->pad = 0;
	search->pad2 = 0;
	memcpy(search->name, search_domain, search_len);
	memset(&search->name[search_len], 0, search_padded - search_len);


	size_t routes_cnt = 0;
	struct {
		uint8_t type;
		uint8_t len;
		uint8_t prefix;
		uint8_t flags;
		uint32_t lifetime;
		uint32_t addr[4];
	} routes[RELAYD_MAX_PREFIXES];

	for (ssize_t i = 0; i < ipcnt; ++i) {
		struct odhcpd_ipaddr *addr = &addrs[i];
		if (addr->dprefix > 64 || addr->dprefix == 0 || addr->valid <= (uint32_t)now ||
				(addr->dprefix == 64 && addr->prefix == 64)) {
			continue; // Address not suitable
		} else if (addr->dprefix > 32) {
			addr->addr.s6_addr32[1] &= htonl(~((1U << (64 - addr->dprefix)) - 1));
		} else if (addr->dprefix <= 32) {
			addr->addr.s6_addr32[0] &= htonl(~((1U << (32 - addr->dprefix)) - 1));
			addr->addr.s6_addr32[1] = 0;
		}

		routes[routes_cnt].type = ND_OPT_ROUTE_INFO;
		routes[routes_cnt].len = sizeof(*routes) / 8;
		routes[routes_cnt].prefix = addr->dprefix;
		routes[routes_cnt].flags = 0;
		if (iface->route_preference < 0)
			routes[routes_cnt].flags |= ND_RA_PREF_LOW;
		else if (iface->route_preference > 0)
			routes[routes_cnt].flags |= ND_RA_PREF_HIGH;
		routes[routes_cnt].lifetime = htonl(TIME_LEFT(addr->valid, now));
		routes[routes_cnt].addr[0] = addr->addr.s6_addr32[0];
		routes[routes_cnt].addr[1] = addr->addr.s6_addr32[1];
		routes[routes_cnt].addr[2] = 0;
		routes[routes_cnt].addr[3] = 0;

		++routes_cnt;
	}

	search->lifetime = htonl(maxival*10);
	dns.lifetime = search->lifetime;

	struct icmpv6_opt adv_interval = {
		.type = ND_OPT_RTR_ADV_INTERVAL,
		.len = 1,
		.data = {0, 0, (maxival*1000) >> 24, (maxival*1000) >> 16, (maxival*1000) >> 8, maxival*1000}
	};

	struct iovec iov[RA_IOV_LEN] = {
			{&adv, (uint8_t*)&adv.prefix[cnt] - (uint8_t*)&adv},
			{&routes, routes_cnt * sizeof(*routes)},
			{&dns, (dns_cnt) ? sizeof(dns) : 0},
			{dns_addr, dns_cnt * sizeof(*dns_addr)},
			{search, search->len * 8},
			{&adv_interval, adv_interval.len * 8}};
	struct sockaddr_in6 dest = {AF_INET6, 0, 0, ALL_IPV6_NODES, 0};

	if (from && !IN6_IS_ADDR_UNSPECIFIED(from))
		dest.sin6_addr = *from;

	odhcpd_send(router_event.uloop.fd,
			&dest, iov, ARRAY_SIZE(iov), iface);

	return msecs;
}


static void trigger_router_advert(struct uloop_timeout *event)
{
	struct interface *iface = container_of(event, struct interface, timer_rs);
	int msecs = send_router_advert(iface, NULL);

	// Rearm timer if not shut down
	if (event->cb)
		uloop_timeout_set(event, msecs);
}


// Event handler for incoming ICMPv6 packets
static void handle_icmpv6(void *addr, void *data, size_t len,
		struct interface *iface, _unused void *dest)
{
	struct icmp6_hdr *hdr = data;
	struct sockaddr_in6 *from = addr;

	if (!router_icmpv6_valid(addr, data, len))
		return;

	if ((iface->ra == RELAYD_SERVER && !iface->master)) { // Server mode
		if (hdr->icmp6_type == ND_ROUTER_SOLICIT)
			send_router_advert(iface, &from->sin6_addr);
	} else if (iface->ra == RELAYD_RELAY) { // Relay mode
		if (hdr->icmp6_type == ND_ROUTER_ADVERT && iface->master)
			forward_router_advertisement(data, len);
		else if (hdr->icmp6_type == ND_ROUTER_SOLICIT && !iface->master)
			forward_router_solicitation(odhcpd_get_master_interface());
	}
}


// Forward router solicitation
static void forward_router_solicitation(const struct interface *iface)
{
	if (!iface)
		return;

	struct icmp6_hdr rs = {ND_ROUTER_SOLICIT, 0, 0, {{0}}};
	struct iovec iov = {&rs, sizeof(rs)};
	struct sockaddr_in6 all_routers =
		{AF_INET6, 0, 0, ALL_IPV6_ROUTERS, iface->ifindex};

	syslog(LOG_NOTICE, "Sending RS to %s", iface->ifname);
	odhcpd_send(router_event.uloop.fd, &all_routers, &iov, 1, iface);
}


// Handler for incoming router solicitations on slave interfaces
static void forward_router_advertisement(uint8_t *data, size_t len)
{
	struct nd_router_advert *adv = (struct nd_router_advert *)data;

	// Rewrite options
	uint8_t *end = data + len;
	uint8_t *mac_ptr = NULL;
	struct in6_addr *dns_ptr = NULL;
	size_t dns_count = 0;

	struct icmpv6_opt *opt;
	icmpv6_for_each_option(opt, &adv[1], end) {
		if (opt->type == ND_OPT_SOURCE_LINKADDR) {
			// Store address of source MAC-address
			mac_ptr = opt->data;
		} else if (opt->type == ND_OPT_RECURSIVE_DNS && opt->len > 1) {
			// Check if we have to rewrite DNS
			dns_ptr = (struct in6_addr*)&opt->data[6];
			dns_count = (opt->len - 1) / 2;
		}
	}

	syslog(LOG_NOTICE, "Got a RA");

	// Indicate a proxy, however we don't follow the rest of RFC 4389 yet
	adv->nd_ra_flags_reserved |= ND_RA_FLAG_PROXY;

	// Forward advertisement to all slave interfaces
	struct sockaddr_in6 all_nodes = {AF_INET6, 0, 0, ALL_IPV6_NODES, 0};
	struct iovec iov = {data, len};

	struct interface *iface;
	list_for_each_entry(iface, &interfaces, head) {
		if (iface->ra != RELAYD_RELAY || iface->master)
			continue;

		// Fixup source hardware address option
		if (mac_ptr)
			odhcpd_get_mac(iface, mac_ptr);

		// If we have to rewrite DNS entries
		if (iface->always_rewrite_dns && dns_ptr && dns_count > 0) {
			const struct in6_addr *rewrite = iface->dns;
			struct in6_addr addr;
			size_t rewrite_cnt = iface->dns_cnt;

			if (rewrite_cnt == 0) {
				if (odhcpd_get_interface_dns_addr(iface, &addr))
					continue; // Unable to comply

				rewrite = &addr;
				rewrite_cnt = 1;
			}

			// Copy over any other addresses
			for (size_t i = 0; i < dns_count; ++i) {
				size_t j = (i < rewrite_cnt) ? i : rewrite_cnt - 1;
				dns_ptr[i] = rewrite[j];
			}
		}

		odhcpd_send(router_event.uloop.fd, &all_nodes, &iov, 1, iface);
	}
}
