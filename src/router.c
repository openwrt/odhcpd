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
		syslog(LOG_ERR, "fopen(/proc/net/ipv6_route): %m");
		ret = -1;
		goto out;
	}

	if (netlink_add_netevent_handler(&router_netevent_handler) < 0) {
		syslog(LOG_ERR, "Failed to add netevent handler");
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
				syslog(LOG_ERR, "socket(AF_INET6): %m");
				ret = -1;
				goto out;
			}

			if (setsockopt(iface->router_event.uloop.fd, SOL_SOCKET, SO_BINDTODEVICE,
				       iface->ifname, strlen(iface->ifname)) < 0) {
				syslog(LOG_ERR, "setsockopt(SO_BINDTODEVICE): %m");
				ret = -1;
				goto out;
			}

			/* Let the kernel compute our checksums */
			if (setsockopt(iface->router_event.uloop.fd, IPPROTO_RAW, IPV6_CHECKSUM,
				       &val, sizeof(val)) < 0) {
				syslog(LOG_ERR, "setsockopt(IPV6_CHECKSUM): %m");
				ret = -1;
				goto out;
			}

			/* This is required by RFC 4861 */
			val = 255;
			if (setsockopt(iface->router_event.uloop.fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
				       &val, sizeof(val)) < 0) {
				syslog(LOG_ERR, "setsockopt(IPV6_MULTICAST_HOPS): %m");
				ret = -1;
				goto out;
			}

			if (setsockopt(iface->router_event.uloop.fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
				       &val, sizeof(val)) < 0) {
				syslog(LOG_ERR, "setsockopt(IPV6_UNICAST_HOPS): %m");
				ret = -1;
				goto out;
			}

			/* We need to know the source interface */
			val = 1;
			if (setsockopt(iface->router_event.uloop.fd, IPPROTO_IPV6, IPV6_RECVPKTINFO,
				       &val, sizeof(val)) < 0) {
				syslog(LOG_ERR, "setsockopt(IPV6_RECVPKTINFO): %m");
				ret = -1;
				goto out;
			}

			if (setsockopt(iface->router_event.uloop.fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
				       &val, sizeof(val)) < 0) {
				syslog(LOG_ERR, "setsockopt(IPV6_RECVHOPLIMIT): %m");
				ret = -1;
				goto out;
			}

			/* Don't loop back */
			val = 0;
			if (setsockopt(iface->router_event.uloop.fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
				       &val, sizeof(val)) < 0) {
				syslog(LOG_ERR, "setsockopt(IPV6_MULTICAST_LOOP): %m");
				ret = -1;
				goto out;
			}

			/* Filter ICMPv6 package types */
			ICMP6_FILTER_SETBLOCKALL(&filt);
			ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filt);
			ICMP6_FILTER_SETPASS(ND_ROUTER_SOLICIT, &filt);
			if (setsockopt(iface->router_event.uloop.fd, IPPROTO_ICMPV6, ICMP6_FILTER,
				       &filt, sizeof(filt)) < 0) {
				syslog(LOG_ERR, "setsockopt(ICMP6_FILTER): %m");
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
			syslog(LOG_ERR, "setsockopt(IPV6_ADD_MEMBERSHIP): %m");
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
	struct odhcpd_ipaddr p = { .addr.in6 = IN6ADDR_ANY_INIT, .prefix = 0,
					.dprefix = 0, .preferred = 0, .valid = 0};
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
				&p.addr.in6.s6_addr32[0], &p.addr.in6.s6_addr32[1], &p.prefix, &rflags) &&
				p.prefix > 0 && (rflags & RTF_NONEXTHOP) && (rflags & RTF_REJECT)) {
			// Find source prefixes by scanning through unreachable-routes
			p.addr.in6.s6_addr32[0] = htonl(p.addr.in6.s6_addr32[0]);
			p.addr.in6.s6_addr32[1] = htonl(p.addr.in6.s6_addr32[1]);

			for (ssize_t i = 0; i < len; ++i) {
				if (n[i].prefix <= 64 && n[i].prefix >= p.prefix &&
						!odhcpd_bmemcmp(&p.addr.in6, &n[i].addr.in6, p.prefix)) {
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

	/* RFC 2461 6.2.4 For the first MAX_INITIAL_RTR_ADVERTISEMENTS advertisements */
	/* if the timer is bigger than MAX_INITIAL_RTR_ADVERT_INTERVAL it should be   */
	/* set to MAX_INITIAL_RTR_ADVERT_INTERVAL                                     */
	/* Off by one as an initial interval timer has already expired                */
	if ((iface->ra_sent + 1) < MaxInitialRtAdvs && msecs > MaxInitialRtrAdvInterval*1000)
		msecs = MaxInitialRtrAdvInterval*1000;

	return msecs;
}

static uint32_t calc_ra_lifetime(struct interface *iface, uint32_t maxival)
{
	uint32_t lifetime = maxival * 3;

	if (iface->ra_lifetime >= 0) {
		lifetime = iface->ra_lifetime;
		if (lifetime > 0 && lifetime < maxival)
			lifetime = maxival;
		else if (lifetime > 9000)
			lifetime = 9000;
	}

	return lifetime;
}

enum {
	IOV_RA_ADV=0,
	IOV_RA_PFXS,
	IOV_RA_ROUTES,
	IOV_RA_DNS,
	IOV_RA_SEARCH,
	IOV_RA_PREF64,
	IOV_RA_ADV_INTERVAL,
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
	uint8_t pad;
	uint8_t pad2;
	uint32_t lifetime;
	uint8_t name[];
};

struct nd_opt_route_info {
	uint8_t type;
	uint8_t len;
	uint8_t prefix;
	uint8_t flags;
	uint32_t lifetime;
	uint32_t addr[4];
};

struct nd_opt_pref64_info {
	uint8_t type;
	uint8_t len;
	uint16_t lifetime_plc;
	uint32_t addr[3];
};

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
	struct nd_opt_adv_interval adv_interval;
	struct iovec iov[IOV_RA_TOTAL];
	struct sockaddr_in6 dest;
	size_t dns_sz = 0, search_sz = 0, pref64_sz = 0;
	size_t pfxs_cnt = 0, routes_cnt = 0;
	ssize_t valid_addr_cnt = 0, invalid_addr_cnt = 0;
	uint32_t minvalid = UINT32_MAX, maxival, lifetime;
	int msecs, mtu = iface->ra_mtu, hlim = iface->ra_hoplimit;
	bool default_route = false;
	bool valid_prefix = false;
	char buf[INET6_ADDRSTRLEN];

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

	adv.h.nd_ra_reachable = htonl(iface->ra_reachabletime);
	adv.h.nd_ra_retransmit = htonl(iface->ra_retranstime);

	adv.lladdr.type = ND_OPT_SOURCE_LINKADDR;
	adv.lladdr.len = 1;
	odhcpd_get_mac(iface, adv.lladdr.data);

	adv.mtu.nd_opt_mtu_type = ND_OPT_MTU;
	adv.mtu.nd_opt_mtu_len = 1;

	if (mtu == 0)
		mtu = odhcpd_get_interface_config(iface->ifname, "mtu");

	if (mtu < 1280)
		mtu = 1280;

	adv.mtu.nd_opt_mtu_mtu = htonl(mtu);

	iov[IOV_RA_ADV].iov_base = (char *)&adv;
	iov[IOV_RA_ADV].iov_len = sizeof(adv);

	valid_addr_cnt = (iface->timer_rs.cb /* if not shutdown */ ? iface->addr6_len : 0);
	invalid_addr_cnt = iface->invalid_addr6_len;

	// check ra_default
	if (iface->default_router) {
		default_route = true;

		if (iface->default_router > 1)
			valid_prefix = true;
	}

	if (valid_addr_cnt + invalid_addr_cnt) {
		addrs = alloca(sizeof(*addrs) * (valid_addr_cnt + invalid_addr_cnt));

		if (valid_addr_cnt) {
			memcpy(addrs, iface->addr6, sizeof(*addrs) * valid_addr_cnt);

			/* Check default route */
			if (!default_route && parse_routes(addrs, valid_addr_cnt))
				default_route = true;
		}

		if (invalid_addr_cnt) {
			size_t i = 0;

			memcpy(&addrs[valid_addr_cnt], iface->invalid_addr6, sizeof(*addrs) * invalid_addr_cnt);

			/* Remove invalid prefixes that were advertised 3 times */
			while (i < iface->invalid_addr6_len) {
				if (++iface->invalid_addr6[i].invalid_advertisements >= 3) {
					if (i + 1 < iface->invalid_addr6_len)
						memmove(&iface->invalid_addr6[i], &iface->invalid_addr6[i + 1], sizeof(*addrs) * (iface->invalid_addr6_len - i - 1));

					iface->invalid_addr6_len--;

					if (iface->invalid_addr6_len) {
						struct odhcpd_ipaddr *new_invalid_addr6 = realloc(iface->invalid_addr6, sizeof(*addrs) * iface->invalid_addr6_len);

						if (new_invalid_addr6)
							iface->invalid_addr6 = new_invalid_addr6;
					} else {
						free(iface->invalid_addr6);
						iface->invalid_addr6 = NULL;
					}
				} else
					++i;
			}
		}
	}

	/* Construct Prefix Information options */
	for (ssize_t i = 0; i < valid_addr_cnt + invalid_addr_cnt; ++i) {
		struct odhcpd_ipaddr *addr = &addrs[i];
		struct nd_opt_prefix_info *p = NULL;
		uint32_t preferred = 0;
		uint32_t valid = 0;

		if (addr->prefix > 96 || (i < valid_addr_cnt && addr->valid <= (uint32_t)now)) {
			syslog(LOG_INFO, "Address %s (prefix %d, valid %u) not suitable as RA prefix on %s",
				inet_ntop(AF_INET6, &addr->addr.in6, buf, sizeof(buf)), addr->prefix,
				addr->valid, iface->name);
			continue;
		}

		if (ADDR_MATCH_PIO_FILTER(addr, iface)) {
			syslog(LOG_INFO, "Address %s filtered out as RA prefix on %s",
			       inet_ntop(AF_INET6, &addr->addr.in6, buf, sizeof(buf)),
			       iface->name);
			continue; /* PIO filtered out of this RA */
		}

		for (size_t i = 0; i < pfxs_cnt; ++i) {
			if (addr->prefix == pfxs[i].nd_opt_pi_prefix_len &&
					!odhcpd_bmemcmp(&pfxs[i].nd_opt_pi_prefix,
					&addr->addr.in6, addr->prefix))
				p = &pfxs[i];
		}

		if (!p) {
			struct nd_opt_prefix_info *tmp;

			tmp = realloc(pfxs, sizeof(*pfxs) * (pfxs_cnt + 1));
			if (!tmp) {
				syslog(LOG_ERR, "Realloc failed for RA prefix option on %s", iface->name);
				continue;
			}

			pfxs = tmp;
			p = &pfxs[pfxs_cnt++];
			memset(p, 0, sizeof(*p));
		}

		if (addr->preferred > (uint32_t)now) {
			preferred = TIME_LEFT(addr->preferred, now);

			if (iface->max_preferred_lifetime && preferred > iface->max_preferred_lifetime)
				preferred = iface->max_preferred_lifetime;
		}

		if (addr->valid > (uint32_t)now) {
			valid = TIME_LEFT(addr->valid, now);

			if (iface->max_valid_lifetime && valid > iface->max_valid_lifetime)
				valid = iface->max_valid_lifetime;
		}

		if (minvalid > valid)
			minvalid = valid;

		if ((!IN6_IS_ADDR_ULA(&addr->addr.in6) || iface->default_router) && valid)
			valid_prefix = true;

		odhcpd_bmemcpy(&p->nd_opt_pi_prefix, &addr->addr.in6,
				(iface->ra_advrouter) ? 128 : addr->prefix);
		p->nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
		p->nd_opt_pi_len = 4;
		p->nd_opt_pi_prefix_len = (addr->prefix < 64) ? 64 : addr->prefix;
		p->nd_opt_pi_flags_reserved = 0;
		if (!iface->ra_not_onlink)
			p->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_ONLINK;
		if (iface->ra_slaac && addr->prefix <= 64)
			p->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_AUTO;
		if (iface->ra_advrouter)
			p->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_RADDR;
		p->nd_opt_pi_preferred_time = htonl(preferred);
		p->nd_opt_pi_valid_time = htonl(valid);
	}

	iov[IOV_RA_PFXS].iov_base = (char *)pfxs;
	iov[IOV_RA_PFXS].iov_len = pfxs_cnt * sizeof(*pfxs);

	/* Calculate periodic transmit */
	msecs = calc_adv_interval(iface, minvalid, &maxival);
	lifetime = calc_ra_lifetime(iface, maxival);

	if (!iface->have_link_local) {
		syslog(LOG_NOTICE, "Skip sending a RA on %s as no link local address is available", iface->name);
		goto out;
	}

	if (default_route && valid_prefix) {
		adv.h.nd_ra_router_lifetime = htons(lifetime < UINT16_MAX ? lifetime : UINT16_MAX);
	} else {
		adv.h.nd_ra_router_lifetime = 0;

		if (default_route) {
			syslog(LOG_WARNING, "A default route is present but there is no public prefix "
					    "on %s thus we don't announce a default route by setting ra_lifetime to zero!", iface->name);
		} else {
			syslog(LOG_WARNING, "No default route present, setting ra_lifetime to zero!");
		}
	}

	syslog(LOG_DEBUG, "Using a RA lifetime of %d seconds on %s", ntohs(adv.h.nd_ra_router_lifetime), iface->name);

	/* DNS options */
	if (iface->ra_dns) {
		struct in6_addr dns_pref, *dns_addr = NULL;
		size_t dns_cnt = 0, search_len = iface->search_len;
		uint8_t *search_domain = iface->search;
		uint8_t search_buf[256];

		/* DNS Recursive DNS */
		if (iface->dns_cnt > 0) {
			dns_addr = iface->dns;
			dns_cnt = iface->dns_cnt;
		} else if (!odhcpd_get_interface_dns_addr(iface, &dns_pref)) {
			dns_addr = &dns_pref;
			dns_cnt = 1;
		}

		if (dns_cnt) {
			dns_sz = sizeof(*dns) + sizeof(struct in6_addr)*dns_cnt;

			dns = alloca(dns_sz);
			memset(dns, 0, dns_sz);
			dns->type = ND_OPT_RECURSIVE_DNS;
			dns->len = 1 + (2 * dns_cnt);
			dns->lifetime = htonl(lifetime);
			memcpy(dns->addr, dns_addr, sizeof(struct in6_addr)*dns_cnt);
		}

		/* DNS Search options */
		if (!search_domain && !res_init() && _res.dnsrch[0] && _res.dnsrch[0][0]) {
			int len = dn_comp(_res.dnsrch[0], search_buf,
					sizeof(search_buf), NULL, NULL);
			if (len > 0) {
				search_domain = search_buf;
				search_len = len;
			}
		}

		if (search_len > 0) {
			size_t search_padded = ((search_len + 7) & (~7)) + 8;

			search_sz = sizeof(*search) + search_padded;

			search = alloca(search_sz);
			memset(search, 0, search_sz);
			search->type = ND_OPT_DNS_SEARCH;
			search->len = search_len ? ((sizeof(*search) + search_padded) / 8) : 0;
			search->lifetime = htonl(lifetime);
			memcpy(search->name, search_domain, search_len);
			memset(&search->name[search_len], 0, search_padded - search_len);
		}
	}

	iov[IOV_RA_DNS].iov_base = (char *)dns;
	iov[IOV_RA_DNS].iov_len = dns_sz;
	iov[IOV_RA_SEARCH].iov_base = (char *)search;
	iov[IOV_RA_SEARCH].iov_len = search_sz;

	if (iface->pref64_length) {
		/* RFC 8781 § 4.1 rounding up lifetime to multiply of 8 */
		uint16_t pref64_lifetime = lifetime < (UINT16_MAX - 7) ? lifetime + 7 : (UINT16_MAX - 7);
		uint8_t prefix_length_code;
		uint32_t mask_a1, mask_a2;

		switch (iface->pref64_length) {
		case 96:
			prefix_length_code = 0;
			mask_a1 = 0xffffffff;
			mask_a2 = 0xffffffff;
			break;
		case 64:
			prefix_length_code = 1;
			mask_a1 = 0xffffffff;
			mask_a2 = 0x00000000;
			break;
		case 56:
			prefix_length_code = 2;
			mask_a1 = 0xffffff00;
			mask_a2 = 0x00000000;
			break;
		case 48:
			prefix_length_code = 3;
			mask_a1 = 0xffff0000;
			mask_a2 = 0x00000000;
			break;
		case 40:
			prefix_length_code = 4;
			mask_a1 = 0xff000000;
			mask_a2 = 0x00000000;
			break;
		case 32:
			prefix_length_code = 5;
			mask_a1 = 0x00000000;
			mask_a2 = 0x00000000;
			break;
		default:
			syslog(LOG_WARNING, "Invalid PREF64 prefix size (%d), "
					"ignoring ra_pref64 option!", iface->pref64_length);
			goto pref64_out;
			break;
		}

		pref64_sz = sizeof(*pref64);
		pref64 = alloca(pref64_sz);
		memset(pref64, 0, pref64_sz);
		pref64->type = ND_OPT_PREF64;
		pref64->len = 2;
		pref64->lifetime_plc = htons((0xfff8 & pref64_lifetime) |
						(0x7 & prefix_length_code));
		pref64->addr[0] = iface->pref64_addr.s6_addr32[0];
		pref64->addr[1] = iface->pref64_addr.s6_addr32[1] & htonl(mask_a1);
		pref64->addr[2] = iface->pref64_addr.s6_addr32[2] & htonl(mask_a2);
	}
pref64_out:
	iov[IOV_RA_PREF64].iov_base = (char *)pref64;
	iov[IOV_RA_PREF64].iov_len = pref64_sz;

	/*
	 * RFC7084 § 4.3 :
	 *    L-3:   An IPv6 CE router MUST advertise itself as a router for the
	 *           delegated prefix(es) (and ULA prefix if configured to provide
	 *           ULA addressing) using the "Route Information Option" specified
	 *           in Section 2.3 of [RFC4191].  This advertisement is
	 *           independent of having or not having IPv6 connectivity on the
	 *           WAN interface.
	 */

	for (ssize_t i = 0; i < valid_addr_cnt; ++i) {
		struct odhcpd_ipaddr *addr = &addrs[i];
		struct nd_opt_route_info *tmp;
		uint32_t valid;

		if (addr->dprefix >= 64 || addr->dprefix == 0 || addr->valid <= (uint32_t)now) {
			syslog(LOG_INFO, "Address %s (dprefix %d, valid %u) not suitable as RA route on %s",
				inet_ntop(AF_INET6, &addr->addr.in6, buf, sizeof(buf)),
				addr->dprefix, addr->valid, iface->name);

			continue; /* Address not suitable */
		}

		if (ADDR_MATCH_PIO_FILTER(addr, iface)) {
			syslog(LOG_INFO, "Address %s filtered out as RA route on %s",
			       inet_ntop(AF_INET6, &addr->addr.in6, buf, sizeof(buf)),
			       iface->name);
			continue; /* PIO filtered out of this RA */
		}

		if (addr->dprefix > 32) {
			addr->addr.in6.s6_addr32[1] &= htonl(~((1U << (64 - addr->dprefix)) - 1));
		} else if (addr->dprefix <= 32) {
			addr->addr.in6.s6_addr32[0] &= htonl(~((1U << (32 - addr->dprefix)) - 1));
			addr->addr.in6.s6_addr32[1] = 0;
		}

		tmp = realloc(routes, sizeof(*routes) * (routes_cnt + 1));
		if (!tmp) {
			syslog(LOG_ERR, "Realloc failed for RA route option on %s", iface->name);
			continue;
		}

		routes = tmp;

		memset(&routes[routes_cnt], 0, sizeof(*routes));
		routes[routes_cnt].type = ND_OPT_ROUTE_INFO;
		routes[routes_cnt].len = sizeof(*routes) / 8;
		routes[routes_cnt].prefix = addr->dprefix;
		routes[routes_cnt].flags = 0;
		if (iface->route_preference < 0)
			routes[routes_cnt].flags |= ND_RA_PREF_LOW;
		else if (iface->route_preference > 0)
			routes[routes_cnt].flags |= ND_RA_PREF_HIGH;

		valid = TIME_LEFT(addr->valid, now);
		routes[routes_cnt].lifetime = htonl(valid < lifetime ? valid : lifetime);
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

	memset(&dest, 0, sizeof(dest));
	dest.sin6_family = AF_INET6;

	if (from && !IN6_IS_ADDR_UNSPECIFIED(from))
		dest.sin6_addr = *from;
	else
		inet_pton(AF_INET6, ALL_IPV6_NODES, &dest.sin6_addr);

	syslog(LOG_NOTICE, "Sending a RA on %s", iface->name);

	if (odhcpd_send(iface->router_event.uloop.fd, &dest, iov, ARRAY_SIZE(iov), iface) > 0)
		iface->ra_sent++;

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
		struct interface *iface, _unused void *dest)
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


/* Forward router solicitation */
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

	syslog(LOG_NOTICE, "Sending RS to %s", iface->name);
	odhcpd_send(iface->router_event.uloop.fd, &all_routers, &iov, 1, iface);
}


/* Handler for incoming router solicitations on slave interfaces */
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
	struct in6_addr *dns_ptr = NULL;
	size_t dns_count = 0;

	icmpv6_for_each_option(opt, &adv[1], end) {
		if (opt->type == ND_OPT_SOURCE_LINKADDR) {
			/* Store address of source MAC-address */
			mac_ptr = opt->data;
		} else if (opt->type == ND_OPT_RECURSIVE_DNS && opt->len > 1) {
			/* Check if we have to rewrite DNS */
			dns_ptr = (struct in6_addr*)&opt->data[6];
			dns_count = (opt->len - 1) / 2;
		}
	}

	syslog(LOG_NOTICE, "Got a RA on %s", iface->name);

	/* Indicate a proxy, however we don't follow the rest of RFC 4389 yet */
	adv->nd_ra_flags_reserved |= ND_RA_FLAG_PROXY;

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

		/* If we have to rewrite DNS entries */
		if (c->always_rewrite_dns && dns_ptr && dns_count > 0) {
			const struct in6_addr *rewrite = c->dns;
			struct in6_addr addr;
			size_t rewrite_cnt = c->dns_cnt;

			if (rewrite_cnt == 0) {
				if (odhcpd_get_interface_dns_addr(c, &addr))
					continue; /* Unable to comply */

				rewrite = &addr;
				rewrite_cnt = 1;
			}

			/* Copy over any other addresses */
			for (size_t i = 0; i < dns_count; ++i) {
				size_t j = (i < rewrite_cnt) ? i : rewrite_cnt - 1;
				dns_ptr[i] = rewrite[j];
			}
		}

		syslog(LOG_NOTICE, "Forward a RA on %s", c->name);

		odhcpd_send(c->router_event.uloop.fd, &all_nodes, &iov, 1, c);
	}
}
