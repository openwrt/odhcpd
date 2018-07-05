/**
 * Copyright (C) 2012-2013 Steven Barth <steven@midlink.org>
 * Copyright (C) 2016 Hans Dedecker <dedeckeh@gmail.com>
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
 *
 */

#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stddef.h>
#include <stdlib.h>
#include <resolv.h>
#include <limits.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <sys/timerfd.h>
#include <arpa/inet.h>

#include <libubox/md5.h>

#include "odhcpd.h"
#include "dhcpv4.h"
#include "dhcpv6.h"

static void dhcpv4_netevent_cb(unsigned long event, struct netevent_handler_info *info);
static int setup_dhcpv4_addresses(struct interface *iface);
static void update_static_assignments(struct interface *iface);
static bool addr_is_fr_ip(struct interface *iface, struct in_addr *addr);
static void valid_until_cb(struct uloop_timeout *event);
static void handle_addrlist_change(struct interface *iface);
static void free_dhcpv4_assignment(struct dhcpv4_assignment *a);
static void dhcpv4_fr_start(struct dhcpv4_assignment *a);
static void dhcpv4_fr_rand_delay(struct dhcpv4_assignment *a);
static void dhcpv4_fr_stop(struct dhcpv4_assignment *a);
static void handle_dhcpv4(void *addr, void *data, size_t len,
		struct interface *iface, void *dest_addr);
static struct dhcpv4_assignment* dhcpv4_lease(struct interface *iface,
		enum dhcpv4_msg msg, const uint8_t *mac, const uint32_t reqaddr,
		uint32_t *leasetime, const char *hostname, const size_t hostname_len,
		const bool accept_fr_nonce, bool *incl_fr_opt, uint32_t *fr_serverid);

static struct netevent_handler dhcpv4_netevent_handler = { .cb = dhcpv4_netevent_cb, };
static struct uloop_timeout valid_until_timeout = {.cb = valid_until_cb};
static uint32_t serial = 0;

struct odhcpd_ref_ip {
	struct list_head head;
	int ref_cnt;
	struct odhcpd_ipaddr addr;
};

/* Create socket and register events */
int dhcpv4_init(void)
{
	uloop_timeout_set(&valid_until_timeout, 1000);
	netlink_add_netevent_handler(&dhcpv4_netevent_handler);

	return 0;
}

int dhcpv4_setup_interface(struct interface *iface, bool enable)
{
	int ret = 0;

	if (iface->dhcpv4_event.uloop.fd > 0) {
		uloop_fd_delete(&iface->dhcpv4_event.uloop);
		close(iface->dhcpv4_event.uloop.fd);
		iface->dhcpv4_event.uloop.fd = -1;
	}

	if (iface->dhcpv4 && enable) {
		struct sockaddr_in bind_addr = {AF_INET, htons(DHCPV4_SERVER_PORT),
					{INADDR_ANY}, {0}};
		int val = 1;

		if (!iface->dhcpv4_assignments.next)
			INIT_LIST_HEAD(&iface->dhcpv4_assignments);

		if (!iface->dhcpv4_fr_ips.next)
			INIT_LIST_HEAD(&iface->dhcpv4_fr_ips);

		iface->dhcpv4_event.uloop.fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
		if (iface->dhcpv4_event.uloop.fd < 0) {
			syslog(LOG_ERR, "socket(AF_INET): %m");
			ret = -1;
			goto out;
		}

		/* Basic IPv4 configuration */
		if (setsockopt(iface->dhcpv4_event.uloop.fd, SOL_SOCKET, SO_REUSEADDR,
					&val, sizeof(val)) < 0) {
			syslog(LOG_ERR, "setsockopt(SO_REUSEADDR): %m");
			ret = -1;
			goto out;
		}

		if (setsockopt(iface->dhcpv4_event.uloop.fd, SOL_SOCKET, SO_BROADCAST,
					&val, sizeof(val)) < 0) {
			syslog(LOG_ERR, "setsockopt(SO_BROADCAST): %m");
			ret = -1;
			goto out;
		}

		if (setsockopt(iface->dhcpv4_event.uloop.fd, IPPROTO_IP, IP_PKTINFO,
					&val, sizeof(val)) < 0) {
			syslog(LOG_ERR, "setsockopt(IP_PKTINFO): %m");
			ret = -1;
			goto out;
		}

		val = IPTOS_PREC_INTERNETCONTROL;
		if (setsockopt(iface->dhcpv4_event.uloop.fd, IPPROTO_IP, IP_TOS,
					&val, sizeof(val)) < 0) {
			syslog(LOG_ERR, "setsockopt(IP_TOS): %m");
			ret = -1;
			goto out;
		}

		val = IP_PMTUDISC_DONT;
		if (setsockopt(iface->dhcpv4_event.uloop.fd, IPPROTO_IP, IP_MTU_DISCOVER,
					&val, sizeof(val)) < 0) {
			syslog(LOG_ERR, "setsockopt(IP_MTU_DISCOVER): %m");
			ret = -1;
			goto out;
		}

		if (setsockopt(iface->dhcpv4_event.uloop.fd, SOL_SOCKET, SO_BINDTODEVICE,
					iface->ifname, strlen(iface->ifname)) < 0) {
			syslog(LOG_ERR, "setsockopt(SO_BINDTODEVICE): %m");
			ret = -1;
			goto out;
		}

		if (bind(iface->dhcpv4_event.uloop.fd, (struct sockaddr*)&bind_addr,
					sizeof(bind_addr)) < 0) {
			syslog(LOG_ERR, "bind(): %m");
			ret = -1;
			goto out;
		}

		if (setup_dhcpv4_addresses(iface) < 0) {
			ret = -1;
			goto out;
		}

		iface->dhcpv4_event.handle_dgram = handle_dhcpv4;
		odhcpd_register(&iface->dhcpv4_event);

		update_static_assignments(iface);
	} else if (iface->dhcpv4_assignments.next) {
		while (!list_empty(&iface->dhcpv4_assignments))
			free_dhcpv4_assignment(list_first_entry(&iface->dhcpv4_assignments,
							struct dhcpv4_assignment, head));
	}

out:
	if (ret < 0 && iface->dhcpv4_event.uloop.fd > 0) {
		close(iface->dhcpv4_event.uloop.fd);
		iface->dhcpv4_event.uloop.fd = -1;
	}

	return ret;
}


static void dhcpv4_netevent_cb(unsigned long event, struct netevent_handler_info *info)
{
	struct interface *iface = info->iface;

	if (!iface || iface->dhcpv4 == MODE_DISABLED)
		return;

	switch (event) {
	case NETEV_IFINDEX_CHANGE:
		dhcpv4_setup_interface(iface, true);
		break;
	case NETEV_ADDRLIST_CHANGE:
		handle_addrlist_change(iface);
		break;
	default:
		break;
	}
}

static struct dhcpv4_assignment *find_assignment_by_hwaddr(struct interface *iface, const uint8_t *hwaddr)
{
	struct dhcpv4_assignment *a;

	list_for_each_entry(a, &iface->dhcpv4_assignments, head)
		if (!memcmp(a->hwaddr, hwaddr, 6))
			return a;

	return NULL;
}

static struct dhcpv4_assignment *find_assignment_by_addr(struct interface *iface, const uint32_t addr)
{
	struct dhcpv4_assignment *a;

	list_for_each_entry(a, &iface->dhcpv4_assignments, head)
		if (a->addr == addr)
			return a;

	return NULL;
}

static int setup_dhcpv4_addresses(struct interface *iface)
{
	iface->dhcpv4_start_ip.s_addr = INADDR_ANY;
	iface->dhcpv4_end_ip.s_addr = INADDR_ANY;
	iface->dhcpv4_local.s_addr = INADDR_ANY;
	iface->dhcpv4_bcast.s_addr = INADDR_ANY;
	iface->dhcpv4_mask.s_addr = INADDR_ANY;

	/* Sanity checks */
	if (iface->dhcpv4_start.s_addr & htonl(0xffff0000) ||
	    iface->dhcpv4_end.s_addr & htonl(0xffff0000) ||
	    ntohl(iface->dhcpv4_start.s_addr) > ntohl(iface->dhcpv4_end.s_addr)) {
		syslog(LOG_ERR, "invalid DHCP range for %s", iface->name);
		return -1;
	}

	if (!iface->addr4_len) {
		syslog(LOG_WARNING, "no network(s) available on %s", iface->name);
		return -1;
	}

	uint32_t start = ntohl(iface->dhcpv4_start.s_addr);
	uint32_t end = ntohl(iface->dhcpv4_end.s_addr);

	for (size_t i = 0; i < iface->addr4_len && start && end; i++) {
		struct in_addr *addr = &iface->addr4[i].addr.in;
		struct in_addr mask;

		if (addr_is_fr_ip(iface, addr))
			continue;

		odhcpd_bitlen2netmask(false, iface->addr4[i].prefix, &mask);
		if ((start & ntohl(~mask.s_addr)) == start &&
			    (end & ntohl(~mask.s_addr)) == end) {
			iface->dhcpv4_start_ip.s_addr = htonl(start) |
							(addr->s_addr & mask.s_addr);
			iface->dhcpv4_end_ip.s_addr = htonl(end) |
							(addr->s_addr & mask.s_addr);
			iface->dhcpv4_local = *addr;
			iface->dhcpv4_bcast = iface->addr4[i].broadcast;
			iface->dhcpv4_mask = mask;
			return 0;
		}
	}

	/* Don't allocate IP range for subnets bigger than 28 */
	if (iface->addr4[0].prefix > 28) {
		syslog(LOG_WARNING, "auto allocation of DHCP range fails on %s", iface->name);
		return -1;
	}

	iface->dhcpv4_local = iface->addr4[0].addr.in;
	iface->dhcpv4_bcast = iface->addr4[0].broadcast;
	odhcpd_bitlen2netmask(false, iface->addr4[0].prefix, &iface->dhcpv4_mask);
	end = start = iface->dhcpv4_local.s_addr & iface->dhcpv4_mask.s_addr;

	/* Auto allocate ranges */
	if (ntohl(iface->dhcpv4_mask.s_addr) <= 0xffffff00) {
		iface->dhcpv4_start_ip.s_addr = start | htonl(100);
		iface->dhcpv4_end_ip.s_addr = end | htonl(250);
	} else if (ntohl(iface->dhcpv4_mask.s_addr) <= 0xffffffc0) {
		iface->dhcpv4_start_ip.s_addr = start | htonl(10);
		iface->dhcpv4_end_ip.s_addr = end | htonl(60);
	} else if (ntohl(iface->dhcpv4_mask.s_addr) <= 0xffffffe0) {
		iface->dhcpv4_start_ip.s_addr = start | htonl(10);
		iface->dhcpv4_end_ip.s_addr = end | htonl(30);
	} else {
		iface->dhcpv4_start_ip.s_addr = start | htonl(3);
		iface->dhcpv4_end_ip.s_addr = end | htonl(12);
	}

	return 0;
}

static void update_static_assignments(struct interface *iface)
{
	struct dhcpv4_assignment *a, *c;

	/* Cleanup static entries not belonging to the network */
	list_for_each_entry_safe(a, c, &iface->dhcpv4_assignments, head) {
		if ((a->flags & OAF_STATIC) &&
				((a->addr & iface->dhcpv4_mask.s_addr) !=
				 (iface->dhcpv4_start.s_addr & iface->dhcpv4_mask.s_addr)))
			free_dhcpv4_assignment(a);
	}

	/* Parse static entries */
	struct lease *lease;
	list_for_each_entry(lease, &leases, head) {
		if ((iface->dhcpv4_start_ip.s_addr & iface->dhcpv4_mask.s_addr) !=
				(lease->ipaddr.s_addr & iface->dhcpv4_mask.s_addr)) {
			continue;
		}

		a = find_assignment_by_hwaddr(iface, lease->mac.ether_addr_octet);

		if (!a) {
			/* Check if there's an assignment with the specified IP address */
			if (find_assignment_by_addr(iface, lease->ipaddr.s_addr))
				continue;

			/* Construct entry */
			a = calloc(1, sizeof(*a));
			if (!a) {
				syslog(LOG_ERR, "Calloc failed for static lease on interface %s",
					iface->ifname);
				continue;
			}
			memcpy(a->hwaddr, lease->mac.ether_addr_octet, sizeof(a->hwaddr));
		}

		a->leasetime = lease->dhcpv4_leasetime;

		a->addr = lease->ipaddr.s_addr;
		/* Static assignment */
		a->flags |= OAF_STATIC;
		/* Infinite valid */
		a->valid_until = 0;
		a->iface = iface;
		if (lease->hostname[0]) {
			free(a->hostname);
			a->hostname = strdup(lease->hostname);
		}

		/* Assign to all interfaces */
		list_for_each_entry(c, &iface->dhcpv4_assignments, head) {
			if (ntohl(c->addr) > ntohl(a->addr)) {
				list_add_tail(&a->head, &c->head);
				break;
			}
		}

		if (&c->head == &iface->dhcpv4_assignments)
			list_add(&a->head, &iface->dhcpv4_assignments);
	}
}

static void inc_ref_cnt_ip(struct odhcpd_ref_ip **ptr, struct odhcpd_ref_ip *ip)
{
	*ptr = ip;
	ip->ref_cnt++;
}

static void decr_ref_cnt_ip(struct odhcpd_ref_ip **ptr, struct interface *iface)
{
	struct odhcpd_ref_ip *ip = *ptr;

	if (--ip->ref_cnt == 0) {
		netlink_setup_addr(&ip->addr, iface->ifindex, false, false);

		list_del(&ip->head);
		free(ip);
	}

	*ptr = NULL;
}

static bool addr_is_fr_ip(struct interface *iface, struct in_addr *addr)
{
	struct odhcpd_ref_ip *p;

	list_for_each_entry(p, &iface->dhcpv4_fr_ips, head) {
		if (addr->s_addr == p->addr.addr.in.s_addr)
			return true;
	}

	return false;
}

static bool leases_require_fr(struct interface *iface, struct odhcpd_ipaddr *addr,
				uint32_t mask)
{
	struct dhcpv4_assignment *a = NULL;
	struct odhcpd_ref_ip *fr_ip = NULL;

	list_for_each_entry(a, &iface->dhcpv4_assignments, head) {
		if ((a->accept_fr_nonce || iface->dhcpv4_forcereconf) &&
		    !a->fr_ip &&
		    ((a->addr & mask) == (addr->addr.in.s_addr & mask))) {
			if (!fr_ip) {
				fr_ip = calloc(1, sizeof(*fr_ip));
				if (!fr_ip)
					break;

				list_add(&fr_ip->head, &iface->dhcpv4_fr_ips);
				fr_ip->addr = *addr;
			}
			inc_ref_cnt_ip(&a->fr_ip, fr_ip);
		}
	}

	return fr_ip ? true : false;
}

static void valid_until_cb(struct uloop_timeout *event)
{
	time_t now = odhcpd_time();
	struct interface *iface;
	list_for_each_entry(iface, &interfaces, head) {
		if (iface->dhcpv4 != MODE_SERVER || iface->dhcpv4_assignments.next == NULL)
			continue;

		struct dhcpv4_assignment *a, *n;
		list_for_each_entry_safe(a, n, &iface->dhcpv4_assignments, head) {
			if (!INFINITE_VALID(a->valid_until) && a->valid_until < now)
				free_dhcpv4_assignment(a);
		}
	}
	uloop_timeout_set(event, 1000);
}

static void handle_addrlist_change(struct interface *iface)
{
	struct odhcpd_ipaddr ip;
	struct odhcpd_ref_ip *a;
	struct dhcpv4_assignment *c;
	uint32_t mask = iface->dhcpv4_mask.s_addr;

	memset(&ip, 0, sizeof(ip));
	ip.addr.in = iface->dhcpv4_local;
	ip.prefix = odhcpd_netmask2bitlen(false, &iface->dhcpv4_mask);
	ip.broadcast = iface->dhcpv4_bcast;

	setup_dhcpv4_addresses(iface);

	if ((ip.addr.in.s_addr & mask) ==
	    (iface->dhcpv4_local.s_addr & iface->dhcpv4_mask.s_addr))
		return;

	if (ip.addr.in.s_addr && !leases_require_fr(iface, &ip, mask))
		return;

	if (iface->dhcpv4_local.s_addr == INADDR_ANY || list_empty(&iface->dhcpv4_fr_ips))
		return;

	a = list_first_entry(&iface->dhcpv4_fr_ips, struct odhcpd_ref_ip, head);

	if (netlink_setup_addr(&a->addr, iface->ifindex, false, true)) {
		syslog(LOG_ERR, "Failed to add ip address");
		return;
	}

	list_for_each_entry(c, &iface->dhcpv4_assignments, head) {
		if ((c->flags & OAF_BOUND) && c->fr_ip && !c->fr_cnt) {
			if (c->accept_fr_nonce || iface->dhcpv4_forcereconf)
				dhcpv4_fr_rand_delay(c);
			else
				dhcpv4_fr_stop(c);
		}
	}
}

static char *dhcpv4_msg_to_string(uint8_t reqmsg)
{
	switch (reqmsg) {
	case (DHCPV4_MSG_DISCOVER):
		return "DHCPV4_MSG_DISCOVER";
	case (DHCPV4_MSG_OFFER):
		return "DHCPV4_MSG_OFFER";
	case (DHCPV4_MSG_REQUEST):
		return "DHCPV4_MSG_REQUEST";
	case (DHCPV4_MSG_DECLINE):
		return "DHCPV4_MSG_DECLINE";
	case (DHCPV4_MSG_ACK):
		return "DHCPV4_MSG_ACK";
	case (DHCPV4_MSG_NAK):
		return "DHCPV4_MSG_NAK";
	case (DHCPV4_MSG_RELEASE):
		return "DHCPV4_MSG_RELEASE";
	case (DHCPV4_MSG_INFORM):
		return "DHCPV4_MSG_INFORM";
	case (DHCPV4_MSG_FORCERENEW):
		return "DHCPV4_MSG_FORCERENEW";
	default:
		return "UNKNOWN";
	}
}

static void free_dhcpv4_assignment(struct dhcpv4_assignment *a)
{
	if (a->head.next)
		list_del(&a->head);

	if (a->fr_ip)
		dhcpv4_fr_stop(a);

	free(a->hostname);
	free(a);
}

static void dhcpv4_put(struct dhcpv4_message *msg, uint8_t **cookie,
		uint8_t type, uint8_t len, const void *data)
{
	uint8_t *c = *cookie;
	uint8_t *end = (uint8_t *)msg + sizeof(*msg);

	if (*cookie + 2 + len > end)
		return;

	*c++ = type;
	*c++ = len;
	memcpy(c, data, len);

	*cookie = c + len;
}

static void dhcpv4_fr_send(struct dhcpv4_assignment *a)
{
	struct dhcpv4_message fr_msg = {
		.op = DHCPV4_BOOTREPLY,
		.htype = 1,
		.hlen = 6,
		.hops = 0,
		.secs = 0,
		.flags = 0,
		.ciaddr = {INADDR_ANY},
		.yiaddr = {INADDR_ANY},
		.siaddr = {INADDR_ANY},
		.giaddr = {INADDR_ANY},
		.chaddr = {0},
		.sname = {0},
		.file = {0},
	};
	struct dhcpv4_auth_forcerenew *auth_o, auth = {
		.protocol = 3,
		.algorithm = 1,
		.rdm = 0,
		.replay = {htonl(time(NULL)), htonl(++serial)},
		.type = 2,
		.key = {0},
	};
	struct interface *iface = a->iface;

	odhcpd_urandom(&fr_msg.xid, sizeof(fr_msg.xid));
	memcpy(fr_msg.chaddr, a->hwaddr, fr_msg.hlen);

	fr_msg.options[0] = 0x63;
	fr_msg.options[1] = 0x82;
	fr_msg.options[2] = 0x53;
	fr_msg.options[3] = 0x63;

	uint8_t *cookie = &fr_msg.options[4];
	uint8_t msg = DHCPV4_MSG_FORCERENEW;

	dhcpv4_put(&fr_msg, &cookie, DHCPV4_OPT_MESSAGE, 1, &msg);
	if (a->accept_fr_nonce) {
		dhcpv4_put(&fr_msg, &cookie, DHCPV4_OPT_AUTHENTICATION, sizeof(auth), &auth);
		auth_o = (struct dhcpv4_auth_forcerenew *)(cookie - sizeof(auth));
		dhcpv4_put(&fr_msg, &cookie, DHCPV4_OPT_END, 0, NULL);

		md5_ctx_t md5;
		uint8_t secretbytes[64];
		memset(secretbytes, 0, sizeof(secretbytes));
		memcpy(secretbytes, a->key, sizeof(a->key));

		for (size_t i = 0; i < sizeof(secretbytes); ++i)
			secretbytes[i] ^= 0x36;

		md5_begin(&md5);
		md5_hash(secretbytes, sizeof(secretbytes), &md5);
		md5_hash(&fr_msg, sizeof(fr_msg), &md5);
		md5_end(auth_o->key, &md5);

		for (size_t i = 0; i < sizeof(secretbytes); ++i) {
			secretbytes[i] ^= 0x36;
			secretbytes[i] ^= 0x5c;
		}

		md5_begin(&md5);
		md5_hash(secretbytes, sizeof(secretbytes), &md5);
		md5_hash(auth_o->key, sizeof(auth_o->key), &md5);
		md5_end(auth_o->key, &md5);
	} else {
		dhcpv4_put(&fr_msg, &cookie, DHCPV4_OPT_SERVERID, 4,
				&a->fr_ip->addr.addr.in.s_addr);
		dhcpv4_put(&fr_msg, &cookie, DHCPV4_OPT_END, 0, NULL);
	}

	struct sockaddr_in dest;
	memset(&dest, 0, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_port = htons(DHCPV4_CLIENT_PORT);
	dest.sin_addr.s_addr = a->addr;

	if (sendto(iface->dhcpv4_event.uloop.fd, &fr_msg, sizeof(fr_msg),
			MSG_DONTWAIT, (struct sockaddr*)&dest, sizeof(dest)) < 0)
		syslog(LOG_ERR, "Failed to send %s to %s - %s: %m", dhcpv4_msg_to_string(msg),
			odhcpd_print_mac(a->hwaddr, sizeof(a->hwaddr)), inet_ntoa(dest.sin_addr));
	else
		syslog(LOG_WARNING, "Sent %s to %s - %s", dhcpv4_msg_to_string(msg),
			odhcpd_print_mac(a->hwaddr, sizeof(a->hwaddr)), inet_ntoa(dest.sin_addr));
}

static void dhcpv4_fr_timer(struct uloop_timeout *event)
{
	struct dhcpv4_assignment *a = container_of(event, struct dhcpv4_assignment, fr_timer);

	if (a->fr_cnt > 0 && a->fr_cnt < 8) {
		dhcpv4_fr_send(a);
		uloop_timeout_set(&a->fr_timer, 1000 << a->fr_cnt);
		a->fr_cnt++;
	} else
		dhcpv4_fr_stop(a);
}

static void dhcpv4_fr_start(struct dhcpv4_assignment *a)
{
	uloop_timeout_set(&a->fr_timer, 1000 << a->fr_cnt);
	a->fr_timer.cb = dhcpv4_fr_timer;
	a->fr_cnt++;

	dhcpv4_fr_send(a);
}

static void dhcpv4_fr_delay_timer(struct uloop_timeout *event)
{
	struct dhcpv4_assignment *a = container_of(event, struct dhcpv4_assignment, fr_timer);
	struct interface *iface = a->iface;

	(iface->dhcpv4_event.uloop.fd == -1 ? dhcpv4_fr_rand_delay(a) : dhcpv4_fr_start(a));
}

static void dhcpv4_fr_rand_delay(struct dhcpv4_assignment *a)
{
#define MIN_DELAY   500
#define MAX_FUZZ    500
	int msecs;

	odhcpd_urandom(&msecs, sizeof(msecs));

	msecs = labs(msecs)%MAX_FUZZ + MIN_DELAY;

	uloop_timeout_set(&a->fr_timer, msecs);
	a->fr_timer.cb = dhcpv4_fr_delay_timer;
}

static void dhcpv4_fr_stop(struct dhcpv4_assignment *a)
{
	uloop_timeout_cancel(&a->fr_timer);
	decr_ref_cnt_ip(&a->fr_ip, a->iface);
	a->fr_cnt = 0;
	a->fr_timer.cb = NULL;
}

/* Handler for DHCPv4 messages */
static void handle_dhcpv4(void *addr, void *data, size_t len,
		struct interface *iface, _unused void *dest_addr)
{
	if (!iface->dhcpv4)
		return;

	struct dhcpv4_message *req = data;
	if (len < offsetof(struct dhcpv4_message, options) + 4 ||
			req->op != DHCPV4_BOOTREQUEST || req->hlen != 6)
		return;


	syslog(LOG_NOTICE, "Got DHCPv4 request");

	if (!iface->dhcpv4_start_ip.s_addr && !iface->dhcpv4_end_ip.s_addr) {
		syslog(LOG_WARNING, "No DHCP range available on %s", iface->name);
		return;
	}

	int sock = iface->dhcpv4_event.uloop.fd;

	struct dhcpv4_message reply = {
		.op = DHCPV4_BOOTREPLY,
		.htype = req->htype,
		.hlen = req->hlen,
		.hops = 0,
		.xid = req->xid,
		.secs = 0,
		.flags = req->flags,
		.ciaddr = {INADDR_ANY},
		.giaddr = req->giaddr,
		.siaddr = iface->dhcpv4_local,
	};
	memcpy(reply.chaddr, req->chaddr, sizeof(reply.chaddr));

	reply.options[0] = 0x63;
	reply.options[1] = 0x82;
	reply.options[2] = 0x53;
	reply.options[3] = 0x63;

	uint8_t *cookie = &reply.options[4];
	uint8_t reqmsg = DHCPV4_MSG_REQUEST;
	uint8_t msg = DHCPV4_MSG_ACK;

	uint32_t reqaddr = INADDR_ANY;
	uint32_t leasetime = 0;
	size_t hostname_len = 0;
	char hostname[256];
	bool accept_fr_nonce = false;
	bool incl_fr_opt = false;

	uint8_t *start = &req->options[4];
	uint8_t *end = ((uint8_t*)data) + len;
	struct dhcpv4_option *opt;
	dhcpv4_for_each_option(start, end, opt) {
		if (opt->type == DHCPV4_OPT_MESSAGE && opt->len == 1)
			reqmsg = opt->data[0];
		else if (opt->type == DHCPV4_OPT_HOSTNAME && opt->len > 0) {
			hostname_len = opt->len;
			memcpy(hostname, opt->data, hostname_len);
			hostname[hostname_len] = 0;
		} else if (opt->type == DHCPV4_OPT_IPADDRESS && opt->len == 4)
			memcpy(&reqaddr, opt->data, 4);
		else if (opt->type == DHCPV4_OPT_SERVERID && opt->len == 4) {
			if (memcmp(opt->data, &iface->dhcpv4_local, 4))
				return;
		} else if (iface->filter_class && opt->type == DHCPV4_OPT_USER_CLASS) {
			uint8_t *c = opt->data, *cend = &opt->data[opt->len];
			for (; c < cend && &c[*c] < cend; c = &c[1 + *c]) {
				size_t elen = strlen(iface->filter_class);
				if (*c == elen && !memcmp(&c[1], iface->filter_class, elen))
					return; // Ignore from homenet
			}
		} else if (opt->type == DHCPV4_OPT_LEASETIME && opt->len == 4)
			memcpy(&leasetime, opt->data, 4);
		else if (opt->type == DHCPV4_OPT_FORCERENEW_NONCE_CAPABLE && opt->len > 0) {
			for (uint8_t i = 0; i < opt->len; i++) {
				if (opt->data[i] == 1) {
					accept_fr_nonce = true;
					break;
				}
			}

		}
	}

	if (reqmsg != DHCPV4_MSG_DISCOVER && reqmsg != DHCPV4_MSG_REQUEST &&
			reqmsg != DHCPV4_MSG_INFORM && reqmsg != DHCPV4_MSG_DECLINE &&
			reqmsg != DHCPV4_MSG_RELEASE)
		return;

	struct dhcpv4_assignment *lease = NULL;
	uint32_t serverid = iface->dhcpv4_local.s_addr;
	uint32_t fr_serverid = INADDR_ANY;

	if (reqmsg != DHCPV4_MSG_INFORM)
		lease = dhcpv4_lease(iface, reqmsg, req->chaddr, reqaddr,
					&leasetime, hostname, hostname_len,
					accept_fr_nonce, &incl_fr_opt, &fr_serverid);

	if (!lease) {
		if (reqmsg == DHCPV4_MSG_REQUEST)
			msg = DHCPV4_MSG_NAK;
		else if (reqmsg == DHCPV4_MSG_DISCOVER)
			return;
	} else if (reqmsg == DHCPV4_MSG_DISCOVER)
		msg = DHCPV4_MSG_OFFER;
	else if (reqmsg == DHCPV4_MSG_REQUEST &&
			((reqaddr && reqaddr != lease->addr) ||
			 (req->ciaddr.s_addr && req->ciaddr.s_addr != lease->addr))) {
		msg = DHCPV4_MSG_NAK;
		/*
		 * DHCP client requested an IP which we can't offer to him. Probably the
		 * client changed the network or the network has been changed. The reply
		 * type is set to DHCPV4_MSG_NAK, because the client should not use that IP.
		 *
		 * For modern devices we build an answer that includes a valid IP, like
		 * a DHCPV4_MSG_ACK. The client will use that IP and doesn't need to
		 * perform additional DHCP round trips.
		 *
		 */

		/*
		 *
		 * Buggy clients do serverid checking in nack messages; therefore set the
		 * serverid in nack messages triggered by a previous force renew equal to
		 * the server id in use at that time by the server
		 *
		 */
		if (fr_serverid)
			serverid = fr_serverid;

		if (req->ciaddr.s_addr &&
				((iface->dhcpv4_start_ip.s_addr & iface->dhcpv4_mask.s_addr) !=
				 (req->ciaddr.s_addr & iface->dhcpv4_mask.s_addr)))
			req->ciaddr.s_addr = INADDR_ANY;
	}

	syslog(LOG_WARNING, "received %s from %s", dhcpv4_msg_to_string(reqmsg),
			odhcpd_print_mac(req->chaddr, req->hlen));

#ifdef WITH_UBUS
	if (reqmsg == DHCPV4_MSG_RELEASE)
		ubus_bcast_dhcp_event("dhcp.release", req->chaddr, req->hlen,
					&req->ciaddr, hostname, iface->ifname);
#endif
	if (reqmsg == DHCPV4_MSG_DECLINE || reqmsg == DHCPV4_MSG_RELEASE)
		return;

	dhcpv4_put(&reply, &cookie, DHCPV4_OPT_MESSAGE, 1, &msg);
	dhcpv4_put(&reply, &cookie, DHCPV4_OPT_SERVERID, 4, &serverid);

	if (lease) {
		uint32_t val;

		reply.yiaddr.s_addr = lease->addr;

		val = htonl(leasetime);
		dhcpv4_put(&reply, &cookie, DHCPV4_OPT_LEASETIME, 4, &val);

		if (leasetime != UINT32_MAX) {
			val = htonl(500 * leasetime / 1000);
			dhcpv4_put(&reply, &cookie, DHCPV4_OPT_RENEW, 4, &val);

			val = htonl(875 * leasetime / 1000);
			dhcpv4_put(&reply, &cookie, DHCPV4_OPT_REBIND, 4, &val);
		}

		dhcpv4_put(&reply, &cookie, DHCPV4_OPT_NETMASK, 4,
				&iface->dhcpv4_mask.s_addr);

		if (lease->hostname)
			dhcpv4_put(&reply, &cookie, DHCPV4_OPT_HOSTNAME,
					strlen(lease->hostname), lease->hostname);

		if (iface->dhcpv4_bcast.s_addr != INADDR_ANY)
			dhcpv4_put(&reply, &cookie, DHCPV4_OPT_BROADCAST, 4, &iface->dhcpv4_bcast);

		if (incl_fr_opt) {
			if (reqmsg == DHCPV4_MSG_REQUEST) {
				struct dhcpv4_auth_forcerenew auth = {
					.protocol = 3,
					.algorithm = 1,
					.rdm = 0,
					.replay = {htonl(time(NULL)), htonl(++serial)},
					.type = 1,
					.key = {0},
				};

				memcpy(auth.key, lease->key, sizeof(auth.key));
				dhcpv4_put(&reply, &cookie, DHCPV4_OPT_AUTHENTICATION, sizeof(auth), &auth);
			} else {
				uint8_t one = 1;
				dhcpv4_put(&reply, &cookie, DHCPV4_OPT_FORCERENEW_NONCE_CAPABLE,
					sizeof(one), &one);
			}
		}
	}

	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iface->ifname, sizeof(ifr.ifr_name) - 1);

	if (!ioctl(sock, SIOCGIFMTU, &ifr)) {
		uint16_t mtu = htons(ifr.ifr_mtu);
		dhcpv4_put(&reply, &cookie, DHCPV4_OPT_MTU, 2, &mtu);
	}

	if (iface->search && iface->search_len <= 255)
		dhcpv4_put(&reply, &cookie, DHCPV4_OPT_SEARCH_DOMAIN,
				iface->search_len, iface->search);
	else if (!res_init() && _res.dnsrch[0] && _res.dnsrch[0][0]) {
		uint8_t search_buf[256];
		int len = dn_comp(_res.dnsrch[0], search_buf,
						sizeof(search_buf), NULL, NULL);
		if (len > 0)
			dhcpv4_put(&reply, &cookie, DHCPV4_OPT_SEARCH_DOMAIN,
					len, search_buf);
	}

	if (iface->dhcpv4_router_cnt == 0)
		dhcpv4_put(&reply, &cookie, DHCPV4_OPT_ROUTER, 4, &iface->dhcpv4_local);
	else
		dhcpv4_put(&reply, &cookie, DHCPV4_OPT_ROUTER,
				4 * iface->dhcpv4_router_cnt, iface->dhcpv4_router);


	if (iface->dhcpv4_dns_cnt == 0)
		dhcpv4_put(&reply, &cookie, DHCPV4_OPT_DNSSERVER, 4, &iface->dhcpv4_local);
	else
		dhcpv4_put(&reply, &cookie, DHCPV4_OPT_DNSSERVER,
				4 * iface->dhcpv4_dns_cnt, iface->dhcpv4_dns);


	dhcpv4_put(&reply, &cookie, DHCPV4_OPT_END, 0, NULL);

	struct sockaddr_in dest = *((struct sockaddr_in*)addr);
	if (req->giaddr.s_addr) {
		/*
		 * relay agent is configured, send reply to the agent
		 */
		dest.sin_addr = req->giaddr;
		dest.sin_port = htons(DHCPV4_SERVER_PORT);
	} else if (req->ciaddr.s_addr && req->ciaddr.s_addr != dest.sin_addr.s_addr) {
		/*
		 * client has existing configuration (ciaddr is set) AND this address is
		 * not the address it used for the dhcp message
		 */
		dest.sin_addr = req->ciaddr;
		dest.sin_port = htons(DHCPV4_CLIENT_PORT);
	} else if ((ntohs(req->flags) & DHCPV4_FLAG_BROADCAST) ||
			req->hlen != reply.hlen || !reply.yiaddr.s_addr) {
		/*
		 * client requests a broadcast reply OR we can't offer an IP
		 */
		dest.sin_addr.s_addr = INADDR_BROADCAST;
		dest.sin_port = htons(DHCPV4_CLIENT_PORT);
	} else if (!req->ciaddr.s_addr && msg == DHCPV4_MSG_NAK) {
		/*
		 * client has no previous configuration -> no IP, so we need to reply
		 * with a broadcast packet
		 */
		dest.sin_addr.s_addr = INADDR_BROADCAST;
		dest.sin_port = htons(DHCPV4_CLIENT_PORT);
	} else {
		/*
		 * send reply to the newly (in this proccess) allocated IP
		 */
		dest.sin_addr = reply.yiaddr;
		dest.sin_port = htons(DHCPV4_CLIENT_PORT);

		struct arpreq arp = {.arp_flags = ATF_COM};
		memcpy(arp.arp_ha.sa_data, req->chaddr, 6);
		memcpy(&arp.arp_pa, &dest, sizeof(arp.arp_pa));
		memcpy(arp.arp_dev, iface->ifname, sizeof(arp.arp_dev));
		ioctl(sock, SIOCSARP, &arp);
	}


	if (sendto(sock, &reply, sizeof(reply), MSG_DONTWAIT,
			(struct sockaddr*)&dest, sizeof(dest)) < 0)
		syslog(LOG_ERR, "Failed to send %s to %s - %s: %m",
			dhcpv4_msg_to_string(msg),
			dest.sin_addr.s_addr == INADDR_BROADCAST ?
			"ff:ff:ff:ff:ff:ff": odhcpd_print_mac(req->chaddr, req->hlen),
			inet_ntoa(dest.sin_addr));
	else
		syslog(LOG_ERR, "Sent %s to %s - %s",
			dhcpv4_msg_to_string(msg),
			dest.sin_addr.s_addr == INADDR_BROADCAST ?
			"ff:ff:ff:ff:ff:ff": odhcpd_print_mac(req->chaddr, req->hlen),
			inet_ntoa(dest.sin_addr));


#ifdef WITH_UBUS
	if (msg == DHCPV4_MSG_ACK)
		ubus_bcast_dhcp_event("dhcp.ack", req->chaddr, req->hlen, &reply.yiaddr,
					hostname, iface->ifname);
#endif
}

static bool dhcpv4_assign(struct interface *iface,
		struct dhcpv4_assignment *assign, uint32_t raddr)
{
	uint32_t start = ntohl(iface->dhcpv4_start_ip.s_addr);
	uint32_t end = ntohl(iface->dhcpv4_end_ip.s_addr);
	uint32_t count = end - start + 1;

	/* try to assign the IP the client asked for */
	if (start <= ntohl(raddr) && ntohl(raddr) <= end &&
			!find_assignment_by_addr(iface, raddr)) {
		assign->addr = raddr;
		syslog(LOG_INFO, "assigning the IP the client asked for: %u.%u.%u.%u",
				((uint8_t *)&assign->addr)[0],
				((uint8_t *)&assign->addr)[1],
				((uint8_t *)&assign->addr)[2],
				((uint8_t *)&assign->addr)[3]);
		return true;
	}

	/* Seed RNG with checksum of hwaddress */
	uint32_t seed = 0;
	for (size_t i = 0; i < sizeof(assign->hwaddr); ++i) {
		/* Knuth's multiplicative method */
		uint8_t o = assign->hwaddr[i];
		seed += (o*2654435761) % UINT32_MAX;
	}

	srand(seed);

	uint32_t try = (((uint32_t)rand()) % count) + start;

	if (list_empty(&iface->dhcpv4_assignments)) {
		assign->addr = htonl(try);
		syslog(LOG_INFO, "assigning mapped IP (empty list): %u.%u.%u.%u",
				((uint8_t *)&assign->addr)[0],
				((uint8_t *)&assign->addr)[1],
				((uint8_t *)&assign->addr)[2],
				((uint8_t *)&assign->addr)[3]);
		return true;
	}

	for (uint32_t i = 0; i < count; ++i) {
		if (!find_assignment_by_addr(iface, htonl(try))) {
			/* test was successful: IP address is not assigned, assign it */
			assign->addr = htonl(try);
			syslog(LOG_DEBUG, "assigning mapped IP: %u.%u.%u.%u (try %u of %u)",
					((uint8_t *)&assign->addr)[0],
					((uint8_t *)&assign->addr)[1],
					((uint8_t *)&assign->addr)[2],
					((uint8_t *)&assign->addr)[3],
					i, count);
			return true;
		}
		try = (((try - start) + 1) % count) + start;
	}

	syslog(LOG_WARNING, "can't assign any IP address -> address space is full");
	return false;
}


static struct dhcpv4_assignment* dhcpv4_lease(struct interface *iface,
		enum dhcpv4_msg msg, const uint8_t *mac, const uint32_t reqaddr,
		uint32_t *leasetime, const char *hostname, const size_t hostname_len,
		const bool accept_fr_nonce, bool *incl_fr_opt, uint32_t *fr_serverid)
{
	struct dhcpv4_assignment *a = find_assignment_by_hwaddr(iface, mac);
	struct dhcpv4_assignment *lease = NULL;
	time_t now = odhcpd_time();

	if (a && (a->flags & OAF_BOUND) && a->fr_ip) {
		*fr_serverid = a->fr_ip->addr.addr.in.s_addr;
		dhcpv4_fr_stop(a);
	}

	if (msg == DHCPV4_MSG_DISCOVER || msg == DHCPV4_MSG_REQUEST) {
		bool assigned = !!a;

		if (!a) {
			if (!iface->no_dynamic_dhcp) {
				/* Create new binding */
				a = calloc(1, sizeof(*a));
				if (!a) {
					syslog(LOG_ERR, "Failed to calloc binding on interface %s",
							iface->ifname);
					return NULL;
				}
				memcpy(a->hwaddr, mac, sizeof(a->hwaddr));
				/* Don't consider new assignment as infinite */
				a->valid_until = now;

				assigned = dhcpv4_assign(iface, a, reqaddr);
				if (assigned) {
					a->iface = iface;
					list_add(&a->head, &iface->dhcpv4_assignments);
				}
			}
		} else if ((a->addr & iface->dhcpv4_mask.s_addr) !=
				(iface->dhcpv4_start_ip.s_addr & iface->dhcpv4_mask.s_addr)) {
			list_del(&a->head);

			assigned = dhcpv4_assign(iface, a, reqaddr);
			if (assigned)
				list_add(&a->head, &iface->dhcpv4_assignments);
		}

		if (assigned) {
			uint32_t my_leasetime;

			if (a->leasetime)
				my_leasetime = a->leasetime;
			else
				my_leasetime = iface->dhcpv4_leasetime;

			if ((*leasetime == 0) || (my_leasetime < *leasetime))
				*leasetime = my_leasetime;

			if (msg == DHCPV4_MSG_DISCOVER) {
				a->flags &= ~OAF_BOUND;

				*incl_fr_opt = accept_fr_nonce;
				if (!(a->flags & OAF_STATIC))
					a->valid_until = now;
			} else {
				if (hostname_len > 0) {
					a->hostname = realloc(a->hostname, hostname_len + 1);
					if (a->hostname) {
						memcpy(a->hostname, hostname, hostname_len);
						a->hostname[hostname_len] = 0;
					}
				}

				if (!(a->flags & OAF_BOUND)) {
					a->accept_fr_nonce = accept_fr_nonce;
					*incl_fr_opt = accept_fr_nonce;
					odhcpd_urandom(a->key, sizeof(a->key));
					a->flags |= OAF_BOUND;
				} else
					*incl_fr_opt = false;

				if (!(a->flags & OAF_STATIC))
					a->valid_until = ((*leasetime == UINT32_MAX) ? 0 : (time_t)(now + *leasetime));
			}
		} else if (!assigned && a) {
			/* Cleanup failed assignment */
			free_dhcpv4_assignment(a);
			a = NULL;
		}

		if (assigned && a)
			lease = a;
	} else if (msg == DHCPV4_MSG_RELEASE && a) {
		a->flags &= ~OAF_BOUND;

		if (!(a->flags & OAF_STATIC))
			a->valid_until = now - 1;

	} else if (msg == DHCPV4_MSG_DECLINE && a) {
		a->flags &= ~OAF_BOUND;

		if (!(a->flags & OAF_STATIC)) {
			memset(a->hwaddr, 0, sizeof(a->hwaddr));
			a->valid_until = now + 3600; /* Block address for 1h */
		}
	}

	dhcpv6_write_statefile();

	return lease;
}
