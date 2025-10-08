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
#include <alloca.h>
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

#define MAX_PREFIX_LEN 28

static uint32_t serial = 0;

struct odhcpd_ref_ip {
	struct list_head head;
	int ref_cnt;
	struct odhcpd_ipaddr addr;
};

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
	struct dhcp_assignment *a = NULL;
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

static const char *dhcpv4_msg_to_string(uint8_t req_msg)
{
	static const char *dhcpv4_msg_names[] = {
		[DHCPV4_MSG_DISCOVER]		= "DHCPV4_MSG_DISCOVER",
		[DHCPV4_MSG_OFFER]		= "DHCPV4_MSG_OFFER",
		[DHCPV4_MSG_REQUEST]		= "DHCPV4_MSG_REQUEST",
		[DHCPV4_MSG_DECLINE]		= "DHCPV4_MSG_DECLINE",
		[DHCPV4_MSG_ACK]		= "DHCPV4_MSG_ACK",
		[DHCPV4_MSG_NAK]		= "DHCPV4_MSG_NAK",
		[DHCPV4_MSG_RELEASE]		= "DHCPV4_MSG_RELEASE",
		[DHCPV4_MSG_INFORM]		= "DHCPV4_MSG_INFORM",
		[DHCPV4_MSG_FORCERENEW]		= "DHCPV4_MSG_FORCERENEW",
		[DHCPV4_MSG_LEASEQUERY]		= "DHCPV4_MSG_LEASEQUERY",
		[DHCPV4_MSG_LEASEUNASSIGNED]	= "DHCPV4_MSG_LEASEUNASSIGNED",
		[DHCPV4_MSG_LEASEUNKNOWN]	= "DHCPV4_MSG_LEASEUNKNOWN",
		[DHCPV4_MSG_LEASEACTIVE]	= "DHCPV4_MSG_LEASEACTIVE",
		[DHCPV4_MSG_BULKLEASEQUERY]	= "DHCPV4_MSG_BULKLEASEQUERY",
		[DHCPV4_MSG_LEASEQUERYDONE]	= "DHCPV4_MSG_LEASEQUERYDONE",
		[DHCPV4_MSG_ACTIVELEASEQUERY]	= "DHCPV4_MSG_ACTIVELEASEQUERY",
		[DHCPV4_MSG_LEASEQUERYSTATUS]	= "DHCPV4_MSG_LEASEQUERYSTATUS",
		[DHCPV4_MSG_TLS]		= "DHCPV4_MSG_TLS",
	};

	if (req_msg >= ARRAY_SIZE(dhcpv4_msg_names))
		return "UNKNOWN";
	return dhcpv4_msg_names[req_msg];
}

static ssize_t dhcpv4_send_reply(struct iovec *iov, size_t iov_len,
				 struct sockaddr *dest, socklen_t dest_len,
				 void *opaque)
{
	int *sock = opaque;
	struct msghdr msg = {
		.msg_name = dest,
		.msg_namelen = dest_len,
		.msg_iov = iov,
		.msg_iovlen = iov_len,
	};

	return sendmsg(*sock, &msg, MSG_DONTWAIT);
}

static void dhcpv4_add_padding(struct iovec *iov, size_t iovlen)
{
	// Theoretical max padding = vendor-specific area, RFC951, §3
	static uint8_t padding[64] = { 0 };
	size_t len = 0;

	if (!iov || !iovlen)
		return;

	iov[iovlen - 1].iov_base = padding;
	iov[iovlen - 1].iov_len = 0;

	for (size_t i = 0; i < iovlen; i++)
		len += iov[i].iov_len;

	if (len < DHCPV4_MIN_PACKET_SIZE)
		iov[iovlen - 1].iov_len = DHCPV4_MIN_PACKET_SIZE - len;
}

enum {
	IOV_FR_HEADER = 0,
	IOV_FR_MESSAGE,
	IOV_FR_AUTH,
	IOV_FR_AUTH_BODY,
	IOV_FR_SERVERID,
	IOV_FR_END,
	IOV_FR_PADDING,
	IOV_FR_TOTAL
};

static void dhcpv4_fr_send(struct dhcp_assignment *a)
{
	struct dhcpv4_message fr = {
		.op = DHCPV4_OP_BOOTREPLY,
		.htype = ARPHRD_ETHER,
		.hlen = ETH_ALEN,
		.hops = 0,
		.xid = 0,
		.secs = 0,
		.flags = 0,
		.ciaddr = { INADDR_ANY },
		.yiaddr = { INADDR_ANY },
		.siaddr = { INADDR_ANY },
		.giaddr = { INADDR_ANY },
		.chaddr = { 0 },
		.sname = { 0 },
		.file = { 0 },
		.cookie = htonl(DHCPV4_MAGIC_COOKIE),
	};
	struct dhcpv4_option_u8 fr_msg = {
		.code = DHCPV4_OPT_MESSAGE,
		.len = sizeof(uint8_t),
		.data = DHCPV4_MSG_FORCERENEW,
	};
	struct dhcpv4_auth_forcerenew fr_auth_body = {
		.protocol = DHCPV4_AUTH_PROTO_RKAP,
		.algorithm = DHCPV4_AUTH_ALG_HMAC_MD5,
		.rdm = DHCPV4_AUTH_RDM_MONOTONIC,
		.type = DHCPV4_AUTH_RKAP_AI_TYPE_MD5_DIGEST,
		.key = { 0 },
	};
	struct dhcpv4_option fr_auth = {
		.code = DHCPV4_OPT_AUTHENTICATION,
		.len = sizeof(fr_auth_body),
	};
	struct dhcpv4_option_u32 fr_serverid = {
		.code = DHCPV4_OPT_SERVERID,
		.len = sizeof(struct in_addr),
		.data = a->fr_ip->addr.addr.in.s_addr,
	};
	uint8_t fr_end = DHCPV4_OPT_END;

	struct iovec iov[IOV_FR_TOTAL] = {
		[IOV_FR_HEADER]		= { &fr, sizeof(fr) },
		[IOV_FR_MESSAGE]	= { &fr_msg, sizeof(fr_msg) },
		[IOV_FR_AUTH]		= { &fr_auth, 0 },
		[IOV_FR_AUTH_BODY]	= { &fr_auth_body, 0 },
		[IOV_FR_SERVERID]	= { &fr_serverid, 0 },
		[IOV_FR_END]		= { &fr_end, sizeof(fr_end) },
		[IOV_FR_PADDING]	= { NULL, 0 },
	};

	struct sockaddr_in dest = {
		.sin_family = AF_INET,
		.sin_port = htons(DHCPV4_CLIENT_PORT),
		.sin_addr = { a->addr },
	};

	odhcpd_urandom(&fr.xid, sizeof(fr.xid));
	memcpy(fr.chaddr, a->hwaddr, fr.hlen);

	if (a->accept_fr_nonce) {
		uint8_t secretbytes[64] = { 0 };
		md5_ctx_t md5;

		fr_auth_body.replay[0] = htonl(time(NULL));
		fr_auth_body.replay[1] = htonl(++serial);
		iov[IOV_FR_AUTH].iov_len = sizeof(fr_auth);
		iov[IOV_FR_AUTH_BODY].iov_len = sizeof(fr_auth_body);
		dhcpv4_add_padding(iov, ARRAY_SIZE(iov));

		memcpy(secretbytes, a->key, sizeof(a->key));
		for (size_t i = 0; i < sizeof(secretbytes); ++i)
			secretbytes[i] ^= 0x36;

		md5_begin(&md5);
		md5_hash(secretbytes, sizeof(secretbytes), &md5);
		for (size_t i = 0; i < ARRAY_SIZE(iov); i++)
			md5_hash(iov[i].iov_base, iov[i].iov_len, &md5);
		md5_end(fr_auth_body.key, &md5);

		for (size_t i = 0; i < sizeof(secretbytes); ++i) {
			secretbytes[i] ^= 0x36;
			secretbytes[i] ^= 0x5c;
		}

		md5_begin(&md5);
		md5_hash(secretbytes, sizeof(secretbytes), &md5);
		md5_hash(fr_auth_body.key, sizeof(fr_auth_body.key), &md5);
		md5_end(fr_auth_body.key, &md5);
	} else {
		iov[IOV_FR_SERVERID].iov_len = sizeof(fr_serverid);
		dhcpv4_add_padding(iov, ARRAY_SIZE(iov));
	}

	if (dhcpv4_send_reply(iov, ARRAY_SIZE(iov), (struct sockaddr *)&dest, sizeof(dest),
			      &a->iface->dhcpv4_event.uloop.fd) < 0)
		error("Failed to send %s to %s - %s: %m", dhcpv4_msg_to_string(fr_msg.data),
		      odhcpd_print_mac(a->hwaddr, sizeof(a->hwaddr)), inet_ntoa(dest.sin_addr));
	else
		debug("Sent %s to %s - %s", dhcpv4_msg_to_string(fr_msg.data),
		      odhcpd_print_mac(a->hwaddr, sizeof(a->hwaddr)), inet_ntoa(dest.sin_addr));
}

static void dhcpv4_fr_stop(struct dhcp_assignment *a)
{
	uloop_timeout_cancel(&a->fr_timer);
	decr_ref_cnt_ip(&a->fr_ip, a->iface);
	a->fr_cnt = 0;
	a->fr_timer.cb = NULL;
}

static void dhcpv4_fr_timer(struct uloop_timeout *event)
{
	struct dhcp_assignment *a = container_of(event, struct dhcp_assignment, fr_timer);

	if (a->fr_cnt > 0 && a->fr_cnt < 8) {
		dhcpv4_fr_send(a);
		uloop_timeout_set(&a->fr_timer, 1000 << a->fr_cnt);
		a->fr_cnt++;
	} else
		dhcpv4_fr_stop(a);
}

static void dhcpv4_fr_start(struct dhcp_assignment *a)
{
	uloop_timeout_set(&a->fr_timer, 1000 << a->fr_cnt);
	a->fr_timer.cb = dhcpv4_fr_timer;
	a->fr_cnt++;

	dhcpv4_fr_send(a);
}

static void dhcpv4_fr_rand_delay(struct dhcp_assignment *a);

static void dhcpv4_fr_delay_timer(struct uloop_timeout *event)
{
	struct dhcp_assignment *a = container_of(event, struct dhcp_assignment, fr_timer);
	struct interface *iface = a->iface;

	(iface->dhcpv4_event.uloop.fd == -1 ? dhcpv4_fr_rand_delay(a) : dhcpv4_fr_start(a));
}

static void dhcpv4_fr_rand_delay(struct dhcp_assignment *a)
{
	int msecs;

	odhcpd_urandom(&msecs, sizeof(msecs));

	msecs = abs(msecs) % DHCPV4_FR_MAX_FUZZ + DHCPV4_FR_MIN_DELAY;

	uloop_timeout_set(&a->fr_timer, msecs);
	a->fr_timer.cb = dhcpv4_fr_delay_timer;
}

static void dhcpv4_free_assignment(struct dhcp_assignment *a)
{
	if (a->fr_ip)
		dhcpv4_fr_stop(a);
}

static bool dhcpv4_insert_assignment(struct list_head *list, struct dhcp_assignment *a,
				     uint32_t addr)
{
	uint32_t h_addr = ntohl(addr);
	struct dhcp_assignment *c;

	list_for_each_entry(c, list, head) {
		uint32_t c_addr = ntohl(c->addr);

		if (c_addr == h_addr)
			return false;

		if (c_addr > h_addr)
			break;
	}

	/* Insert new node before c (might match list head) */
	a->addr = addr;
	list_add_tail(&a->head, &c->head);

	return true;
}

static bool dhcpv4_assign(struct interface *iface, struct dhcp_assignment *a,
			  uint32_t raddr)
{
	uint32_t start = ntohl(iface->dhcpv4_start_ip.s_addr);
	uint32_t end = ntohl(iface->dhcpv4_end_ip.s_addr);
	uint32_t count = end - start + 1;
	uint32_t seed = 0;
	char ipv4_str[INET_ADDRSTRLEN];

	/* Preconfigured IP address by static lease */
	if (a->addr) {
		if (!dhcpv4_insert_assignment(&iface->dhcpv4_assignments, a, a->addr)) {
			error("The static IP address is already assigned: %s",
			      inet_ntop(AF_INET, &a->addr, ipv4_str, sizeof(ipv4_str)));
			return false;
		}

		debug("Assigned static IP address: %s",
		      inet_ntop(AF_INET, &a->addr, ipv4_str, sizeof(ipv4_str)));
		return true;
	}

	/* The client asked for a specific address, let's try... */
	if (ntohl(raddr) < start || ntohl(raddr) > end) {
		debug("The requested IP address is outside the pool: %s",
		      inet_ntop(AF_INET, &raddr, ipv4_str, sizeof(ipv4_str)));
	} else if (config_find_lease_by_ipaddr(raddr)) {
		debug("The requested IP address is statically assigned: %s",
		      inet_ntop(AF_INET, &raddr, ipv4_str, sizeof(ipv4_str)));
	} else if (!dhcpv4_insert_assignment(&iface->dhcpv4_assignments, a, raddr)) {
		debug("The requested IP address is already assigned: %s",
		      inet_ntop(AF_INET, &raddr, ipv4_str, sizeof(ipv4_str)));
	} else {
		debug("Assigned the requested IP address: %s",
		      inet_ntop(AF_INET, &a->addr, ipv4_str, sizeof(ipv4_str)));
		return true;
	}

	/* Ok, we'll have to pick an address for the client... */
	for (size_t i = 0; i < sizeof(a->hwaddr); ++i) {
		/* ...hash the hwaddr (Knuth's multiplicative method)... */
		uint8_t o = a->hwaddr[i];
		seed += (o * 2654435761) % UINT32_MAX;
	}

	/* ...use it to seed the RNG... */
	srand(seed);

	/* ...and try a bunch of times to assign a randomly chosen address */
	for (uint32_t i = 0, try = (((uint32_t)rand()) % count) + start; i < count;
	     ++i, try = (((try - start) + 1) % count) + start) {
		uint32_t n_try = htonl(try);

		if (config_find_lease_by_ipaddr(n_try))
			continue;

		if (dhcpv4_insert_assignment(&iface->dhcpv4_assignments, a, n_try)) {
			debug("Assigned IP adress from pool: %s (succeeded on attempt %u of %u)",
			      inet_ntop(AF_INET, &a->addr, ipv4_str, sizeof(ipv4_str)),
			      i + 1, count);
			return true;
		}
	}

	warn("Can't assign any IP address -> address space is full");

	return false;
}

static struct dhcp_assignment *find_assignment_by_hwaddr(struct interface *iface, const uint8_t *hwaddr)
{
	struct dhcp_assignment *a;

	list_for_each_entry(a, &iface->dhcpv4_assignments, head)
		if (!memcmp(a->hwaddr, hwaddr, 6))
			return a;

	return NULL;
}

static struct dhcp_assignment *
dhcpv4_lease(struct interface *iface, enum dhcpv4_msg req_msg, const uint8_t *req_mac,
	     const uint32_t req_addr, uint32_t *req_leasetime, const char *req_hostname,
	     const size_t req_hostname_len, const bool req_accept_fr, bool *reply_incl_fr,
	     uint32_t *fr_serverid)
{
	struct dhcp_assignment *a = find_assignment_by_hwaddr(iface, req_mac);
	struct lease *l = config_find_lease_by_mac(req_mac);
	time_t now = odhcpd_time();

	/*
	 * If we found a static lease cfg, but no old assignment for this
	 * hwaddr, we need to clear out any old assignments given to other
	 * hwaddrs in order to take over the IP address.
	 */
	if (l && !a && (req_msg == DHCPV4_MSG_DISCOVER || req_msg == DHCPV4_MSG_REQUEST)) {
		struct dhcp_assignment *c, *tmp;

		list_for_each_entry_safe(c, tmp, &l->assignments, lease_list) {
			if (c->flags & OAF_DHCPV4 && c->flags & OAF_STATIC)
				free_assignment(c);
		}
	}

	if (l && a && a->lease != l) {
		free_assignment(a);
		a = NULL;
	}

	if (a && (a->flags & OAF_BOUND) && a->fr_ip) {
		*fr_serverid = a->fr_ip->addr.addr.in.s_addr;
		dhcpv4_fr_stop(a);
	}

	switch (req_msg) {
	case DHCPV4_MSG_RELEASE:
		if (!a)
			return NULL;

		ubus_bcast_dhcp_event("dhcp.release", req_mac,
				      (struct in_addr *)&a->addr,
				      a->hostname, iface->ifname);
		free_assignment(a);
		a = NULL;
		break;

	case DHCPV4_MSG_DECLINE:
		if (!a)
			return NULL;

		a->flags &= ~OAF_BOUND;

		if (!(a->flags & OAF_STATIC) || a->lease->ipaddr != a->addr) {
			memset(a->hwaddr, 0, sizeof(a->hwaddr));
			a->valid_until = now + 3600; /* Block address for 1h */
		} else {
			a->valid_until = now - 1;
		}
		break;

	case DHCPV4_MSG_DISCOVER:
		_fallthrough;

	case DHCPV4_MSG_REQUEST:
		if (!a && iface->no_dynamic_dhcp && !l)
			return NULL;

		/* Old assignment, but with an address that is out-of-scope? */
		if (a && ((a->addr & iface->dhcpv4_mask.s_addr) !=
		     (iface->dhcpv4_start_ip.s_addr & iface->dhcpv4_mask.s_addr)) &&
		    !(a->flags & OAF_STATIC)) {
			/* Try to reassign to an address that is in-scope */
			list_del_init(&a->head);
			a->addr = INADDR_ANY;
			if (!dhcpv4_assign(iface, a, req_addr)) {
				free_assignment(a);
				a = NULL;
				break;
			}
		}

		if (!a) {
			/* Create new binding */
			a = alloc_assignment(0);
			if (!a) {
				warn("Failed to allocate memory for DHCPv4 lease on interface %s", iface->ifname);
				return NULL;
			}

			memcpy(a->hwaddr, req_mac, sizeof(a->hwaddr));
			a->dhcp_free_cb = dhcpv4_free_assignment;
			a->iface = iface;
			a->flags = OAF_DHCPV4;

			/* static lease => infinite (0), else a placeholder */
			a->valid_until = l ? 0 : now;
			a->addr = l ? l->ipaddr : INADDR_ANY;

			if (!dhcpv4_assign(iface, a, req_addr)) {
				free_assignment(a);
				return NULL;
			}

			if (l) {
				a->flags |= OAF_STATIC;

				if (l->hostname)
					a->hostname = strdup(l->hostname);

				if (l->leasetime)
					a->leasetime = l->leasetime;

				list_add(&a->lease_list, &l->assignments);
				a->lease = l;
			}
		}

		/* See if we need to clamp the requested leasetime */
		uint32_t my_leasetime;
		if (a->leasetime)
			my_leasetime = a->leasetime;
		else
			my_leasetime = iface->dhcp_leasetime;

		if ((*req_leasetime == 0) || (my_leasetime < *req_leasetime))
			*req_leasetime = my_leasetime;

		if (req_msg == DHCPV4_MSG_DISCOVER) {
			a->flags &= ~OAF_BOUND;
			*reply_incl_fr = req_accept_fr;
			a->valid_until = now;
			break;
		}

		if ((!(a->flags & OAF_STATIC) || !a->hostname) && req_hostname_len > 0) {
			char *new_name = realloc(a->hostname, req_hostname_len + 1);
			if (new_name) {
				a->hostname = new_name;
				memcpy(a->hostname, req_hostname, req_hostname_len);
				a->hostname[req_hostname_len] = 0;

				if (odhcpd_valid_hostname(a->hostname))
					a->flags &= ~OAF_BROKEN_HOSTNAME;
				else
					a->flags |= OAF_BROKEN_HOSTNAME;
			}
		}

		*reply_incl_fr = false;
		if (!(a->flags & OAF_BOUND)) {
			/* This is the client's first request for the address */
			if (req_accept_fr) {
				a->accept_fr_nonce = true;
				*reply_incl_fr = true;
				odhcpd_urandom(a->key, sizeof(a->key));
			}
			a->flags |= OAF_BOUND;
		}

		if (*req_leasetime == UINT32_MAX)
			a->valid_until = 0;
		else
			a->valid_until = (time_t)(now + *req_leasetime);
		break;

	default:
		return NULL;
	}

	dhcpv6_ia_write_statefile();
	return a;
}

static void dhcpv4_set_dest_addr(const struct interface *iface,
				 uint8_t reply_msg,
				 const struct dhcpv4_message *req,
				 const struct dhcpv4_message *reply,
				 const struct sockaddr_in *src,
				 struct sockaddr_in *dest)
{
	*dest = *src;

	//struct sockaddr_in dest = *((struct sockaddr_in*)addr);
	if (req->giaddr.s_addr) {
		/*
		 * relay agent is configured, send reply to the agent
		 */
		dest->sin_addr = req->giaddr;
		dest->sin_port = htons(DHCPV4_SERVER_PORT);

	} else if (req->ciaddr.s_addr && req->ciaddr.s_addr != dest->sin_addr.s_addr) {
		/*
		 * client has existing configuration (ciaddr is set) AND this
		 * address is not the address it used for the dhcp message
		 */
		dest->sin_addr = req->ciaddr;
		dest->sin_port = htons(DHCPV4_CLIENT_PORT);

	} else if (ntohs(req->flags) & DHCPV4_FLAG_BROADCAST ||
		   req->hlen != reply->hlen || !reply->yiaddr.s_addr) {
		/*
		 * client requests a broadcast reply OR we can't offer an IP
		 */
		dest->sin_addr.s_addr = INADDR_BROADCAST;
		dest->sin_port = htons(DHCPV4_CLIENT_PORT);

	} else if (!req->ciaddr.s_addr && reply_msg == DHCPV4_MSG_NAK) {
		/*
		 * client has no previous configuration -> no IP, so we need to
		 * reply with a broadcast packet
		 */
		dest->sin_addr.s_addr = INADDR_BROADCAST;
		dest->sin_port = htons(DHCPV4_CLIENT_PORT);

	} else {
		/*
		 * send reply to the newly allocated IP
		 */
		dest->sin_addr = reply->yiaddr;
		dest->sin_port = htons(DHCPV4_CLIENT_PORT);

		if (!(iface->ifflags & IFF_NOARP)) {
			struct arpreq arp = { .arp_flags = ATF_COM };

			memcpy(arp.arp_ha.sa_data, req->chaddr, 6);
			memcpy(&arp.arp_pa, dest, sizeof(arp.arp_pa));
			memcpy(arp.arp_dev, iface->ifname, sizeof(arp.arp_dev));

			if (ioctl(iface->dhcpv4_event.uloop.fd, SIOCSARP, &arp) < 0)
				error("ioctl(SIOCSARP): %m");
		}
	}
}

enum {
	IOV_HEADER = 0,
	IOV_MESSAGE,
	IOV_SERVERID,
	IOV_NETMASK,
	IOV_ROUTER,
	IOV_ROUTER_ADDR,
	IOV_DNSSERVER,
	IOV_DNSSERVER_ADDR,
	IOV_HOSTNAME,
	IOV_HOSTNAME_NAME,
	IOV_MTU,
	IOV_BROADCAST,
	IOV_NTP,
	IOV_NTP_ADDR,
	IOV_LEASETIME,
	IOV_RENEW,
	IOV_REBIND,
	IOV_AUTH,
	IOV_AUTH_BODY,
	IOV_SRCH_DOMAIN,
	IOV_SRCH_DOMAIN_NAME,
	IOV_FR_NONCE_CAP,
	IOV_DNR,
	IOV_DNR_BODY,
	IOV_END,
	IOV_PADDING,
	IOV_TOTAL
};

void dhcpv4_handle_msg(void *src_addr, void *data, size_t len,
		struct interface *iface, _unused void *our_dest_addr,
	        send_reply_cb_t send_reply, void *opaque)
{
	/* Request variables */
	struct dhcpv4_message *req = data;
	uint8_t req_msg = DHCPV4_MSG_REQUEST;
	uint8_t *req_opts = NULL;
	size_t req_opts_len = 0;
	uint32_t req_addr = INADDR_ANY;
	uint32_t req_leasetime = 0;
	char *req_hostname = NULL;
	size_t req_hostname_len = 0;
	bool req_accept_fr = false;

	/* Reply variables */
	struct dhcpv4_message reply = {
		.op = DHCPV4_OP_BOOTREPLY,
		.htype = ARPHRD_ETHER,
		.hlen = ETH_ALEN,
		.hops = 0,
		.xid = req->xid,
		.secs = 0,
		.flags = req->flags,
		.ciaddr = { INADDR_ANY },
		.yiaddr = { INADDR_ANY },
		.siaddr = iface->dhcpv4_local,
		.giaddr = req->giaddr,
		.chaddr = { 0 },
		.sname = { 0 },
		.file = { 0 },
		.cookie = htonl(DHCPV4_MAGIC_COOKIE),
	};
	struct dhcpv4_option_u8 reply_msg = {
		.code = DHCPV4_OPT_MESSAGE,
		.len = sizeof(uint8_t),
		.data = DHCPV4_MSG_ACK,
	};
	struct dhcpv4_option_u32 reply_serverid = {
		.code = DHCPV4_OPT_SERVERID,
		.len = sizeof(struct in_addr),
		.data = iface->dhcpv4_local.s_addr,
	};
	struct dhcpv4_option_u32 reply_netmask = {
		.code = DHCPV4_OPT_NETMASK,
		.len = sizeof(uint32_t),
	};
	struct dhcpv4_option reply_router = {
		.code = DHCPV4_OPT_ROUTER,
	};
	struct dhcpv4_option reply_dnsserver = {
		.code = DHCPV4_OPT_DNSSERVER,
	};
	struct dhcpv4_option reply_hostname = {
		.code = DHCPV4_OPT_HOSTNAME,
	};
	struct dhcpv4_option_u16 reply_mtu = {
		.code = DHCPV4_OPT_MTU,
		.len = sizeof(uint16_t),
	};
	struct dhcpv4_option_u32 reply_broadcast = {
		.code = DHCPV4_OPT_BROADCAST,
		.len = sizeof(uint32_t),
	};
	struct dhcpv4_option reply_ntp = {
		.code = DHCPV4_OPT_NTPSERVER,
		.len = iface->dhcpv4_ntp_cnt * sizeof(*iface->dhcpv4_ntp),
	};
	struct dhcpv4_option_u32 reply_leasetime = {
		.code = DHCPV4_OPT_LEASETIME,
		.len = sizeof(uint32_t),
	};
	struct dhcpv4_option_u32 reply_renew = {
		.code = DHCPV4_OPT_RENEW,
		.len = sizeof(uint32_t),
	};
	struct dhcpv4_option_u32 reply_rebind = {
		.code = DHCPV4_OPT_REBIND,
		.len = sizeof(uint32_t),
	};
	struct dhcpv4_auth_forcerenew reply_auth_body = {
		.protocol = DHCPV4_AUTH_PROTO_RKAP,
		.algorithm = DHCPV4_AUTH_ALG_HMAC_MD5,
		.rdm = DHCPV4_AUTH_RDM_MONOTONIC,
		.type = DHCPV4_AUTH_RKAP_AI_TYPE_KEY,
		.key = { 0 },
	};
	struct dhcpv4_option reply_auth = {
		.code = DHCPV4_OPT_AUTHENTICATION,
		.len = sizeof(reply_auth_body),
	};
	struct dhcpv4_option reply_srch_domain = {
		.code = DHCPV4_OPT_SEARCH_DOMAIN,
	};
	struct dhcpv4_option_u8 reply_fr_nonce_cap = {
		.code = DHCPV4_OPT_FORCERENEW_NONCE_CAPABLE,
		.len = sizeof(uint8_t),
		.data = 1,
	};
	struct dhcpv4_option reply_dnr = {
		.code = DHCPV4_OPT_DNR,
	};
	uint8_t reply_end = DHCPV4_OPT_END;

	struct iovec iov[IOV_TOTAL] = {
		[IOV_HEADER]		= { &reply, sizeof(reply) },
		[IOV_MESSAGE]		= { &reply_msg, sizeof(reply_msg) },
		[IOV_SERVERID]		= { &reply_serverid, sizeof(reply_serverid) },
		[IOV_NETMASK]		= { &reply_netmask, 0 },
		[IOV_ROUTER]		= { &reply_router, 0 },
		[IOV_ROUTER_ADDR]	= { NULL, 0 },
		[IOV_DNSSERVER]		= { &reply_dnsserver, 0 },
		[IOV_DNSSERVER_ADDR]	= { NULL, 0 },
		[IOV_HOSTNAME]		= { &reply_hostname, 0 },
		[IOV_HOSTNAME_NAME]	= { NULL, 0 },
		[IOV_MTU]		= { &reply_mtu, 0 },
		[IOV_BROADCAST]		= { &reply_broadcast, 0 },
		[IOV_NTP]		= { &reply_ntp, 0 },
		[IOV_NTP_ADDR]		= { iface->dhcpv4_ntp, 0 },
		[IOV_LEASETIME]		= { &reply_leasetime, 0 },
		[IOV_RENEW]		= { &reply_renew, 0 },
		[IOV_REBIND]		= { &reply_rebind, 0 },
		[IOV_AUTH]		= { &reply_auth, 0 },
		[IOV_AUTH_BODY]		= { &reply_auth_body, 0 },
		[IOV_SRCH_DOMAIN]	= { &reply_srch_domain, 0 },
		[IOV_SRCH_DOMAIN_NAME]	= { NULL, 0 },
		[IOV_FR_NONCE_CAP]	= { &reply_fr_nonce_cap, 0 },
		[IOV_DNR]		= { &reply_dnr, 0 },
		[IOV_DNR_BODY]		= { NULL, 0 },
		[IOV_END]		= { &reply_end, sizeof(reply_end) },
		[IOV_PADDING]		= { NULL, 0 },
	};

	/* Options which *might* be included in the reply unrequested */
	uint8_t std_opts[] = {
		DHCPV4_OPT_NETMASK,
		DHCPV4_OPT_ROUTER,
		DHCPV4_OPT_DNSSERVER,
		DHCPV4_OPT_HOSTNAME,
		DHCPV4_OPT_MTU,
		DHCPV4_OPT_BROADCAST,
		DHCPV4_OPT_LEASETIME,
		DHCPV4_OPT_RENEW,
		DHCPV4_OPT_REBIND,
		DHCPV4_OPT_AUTHENTICATION,
		DHCPV4_OPT_SEARCH_DOMAIN,
		DHCPV4_OPT_FORCERENEW_NONCE_CAPABLE,
	};

	/* Misc */
	struct sockaddr_in dest_addr;
	bool reply_incl_fr = false;
	struct dhcp_assignment *a = NULL;
	uint32_t fr_serverid = INADDR_ANY;

	if (iface->dhcpv4 == MODE_DISABLED)
		return;

	/* FIXME: would checking the magic cookie value here break any clients? */

	if (len < offsetof(struct dhcpv4_message, options) ||
	    req->op != DHCPV4_OP_BOOTREQUEST ||
	    req->htype != ARPHRD_ETHER ||
	    req->hlen != ETH_ALEN)
		return;

	debug("Got DHCPv4 request on %s", iface->name);

	if (!iface->dhcpv4_start_ip.s_addr && !iface->dhcpv4_end_ip.s_addr) {
		warn("No DHCP range available on %s", iface->name);
		return;
	}

	struct dhcpv4_option *opt;
	dhcpv4_for_each_option(req->options, (uint8_t *)data + len, opt) {
		switch (opt->code) {
		case DHCPV4_OPT_PAD:
			break;
		case DHCPV4_OPT_HOSTNAME:
			req_hostname = (char *)opt->data;
			req_hostname_len = opt->len;
			break;
		case DHCPV4_OPT_IPADDRESS:
			if (opt->len == 4)
				memcpy(&req_addr, opt->data, 4);
			break;
		case DHCPV4_OPT_MESSAGE:
			if (opt->len == 1)
				req_msg = opt->data[0];
			break;
		case DHCPV4_OPT_SERVERID:
			if (opt->len == 4 && memcmp(opt->data, &iface->dhcpv4_local, 4))
				return;
			break;
		case DHCPV4_OPT_REQOPTS:
			if (opt->len > 0) {
				req_opts = opt->data;
				req_opts_len = opt->len;
			}
			break;
		case DHCPV4_OPT_USER_CLASS:
			if (iface->filter_class) {
				uint8_t *c = opt->data, *cend = &opt->data[opt->len];
				for (; c < cend && &c[*c] < cend; c = &c[1 + *c]) {
					size_t elen = strlen(iface->filter_class);
					if (*c == elen && !memcmp(&c[1], iface->filter_class, elen))
						return; // Ignore from homenet
				}
			}
			break;
		case DHCPV4_OPT_LEASETIME:
			if (opt->len == 4) {
				memcpy(&req_leasetime, opt->data, 4);
				req_leasetime = ntohl(req_leasetime);
			}
			break;
		case DHCPV4_OPT_FORCERENEW_NONCE_CAPABLE:
			for (uint8_t i = 0; i < opt->len; i++) {
				if (opt->data[i] == 1) {
					req_accept_fr = true;
					break;
				}
			}
			break;
		}
	}

	info("Received %s from %s on %s", dhcpv4_msg_to_string(req_msg),
	     odhcpd_print_mac(req->chaddr, req->hlen), iface->name);

	switch (req_msg) {
	case DHCPV4_MSG_INFORM:
		break;
	case DHCPV4_MSG_DECLINE:
		_fallthrough;
	case DHCPV4_MSG_RELEASE:
		dhcpv4_lease(iface, req_msg, req->chaddr, req_addr,
			     &req_leasetime, req_hostname, req_hostname_len,
			     req_accept_fr, &reply_incl_fr, &fr_serverid);
		return;
	case DHCPV4_MSG_DISCOVER:
		_fallthrough;
	case DHCPV4_MSG_REQUEST:
		a = dhcpv4_lease(iface, req_msg, req->chaddr, req_addr,
				 &req_leasetime, req_hostname, req_hostname_len,
				 req_accept_fr, &reply_incl_fr, &fr_serverid);
		break;
	default:
		return;
	}

	/* We are at the point where we know the client expects a reply */
	switch (req_msg) {
	case DHCPV4_MSG_DISCOVER:
		if (!a)
			return;
		reply_msg.data = DHCPV4_MSG_OFFER;
		break;

	case DHCPV4_MSG_REQUEST:
		if (!a) {
			reply_msg.data = DHCPV4_MSG_NAK;
			break;
		}

		if ((req_addr && req_addr != a->addr) ||
		    (req->ciaddr.s_addr && req->ciaddr.s_addr != a->addr)) {
			reply_msg.data = DHCPV4_MSG_NAK;
			/*
			 * DHCP client requested an IP which we can't offer to him. Probably the
			 * client changed the network or the network has been changed. The reply
			 * type is set to DHCPV4_MSG_NAK, because the client should not use that IP.
			 *
			 * For modern devices we build an answer that includes a valid IP, like
			 * a DHCPV4_MSG_ACK. The client will use that IP and doesn't need to
			 * perform additional DHCP round trips.
			 *
			 * Buggy clients do serverid checking in nack messages; therefore set the
			 * serverid in nack messages triggered by a previous force renew equal to
			 * the server id in use at that time by the server
			 *
			 */
			if (fr_serverid)
				reply_serverid.data = fr_serverid;

			if (req->ciaddr.s_addr &&
			    ((iface->dhcpv4_start_ip.s_addr & iface->dhcpv4_mask.s_addr) !=
			     (req->ciaddr.s_addr & iface->dhcpv4_mask.s_addr)))
				req->ciaddr.s_addr = INADDR_ANY;
		}
		break;
	}

	/* Note: each option might get called more than once */
	for (size_t i = 0; i < sizeof(std_opts) + req_opts_len; i++) {
		uint8_t opt = i < sizeof(std_opts) ? std_opts[i] : req_opts[i - sizeof(std_opts)];

		switch (opt) {
		case DHCPV4_OPT_NETMASK:
			if (!a)
				break;
			reply_netmask.data = iface->dhcpv4_mask.s_addr;
			iov[IOV_NETMASK].iov_len = sizeof(reply_netmask);
			break;

		case DHCPV4_OPT_ROUTER:
			iov[IOV_ROUTER].iov_len = sizeof(reply_router);
			if (iface->dhcpv4_router_cnt) {
				reply_router.len = iface->dhcpv4_router_cnt * sizeof(*iface->dhcpv4_router);
				iov[IOV_ROUTER_ADDR].iov_base = iface->dhcpv4_router;
			} else {
				reply_router.len = sizeof(iface->dhcpv4_local);
				iov[IOV_ROUTER_ADDR].iov_base = &iface->dhcpv4_local;
			}
			iov[IOV_ROUTER_ADDR].iov_len = reply_router.len;
			break;

		case DHCPV4_OPT_DNSSERVER:
			iov[IOV_DNSSERVER].iov_len = sizeof(reply_dnsserver);
			if (iface->dhcpv4_dns_cnt) {
				reply_dnsserver.len = iface->dhcpv4_dns_cnt * sizeof(*iface->dhcpv4_dns);
				iov[IOV_DNSSERVER_ADDR].iov_base = iface->dhcpv4_dns;
			} else {
				reply_dnsserver.len = sizeof(iface->dhcpv4_local);
				iov[IOV_DNSSERVER_ADDR].iov_base = &iface->dhcpv4_local;
			}
			iov[IOV_DNSSERVER_ADDR].iov_len = reply_dnsserver.len;
			break;

		case DHCPV4_OPT_HOSTNAME:
			if (!a || !a->hostname)
				break;
			reply_hostname.len = strlen(a->hostname);
			iov[IOV_HOSTNAME].iov_len = sizeof(reply_hostname);
			iov[IOV_HOSTNAME_NAME].iov_base = a->hostname;
			iov[IOV_HOSTNAME_NAME].iov_len = reply_hostname.len;
			break;

		case DHCPV4_OPT_MTU:
			if (iov[IOV_MTU].iov_len)
				break;

			struct ifreq ifr = { .ifr_name = { 0x0, } };

			strncpy(ifr.ifr_name, iface->ifname, sizeof(ifr.ifr_name) - 1);
			if (!ioctl(iface->dhcpv4_event.uloop.fd, SIOCGIFMTU, &ifr)) {
				reply_mtu.data = htons(ifr.ifr_mtu);
				iov[IOV_MTU].iov_len = sizeof(reply_mtu);
			}
			break;

		case DHCPV4_OPT_BROADCAST:
			if (!a || iface->dhcpv4_bcast.s_addr == INADDR_ANY)
				break;
			reply_broadcast.data = iface->dhcpv4_bcast.s_addr;
			iov[IOV_BROADCAST].iov_len = sizeof(reply_broadcast);
			break;

		case DHCPV4_OPT_NTPSERVER:
			if (!a)
				break;
			iov[IOV_NTP].iov_len = sizeof(reply_ntp);
			iov[IOV_NTP_ADDR].iov_len = iface->dhcpv4_ntp_cnt * sizeof(*iface->dhcpv4_ntp);
			break;

		case DHCPV4_OPT_LEASETIME:
			if (!a)
				break;
			reply_leasetime.data = htonl(req_leasetime);
			iov[IOV_LEASETIME].iov_len = sizeof(reply_leasetime);
			break;

		case DHCPV4_OPT_RENEW:
			if (!a || req_leasetime == UINT32_MAX)
				break;
			reply_renew.data = htonl(500 * req_leasetime / 1000);
			iov[IOV_RENEW].iov_len = sizeof(reply_renew);
			break;

		case DHCPV4_OPT_REBIND:
			if (!a || req_leasetime == UINT32_MAX)
				break;
			reply_rebind.data = htonl(875 * req_leasetime / 1000);
			iov[IOV_REBIND].iov_len = sizeof(reply_rebind);
			break;

		case DHCPV4_OPT_AUTHENTICATION:
			if (!a || !reply_incl_fr || req_msg != DHCPV4_MSG_REQUEST)
				break;

			memcpy(reply_auth_body.key, a->key, sizeof(reply_auth_body.key));
			reply_auth_body.replay[0] = htonl(time(NULL));
			reply_auth_body.replay[1] = htonl(++serial);
			iov[IOV_AUTH].iov_len = sizeof(reply_auth);
			iov[IOV_AUTH_BODY].iov_len = sizeof(reply_auth_body);
			break;

		case DHCPV4_OPT_SEARCH_DOMAIN:
			if (iov[IOV_SRCH_DOMAIN].iov_len || iface->search_len > UINT8_MAX)
				break;

			if (iface->search) {
				reply_srch_domain.len = iface->search_len;
				iov[IOV_SRCH_DOMAIN].iov_len = sizeof(reply_srch_domain);
				iov[IOV_SRCH_DOMAIN_NAME].iov_base = iface->search;
				iov[IOV_SRCH_DOMAIN_NAME].iov_len = iface->search_len;
			} else if (!res_init() && _res.dnsrch[0] && _res.dnsrch[0][0]) {
				int len;

				if (!iov[IOV_SRCH_DOMAIN_NAME].iov_base)
					iov[IOV_SRCH_DOMAIN_NAME].iov_base = alloca(DNS_MAX_NAME_LEN);

				len = dn_comp(_res.dnsrch[0],
					      iov[IOV_SRCH_DOMAIN_NAME].iov_base,
					      DNS_MAX_NAME_LEN, NULL, NULL);
				if (len < 0)
					break;

				reply_srch_domain.len = len;
				iov[IOV_SRCH_DOMAIN].iov_len = sizeof(reply_srch_domain);
				iov[IOV_SRCH_DOMAIN_NAME].iov_len = len;
			}
			break;

		case DHCPV4_OPT_FORCERENEW_NONCE_CAPABLE:
			if (!a || !reply_incl_fr || req_msg == DHCPV4_MSG_REQUEST)
				break;

			iov[IOV_FR_NONCE_CAP].iov_len = sizeof(reply_fr_nonce_cap);
			break;

		case DHCPV4_OPT_DNR:
			struct dhcpv4_dnr *dnrs;
			size_t dnrs_len = 0;

			if (!a || reply_dnr.len > 0)
				break;

			for (size_t i = 0; i < iface->dnr_cnt; i++) {
				struct dnr_options *dnr = &iface->dnr[i];

				if (dnr->addr4_cnt == 0 && dnr->addr6_cnt > 0)
					continue;

				dnrs_len += sizeof(struct dhcpv4_dnr);
				dnrs_len += dnr->adn_len;

				if (dnr->addr4_cnt > 0 || dnr->svc_len > 0) {
					dnrs_len += sizeof(uint8_t);
					dnrs_len += dnr->addr4_cnt * sizeof(*dnr->addr4);
					dnrs_len += dnr->svc_len;
				}
			}

			if (dnrs_len > UINT8_MAX)
				break;

			dnrs = alloca(dnrs_len);
			uint8_t *pos = (uint8_t *)dnrs;

			for (size_t i = 0; i < iface->dnr_cnt; i++) {
				struct dnr_options *dnr = &iface->dnr[i];
				struct dhcpv4_dnr *d4dnr = (struct dhcpv4_dnr *)pos;
				uint16_t d4dnr_len = sizeof(uint16_t) + sizeof(uint8_t) + dnr->adn_len;
				uint16_t d4dnr_priority_be = htons(dnr->priority);
				uint16_t d4dnr_len_be;

				if (dnr->addr4_cnt == 0 && dnr->addr6_cnt > 0)
					continue;

				/* memcpy as the struct is unaligned */
				memcpy(&d4dnr->priority, &d4dnr_priority_be, sizeof(d4dnr_priority_be));

				d4dnr->adn_len = dnr->adn_len;
				pos = d4dnr->body;
				memcpy(pos, dnr->adn, dnr->adn_len);
				pos += dnr->adn_len;

				if (dnr->addr4_cnt > 0 || dnr->svc_len > 0) {
					uint8_t addr4_len = dnr->addr4_cnt * sizeof(*dnr->addr4);

					*(pos++) = addr4_len;
					memcpy(pos, dnr->addr4, addr4_len);
					pos += addr4_len;
					memcpy(pos, dnr->svc, dnr->svc_len);
					pos += dnr->svc_len;

					d4dnr_len += sizeof(addr4_len) + addr4_len + dnr->svc_len;
				}

				d4dnr_len_be = htons(d4dnr_len);
				memcpy(&d4dnr->len, &d4dnr_len_be, sizeof(d4dnr_len_be));
			}

			reply_dnr.len = dnrs_len;
			iov[IOV_DNR].iov_len = sizeof(reply_dnr);
			iov[IOV_DNR_BODY].iov_base = dnrs;
			iov[IOV_DNR_BODY].iov_len = dnrs_len;
			break;
		}
	}

	if (a)
		reply.yiaddr.s_addr = a->addr;

	memcpy(reply.chaddr, req->chaddr, sizeof(reply.chaddr));
	dhcpv4_set_dest_addr(iface, reply_msg.data, req, &reply, src_addr, &dest_addr);
	dhcpv4_add_padding(iov, ARRAY_SIZE(iov));

	if (send_reply(iov, ARRAY_SIZE(iov), (struct sockaddr *)&dest_addr, sizeof(dest_addr), opaque) < 0)
		error("Failed to send %s to %s - %s: %m",
		      dhcpv4_msg_to_string(reply_msg.data),
		      dest_addr.sin_addr.s_addr == INADDR_BROADCAST ?
		      "ff:ff:ff:ff:ff:ff": odhcpd_print_mac(req->chaddr, req->hlen),
		      inet_ntoa(dest_addr.sin_addr));
	else
		error("Sent %s to %s - %s",
		      dhcpv4_msg_to_string(reply_msg.data),
		      dest_addr.sin_addr.s_addr == INADDR_BROADCAST ?
		      "ff:ff:ff:ff:ff:ff": odhcpd_print_mac(req->chaddr, req->hlen),
		      inet_ntoa(dest_addr.sin_addr));

	if (reply_msg.data == DHCPV4_MSG_ACK && a)
		ubus_bcast_dhcp_event("dhcp.ack", req->chaddr,
				      (struct in_addr *)&a->addr,
				      a->hostname, iface->ifname);
}

/* Handler for DHCPv4 messages */
static void dhcpv4_handle_dgram(void *addr, void *data, size_t len,
				struct interface *iface, _unused void *dest_addr)
{
	int sock = iface->dhcpv4_event.uloop.fd;

	dhcpv4_handle_msg(addr, data, len, iface, dest_addr, dhcpv4_send_reply, &sock);
}

static int dhcpv4_setup_addresses(struct interface *iface)
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
		warn("Invalid DHCP range for %s", iface->name);
		return -1;
	}

	if (!iface->addr4_len) {
		warn("No network(s) available on %s", iface->name);
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
				(end & ntohl(~mask.s_addr)) == end &&
				end < ntohl(~mask.s_addr)) {	/* Exclude broadcast address */
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

	/* Don't allocate IP range for subnets smaller than /28 */
	if (iface->addr4[0].prefix > MAX_PREFIX_LEN) {
		warn("Auto allocation of DHCP range fails on %s (prefix length must be < %d).",
		     iface->name, MAX_PREFIX_LEN + 1);
		return -1;
	}

	iface->dhcpv4_local = iface->addr4[0].addr.in;
	iface->dhcpv4_bcast = iface->addr4[0].broadcast;
	odhcpd_bitlen2netmask(false, iface->addr4[0].prefix, &iface->dhcpv4_mask);
	end = start = iface->dhcpv4_local.s_addr & iface->dhcpv4_mask.s_addr;

	/* Auto allocate ranges */
	if (ntohl(iface->dhcpv4_mask.s_addr) <= 0xffffff00) {		/* /24, 150 of 256, [100..249] */
		iface->dhcpv4_start_ip.s_addr = start | htonl(100);
		iface->dhcpv4_end_ip.s_addr = end | htonl(100 + 150 - 1);
	} else if (ntohl(iface->dhcpv4_mask.s_addr) <= 0xffffff80) {    /* /25, 100 of 128, [20..119] */
		iface->dhcpv4_start_ip.s_addr = start | htonl(20);
		iface->dhcpv4_end_ip.s_addr = end | htonl(20 + 100 - 1);
	} else if (ntohl(iface->dhcpv4_mask.s_addr) <= 0xffffffc0) {    /* /26, 50 of 64, [10..59] */
		iface->dhcpv4_start_ip.s_addr = start | htonl(10);
		iface->dhcpv4_end_ip.s_addr = end | htonl(10 + 50 - 1);
	} else if (ntohl(iface->dhcpv4_mask.s_addr) <= 0xffffffe0) {    /* /27, 20 of 32, [10..29] */
		iface->dhcpv4_start_ip.s_addr = start | htonl(10);
		iface->dhcpv4_end_ip.s_addr = end | htonl(10 + 20 - 1);
	} else {							/* /28, 10 of 16, [3..12] */
		iface->dhcpv4_start_ip.s_addr = start | htonl(3);
		iface->dhcpv4_end_ip.s_addr = end | htonl(3 + 10 - 1);
	}

	return 0;
}

int dhcpv4_setup_interface(struct interface *iface, bool enable)
{
	int ret = 0;
	struct sockaddr_in bind_addr = {
		.sin_family = AF_INET,
		.sin_port = htons(DHCPV4_SERVER_PORT),
		.sin_addr = { INADDR_ANY },
	};
	int val = 1;

	if (iface->dhcpv4_event.uloop.fd >= 0) {
		uloop_fd_delete(&iface->dhcpv4_event.uloop);
		close(iface->dhcpv4_event.uloop.fd);
		iface->dhcpv4_event.uloop.fd = -1;
	}

	if (!enable || iface->dhcpv4 == MODE_DISABLED) {
		while (!list_empty(&iface->dhcpv4_assignments))
			free_assignment(list_first_entry(&iface->dhcpv4_assignments,
							 struct dhcp_assignment, head));
		return 0;
	}

	iface->dhcpv4_event.uloop.fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
	if (iface->dhcpv4_event.uloop.fd < 0) {
		error("socket(AF_INET): %m");
		ret = -1;
		goto out;
	}

	/* Basic IPv4 configuration */
	if (setsockopt(iface->dhcpv4_event.uloop.fd, SOL_SOCKET, SO_REUSEADDR,
		       &val, sizeof(val)) < 0) {
		error("setsockopt(SO_REUSEADDR): %m");
		ret = -1;
		goto out;
	}

	if (setsockopt(iface->dhcpv4_event.uloop.fd, SOL_SOCKET, SO_BROADCAST,
		       &val, sizeof(val)) < 0) {
		error("setsockopt(SO_BROADCAST): %m");
		ret = -1;
		goto out;
	}

	if (setsockopt(iface->dhcpv4_event.uloop.fd, IPPROTO_IP, IP_PKTINFO,
		       &val, sizeof(val)) < 0) {
		error("setsockopt(IP_PKTINFO): %m");
		ret = -1;
		goto out;
	}

	val = IPTOS_PREC_INTERNETCONTROL;
	if (setsockopt(iface->dhcpv4_event.uloop.fd, IPPROTO_IP, IP_TOS, &val,
		       sizeof(val)) < 0) {
		error("setsockopt(IP_TOS): %m");
		ret = -1;
		goto out;
	}

	val = IP_PMTUDISC_DONT;
	if (setsockopt(iface->dhcpv4_event.uloop.fd, IPPROTO_IP, IP_MTU_DISCOVER,
		       &val, sizeof(val)) < 0) {
		error("setsockopt(IP_MTU_DISCOVER): %m");
		ret = -1;
		goto out;
	}

	if (setsockopt(iface->dhcpv4_event.uloop.fd, SOL_SOCKET, SO_BINDTODEVICE,
		       iface->ifname, strlen(iface->ifname)) < 0) {
		error("setsockopt(SO_BINDTODEVICE): %m");
		ret = -1;
		goto out;
	}

	if (bind(iface->dhcpv4_event.uloop.fd, (struct sockaddr *)&bind_addr,
		 sizeof(bind_addr)) < 0) {
		error("bind(): %m");
		ret = -1;
		goto out;
	}

	if (dhcpv4_setup_addresses(iface) < 0) {
		ret = -1;
		goto out;
	}

	iface->dhcpv4_event.handle_dgram = dhcpv4_handle_dgram;
	odhcpd_register(&iface->dhcpv4_event);

out:
	if (ret < 0 && iface->dhcpv4_event.uloop.fd >= 0) {
		close(iface->dhcpv4_event.uloop.fd);
		iface->dhcpv4_event.uloop.fd = -1;
	}

	return ret;
}

static void dhcpv4_addrlist_change(struct interface *iface)
{
	struct odhcpd_ipaddr ip;
	struct odhcpd_ref_ip *a;
	struct dhcp_assignment *c;
	uint32_t mask = iface->dhcpv4_mask.s_addr;

	memset(&ip, 0, sizeof(ip));
	ip.addr.in = iface->dhcpv4_local;
	ip.prefix = odhcpd_netmask2bitlen(false, &iface->dhcpv4_mask);
	ip.broadcast = iface->dhcpv4_bcast;

	dhcpv4_setup_addresses(iface);

	if ((ip.addr.in.s_addr & mask) ==
	    (iface->dhcpv4_local.s_addr & iface->dhcpv4_mask.s_addr))
		return;

	if (ip.addr.in.s_addr && !leases_require_fr(iface, &ip, mask))
		return;

	if (iface->dhcpv4_local.s_addr == INADDR_ANY || list_empty(&iface->dhcpv4_fr_ips))
		return;

	a = list_first_entry(&iface->dhcpv4_fr_ips, struct odhcpd_ref_ip, head);

	if (netlink_setup_addr(&a->addr, iface->ifindex, false, true)) {
		warn("Failed to add ip address on %s", iface->name);
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
		dhcpv4_addrlist_change(iface);
		break;
	default:
		break;
	}
}

static void dhcpv4_valid_until_cb(struct uloop_timeout *event)
{
	struct interface *iface;
	time_t now = odhcpd_time();

	avl_for_each_element(&interfaces, iface, avl) {
		struct dhcp_assignment *a, *n;

		if (iface->dhcpv4 != MODE_SERVER)
			continue;

		list_for_each_entry_safe(a, n, &iface->dhcpv4_assignments, head) {
			if (!INFINITE_VALID(a->valid_until) && a->valid_until < now) {
				ubus_bcast_dhcp_event("dhcp.expire", a->hwaddr,
						      (struct in_addr *)&a->addr,
						      a->hostname, iface->ifname);
				free_assignment(a);
			}
		}
	}
	uloop_timeout_set(event, 1000);
}

/* Create socket and register events */
int dhcpv4_init(void)
{
	static struct netevent_handler dhcpv4_netevent_handler = { .cb = dhcpv4_netevent_cb };
	static struct uloop_timeout valid_until_timeout = { .cb = dhcpv4_valid_until_cb };

	uloop_timeout_set(&valid_until_timeout, 1000);
	netlink_add_netevent_handler(&dhcpv4_netevent_handler);

	return 0;
}
