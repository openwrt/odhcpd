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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
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
#include <netinet/udp.h>
#include <sys/ioctl.h>
#include <sys/timerfd.h>
#include <arpa/inet.h>
#include <linux/filter.h>

#include <libubox/md5.h>

#include "odhcpd.h"
#include "dhcpv4.h"
#include "dhcpv6.h"
#include "statefiles.h"

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

static bool leases_require_fr(struct interface *iface, struct odhcpd_ipaddr *oaddr)
{
	struct dhcpv4_lease *lease = NULL;
	struct odhcpd_ref_ip *fr_ip = NULL;

	avl_for_each_element(&iface->dhcpv4_leases, lease, iface_avl) {
		if (!lease->accept_fr_nonce && !iface->dhcpv4_forcereconf)
			continue;

		if (lease->fr_ip)
			continue;

		if ((lease->ipv4.s_addr & oaddr->netmask) != (oaddr->addr.in.s_addr & oaddr->netmask))
			continue;

		if (!fr_ip) {
			fr_ip = calloc(1, sizeof(*fr_ip));
			if (!fr_ip)
				break;

			list_add(&fr_ip->head, &iface->dhcpv4_fr_ips);
			fr_ip->addr = *oaddr;
		}
		inc_ref_cnt_ip(&lease->fr_ip, fr_ip);
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

static void dhcpv4_fr_send(struct dhcpv4_lease *lease)
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
		.data = lease->fr_ip->addr.addr.in.s_addr,
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
		.sin_addr = lease->ipv4,
	};

	odhcpd_urandom(&fr.xid, sizeof(fr.xid));
	memcpy(fr.chaddr, lease->hwaddr, fr.hlen);

	if (lease->accept_fr_nonce) {
		uint8_t secretbytes[64] = { 0 };
		md5_ctx_t md5;

		fr_auth_body.replay[0] = htonl(time(NULL));
		fr_auth_body.replay[1] = htonl(++serial);
		iov[IOV_FR_AUTH].iov_len = sizeof(fr_auth);
		iov[IOV_FR_AUTH_BODY].iov_len = sizeof(fr_auth_body);
		dhcpv4_add_padding(iov, ARRAY_SIZE(iov));

		memcpy(secretbytes, lease->key, sizeof(lease->key));
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
			      &lease->iface->dhcpv4_event.uloop.fd) < 0) {
		char ipv4_str[INET_ADDRSTRLEN];

		error("Failed to send %s to %s - %s: %m", dhcpv4_msg_to_string(fr_msg.data),
		      odhcpd_print_mac(lease->hwaddr, sizeof(lease->hwaddr)),
		      inet_ntop(AF_INET, &dest, ipv4_str, sizeof(ipv4_str)));
	} else {
		char ipv4_str[INET_ADDRSTRLEN];

		debug("Sent %s to %s - %s", dhcpv4_msg_to_string(fr_msg.data),
		      odhcpd_print_mac(lease->hwaddr, sizeof(lease->hwaddr)),
		      inet_ntop(AF_INET, &dest, ipv4_str, sizeof(ipv4_str)));
	}
}

static void dhcpv4_fr_stop(struct dhcpv4_lease *lease)
{
	uloop_timeout_cancel(&lease->fr_timer);
	decr_ref_cnt_ip(&lease->fr_ip, lease->iface);
	lease->fr_cnt = 0;
	lease->fr_timer.cb = NULL;
}

static void dhcpv4_fr_timer(struct uloop_timeout *event)
{
	struct dhcpv4_lease *lease = container_of(event, struct dhcpv4_lease, fr_timer);

	if (lease->fr_cnt > 0 && lease->fr_cnt < 8) {
		dhcpv4_fr_send(lease);
		uloop_timeout_set(&lease->fr_timer, 1000 << lease->fr_cnt);
		lease->fr_cnt++;
	} else
		dhcpv4_fr_stop(lease);
}

static void dhcpv4_fr_start(struct dhcpv4_lease *lease)
{
	uloop_timeout_set(&lease->fr_timer, 1000 << lease->fr_cnt);
	lease->fr_timer.cb = dhcpv4_fr_timer;
	lease->fr_cnt++;

	dhcpv4_fr_send(lease);
}

static void dhcpv4_fr_rand_delay(struct dhcpv4_lease *lease);

static void dhcpv4_fr_delay_timer(struct uloop_timeout *event)
{
	struct dhcpv4_lease *lease = container_of(event, struct dhcpv4_lease, fr_timer);
	struct interface *iface = lease->iface;

	(iface->dhcpv4_event.uloop.fd == -1 ? dhcpv4_fr_rand_delay(lease) : dhcpv4_fr_start(lease));
}

static void dhcpv4_fr_rand_delay(struct dhcpv4_lease *lease)
{
	int msecs;

	odhcpd_urandom(&msecs, sizeof(msecs));

	msecs = abs(msecs) % DHCPV4_FR_MAX_FUZZ + DHCPV4_FR_MIN_DELAY;

	uloop_timeout_set(&lease->fr_timer, msecs);
	lease->fr_timer.cb = dhcpv4_fr_delay_timer;
}

void dhcpv4_free_lease(struct dhcpv4_lease *lease)
{
	if (!lease)
		return;

	if (lease->fr_ip)
		dhcpv4_fr_stop(lease);

	if (lease->iface) {
		lease->iface->update_statefile = true;
		avl_delete(&lease->iface->dhcpv4_leases, &lease->iface_avl);
	}

	if (lease->lease_cfg)
		lease->lease_cfg->dhcpv4_lease = NULL;

	free(lease->hostname);
	free(lease);
}

static struct dhcpv4_lease *
dhcpv4_alloc_lease(struct interface *iface, const uint8_t *hwaddr,
		   size_t hwaddr_len, const uint8_t *duid, size_t duid_len,
		   uint32_t iaid)
{
	struct dhcpv4_lease *lease;

	if (!iface || !hwaddr || hwaddr_len == 0 || hwaddr_len > sizeof(lease->hwaddr))
		return NULL;

	lease = calloc(1, sizeof(*lease) + duid_len);
	if (!lease)
		return NULL;

	lease->iface_avl.key = &lease->ipv4;
	lease->hwaddr_len = hwaddr_len;
	memcpy(lease->hwaddr, hwaddr, hwaddr_len);
	if (duid_len > 0) {
		lease->duid_len = duid_len;
		memcpy(lease->duid, duid, duid_len);
		lease->iaid = iaid;
	}
	lease->iface = iface;

	return lease;
}

static bool dhcpv4_insert_lease(struct avl_tree *avl, struct dhcpv4_lease *lease,
				struct in_addr addr)
{
	lease->ipv4 = addr;
	if (!avl_insert(avl, &lease->iface_avl))
		return true;
	else
		return false;
}

static bool dhcpv4_assign_random(struct interface *iface,
				 struct dhcpv4_lease *lease)
{
	uint32_t pool_start = ntohl(iface->dhcpv4_start_ip.s_addr);
	uint32_t pool_end = ntohl(iface->dhcpv4_end_ip.s_addr);
	uint32_t pool_size = pool_end - pool_start + 1;
	unsigned short xsubi[3];
	uint32_t try;

	/* Pick a random starting point, using hwaddr as seed... */
	memcpy(xsubi, lease->hwaddr, sizeof(xsubi));
	try = pool_start + nrand48(xsubi) % pool_size;

	/* ...then loop over the whole pool from that point */
	for (uint32_t i = 0; i < pool_size; i++, try++) {
		struct in_addr in_try;

		if (try > pool_end)
			try = pool_start;

		in_try.s_addr = htonl(try);

		if (config_find_lease_cfg_by_ipv4(in_try))
			continue;

		if (dhcpv4_insert_lease(&iface->dhcpv4_leases, lease, in_try))
			return true;
	}

	return false;
}

static bool dhcpv4_assign(struct interface *iface, struct dhcpv4_lease *lease,
			  struct in_addr req_addr)
{
	uint32_t pool_start = ntohl(iface->dhcpv4_start_ip.s_addr);
	uint32_t pool_end = ntohl(iface->dhcpv4_end_ip.s_addr);
	char ipv4_str[INET_ADDRSTRLEN];
	const char *addr_type = NULL;

	/* Preconfigured IP address by static lease */
	if (lease->ipv4.s_addr) {
		if (!dhcpv4_insert_lease(&iface->dhcpv4_leases, lease, lease->ipv4)) {
			error("The static IP address %s is already assigned on %s",
			      inet_ntop(AF_INET, &lease->ipv4, ipv4_str, sizeof(ipv4_str)),
			      iface->name);
			return false;
		}

		addr_type = "static";
		goto out;
	}

	if (iface->no_dynamic_dhcp) {
		debug("Dynamic leases disabled, not assigning lease");
		return false;
	}

	if (req_addr.s_addr != INADDR_ANY) {
		/* The client asked for a specific address, let's try... */
		if (ntohl(req_addr.s_addr) < pool_start || ntohl(req_addr.s_addr) > pool_end) {
			debug("The requested IP address %s is outside the pool on %s",
			      inet_ntop(AF_INET, &req_addr, ipv4_str, sizeof(ipv4_str)),
			      iface->ifname);
		} else if (config_find_lease_cfg_by_ipv4(req_addr)) {
			debug("The requested IP address %s is statically assigned on %s",
			      inet_ntop(AF_INET, &req_addr, ipv4_str, sizeof(ipv4_str)),
			      iface->ifname);
		} else if (!dhcpv4_insert_lease(&iface->dhcpv4_leases, lease, req_addr)) {
			debug("The requested IP address %s is already assigned on %s",
			      inet_ntop(AF_INET, &req_addr, ipv4_str, sizeof(ipv4_str)),
			      iface->ifname);
		} else {
			addr_type = "requested";
			goto out;
		}
	}

	if (!dhcpv4_assign_random(iface, lease)) {
		warn("Can't assign any IP address, DHCP pool exhausted on %s", iface->name);
		return false;
	}
	addr_type = "random";

out:
	debug("Assigned %s IP address %s on %s", addr_type,
	      inet_ntop(AF_INET, &lease->ipv4, ipv4_str, sizeof(ipv4_str)),
	      iface->ifname);
	iface->update_statefile = true;
	return true;
}

static struct dhcpv4_lease *find_lease_by_hwaddr(struct interface *iface, const uint8_t *hwaddr)
{
	struct dhcpv4_lease *lease;

	avl_for_each_element(&iface->dhcpv4_leases, lease, iface_avl)
		if (!memcmp(lease->hwaddr, hwaddr, ETH_ALEN))
			return lease;

	return NULL;
}

static struct dhcpv4_lease *
find_lease_by_duid_iaid(struct interface *iface, const uint8_t *duid,
			size_t duid_len, uint32_t iaid)
{
	struct dhcpv4_lease *lease;

	avl_for_each_element(&iface->dhcpv4_leases, lease, iface_avl) {
		if (lease->duid_len != duid_len || lease->iaid != iaid)
			continue;
		if (!memcmp(lease->duid, duid, duid_len))
			return lease;
	}

	return NULL;
}

static struct dhcpv4_lease *
dhcpv4_lease(struct interface *iface, enum dhcpv4_msg req_msg, const uint8_t *req_mac,
	     const uint8_t *clid, size_t clid_len, const struct in_addr req_addr,
	     uint32_t *req_leasetime, const char *req_hostname, const size_t
	     req_hostname_len, const bool req_accept_fr, bool *reply_incl_fr,
	     uint32_t *fr_serverid)
{
	struct dhcpv4_lease *lease = NULL;
	struct lease_cfg *lease_cfg = NULL;
	const uint8_t *duid = NULL;
	size_t duid_len = 0;
	uint32_t iaid = 0;
	time_t now = odhcpd_time();

	// RFC4361, §6.1, §6.3 - MUST use clid if provided, MAY use chaddr
	if (clid && clid_len > (1 + sizeof(iaid) + DUID_MIN_LEN) &&
	    clid[0] == DHCPV4_CLIENTID_TYPE_DUID_IAID &&
	    clid_len <= (1 + sizeof(iaid) + DUID_MAX_LEN)) {
		memcpy(&iaid, &clid[1], sizeof(uint32_t));
		iaid = ntohl(iaid);

		duid = &clid[1 + sizeof(iaid)];
		duid_len = clid_len - (1 + sizeof(iaid));

		lease = find_lease_by_duid_iaid(iface, duid, duid_len, iaid);
		lease_cfg = config_find_lease_cfg_by_duid_and_iaid(duid, duid_len, iaid);
	}

	if (!lease)
		lease = find_lease_by_hwaddr(iface, req_mac);

	if (!lease_cfg)
		lease_cfg = config_find_lease_cfg_by_mac(req_mac);

	if (lease_cfg && lease_cfg->ignore4)
		return NULL;

	/*
	 * If we found a static lease cfg, but no old assignment for this
	 * hwaddr, we need to clear out any old assignments given to other
	 * hwaddrs in order to take over the IP address.
	 */
	if (lease_cfg && !lease && (req_msg == DHCPV4_MSG_DISCOVER || req_msg == DHCPV4_MSG_REQUEST))
		dhcpv4_free_lease(lease_cfg->dhcpv4_lease);

	if (lease_cfg && lease && lease->lease_cfg != lease_cfg) {
		dhcpv4_free_lease(lease);
		lease = NULL;
	}

	if (lease && lease->bound && lease->fr_ip) {
		*fr_serverid = lease->fr_ip->addr.addr.in.s_addr;
		dhcpv4_fr_stop(lease);
	}

	switch (req_msg) {
	case DHCPV4_MSG_RELEASE:
		if (!lease)
			return NULL;

		ubus_bcast_dhcpv4_event("dhcp.release4", iface->ifname, lease);
                dhcpv4_free_lease(lease);
                lease = NULL;
		break;

	case DHCPV4_MSG_DECLINE:
		if (!lease)
			return NULL;

		lease->bound = false;

		if (!lease->lease_cfg || lease->lease_cfg->ipv4.s_addr != lease->ipv4.s_addr) {
			memset(lease->hwaddr, 0, sizeof(lease->hwaddr));
			lease->valid_until = now + 3600; /* Block address for 1h */
		} else {
			lease->valid_until = now - 1;
		}
		break;

	case DHCPV4_MSG_DISCOVER:
	case DHCPV4_MSG_REQUEST:
		if (!lease && iface->no_dynamic_dhcp && !lease_cfg)
			return NULL;

		/* Old lease, but with an address that is out-of-scope? */
		if (lease && !lease->lease_cfg &&
		    ((lease->ipv4.s_addr & iface->dhcpv4_own_ip.netmask) !=
		     (iface->dhcpv4_start_ip.s_addr & iface->dhcpv4_own_ip.netmask))) {
			/* Try to reassign to an address that is in-scope */
			avl_delete(&iface->dhcpv4_leases, &lease->iface_avl);
			lease->ipv4.s_addr = INADDR_ANY;
			if (!dhcpv4_assign(iface, lease, req_addr)) {
				dhcpv4_free_lease(lease);
				lease = NULL;
				break;
			}
		}

		if (!lease) {
			/* Create new binding */
			lease = dhcpv4_alloc_lease(iface, req_mac, ETH_ALEN, duid, duid_len, iaid);
			if (!lease) {
				warn("Failed to allocate memory for DHCPv4 lease on interface %s", iface->ifname);
				return NULL;
			}

			/* static lease => infinite (0), else a placeholder */
			lease->valid_until = lease_cfg ? 0 : now;
			lease->ipv4.s_addr = lease_cfg ? lease_cfg->ipv4.s_addr : INADDR_ANY;

			if (!dhcpv4_assign(iface, lease, req_addr)) {
				dhcpv4_free_lease(lease);
				return NULL;
			}

			if (lease_cfg) {
				if (lease_cfg->hostname) {
					lease->hostname = strdup(lease_cfg->hostname);
					lease->hostname_valid = true;
				}

				lease_cfg->dhcpv4_lease = lease;
				lease->lease_cfg = lease_cfg;
			}
		}

		/* See if we need to clamp the requested leasetime */
		uint32_t max_leasetime;
		if (lease->lease_cfg && lease->lease_cfg->leasetime)
			max_leasetime = lease->lease_cfg->leasetime;
		else
			max_leasetime = iface->dhcp_leasetime;

		if ((*req_leasetime == 0) || (max_leasetime < *req_leasetime))
			*req_leasetime = max_leasetime;

		if (req_msg == DHCPV4_MSG_DISCOVER) {
			lease->bound = false;
			*reply_incl_fr = req_accept_fr;
			lease->valid_until = now;
			break;
		}

		if (req_hostname_len > 0 && (!lease->lease_cfg || !lease->lease_cfg->hostname)) {
			char *new_name = realloc(lease->hostname, req_hostname_len + 1);
			if (new_name) {
				lease->hostname = new_name;
				memcpy(lease->hostname, req_hostname, req_hostname_len);
				lease->hostname[req_hostname_len] = 0;
				lease->hostname_valid = odhcpd_hostname_valid(lease->hostname);
			}
		}

		*reply_incl_fr = false;
		if (!lease->bound) {
			/* This is the client's first request for the address */
			if (req_accept_fr) {
				lease->accept_fr_nonce = true;
				*reply_incl_fr = true;
				odhcpd_urandom(lease->key, sizeof(lease->key));
			}
			lease->bound = true;
		}

		if (*req_leasetime == UINT32_MAX)
			lease->valid_until = 0;
		else
			lease->valid_until = (time_t)(now + *req_leasetime);
		break;

	default:
		return NULL;
	}

	iface->update_statefile = true;
	return lease;
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
	IOV_CLIENTID,
	IOV_CLIENTID_DATA,
	IOV_NETMASK,
	IOV_ROUTER,
	IOV_ROUTER_ADDR,
	IOV_DNSSERVER,
	IOV_DNSSERVER_ADDRS,
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
	IOV_CAPTIVE_PORTAL,
	IOV_IPV6_ONLY_PREF,
	IOV_END,
	IOV_PADDING,
	IOV_TOTAL
};

void dhcpv4_handle_msg(void *src_addr, void *data, size_t len,
		struct interface *iface, _o_unused void *our_dest_addr,
	        send_reply_cb_t send_reply, void *opaque)
{
	/* Request variables */
	struct dhcpv4_message *req = data;
	uint8_t req_msg = DHCPV4_MSG_REQUEST;
	uint8_t *req_opts = NULL;
	size_t req_opts_len = 0;
	struct in_addr req_addr = { .s_addr = INADDR_ANY };
	uint32_t req_leasetime = 0;
	char *req_hostname = NULL;
	size_t req_hostname_len = 0;
	uint8_t *req_clientid = NULL;
	size_t req_clientid_len = 0;
	bool req_accept_fr = false;
	bool ipv6_only = false;

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
		.siaddr = iface->dhcpv4_own_ip.addr.in,
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
		.data = iface->dhcpv4_own_ip.addr.in.s_addr,
	};
	struct dhcpv4_option reply_clientid = {
		.code = DHCPV4_OPT_CLIENTID,
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
		.code = DHCPV4_OPT_DNS_DOMAIN_SEARCH,
	};
	struct dhcpv4_option_u8 reply_fr_nonce_cap = {
		.code = DHCPV4_OPT_FORCERENEW_NONCE_CAPABLE,
		.len = sizeof(uint8_t),
		.data = 1,
	};
	struct dhcpv4_option reply_dnr = {
		.code = DHCPV4_OPT_DNR,
	};
	struct dhcpv4_option_u32 reply_ipv6_only = {
		.code = DHCPV4_OPT_IPV6_ONLY_PREFERRED,
		.len = sizeof(uint32_t),
		.data = htonl(iface->dhcpv4_v6only_wait),
	};
	uint8_t reply_end = DHCPV4_OPT_END;

	struct iovec iov[IOV_TOTAL] = {
		[IOV_HEADER]		= { &reply, sizeof(reply) },
		[IOV_MESSAGE]		= { &reply_msg, sizeof(reply_msg) },
		[IOV_SERVERID]		= { &reply_serverid, sizeof(reply_serverid) },
		[IOV_CLIENTID]		= { &reply_clientid, 0 },
		[IOV_CLIENTID_DATA]	= { NULL, 0 },
		[IOV_NETMASK]		= { &reply_netmask, 0 },
		[IOV_ROUTER]		= { &reply_router, 0 },
		[IOV_ROUTER_ADDR]	= { NULL, 0 },
		[IOV_DNSSERVER]		= { &reply_dnsserver, 0 },
		[IOV_DNSSERVER_ADDRS]	= { NULL, 0 },
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
		[IOV_CAPTIVE_PORTAL]	= { NULL, 0 },
		[IOV_IPV6_ONLY_PREF]	= { &reply_ipv6_only, 0 },
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
		DHCPV4_OPT_CLIENTID, // Must be in reply if present in req, RFC6842, §3
		DHCPV4_OPT_AUTHENTICATION,
		DHCPV4_OPT_DNS_DOMAIN_SEARCH,
		DHCPV4_OPT_CAPTIVE_PORTAL,
		DHCPV4_OPT_FORCERENEW_NONCE_CAPABLE,
	};

	/* Misc */
	struct sockaddr_in dest_addr;
	bool reply_incl_fr = false;
	struct dhcpv4_lease *lease = NULL;
	uint32_t fr_serverid = INADDR_ANY;

	if (iface->dhcpv4 == MODE_DISABLED)
		return;

	debug("Got DHCPv4 request on %s", iface->name);

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
			if (opt->len == 4 && memcmp(opt->data, &iface->dhcpv4_own_ip, 4))
				return;
			break;
		case DHCPV4_OPT_REQOPTS:
			req_opts = opt->data;
			req_opts_len = opt->len;
			if (iface->dhcpv4_v6only_wait)
				for (uint8_t i = 0; i < opt->len; i++)
					if (opt->data[i] == DHCPV4_OPT_IPV6_ONLY_PREFERRED)
						ipv6_only = true;
			break;
		case DHCPV4_OPT_CLIENTID:
			if (opt->len >= 2) {
				req_clientid = opt->data;
				req_clientid_len = opt->len;
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
	case DHCPV4_MSG_RELEASE:
		dhcpv4_lease(iface, req_msg, req->chaddr, req_clientid,
			     req_clientid_len, req_addr, &req_leasetime,
			     req_hostname, req_hostname_len, req_accept_fr,
			     &reply_incl_fr, &fr_serverid);
		return;
	case DHCPV4_MSG_DISCOVER:
		if (ipv6_only)
			break;
		_o_fallthrough;
	case DHCPV4_MSG_REQUEST:
		lease = dhcpv4_lease(iface, req_msg, req->chaddr, req_clientid,
				     req_clientid_len, req_addr, &req_leasetime,
				     req_hostname, req_hostname_len, req_accept_fr,
				     &reply_incl_fr, &fr_serverid);
		break;
	default:
		return;
	}

	/* We are at the point where we know the client expects a reply */
	switch (req_msg) {
	case DHCPV4_MSG_DISCOVER:
		if (!lease && !ipv6_only)
			return;
		reply_msg.data = DHCPV4_MSG_OFFER;
		break;

	case DHCPV4_MSG_REQUEST:
		if (!lease) {
			reply_msg.data = DHCPV4_MSG_NAK;
			break;
		}

		if ((req_addr.s_addr && req_addr.s_addr != lease->ipv4.s_addr) ||
		    (req->ciaddr.s_addr && req->ciaddr.s_addr != lease->ipv4.s_addr)) {
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
			    ((iface->dhcpv4_start_ip.s_addr & iface->dhcpv4_own_ip.netmask) !=
			     (req->ciaddr.s_addr & iface->dhcpv4_own_ip.netmask)))
				req->ciaddr.s_addr = INADDR_ANY;
		}
		break;
	}

	/* Note: each option might get called more than once */
	for (size_t i = 0; i < sizeof(std_opts) + req_opts_len; i++) {
		uint8_t r_opt = i < sizeof(std_opts) ? std_opts[i] : req_opts[i - sizeof(std_opts)];

		switch (r_opt) {
		case DHCPV4_OPT_NETMASK:
			if (!lease)
				break;
			reply_netmask.data = iface->dhcpv4_own_ip.netmask;
			iov[IOV_NETMASK].iov_len = sizeof(reply_netmask);
			break;

		case DHCPV4_OPT_ROUTER:
			iov[IOV_ROUTER].iov_len = sizeof(reply_router);
			if (iface->dhcpv4_routers_cnt) {
				reply_router.len = iface->dhcpv4_routers_cnt * sizeof(*iface->dhcpv4_routers);
				iov[IOV_ROUTER_ADDR].iov_base = iface->dhcpv4_routers;
			} else {
				reply_router.len = sizeof(iface->dhcpv4_own_ip.addr.in);
				iov[IOV_ROUTER_ADDR].iov_base = &iface->dhcpv4_own_ip.addr.in;
			}
			iov[IOV_ROUTER_ADDR].iov_len = reply_router.len;
			break;

		case DHCPV4_OPT_DNSSERVER:
			iov[IOV_DNSSERVER].iov_len = sizeof(reply_dnsserver);
			if (iface->dns_addrs4_cnt) {
				reply_dnsserver.len = iface->dns_addrs4_cnt * sizeof(*iface->dns_addrs4);
				iov[IOV_DNSSERVER_ADDRS].iov_base = iface->dns_addrs4;
			} else {
				reply_dnsserver.len = sizeof(iface->dhcpv4_own_ip.addr.in);
				iov[IOV_DNSSERVER_ADDRS].iov_base = &iface->dhcpv4_own_ip.addr.in;
			}
			iov[IOV_DNSSERVER_ADDRS].iov_len = reply_dnsserver.len;
			break;

		case DHCPV4_OPT_HOSTNAME:
			if (!lease || !lease->hostname)
				break;
			reply_hostname.len = strlen(lease->hostname);
			iov[IOV_HOSTNAME].iov_len = sizeof(reply_hostname);
			iov[IOV_HOSTNAME_NAME].iov_base = lease->hostname;
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
			if (!lease || iface->dhcpv4_own_ip.broadcast.s_addr == INADDR_ANY)
				break;
			reply_broadcast.data = iface->dhcpv4_own_ip.broadcast.s_addr;
			iov[IOV_BROADCAST].iov_len = sizeof(reply_broadcast);
			break;

		case DHCPV4_OPT_NTPSERVER:
			if (!lease)
				break;
			iov[IOV_NTP].iov_len = sizeof(reply_ntp);
			iov[IOV_NTP_ADDR].iov_len = iface->dhcpv4_ntp_cnt * sizeof(*iface->dhcpv4_ntp);
			break;

		case DHCPV4_OPT_LEASETIME:
			if (!lease)
				break;
			reply_leasetime.data = htonl(req_leasetime);
			iov[IOV_LEASETIME].iov_len = sizeof(reply_leasetime);
			break;

		case DHCPV4_OPT_RENEW:
			if (!lease || req_leasetime == UINT32_MAX)
				break;
			reply_renew.data = htonl(500 * req_leasetime / 1000);
			iov[IOV_RENEW].iov_len = sizeof(reply_renew);
			break;

		case DHCPV4_OPT_REBIND:
			if (!lease || req_leasetime == UINT32_MAX)
				break;
			reply_rebind.data = htonl(875 * req_leasetime / 1000);
			iov[IOV_REBIND].iov_len = sizeof(reply_rebind);
			break;

		case DHCPV4_OPT_CLIENTID:
			if (!req_clientid)
				break;
			reply_clientid.len = req_clientid_len;
			iov[IOV_CLIENTID].iov_len = sizeof(reply_clientid);
			iov[IOV_CLIENTID_DATA].iov_base = req_clientid;
			iov[IOV_CLIENTID_DATA].iov_len = req_clientid_len;
			break;

		case DHCPV4_OPT_AUTHENTICATION:
			if (!lease || !reply_incl_fr || req_msg != DHCPV4_MSG_REQUEST)
				break;

			memcpy(reply_auth_body.key, lease->key, sizeof(reply_auth_body.key));
			reply_auth_body.replay[0] = htonl(time(NULL));
			reply_auth_body.replay[1] = htonl(++serial);
			iov[IOV_AUTH].iov_len = sizeof(reply_auth);
			iov[IOV_AUTH_BODY].iov_len = sizeof(reply_auth_body);
			break;

		case DHCPV4_OPT_DNS_DOMAIN_SEARCH:
			if (iov[IOV_SRCH_DOMAIN].iov_len || iface->dns_search_len > UINT8_MAX)
				break;

			if (iface->dns_search) {
				reply_srch_domain.len = iface->dns_search_len;
				iov[IOV_SRCH_DOMAIN].iov_len = sizeof(reply_srch_domain);
				iov[IOV_SRCH_DOMAIN_NAME].iov_base = iface->dns_search;
				iov[IOV_SRCH_DOMAIN_NAME].iov_len = iface->dns_search_len;
			} else if (!res_init() && _res.dnsrch[0] && _res.dnsrch[0][0]) {
				int dds_len;

				if (!iov[IOV_SRCH_DOMAIN_NAME].iov_base)
					iov[IOV_SRCH_DOMAIN_NAME].iov_base = alloca(DNS_MAX_NAME_LEN);

				dds_len = dn_comp(_res.dnsrch[0],
					      iov[IOV_SRCH_DOMAIN_NAME].iov_base,
					      DNS_MAX_NAME_LEN, NULL, NULL);
				if (dds_len < 0)
					break;

				reply_srch_domain.len = dds_len;
				iov[IOV_SRCH_DOMAIN].iov_len = sizeof(reply_srch_domain);
				iov[IOV_SRCH_DOMAIN_NAME].iov_len = dds_len;
			}
			break;

		case DHCPV4_OPT_FORCERENEW_NONCE_CAPABLE:
			if (!lease || !reply_incl_fr || req_msg == DHCPV4_MSG_REQUEST)
				break;

			iov[IOV_FR_NONCE_CAP].iov_len = sizeof(reply_fr_nonce_cap);
			break;

		case DHCPV4_OPT_DNR:
			struct dhcpv4_dnr *dnrs;
			size_t dnrs_len = 0;

			if (!lease || reply_dnr.len > 0)
				break;

			for (size_t j = 0; j < iface->dnr_cnt; j++) {
				struct dnr_options *dnr = &iface->dnr[j];

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

			for (size_t j = 0; j < iface->dnr_cnt; j++) {
				struct dnr_options *dnr = &iface->dnr[j];
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

		case DHCPV4_OPT_IPV6_ONLY_PREFERRED:
			if (iface->dhcpv4_v6only_wait)
				iov[IOV_IPV6_ONLY_PREF].iov_len = sizeof(reply_ipv6_only);
			break;

		case DHCPV4_OPT_CAPTIVE_PORTAL:
			size_t uri_len = iface->captive_portal_uri_len;
			if (uri_len == 0 || uri_len > UINT8_MAX)
				break;

			uint8_t *buf = alloca(2 + uri_len);
			struct dhcpv4_option *cp_opt = (struct dhcpv4_option *)buf;

			cp_opt->code = DHCPV4_OPT_CAPTIVE_PORTAL;
			cp_opt->len  = uri_len;
			memcpy(cp_opt->data, iface->captive_portal_uri, uri_len);

			iov[IOV_CAPTIVE_PORTAL].iov_base = cp_opt;
			iov[IOV_CAPTIVE_PORTAL].iov_len  = 2 + uri_len;
			break;
		}
	}

	if (lease)
		reply.yiaddr = lease->ipv4;

	memcpy(reply.chaddr, req->chaddr, sizeof(reply.chaddr));
	dhcpv4_set_dest_addr(iface, reply_msg.data, req, &reply, src_addr, &dest_addr);
	dhcpv4_add_padding(iov, ARRAY_SIZE(iov));

	if (send_reply(iov, ARRAY_SIZE(iov), (struct sockaddr *)&dest_addr, sizeof(dest_addr), opaque) < 0) {
		char ipv4_str[INET_ADDRSTRLEN];

		error("Failed to send %s to %s - %s: %m",
		      dhcpv4_msg_to_string(reply_msg.data),
		      dest_addr.sin_addr.s_addr == INADDR_BROADCAST ?
		      "ff:ff:ff:ff:ff:ff": odhcpd_print_mac(req->chaddr, req->hlen),
		      inet_ntop(AF_INET, &dest_addr.sin_addr, ipv4_str, sizeof(ipv4_str)));
	} else {
		char ipv4_str[INET_ADDRSTRLEN];

		error("Sent %s to %s - %s",
		      dhcpv4_msg_to_string(reply_msg.data),
		      dest_addr.sin_addr.s_addr == INADDR_BROADCAST ?
		      "ff:ff:ff:ff:ff:ff": odhcpd_print_mac(req->chaddr, req->hlen),
		      inet_ntop(AF_INET, &dest_addr.sin_addr, ipv4_str, sizeof(ipv4_str)));
	}

	if (reply_msg.data == DHCPV4_MSG_ACK && lease)
		ubus_bcast_dhcpv4_event("dhcp.lease4", iface->ifname, lease);
}

/* Handler for DHCPv4 messages */
static void dhcpv4_handle_dgram(void *addr, void *data, size_t len,
				struct interface *iface, _o_unused void *dest_addr)
{
	int sock = iface->dhcpv4_event.uloop.fd;

	dhcpv4_handle_msg(addr, data, len, iface, dest_addr, dhcpv4_send_reply, &sock);
}

static bool dhcpv4_setup_addresses(struct interface *iface)
{
	uint32_t pool_start = iface->dhcpv4_pool_start;
	uint32_t pool_end = iface->dhcpv4_pool_end;

	iface->dhcpv4_start_ip.s_addr = INADDR_ANY;
	iface->dhcpv4_end_ip.s_addr = INADDR_ANY;
	iface->dhcpv4_own_ip = (struct odhcpd_ipaddr){ .addr.in.s_addr = INADDR_ANY };

	if (iface->no_dynamic_dhcp) {
		if (!iface->oaddrs4_cnt)
			goto error;

		iface->dhcpv4_own_ip = iface->oaddrs4[0];
		info("DHCPv4: providing static leases on interface '%s'", iface->name);
		return true;
	}

	for (size_t i = 0; i < iface->oaddrs4_cnt; i++) {
		struct odhcpd_ipaddr *oaddr = &iface->oaddrs4[i];
		uint32_t hostmask = ntohl(~oaddr->netmask);
		char pool_start_str[INET_ADDRSTRLEN];
		char pool_end_str[INET_ADDRSTRLEN];

		if (oaddr->prefix_len > DHCPV4_MAX_PREFIX_LEN)
			continue;

		if (addr_is_fr_ip(iface, &oaddr->addr.in))
			continue;

		/* pool_start outside range? */
		if (pool_start && ((pool_start & hostmask) != pool_start))
			continue;

		/* pool_end outside range? */
		if (pool_end && ((pool_end & hostmask) != pool_end))
			continue;

		/* pool_end == broadcast? */
		if (pool_end && (pool_end == hostmask))
			continue;

		if (!pool_start || !pool_end) {
			switch (oaddr->prefix_len) {
			case 28:
				pool_start = 3;
				pool_end = 12;
				break;
			case 27:
				pool_start = 10;
				pool_end = 29;
				break;
			case 26:
				pool_start = 10;
				pool_end = 59;
				break;
			case 25:
				pool_start = 20;
				pool_end = 119;
				break;
			default: /* <= 24 */
				pool_start = 100;
				pool_end = 249;
				break;
			}
		}

		iface->dhcpv4_start_ip.s_addr = (oaddr->addr.in.s_addr & oaddr->netmask) | htonl(pool_start);
		iface->dhcpv4_end_ip.s_addr = (oaddr->addr.in.s_addr & oaddr->netmask) | htonl(pool_end);
		iface->dhcpv4_own_ip = *oaddr;

		info("DHCPv4: providing dynamic/static leases on interface '%s', pool: %s - %s", iface->name,
		     inet_ntop(AF_INET, &iface->dhcpv4_start_ip, pool_start_str, sizeof(pool_start_str)),
		     inet_ntop(AF_INET, &iface->dhcpv4_end_ip, pool_end_str, sizeof(pool_end_str)));
		return true;
	}

error:
	warn("DHCPv4: no suitable networks on interface '%s'", iface->name);
	return false;
}

struct dhcpv4_packet {
	struct udphdr udp;
	struct dhcpv4_message dhcp;
} _o_packed;

bool dhcpv4_setup_interface(struct interface *iface, bool enable)
{
	/* Note: we could check more things (but buggy clients exist), e.g.:
	 *  - DHCPV4_MIN_PACKET_SIZE
	 *  - yiaddr zero
	 *  - siaddr zero
	 */
	static const struct sock_filter filter[] = {
		BPF_STMT(BPF_LD + BPF_W + BPF_LEN, 0),						/* A <- packet length */
		BPF_JUMP(BPF_JMP + BPF_JGT + BPF_K,
			 offsetof(struct dhcpv4_packet, dhcp.options), 1, 0),			/* A > offsetof(dhcp.options)? */
		BPF_STMT(BPF_RET + BPF_K, 0),							/* false -> drop */

		BPF_STMT(BPF_LD + BPF_B + BPF_ABS, offsetof(struct dhcpv4_packet, dhcp.op)),	/* A <- dhcp.op */
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, DHCPV4_OP_BOOTREQUEST, 1, 0),		/* A == DHCPV4_OP_BOOTREQUEST? */
		BPF_STMT(BPF_RET + BPF_K, 0),							/* false -> drop */

		BPF_STMT(BPF_LD + BPF_B + BPF_ABS, offsetof(struct dhcpv4_packet, dhcp.htype)),	/* A <- dhcp.htype */
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARPHRD_ETHER, 1, 0),			/* A == ARPHRD_ETHER? */
		BPF_STMT(BPF_RET + BPF_K, 0),							/* false -> drop */

		BPF_STMT(BPF_LD + BPF_B + BPF_ABS, offsetof(struct dhcpv4_packet, dhcp.hlen)),	/* A <- dhcp.hlen */
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETH_ALEN, 1, 0),				/* A == ETH_ALEN? */
		BPF_STMT(BPF_RET + BPF_K, 0),							/* false -> drop */

		BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct dhcpv4_packet, dhcp.cookie)),/* A <- dhcp.cookie */
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, DHCPV4_MAGIC_COOKIE, 1, 0),			/* A == DHCPV4_MAGIC_COOKIE? */
		BPF_STMT(BPF_RET + BPF_K, 0),							/* false -> drop */

		BPF_STMT(BPF_RET + BPF_K, UINT32_MAX),						/* accept */
	};
	static const struct sock_fprog bpf = {
		.len = ARRAY_SIZE(filter),
		.filter = (struct sock_filter *)filter,
	};
	const struct sockaddr_in bind_addr = {
		.sin_family = AF_INET,
		.sin_port = htons(DHCPV4_SERVER_PORT),
		.sin_addr = { INADDR_ANY },
	};
	int val;
	int fd;

	if (iface->dhcpv4_event.uloop.fd >= 0) {
		uloop_fd_delete(&iface->dhcpv4_event.uloop);
		close(iface->dhcpv4_event.uloop.fd);
		iface->dhcpv4_event.uloop.fd = -1;
	}

	if (!enable || iface->dhcpv4 == MODE_DISABLED) {
		struct dhcpv4_lease *lease, *tmp;

		avl_remove_all_elements(&iface->dhcpv4_leases, lease, iface_avl, tmp)
			dhcpv4_free_lease(lease);
		return true;
	}

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
	if (fd < 0) {
		error("socket(AF_INET): %m");
		goto error;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0) {
		error("setsockopt(SO_ATTACH_FILTER): %m");
		goto error;
	}

	val = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0) {
		error("setsockopt(SO_REUSEADDR): %m");
		goto error;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &val, sizeof(val)) < 0) {
		error("setsockopt(SO_BROADCAST): %m");
		goto error;
	}

	if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &val, sizeof(val)) < 0) {
		error("setsockopt(IP_PKTINFO): %m");
		goto error;
	}

	val = IPTOS_CLASS_CS6;
	if (setsockopt(fd, IPPROTO_IP, IP_TOS, &val, sizeof(val)) < 0) {
		error("setsockopt(IP_TOS): %m");
		goto error;
	}

	val = IP_PMTUDISC_DONT;
	if (setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val)) < 0) {
		error("setsockopt(IP_MTU_DISCOVER): %m");
		goto error;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface->ifname,
		       strlen(iface->ifname)) < 0) {
		error("setsockopt(SO_BINDTODEVICE): %m");
		goto error;
	}

	if (bind(fd, (const struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
		error("bind(): %m");
		goto error;
	}

	if (!dhcpv4_setup_addresses(iface))
		goto error;

	iface->dhcpv4_event.uloop.fd = fd;
	iface->dhcpv4_event.handle_dgram = dhcpv4_handle_dgram;
	odhcpd_register(&iface->dhcpv4_event);
	return true;

error:
	close(fd);
	return false;
}

static void dhcpv4_addrlist_change(struct interface *iface)
{
	struct odhcpd_ipaddr ip = iface->dhcpv4_own_ip;
	struct odhcpd_ref_ip *a;
	struct dhcpv4_lease *lease;

	dhcpv4_setup_addresses(iface);

	if ((ip.addr.in.s_addr & ip.netmask) ==
	    (iface->dhcpv4_own_ip.addr.in.s_addr & iface->dhcpv4_own_ip.netmask))
		return;

	if (ip.addr.in.s_addr && !leases_require_fr(iface, &ip))
		return;

	if (iface->dhcpv4_own_ip.addr.in.s_addr == INADDR_ANY)
		return;

	if (list_empty(&iface->dhcpv4_fr_ips))
		return;

	a = list_first_entry(&iface->dhcpv4_fr_ips, struct odhcpd_ref_ip, head);

	if (netlink_setup_addr(&a->addr, iface->ifindex, false, true)) {
		warn("Failed to add ip address on %s", iface->name);
		return;
	}

	avl_for_each_element(&iface->dhcpv4_leases, lease, iface_avl) {
		if (lease->bound && lease->fr_ip && !lease->fr_cnt) {
			if (lease->accept_fr_nonce || iface->dhcpv4_forcereconf)
				dhcpv4_fr_rand_delay(lease);
			else
				dhcpv4_fr_stop(lease);
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
	bool update_statefile = false;

	avl_for_each_element(&interfaces, iface, avl) {
		struct dhcpv4_lease *lease, *tmp;

		if (iface->dhcpv4 != MODE_SERVER)
			continue;

		avl_for_each_element_safe(&iface->dhcpv4_leases, lease, iface_avl, tmp) {
			if (!INFINITE_VALID(lease->valid_until) && lease->valid_until < now) {
				ubus_bcast_dhcpv4_event("dhcp.expire4", iface->ifname, lease);
				dhcpv4_free_lease(lease);
				update_statefile = true;
			}
		}

		if (iface->update_statefile) {
			update_statefile = true;
			iface->update_statefile = false;
		}
	}

	if (update_statefile)
		statefiles_write();

	uloop_timeout_set(event, 5000);
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
