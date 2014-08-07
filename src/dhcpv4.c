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

#include "odhcpd.h"
#include "dhcpv4.h"
#include "dhcpv6.h"


static void handle_dhcpv4(void *addr, void *data, size_t len,
		struct interface *iface, void *dest_addr);
static struct dhcpv4_assignment* dhcpv4_lease(struct interface *iface,
		enum dhcpv4_msg msg, const uint8_t *mac, struct in_addr reqaddr,
		const char *hostname);

// Create socket and register events
int init_dhcpv4(void)
{
	return 0;
}


int setup_dhcpv4_interface(struct interface *iface, bool enable)
{
	if (iface->dhcpv4_event.uloop.fd > 0) {
		uloop_fd_delete(&iface->dhcpv4_event.uloop);
		close(iface->dhcpv4_event.uloop.fd);
		iface->dhcpv4_event.uloop.fd = -1;
	}

	if (iface->dhcpv4 && enable) {
		if (!iface->dhcpv4_assignments.next)
			INIT_LIST_HEAD(&iface->dhcpv4_assignments);

		int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
		if (sock < 0) {
			syslog(LOG_ERR, "Failed to create DHCPv4 server socket: %s",
					strerror(errno));
			return -1;
		}

		// Basic IPv6 configuration
		int val = 1;
		setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
		setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &val, sizeof(val));
		setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &val, sizeof(val));

		val = IPTOS_PREC_INTERNETCONTROL;
		setsockopt(sock, IPPROTO_IP, IP_TOS, &val, sizeof(val));

		val = IP_PMTUDISC_DONT;
		setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val));

		setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE,
				iface->ifname, strlen(iface->ifname));

		struct sockaddr_in bind_addr = {AF_INET, htons(DHCPV4_SERVER_PORT),
					{INADDR_ANY}, {0}};

		if (bind(sock, (struct sockaddr*)&bind_addr, sizeof(bind_addr))) {
			syslog(LOG_ERR, "Failed to open DHCPv4 server socket: %s",
					strerror(errno));
			return -1;
		}


		if (ntohl(iface->dhcpv4_start.s_addr) > ntohl(iface->dhcpv4_end.s_addr)) {
			syslog(LOG_ERR, "Invalid DHCP range");
			return -1;
		}

		// Create a range if not specified
		struct ifreq ifreq;
		strncpy(ifreq.ifr_name, iface->ifname, sizeof(ifreq.ifr_name));

		struct sockaddr_in *saddr = (struct sockaddr_in*)&ifreq.ifr_addr;
		struct sockaddr_in *smask = (struct sockaddr_in*)&ifreq.ifr_netmask;
		if (!(iface->dhcpv4_start.s_addr & htonl(0xffff0000)) &&
				!(iface->dhcpv4_end.s_addr & htonl(0xffff0000)) &&
				!ioctl(sock, SIOCGIFADDR, &ifreq)) {
			struct in_addr addr = saddr->sin_addr;

			ioctl(sock, SIOCGIFNETMASK, &ifreq);
			struct in_addr mask = smask->sin_addr;

			uint32_t start = ntohl(iface->dhcpv4_start.s_addr);
			uint32_t end = ntohl(iface->dhcpv4_end.s_addr);

			if (start && end && start < end &&
					start > ntohl(addr.s_addr & ~mask.s_addr) &&
					(start & ntohl(mask.s_addr)) == start &&
					(end & ntohl(mask.s_addr)) == end) {
				iface->dhcpv4_start.s_addr = htonl(start) |
						(addr.s_addr & mask.s_addr);
				iface->dhcpv4_end.s_addr = htonl(end) |
						(addr.s_addr & mask.s_addr);
			} else if (ntohl(mask.s_addr) <= 0xfffffff0) {
				start = addr.s_addr & mask.s_addr;
				end = addr.s_addr & mask.s_addr;

				if (ntohl(mask.s_addr) <= 0xffffff00) {
					iface->dhcpv4_start.s_addr = start | htonl(100);
					iface->dhcpv4_end.s_addr = end | htonl(250);
				} else if (ntohl(mask.s_addr) <= 0xffffffc0) {
					iface->dhcpv4_start.s_addr = start | htonl(10);
					iface->dhcpv4_end.s_addr = end | htonl(60);
				} else if (ntohl(mask.s_addr) <= 0xffffffe0) {
					iface->dhcpv4_start.s_addr = start | htonl(10);
					iface->dhcpv4_end.s_addr = end | htonl(30);
				} else {
					iface->dhcpv4_start.s_addr = start | htonl(3);
					iface->dhcpv4_end.s_addr = end | htonl(12);
				}
			}


		}

		// Parse static entries
		struct lease *lease;
		list_for_each_entry(lease, &leases, head) {
			// Construct entry
			size_t hostlen = strlen(lease->hostname) + 1;
			struct dhcpv4_assignment *a = calloc(1, sizeof(*a) + hostlen);
			if (!a) {
				syslog(LOG_ERR, "Calloc failed for static lease on interface %s",
					iface->ifname);
				return -1;
			}
			a->addr = ntohl(lease->ipaddr.s_addr);
			memcpy(a->hwaddr, lease->mac.ether_addr_octet, sizeof(a->hwaddr));
			memcpy(a->hostname, lease->hostname, hostlen);
			a->valid_until = LONG_MAX;

			// Assign to all interfaces
			struct dhcpv4_assignment *c;
			list_for_each_entry(c, &iface->dhcpv4_assignments, head) {
				if (c->addr > a->addr) {
					list_add_tail(&a->head, &c->head);
					break;
				} else if (c->addr == a->addr) {
					// Already an assignment with that number
					break;
				}
			}
			if (&c->head == &iface->dhcpv4_assignments) {
				list_add(&a->head, &iface->dhcpv4_assignments);
			}

			if (!a->head.next)
				free(a);
		}

		// Clean invalid assignments
		struct dhcpv4_assignment *a, *n;
		list_for_each_entry_safe(a, n, &iface->dhcpv4_assignments, head) {
			if ((htonl(a->addr) & smask->sin_addr.s_addr) !=
					(iface->dhcpv4_start.s_addr & smask->sin_addr.s_addr)) {
				list_del(&a->head);
				free(a);
			}
		}


		if (iface->dhcpv4_leasetime < 60)
			iface->dhcpv4_leasetime = 43200;

		iface->dhcpv4_event.uloop.fd = sock;
		iface->dhcpv4_event.handle_dgram = handle_dhcpv4;
		odhcpd_register(&iface->dhcpv4_event);
	} else if (iface->dhcpv4_assignments.next) {
		while (!list_empty(&iface->dhcpv4_assignments)) {
			struct dhcpv4_assignment *a = list_first_entry(&iface->dhcpv4_assignments,
					struct dhcpv4_assignment, head);
			list_del(&a->head);
			free(a->hostname);
			free(a);
		}

	}
	return 0;
}


static void dhcpv4_put(struct dhcpv4_message *msg, uint8_t **cookie,
		uint8_t type, uint8_t len, const void *data)
{
	uint8_t *c = *cookie;
	if (*cookie + 2 + len > (uint8_t*)&msg[1])
		return;

	*c++ = type;
	*c++ = len;
	memcpy(c, data, len);

	*cookie = c + len;
}


// Simple DHCPv6-server for information requests
static void handle_dhcpv4(void *addr, void *data, size_t len,
		struct interface *iface, _unused void *dest_addr)
{
	if (!iface->dhcpv4)
		return;

	struct dhcpv4_message *req = data;
	if (len < offsetof(struct dhcpv4_message, options) + 4 ||
			req->op != DHCPV4_BOOTREQUEST || req->hlen != 6)
		return;

	int sock = iface->dhcpv4_event.uloop.fd;
	struct sockaddr_in ifaddr;
	struct sockaddr_in ifnetmask;

	syslog(LOG_NOTICE, "Got DHCPv4 request");

	struct ifreq ifreq;
	memcpy(ifreq.ifr_name, iface->ifname, sizeof(ifreq.ifr_name));
	if (ioctl(sock, SIOCGIFADDR, &ifreq)) {
		syslog(LOG_WARNING, "DHCPv4 failed to detect address: %s", strerror(errno));
		return;
	}

	memcpy(&ifaddr, &ifreq.ifr_addr, sizeof(ifaddr));
	if (ioctl(sock, SIOCGIFNETMASK, &ifreq))
		return;

	memcpy(&ifnetmask, &ifreq.ifr_netmask, sizeof(ifnetmask));
	uint32_t network = ifaddr.sin_addr.s_addr & ifnetmask.sin_addr.s_addr;

	if ((iface->dhcpv4_start.s_addr & ifnetmask.sin_addr.s_addr) != network ||
			(iface->dhcpv4_end.s_addr & ifnetmask.sin_addr.s_addr) != network) {
		syslog(LOG_WARNING, "DHCPv4 range out of assigned network");
		return;
	}

	struct ifreq ifr = {.ifr_name = ""};
	strncpy(ifr.ifr_name, iface->ifname, sizeof(ifr.ifr_name));

	struct dhcpv4_message reply = {
		.op = DHCPV4_BOOTREPLY,
		.htype = 1,
		.hlen = 6,
		.hops = 0,
		.xid = req->xid,
		.secs = 0,
		.flags = req->flags,
		.ciaddr = {INADDR_ANY},
		.giaddr = req->giaddr,
		.siaddr = ifaddr.sin_addr,
	};
	memcpy(reply.chaddr, req->chaddr, sizeof(reply.chaddr));

	reply.options[0] = 0x63;
	reply.options[1] = 0x82;
	reply.options[2] = 0x53;
	reply.options[3] = 0x63;

	uint8_t *cookie = &reply.options[4];
	uint8_t reqmsg = DHCPV4_MSG_REQUEST;
	uint8_t msg = DHCPV4_MSG_ACK;

	struct in_addr reqaddr = {INADDR_ANY};
	char hostname[256];
	hostname[0] = 0;

	uint8_t *start = &req->options[4];
	uint8_t *end = ((uint8_t*)data) + len;
	struct dhcpv4_option *opt;
	dhcpv4_for_each_option(start, end, opt) {
		if (opt->type == DHCPV4_OPT_MESSAGE && opt->len == 1) {
			reqmsg = opt->data[0];
		} else if (opt->type == DHCPV4_OPT_HOSTNAME && opt->len > 0) {
			memcpy(hostname, opt->data, opt->len);
			hostname[opt->len] = 0;
		} else if (opt->type == DHCPV4_OPT_IPADDRESS && opt->len == 4) {
			memcpy(&reqaddr, opt->data, 4);
		} else if (opt->type == DHCPV4_OPT_SERVERID && opt->len == 4) {
			if (memcmp(opt->data, &ifaddr.sin_addr, 4))
				return;
		} else if (iface->filter_class && opt->type == DHCPV4_OPT_USER_CLASS) {
			uint8_t *c = opt->data, *cend = &opt->data[opt->len];
			for (; c < cend && &c[*c] < cend; c = &c[1 + *c]) {
				size_t elen = strlen(iface->filter_class);
				if (*c == elen && !memcmp(&c[1], iface->filter_class, elen))
					return; // Ignore from homenet
			}
		}
	}

	if (reqmsg != DHCPV4_MSG_DISCOVER && reqmsg != DHCPV4_MSG_REQUEST &&
			reqmsg != DHCPV4_MSG_INFORM && reqmsg != DHCPV4_MSG_DECLINE &&
			reqmsg != DHCPV4_MSG_RELEASE)
		return;

	struct dhcpv4_assignment *lease = NULL;
	if (reqmsg != DHCPV4_MSG_INFORM)
		lease = dhcpv4_lease(iface, reqmsg, req->chaddr, reqaddr, hostname);

	if (!lease) {
		if (reqmsg == DHCPV4_MSG_REQUEST)
			msg = DHCPV4_MSG_NAK;
		else if (reqmsg == DHCPV4_MSG_DISCOVER)
			return;
	} else if (reqmsg == DHCPV4_MSG_DISCOVER) {
		msg = DHCPV4_MSG_OFFER;
	} else if (reqmsg == DHCPV4_MSG_REQUEST && reqaddr.s_addr &&
			reqaddr.s_addr != htonl(lease->addr)) {
		msg = DHCPV4_MSG_NAK;
		lease = NULL;
	}

	if (reqmsg == DHCPV4_MSG_DECLINE || reqmsg == DHCPV4_MSG_RELEASE)
		return;

	dhcpv4_put(&reply, &cookie, DHCPV4_OPT_MESSAGE, 1, &msg);
	dhcpv4_put(&reply, &cookie, DHCPV4_OPT_SERVERID, 4, &ifaddr.sin_addr);

	if (lease) {
		reply.yiaddr.s_addr = htonl(lease->addr);

		uint32_t val = htonl(iface->dhcpv4_leasetime);
		dhcpv4_put(&reply, &cookie, DHCPV4_OPT_LEASETIME, 4, &val);

		val = htonl(500 * iface->dhcpv4_leasetime / 1000);
		dhcpv4_put(&reply, &cookie, DHCPV4_OPT_RENEW, 4, &val);

		val = htonl(875 * iface->dhcpv4_leasetime / 1000);
		dhcpv4_put(&reply, &cookie, DHCPV4_OPT_REBIND, 4, &val);

		dhcpv4_put(&reply, &cookie, DHCPV4_OPT_NETMASK, 4, &ifnetmask.sin_addr);

		if (lease->hostname[0])
			dhcpv4_put(&reply, &cookie, DHCPV4_OPT_HOSTNAME,
					strlen(lease->hostname), lease->hostname);

		if (!ioctl(sock, SIOCGIFBRDADDR, &ifr)) {
			struct sockaddr_in *ina = (struct sockaddr_in*)&ifr.ifr_broadaddr;
			dhcpv4_put(&reply, &cookie, DHCPV4_OPT_BROADCAST, 4, &ina->sin_addr);
		}
	}

	if (!ioctl(sock, SIOCGIFMTU, &ifr)) {
		uint16_t mtu = htons(ifr.ifr_mtu);
		dhcpv4_put(&reply, &cookie, DHCPV4_OPT_MTU, 2, &mtu);
	}

	if (iface->search && iface->search_len <= 255) {
		dhcpv4_put(&reply, &cookie, DHCPV4_OPT_SEARCH_DOMAIN,
				iface->search_len, iface->search);
	} else if (!res_init() && _res.dnsrch[0] && _res.dnsrch[0][0]) {
		uint8_t search_buf[256];
		int len = dn_comp(_res.dnsrch[0], search_buf,
						sizeof(search_buf), NULL, NULL);
		if (len > 0)
			dhcpv4_put(&reply, &cookie, DHCPV4_OPT_SEARCH_DOMAIN,
					len, search_buf);
	}

	dhcpv4_put(&reply, &cookie, DHCPV4_OPT_ROUTER, 4, &ifaddr.sin_addr);



	if (iface->dhcpv4_dns_cnt == 0)
		dhcpv4_put(&reply, &cookie, DHCPV4_OPT_DNSSERVER, 4, &ifaddr.sin_addr);
	else
		dhcpv4_put(&reply, &cookie, DHCPV4_OPT_DNSSERVER,
				4 * iface->dhcpv4_dns_cnt, iface->dhcpv4_dns);


	dhcpv4_put(&reply, &cookie, DHCPV4_OPT_END, 0, NULL);

	struct sockaddr_in dest = *((struct sockaddr_in*)addr);
	if (req->giaddr.s_addr) {
		dest.sin_addr = req->giaddr;
		dest.sin_port = htons(DHCPV4_SERVER_PORT);
	} else if (req->ciaddr.s_addr && req->ciaddr.s_addr != dest.sin_addr.s_addr) {
		dest.sin_addr = req->ciaddr;
		dest.sin_port = htons(DHCPV4_CLIENT_PORT);
	} else if ((ntohs(req->flags) & DHCPV4_FLAG_BROADCAST) ||
			req->hlen != reply.hlen || !reply.yiaddr.s_addr) {
		dest.sin_addr.s_addr = INADDR_BROADCAST;
		dest.sin_port = htons(DHCPV4_CLIENT_PORT);
	} else {
		dest.sin_addr = reply.yiaddr;
		dest.sin_port = htons(DHCPV4_CLIENT_PORT);

		struct arpreq arp = {.arp_flags = ATF_COM};
		memcpy(arp.arp_ha.sa_data, req->chaddr, 6);
		memcpy(&arp.arp_pa, &dest, sizeof(arp.arp_pa));
		memcpy(arp.arp_dev, iface->ifname, sizeof(arp.arp_dev));
		ioctl(sock, SIOCSARP, &arp);
	}

	sendto(sock, &reply, sizeof(reply), MSG_DONTWAIT,
			(struct sockaddr*)&dest, sizeof(dest));
}


static bool dhcpv4_assign(struct interface *iface,
		struct dhcpv4_assignment *assign, uint32_t raddr)
{
	const unsigned tries = 10;
	uint32_t start = ntohl(iface->dhcpv4_start.s_addr);
	uint32_t end = ntohl(iface->dhcpv4_end.s_addr);
	uint32_t count = end - start + 1;

	// Seed RNG with checksum of DUID
	uint32_t seed = 0;
	for (size_t i = 0; i < sizeof(assign->hwaddr); ++i)
		seed += assign->hwaddr[i];
	srand(seed);

	// Try to assign up to 100x
	for (unsigned i = 0; i < tries; ++i) {
		uint32_t try = (((uint32_t)rand()) % count) + start;
		if (i == 0 && raddr >= start && raddr <= end)
			try = raddr;
		else if (i == tries - 1)
			try = start;

		if (list_empty(&iface->dhcpv4_assignments)) {
			assign->addr = try;
			list_add(&assign->head, &iface->dhcpv4_assignments);
			return true;
		}

		struct dhcpv4_assignment *c;
		list_for_each_entry(c, &iface->dhcpv4_assignments, head) {
			if (c->addr > try) {
				assign->addr = try;
				list_add_tail(&assign->head, &c->head);
				return true;
			} else if (c->addr == try) {
				if (i < tries - 1)
					break;
				else
					++try;
			}
		}
	}

	return false;
}


static struct dhcpv4_assignment* dhcpv4_lease(struct interface *iface,
		enum dhcpv4_msg msg, const uint8_t *mac, struct in_addr reqaddr,
		const char *hostname)
{
	struct dhcpv4_assignment *lease = NULL;
	uint32_t raddr = ntohl(reqaddr.s_addr);
	time_t now = odhcpd_time();

	struct dhcpv4_assignment *c, *n, *a = NULL;
	list_for_each_entry_safe(c, n, &iface->dhcpv4_assignments, head) {
		if (!memcmp(c->hwaddr, mac, 6)) {
			a = c;
			if (c->addr == raddr)
				break;
		} else if (c->valid_until < now) {
			list_del(&c->head);
			free(c);
		}
	}

	if (msg == DHCPV4_MSG_DISCOVER || msg == DHCPV4_MSG_REQUEST) {
		bool assigned = !!a;
		size_t hostlen = strlen(hostname) + 1;

		if (!a && !iface->no_dynamic_dhcp) { // Create new binding
			a = calloc(1, sizeof(*a) + hostlen);
			if (!a) {
				syslog(LOG_ERR, "Failed to calloc binding on interface %s", iface->ifname);
				return NULL;
			}
			memcpy(a->hwaddr, mac, sizeof(a->hwaddr));
			memcpy(a->hostname, hostname, hostlen);

			assigned = dhcpv4_assign(iface, a, raddr);
		}

		if (assigned && !a->hostname[0] && hostname) {
			a = realloc(a, sizeof(*a) + hostlen);
			if (!a) {
				syslog(LOG_ERR, "Failed to realloc binding on interface %s", iface->ifname);
				return NULL;
			}
			memcpy(a->hostname, hostname, hostlen);

			// Fixup list
			a->head.next->prev = &a->head;
			a->head.prev->next = &a->head;
		}

		// Was only a solicitation: mark binding for removal
		if (assigned && a->valid_until < now) {
			a->valid_until = (msg == DHCPV4_MSG_DISCOVER) ? 0 :
					(now + iface->dhcpv4_leasetime);
		} else if (!assigned && a) { // Cleanup failed assignment
			free(a);
			a = NULL;
		}

		if (assigned && a)
			lease = a;
	} else if (msg == DHCPV4_MSG_RELEASE) {
		if (a) {
			a->valid_until = 0;
		}
	} else if (msg == DHCPV4_MSG_DECLINE) {
		memset(a->hwaddr, 0, sizeof(a->hwaddr));
		a->valid_until = now + 3600; // Block address for 1h
	}

	dhcpv6_write_statefile();

	return lease;
}

