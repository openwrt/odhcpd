/**
 * Copyright (C) 2013 Steven Barth <steven@midlink.org>
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
 */

#include "odhcpd.h"
#include "dhcpv6.h"
#include "dhcpv4.h"
#include "libubox/md5.h"
#include "libubox/usock.h"

#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <poll.h>
#include <alloca.h>
#include <resolv.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/timerfd.h>

#define ADDR_ENTRY_VALID_IA_ADDR(iface, i, m, addrs) \
    ((iface)->managed == RELAYD_MANAGED_NO_AFLAG || (i) == (m) || \
     (addrs)[(i)].prefix > 64)

static void free_dhcpv6_assignment(struct dhcpv6_assignment *c);
static void reconf_timer(struct uloop_timeout *event);
static struct uloop_timeout reconf_event = {.cb = reconf_timer};
static uint32_t serial = 0;
static uint8_t statemd5[16];

int dhcpv6_ia_init(void)
{
	uloop_timeout_set(&reconf_event, 2000);
	return 0;
}

int setup_dhcpv6_ia_interface(struct interface *iface, bool enable)
{
	if (!enable && iface->ia_assignments.next) {
		struct dhcpv6_assignment *c;

		while (!list_empty(&iface->ia_assignments)) {
			c = list_first_entry(&iface->ia_assignments, struct dhcpv6_assignment, head);
			free_dhcpv6_assignment(c);
		}
	}

	if (enable && iface->dhcpv6 == RELAYD_SERVER) {
		if (!iface->ia_assignments.next)
			INIT_LIST_HEAD(&iface->ia_assignments);

		if (list_empty(&iface->ia_assignments)) {
			struct dhcpv6_assignment *border = calloc(1, sizeof(*border));
			if (!border) {
				syslog(LOG_ERR, "Calloc failed for border on interface %s", iface->ifname);
				return -1;
			}

			border->length = 64;
			list_add(&border->head, &iface->ia_assignments);
		}

		/* Parse static entries */
		struct lease *lease;
		list_for_each_entry(lease, &leases, head) {
			/* Construct entry */
			size_t duid_len = lease->duid_len ? lease->duid_len : 14;
			struct dhcpv6_assignment *a = calloc(1, sizeof(*a) + duid_len);
			if (!a) {
				syslog(LOG_ERR, "Calloc failed for static lease assignment on interface %s",
					iface->ifname);
				return -1;
			}

			if (lease->dhcpv4_leasetime > 0)
				a->leasetime = lease->dhcpv4_leasetime;

			a->clid_len = duid_len;
			a->length = 128;
			if (lease->hostid) {
				a->assigned = lease->hostid;
			} else {
				uint32_t i4a = ntohl(lease->ipaddr.s_addr) & 0xff;
				a->assigned = ((i4a / 100) << 8) | (((i4a % 100) / 10) << 4) | (i4a % 10);
			}

			odhcpd_urandom(a->key, sizeof(a->key));
			memcpy(a->clid_data, lease->duid, lease->duid_len);
			memcpy(a->mac, lease->mac.ether_addr_octet, sizeof(a->mac));
			/* Static assignment */
			a->flags |= OAF_STATIC;
			/* Infinite valid */
			a->valid_until = 0;

			/* Assign to all interfaces */
			struct dhcpv6_assignment *c;
			list_for_each_entry(c, &iface->ia_assignments, head) {
				if (c->length != 128 || c->assigned > a->assigned) {
					list_add_tail(&a->head, &c->head);
					break;
				} else if (c->assigned == a->assigned)
					/* Already an assignment with that number */
					break;
			}

			if (a->head.next) {
				if (lease->hostname[0]) {
					free(a->hostname);
					a->hostname = strdup(lease->hostname);
				}
			} else
				free_dhcpv6_assignment(a);
		}
	}
	return 0;
}

static void free_dhcpv6_assignment(struct dhcpv6_assignment *c)
{
	if (c->managed_sock.fd.registered) {
		ustream_free(&c->managed_sock.stream);
		close(c->managed_sock.fd.fd);
	}

	if (c->head.next)
		list_del(&c->head);

	free(c->managed);
	free(c->hostname);
	free(c);
}

static inline bool valid_addr(const struct odhcpd_ipaddr *addr, time_t now)
{
	return (addr->prefix <= 96 && addr->preferred > (uint32_t)now);
}

static size_t elect_addr(const struct odhcpd_ipaddr *addrs, const size_t addrlen)
{
	size_t i, m;

	for (i = 0, m = 0; i < addrlen; ++i) {
		if (addrs[i].preferred > addrs[m].preferred ||
			(addrs[i].preferred == addrs[m].preferred &&
			 memcmp(&addrs[i].addr, &addrs[m].addr, 16) > 0))
			m = i;
	}

	return m;
}

static int send_reconf(struct interface *iface, struct dhcpv6_assignment *assign)
{
	struct {
		struct dhcpv6_client_header hdr;
		uint16_t srvid_type;
		uint16_t srvid_len;
		uint16_t duid_type;
		uint16_t hardware_type;
		uint8_t mac[6];
		uint16_t msg_type;
		uint16_t msg_len;
		uint8_t msg_id;
		struct dhcpv6_auth_reconfigure auth;
		uint16_t clid_type;
		uint16_t clid_len;
		uint8_t clid_data[128];
	} __attribute__((packed)) reconf_msg = {
		.hdr = {DHCPV6_MSG_RECONFIGURE, {0, 0, 0}},
		.srvid_type = htons(DHCPV6_OPT_SERVERID),
		.srvid_len = htons(10),
		.duid_type = htons(3),
		.hardware_type = htons(1),
		.msg_type = htons(DHCPV6_OPT_RECONF_MSG),
		.msg_len = htons(1),
		.msg_id = DHCPV6_MSG_RENEW,
		.auth = {htons(DHCPV6_OPT_AUTH),
				htons(sizeof(reconf_msg.auth) - 4), 3, 1, 0,
				{htonl(time(NULL)), htonl(++serial)}, 2, {0}},
		.clid_type = htons(DHCPV6_OPT_CLIENTID),
		.clid_len = htons(assign->clid_len),
		.clid_data = {0},
	};

	odhcpd_get_mac(iface, reconf_msg.mac);
	memcpy(reconf_msg.clid_data, assign->clid_data, assign->clid_len);
	struct iovec iov = {&reconf_msg, sizeof(reconf_msg) - 128 + assign->clid_len};

	md5_ctx_t md5;
	uint8_t secretbytes[64];
	memset(secretbytes, 0, sizeof(secretbytes));
	memcpy(secretbytes, assign->key, sizeof(assign->key));

	for (size_t i = 0; i < sizeof(secretbytes); ++i)
		secretbytes[i] ^= 0x36;

	md5_begin(&md5);
	md5_hash(secretbytes, sizeof(secretbytes), &md5);
	md5_hash(iov.iov_base, iov.iov_len, &md5);
	md5_end(reconf_msg.auth.key, &md5);

	for (size_t i = 0; i < sizeof(secretbytes); ++i) {
		secretbytes[i] ^= 0x36;
		secretbytes[i] ^= 0x5c;
	}

	md5_begin(&md5);
	md5_hash(secretbytes, sizeof(secretbytes), &md5);
	md5_hash(reconf_msg.auth.key, 16, &md5);
	md5_end(reconf_msg.auth.key, &md5);

	return odhcpd_send(iface->dhcpv6_event.uloop.fd, &assign->peer, &iov, 1, iface);
}

void dhcpv6_write_statefile(void)
{
	md5_ctx_t md5;
	md5_begin(&md5);

	if (config.dhcp_statefile) {
		time_t now = odhcpd_time(), wall_time = time(NULL);
		int fd = open(config.dhcp_statefile, O_CREAT | O_WRONLY | O_CLOEXEC, 0644);
		if (fd < 0)
			return;

		lockf(fd, F_LOCK, 0);
		if (ftruncate(fd, 0) < 0) {}

		FILE *fp = fdopen(fd, "w");
		if (!fp) {
			close(fd);
			return;
		}

		struct interface *iface;
		list_for_each_entry(iface, &interfaces, head) {
			if (iface->dhcpv6 != RELAYD_SERVER && iface->dhcpv4 != RELAYD_SERVER)
				continue;

			if (iface->dhcpv6 == RELAYD_SERVER && iface->ia_assignments.next) {
				struct dhcpv6_assignment *c;
				list_for_each_entry(c, &iface->ia_assignments, head) {
					if (!(c->flags & OAF_BOUND) || c->managed_size < 0)
						continue;

					char ipbuf[INET6_ADDRSTRLEN];
					char leasebuf[512];
					char duidbuf[264];
					odhcpd_hexlify(duidbuf, c->clid_data, c->clid_len);

					/* iface DUID iaid hostname lifetime assigned length [addrs...] */
					int l = snprintf(leasebuf, sizeof(leasebuf), "# %s %s %x %s %ld %x %u ",
							iface->ifname, duidbuf, ntohl(c->iaid),
							(c->hostname ? c->hostname : "-"),
							(c->valid_until > now ?
								(c->valid_until - now + wall_time) :
								(INFINITE_VALID(c->valid_until) ? -1 : 0)),
							c->assigned, (unsigned)c->length);

					struct in6_addr addr;
					struct odhcpd_ipaddr *addrs = (c->managed) ? c->managed : iface->ia_addr;
					size_t addrlen = (c->managed) ? (size_t)c->managed_size : iface->ia_addr_len;
					size_t m = elect_addr(addrs, addrlen);

					for (size_t i = 0; i < addrlen; ++i) {
						if (!valid_addr(&addrs[i], now) ||
							    (!INFINITE_VALID(c->valid_until) && c->valid_until <= now) ||
							    !ADDR_ENTRY_VALID_IA_ADDR(iface, i, m, addrs))
							continue;

						addr = addrs[i].addr;
						if (c->length == 128)
							addr.s6_addr32[3] = htonl(c->assigned);
						else
							addr.s6_addr32[1] |= htonl(c->assigned);

						inet_ntop(AF_INET6, &addr, ipbuf, sizeof(ipbuf) - 1);

						if (c->length == 128 && c->hostname) {
							fputs(ipbuf, fp);

							char b[256];
							if (dn_expand(iface->search, iface->search + iface->search_len,
									iface->search, b, sizeof(b)) > 0)
								fprintf(fp, "\t%s.%s", c->hostname, b);

							fprintf(fp, "\t%s\n", c->hostname);
							md5_hash(ipbuf, strlen(ipbuf), &md5);
							md5_hash(c->hostname, strlen(c->hostname), &md5);
						}

						l += snprintf(leasebuf + l, sizeof(leasebuf) - l, "%s/%d ", ipbuf,
								(c->managed_size) ? addrs[i].prefix : c->length);
					}
					leasebuf[l - 1] = '\n';
					fwrite(leasebuf, 1, l, fp);
				}
			}

			if (iface->dhcpv4 == RELAYD_SERVER && iface->dhcpv4_assignments.next) {
				struct dhcpv4_assignment *c;
				list_for_each_entry(c, &iface->dhcpv4_assignments, head) {
					if (!(c->flags & OAF_BOUND))
						continue;

					char ipbuf[INET6_ADDRSTRLEN];
					char leasebuf[512];
					char duidbuf[16];
					odhcpd_hexlify(duidbuf, c->hwaddr, sizeof(c->hwaddr));

					/* iface DUID iaid hostname lifetime assigned length [addrs...] */
					int l = snprintf(leasebuf, sizeof(leasebuf), "# %s %s ipv4 %s %ld %x 32 ",
							iface->ifname, duidbuf,
							(c->hostname ? c->hostname : "-"),
							(c->valid_until > now ?
								(c->valid_until - now + wall_time) :
								(INFINITE_VALID(c->valid_until) ? -1 : 0)),
							c->addr);

					struct in_addr addr = {htonl(c->addr)};
					inet_ntop(AF_INET, &addr, ipbuf, sizeof(ipbuf) - 1);

					if (c->hostname) {
						fputs(ipbuf, fp);

						char b[256];
						if (dn_expand(iface->search, iface->search + iface->search_len,
								iface->search, b, sizeof(b)) > 0)
							fprintf(fp, "\t%s.%s", c->hostname, b);

						fprintf(fp, "\t%s\n", c->hostname);
						md5_hash(ipbuf, strlen(ipbuf), &md5);
						md5_hash(c->hostname, strlen(c->hostname), &md5);
					}

					l += snprintf(leasebuf + l, sizeof(leasebuf) - l, "%s/32 ", ipbuf);
					leasebuf[l - 1] = '\n';
					fwrite(leasebuf, 1, l, fp);
				}
			}
		}

		fclose(fp);
	}

	uint8_t newmd5[16];
	md5_end(newmd5, &md5);

	if (config.dhcp_cb && memcmp(newmd5, statemd5, sizeof(newmd5))) {
		memcpy(statemd5, newmd5, sizeof(statemd5));
		char *argv[2] = {config.dhcp_cb, NULL};
		if (!vfork()) {
			execv(argv[0], argv);
			_exit(128);
		}
	}
}


static void apply_lease(struct interface *iface, struct dhcpv6_assignment *a, bool add)
{
	if (a->length > 64 || a->managed_size < 0)
		return;

	struct odhcpd_ipaddr *addrs = (a->managed) ? a->managed : iface->ia_addr;
	size_t addrlen = (a->managed) ? (size_t)a->managed_size : iface->ia_addr_len;

	for (size_t i = 0; i < addrlen; ++i) {
		struct in6_addr prefix = addrs[i].addr;
		prefix.s6_addr32[1] |= htonl(a->assigned);
		odhcpd_setup_route(&prefix, (a->managed_size) ? addrs[i].prefix : a->length,
				iface, &a->peer.sin6_addr, 1024, add);
	}
}

/* More data was received from TCP connection */
static void managed_handle_pd_data(struct ustream *s, _unused int bytes_new)
{
	struct dhcpv6_assignment *c = container_of(s, struct dhcpv6_assignment, managed_sock);
	time_t now = odhcpd_time();
	bool first = c->managed_size < 0;

	for (;;) {
		int pending;
		char *data = ustream_get_read_buf(s, &pending);
		char *end = memmem(data, pending, "\n\n", 2);

		if (!end)
			break;

		end += 2;
		end[-1] = 0;

		c->managed_size = 0;
		if (c->accept_reconf)
			c->reconf_cnt = 1;

		char *saveptr;
		for (char *line = strtok_r(data, "\n", &saveptr); line; line = strtok_r(NULL, "\n", &saveptr)) {
			c->managed = realloc(c->managed, (c->managed_size + 1) * sizeof(*c->managed));
			struct odhcpd_ipaddr *n = &c->managed[c->managed_size];

			char *saveptr2, *x = strtok_r(line, "/", &saveptr2);
			if (!x || inet_pton(AF_INET6, x, &n->addr) < 1)
				continue;

			x = strtok_r(NULL, ",", &saveptr2);
			if (sscanf(x, "%hhu", &n->prefix) < 1)
				continue;

			x = strtok_r(NULL, ",", &saveptr2);
			if (sscanf(x, "%u", &n->preferred) < 1)
				continue;

			x = strtok_r(NULL, ",", &saveptr2);
			if (sscanf(x, "%u", &n->valid) < 1)
				continue;

			if (n->preferred > n->valid)
				continue;

			if (UINT32_MAX - now < n->preferred)
				n->preferred = UINT32_MAX;
			else
				n->preferred += now;

			if (UINT32_MAX - now < n->valid)
				n->valid = UINT32_MAX;
			else
				n->valid += now;

			n->dprefix = 0;

			++c->managed_size;
		}

		ustream_consume(s, end - data);
	}

	if (first && c->managed_size == 0)
		free_dhcpv6_assignment(c);
	else if (first && !(c->flags & OAF_STATIC))
		c->valid_until = now + 150;
}


/* TCP transmission has ended, either because of success or timeout or other error */
static void managed_handle_pd_done(struct ustream *s)
{
	struct dhcpv6_assignment *c = container_of(s, struct dhcpv6_assignment, managed_sock);

	if (!(c->flags & OAF_STATIC))
		c->valid_until = odhcpd_time() + 15;

	c->managed_size = 0;

	if (c->accept_reconf)
		c->reconf_cnt = 1;
}

static bool assign_pd(struct interface *iface, struct dhcpv6_assignment *assign)
{
	struct dhcpv6_assignment *c;

	if (iface->dhcpv6_pd_manager[0]) {
		int fd = usock(USOCK_UNIX | USOCK_TCP, iface->dhcpv6_pd_manager, NULL);
		if (fd >= 0) {
			char iaidbuf[298];
			odhcpd_hexlify(iaidbuf, assign->clid_data, assign->clid_len);

			assign->managed_sock.stream.notify_read = managed_handle_pd_data;
			assign->managed_sock.stream.notify_state = managed_handle_pd_done;
			ustream_fd_init(&assign->managed_sock, fd);
			ustream_printf(&assign->managed_sock.stream, "%s,%x\n::/%d,0,0\n\n",
					iaidbuf, assign->iaid, assign->length);
			ustream_write_pending(&assign->managed_sock.stream);
			assign->managed_size = -1;

			if (!(assign->flags & OAF_STATIC))
				assign->valid_until = odhcpd_time() + 15;

			list_add(&assign->head, &iface->ia_assignments);

			/* Wait initial period of up to 250ms for immediate assignment */
			struct pollfd pfd = { .fd = fd, .events = POLLIN };
			poll(&pfd, 1, 250);
			managed_handle_pd_data(&assign->managed_sock.stream, 0);

			if (fcntl(fd, F_GETFL) >= 0 && assign->managed_size > 0)
				return true;
		}

		return false;
	} else if (iface->ia_addr_len < 1)
		return false;

	/* Try honoring the hint first */
	uint32_t current = 1, asize = (1 << (64 - assign->length)) - 1;
	if (assign->assigned) {
		list_for_each_entry(c, &iface->ia_assignments, head) {
			if (c->length == 128 || c->length == 0)
				continue;

			if (assign->assigned >= current && assign->assigned + asize < c->assigned) {
				list_add_tail(&assign->head, &c->head);
				apply_lease(iface, assign, true);
				return true;
			}

			if (c->assigned != 0)
				current = (c->assigned + (1 << (64 - c->length)));
		}
	}

	/* Fallback to a variable assignment */
	current = 1;
	list_for_each_entry(c, &iface->ia_assignments, head) {
		if (c->length == 128 || c->length == 0)
			continue;

		current = (current + asize) & (~asize);
		if (current + asize < c->assigned) {
			assign->assigned = current;
			list_add_tail(&assign->head, &c->head);
			apply_lease(iface, assign, true);
			return true;
		}

		if (c->assigned != 0)
			current = (c->assigned + (1 << (64 - c->length)));
	}

	return false;
}

static bool assign_na(struct interface *iface, struct dhcpv6_assignment *assign)
{
	/* Seed RNG with checksum of DUID */
	uint32_t seed = 0;
	for (size_t i = 0; i < assign->clid_len; ++i)
		seed += assign->clid_data[i];
	srand(seed);

	/* Try to assign up to 100x */
	for (size_t i = 0; i < 100; ++i) {
		uint32_t try;
		do try = ((uint32_t)rand()) % 0x0fff; while (try < 0x100);

		struct dhcpv6_assignment *c;
		list_for_each_entry(c, &iface->ia_assignments, head) {
			if (c->length == 0)
				continue;

			if (c->assigned > try || c->length != 128) {
				assign->assigned = try;
				list_add_tail(&assign->head, &c->head);
				return true;
			} else if (c->assigned == try)
				break;
		}
	}

	return false;
}

void dhcpv6_ia_preupdate(struct interface *iface)
{
	if (iface->dhcpv6 != RELAYD_SERVER)
		return;

	struct dhcpv6_assignment *c, *border = list_last_entry(
			&iface->ia_assignments, struct dhcpv6_assignment, head);

	list_for_each_entry(c, &iface->ia_assignments, head)
		if (c != border && !iface->managed)
			apply_lease(iface, c, false);
}

void dhcpv6_ia_postupdate(struct interface *iface, time_t now)
{
	if (iface->dhcpv6 != RELAYD_SERVER)
		return;

	int minprefix = -1;
	for (size_t i = 0; i < iface->ia_addr_len; ++i) {
		if (iface->ia_addr[i].preferred > (uint32_t)now &&
				iface->ia_addr[i].prefix < 64 &&
				iface->ia_addr[i].prefix > minprefix)
			minprefix = iface->ia_addr[i].prefix;
	}

	struct dhcpv6_assignment *border = list_last_entry(
			&iface->ia_assignments, struct dhcpv6_assignment, head);

	if (minprefix > 32 && minprefix <= 64)
		border->assigned = 1U << (64 - minprefix);
	else
		border->assigned = 0;

	struct list_head reassign = LIST_HEAD_INIT(reassign);
	struct dhcpv6_assignment *c, *d;
	list_for_each_entry_safe(c, d, &iface->ia_assignments, head) {
		if (c->clid_len == 0 || (!INFINITE_VALID(c->valid_until) && c->valid_until < now) ||
				c->managed_size)
			continue;

		if (c->length < 128 && c->assigned >= border->assigned && c != border)
			list_move(&c->head, &reassign);
		else if (c != border)
			apply_lease(iface, c, true);

		if (c->accept_reconf && c->reconf_cnt == 0) {
			c->reconf_cnt = 1;
			c->reconf_sent = now;
			send_reconf(iface, c);

			/* Leave all other assignments of that client alone */
			struct dhcpv6_assignment *a;
			list_for_each_entry(a, &iface->ia_assignments, head)
				if (a != c && a->clid_len == c->clid_len &&
						!memcmp(a->clid_data, c->clid_data, a->clid_len))
					c->reconf_cnt = INT_MAX;
		}
	}

	while (!list_empty(&reassign)) {
		c = list_first_entry(&reassign, struct dhcpv6_assignment, head);
		list_del(&c->head);
		if (!assign_pd(iface, c)) {
			c->assigned = 0;
			list_add(&c->head, &iface->ia_assignments);
		}
	}

	dhcpv6_write_statefile();
}

static void reconf_timer(struct uloop_timeout *event)
{
	time_t now = odhcpd_time();
	struct interface *iface;
	list_for_each_entry(iface, &interfaces, head) {
		if (iface->dhcpv6 != RELAYD_SERVER || iface->ia_assignments.next == NULL)
			continue;

		struct dhcpv6_assignment *a, *n;
		list_for_each_entry_safe(a, n, &iface->ia_assignments, head) {
			if (!INFINITE_VALID(a->valid_until) && a->valid_until < now) {
				if ((a->length < 128 && a->clid_len > 0) ||
						(a->length == 128 && a->clid_len == 0))
					free_dhcpv6_assignment(a);

			} else if (a->reconf_cnt > 0 && a->reconf_cnt < 8 &&
					now > a->reconf_sent + (1 << a->reconf_cnt)) {
				++a->reconf_cnt;
				a->reconf_sent = now;
				send_reconf(iface, a);
			}
		}
	}
	uloop_timeout_set(event, 2000);
}

static size_t append_reply(uint8_t *buf, size_t buflen, uint16_t status,
		const struct dhcpv6_ia_hdr *ia, struct dhcpv6_assignment *a,
		struct interface *iface, bool request)
{
	if (buflen < sizeof(*ia) + sizeof(struct dhcpv6_ia_prefix))
		return 0;

	struct dhcpv6_ia_hdr out = {ia->type, 0, ia->iaid, 0, 0};
	size_t datalen = sizeof(out);
	time_t now = odhcpd_time();

	if (status) {
		struct __attribute__((packed)) {
			uint16_t type;
			uint16_t len;
			uint16_t value;
		} stat = {htons(DHCPV6_OPT_STATUS), htons(sizeof(stat) - 4),
				htons(status)};

		memcpy(buf + datalen, &stat, sizeof(stat));
		datalen += sizeof(stat);
	} else {
		if (a) {
			uint32_t leasetime;
			if (a->leasetime > 0)
				leasetime = a->leasetime;
			else
				leasetime = iface->dhcpv4_leasetime;

			if (leasetime == 0)
				leasetime = 3600;
			else if (leasetime < 60)
				leasetime = 60;

			uint32_t pref = leasetime;
			uint32_t valid = leasetime;

			struct odhcpd_ipaddr *addrs = (a->managed) ? a->managed : iface->ia_addr;
			size_t addrlen = (a->managed) ? (size_t)a->managed_size : iface->ia_addr_len;
			size_t m = elect_addr(addrs, addrlen);

			for (size_t i = 0; i < addrlen; ++i) {
				uint32_t prefix_pref = addrs[i].preferred;
				uint32_t prefix_valid = addrs[i].valid;

				if (!valid_addr(&addrs[i], now))
					continue;

				if (prefix_pref != UINT32_MAX)
					prefix_pref -= now;

				if (prefix_valid != UINT32_MAX)
					prefix_valid -= now;

				if (a->length < 128) {
					struct dhcpv6_ia_prefix p = {
						.type = htons(DHCPV6_OPT_IA_PREFIX),
						.len = htons(sizeof(p) - 4),
						.preferred = htonl(prefix_pref),
						.valid = htonl(prefix_valid),
						.prefix = (a->managed_size) ? addrs[i].prefix : a->length,
						.addr = addrs[i].addr
					};
					p.addr.s6_addr32[1] |= htonl(a->assigned);

					size_t entrlen = sizeof(p) - 4;

					if (datalen + entrlen + 4 > buflen ||
							(a->assigned == 0 && a->managed_size == 0) ||
							(!a->managed_size && a->length <= addrs[i].prefix))
						continue;

					memcpy(buf + datalen, &p, sizeof(p));
					datalen += entrlen + 4;
				} else {
					struct dhcpv6_ia_addr n = {
						.type = htons(DHCPV6_OPT_IA_ADDR),
						.len = htons(sizeof(n) - 4),
						.addr = addrs[i].addr,
						.preferred = htonl(prefix_pref),
						.valid = htonl(prefix_valid)
					};
					n.addr.s6_addr32[3] = htonl(a->assigned);
					size_t entrlen = sizeof(n) - 4;

					if (!ADDR_ENTRY_VALID_IA_ADDR(iface, i, m, addrs) ||
							a->assigned == 0 ||
							datalen + entrlen + 4 > buflen)
						continue;

					memcpy(buf + datalen, &n, sizeof(n));
					datalen += entrlen + 4;
				}

				/* Calculate T1 / T2 based on non-deprecated addresses */
				if (prefix_pref > 0) {
					if (prefix_pref < pref)
						pref = prefix_pref;

					if (prefix_valid < valid)
						valid = prefix_valid;
				}
			}

			if (!INFINITE_VALID(a->valid_until))
				/* UINT32_MAX is considered as infinite leasetime */
				a->valid_until = (valid == UINT32_MAX) ? 0 : valid + now;

			out.t1 = htonl((pref == UINT32_MAX) ? pref : pref * 5 / 10);
			out.t2 = htonl((pref == UINT32_MAX) ? pref : pref * 8 / 10);

			if (!out.t1)
				out.t1 = htonl(1);

			if (!out.t2)
				out.t2 = htonl(1);
		}

		if (!request) {
			uint8_t *odata, *end = ((uint8_t*)ia) + htons(ia->len) + 4;
			uint16_t otype, olen;
			dhcpv6_for_each_option((uint8_t*)&ia[1], end, otype, olen, odata) {
				struct dhcpv6_ia_prefix *p = (struct dhcpv6_ia_prefix*)&odata[-4];
				struct dhcpv6_ia_addr *n = (struct dhcpv6_ia_addr*)&odata[-4];
				if ((otype != DHCPV6_OPT_IA_PREFIX || olen < sizeof(*p) - 4) &&
						(otype != DHCPV6_OPT_IA_ADDR || olen < sizeof(*n) - 4))
					continue;

				bool found = false;
				if (a) {
					struct odhcpd_ipaddr *addrs = (a->managed) ? a->managed : iface->ia_addr;
					size_t addrlen = (a->managed) ? (size_t)a->managed_size : iface->ia_addr_len;

					for (size_t i = 0; i < addrlen; ++i) {
						if (!valid_addr(&addrs[i], now))
							continue;

						struct in6_addr addr = addrs[i].addr;
						if (ia->type == htons(DHCPV6_OPT_IA_PD)) {
							addr.s6_addr32[1] |= htonl(a->assigned);

							if (!memcmp(&p->addr, &addr, sizeof(addr)) &&
									p->prefix == ((a->managed) ? addrs[i].prefix : a->length))
								found = true;
						} else {
							addr.s6_addr32[3] = htonl(a->assigned);

							if (!memcmp(&n->addr, &addr, sizeof(addr)))
								found = true;
						}
					}
				}

				if (!found) {
					if (otype == DHCPV6_OPT_IA_PREFIX) {
						struct dhcpv6_ia_prefix inv = {
							.type = htons(DHCPV6_OPT_IA_PREFIX),
							.len = htons(sizeof(inv) - 4),
							.preferred = 0,
							.valid = 0,
							.prefix = p->prefix,
							.addr = p->addr
						};

						if (datalen + sizeof(inv) > buflen)
							continue;

						memcpy(buf + datalen, &inv, sizeof(inv));
						datalen += sizeof(inv);
					} else {
						struct dhcpv6_ia_addr inv = {
							.type = htons(DHCPV6_OPT_IA_ADDR),
							.len = htons(sizeof(inv) - 4),
							.addr = n->addr,
							.preferred = 0,
							.valid = 0
						};

						if (datalen + sizeof(inv) > buflen)
							continue;

						memcpy(buf + datalen, &inv, sizeof(inv));
						datalen += sizeof(inv);
					}
				}
			}
		}
	}

	out.len = htons(datalen - 4);
	memcpy(buf, &out, sizeof(out));
	return datalen;
}

static void dhcpv6_log(uint8_t msgtype, struct interface *iface, time_t now,
		const char *duidbuf, bool is_pd, struct dhcpv6_assignment *a, int code)
{
	const char *type = "UNKNOWN";
	const char *status = "UNKNOWN";

	if (msgtype == DHCPV6_MSG_RENEW)
		return;

	switch (msgtype) {
	case DHCPV6_MSG_SOLICIT:
		type = "SOLICIT";
		break;
	case DHCPV6_MSG_REQUEST:
		type = "REQUEST";
		break;
	case DHCPV6_MSG_CONFIRM:
		type = "CONFIRM";
		break;
	case DHCPV6_MSG_RENEW:
		type = "RENEW";
		break;
	case DHCPV6_MSG_REBIND:
		type = "REBIND";
		break;
	case DHCPV6_MSG_RELEASE:
		type = "RELEASE";
		break;
	case DHCPV6_MSG_DECLINE:
		type = "DECLINE";
		break;
	}

	switch (code) {
	case DHCPV6_STATUS_OK:
		status = "ok";
		break;
	case DHCPV6_STATUS_NOADDRSAVAIL:
		status = "no addresses available";
		break;
	case DHCPV6_STATUS_NOBINDING:
		status = "no binding";
		break;
	case DHCPV6_STATUS_NOTONLINK:
		status = "not on-link";
		break;
	case DHCPV6_STATUS_NOPREFIXAVAIL:
		status = "no prefix available";
		break;
	}

	char leasebuf[256] = "";

	if (a) {
		struct odhcpd_ipaddr *addrs = (a->managed) ? a->managed : iface->ia_addr;
		size_t addrlen = (a->managed) ? (size_t)a->managed_size : iface->ia_addr_len;
		size_t lbsize = 0;
		size_t m = elect_addr(addrs, addrlen);
		char addrbuf[INET6_ADDRSTRLEN];

		for (size_t i = 0; i < addrlen; ++i) {
			if (!valid_addr(&addrs[i], now))
				continue;

			struct in6_addr addr = addrs[i].addr;
			int prefix = a->managed ? addrs[i].prefix : a->length;
			if (prefix == 128) {
				if (!ADDR_ENTRY_VALID_IA_ADDR(iface, i, m, addrs) ||
						a->assigned == 0)
					continue;

				addr.s6_addr32[3] = htonl(a->assigned);
			}
			else
				addr.s6_addr32[1] |= htonl(a->assigned);

			inet_ntop(AF_INET6, &addr, addrbuf, sizeof(addrbuf));
			lbsize += snprintf(leasebuf + lbsize, sizeof(leasebuf) - lbsize, "%s/%d ", addrbuf, prefix);
		}
	}

	syslog(LOG_WARNING, "DHCPV6 %s %s from %s on %s: %s %s", type, (is_pd) ? "IA_PD" : "IA_NA",
			duidbuf, iface->ifname, status, leasebuf);
}

ssize_t dhcpv6_handle_ia(uint8_t *buf, size_t buflen, struct interface *iface,
		const struct sockaddr_in6 *addr, const void *data, const uint8_t *end)
{
	time_t now = odhcpd_time();
	size_t response_len = 0;
	const struct dhcpv6_client_header *hdr = data;
	uint8_t *start = (uint8_t*)&hdr[1], *odata;
	uint16_t otype, olen;
	/* Find and parse client-id and hostname */
	bool accept_reconf = false;
	uint8_t *clid_data = NULL, clid_len = 0, mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	char hostname[256];
	size_t hostname_len = 0;
	bool notonlink = false;
	char duidbuf[261];

	dhcpv6_for_each_option(start, end, otype, olen, odata) {
		if (otype == DHCPV6_OPT_CLIENTID) {
			clid_data = odata;
			clid_len = olen;

			if (olen == 14 && odata[0] == 0 && odata[1] == 1)
				memcpy(mac, &odata[8], sizeof(mac));
			else if (olen == 10 && odata[0] == 0 && odata[1] == 3)
				memcpy(mac, &odata[4], sizeof(mac));

			if (olen <= 130)
				odhcpd_hexlify(duidbuf, odata, olen);
		} else if (otype == DHCPV6_OPT_FQDN && olen >= 2 && olen <= 255) {
			uint8_t fqdn_buf[256];
			memcpy(fqdn_buf, odata, olen);
			fqdn_buf[olen++] = 0;

			if (dn_expand(&fqdn_buf[1], &fqdn_buf[olen], &fqdn_buf[1], hostname, sizeof(hostname)) > 0)
				hostname_len = strcspn(hostname, ".");
		} else if (otype == DHCPV6_OPT_RECONF_ACCEPT)
			accept_reconf = true;
	}

	if (!clid_data || !clid_len || clid_len > 130)
		goto out;

	struct dhcpv6_assignment *first = NULL;
	dhcpv6_for_each_option(start, end, otype, olen, odata) {
		bool is_pd = (otype == DHCPV6_OPT_IA_PD);
		bool is_na = (otype == DHCPV6_OPT_IA_NA);
		bool ia_addr_present = false;
		if (!is_pd && !is_na)
			continue;

		struct dhcpv6_ia_hdr *ia = (struct dhcpv6_ia_hdr*)&odata[-4];
		size_t ia_response_len = 0;
		uint8_t reqlen = (is_pd) ? 62 : 128;
		uint32_t reqhint = 0;

		/* Parse request hint for IA-PD */
		if (is_pd) {
			uint8_t *sdata;
			uint16_t stype, slen;
			dhcpv6_for_each_option(&ia[1], odata + olen, stype, slen, sdata) {
				if (stype != DHCPV6_OPT_IA_PREFIX || slen < sizeof(struct dhcpv6_ia_prefix) - 4)
					continue;

				struct dhcpv6_ia_prefix *p = (struct dhcpv6_ia_prefix*)&sdata[-4];
				if (p->prefix) {
					reqlen = p->prefix;
					reqhint = ntohl(p->addr.s6_addr32[1]);
					if (reqlen > 32 && reqlen <= 64)
						reqhint &= (1U << (64 - reqlen)) - 1;
				}
			}

			if (reqlen > 64)
				reqlen = 64;
		} else if (is_na) {
			uint8_t *sdata;
			uint16_t stype, slen;
			dhcpv6_for_each_option(&ia[1], odata + olen, stype, slen, sdata) {
				if (stype != DHCPV6_OPT_IA_ADDR || slen < sizeof(struct dhcpv6_ia_addr) - 4)
					continue;

				ia_addr_present = true;
			}
		}

		/* Find assignment */
		struct dhcpv6_assignment *c, *a = NULL;
		list_for_each_entry(c, &iface->ia_assignments, head) {
			if (((c->clid_len == clid_len && !memcmp(c->clid_data, clid_data, clid_len)) ||
					(c->clid_len >= clid_len && !c->clid_data[0] && !c->clid_data[1]
						&& !memcmp(c->mac, mac, sizeof(mac)))) &&
					(c->iaid == ia->iaid || INFINITE_VALID(c->valid_until) || now < c->valid_until) &&
					((is_pd && c->length <= 64) || (is_na && c->length == 128))) {
				a = c;

				/* Reset state */
				apply_lease(iface, a, false);
				memcpy(a->clid_data, clid_data, clid_len);
				a->clid_len = clid_len;
				a->iaid = ia->iaid;
				a->peer = *addr;
				a->reconf_cnt = 0;
				a->reconf_sent = 0;
				break;
			}
		}

		/* Generic message handling */
		uint16_t status = DHCPV6_STATUS_OK;
		if (a && a->managed_size < 0)
			return -1;

		if (hdr->msg_type == DHCPV6_MSG_SOLICIT || hdr->msg_type == DHCPV6_MSG_REQUEST) {
			bool assigned = !!a;

			if (!a && !iface->no_dynamic_dhcp) {
				/* Create new binding */
				a = calloc(1, sizeof(*a) + clid_len);
				if (a) {
					a->clid_len = clid_len;
					a->iaid = ia->iaid;
					a->length = reqlen;
					a->peer = *addr;
					a->assigned = reqhint;
					/* Set valid time to current time indicating  */
					/* assignment is not having infinite lifetime */
					a->valid_until = now;

					if (first)
						memcpy(a->key, first->key, sizeof(a->key));
					else
						odhcpd_urandom(a->key, sizeof(a->key));
					memcpy(a->clid_data, clid_data, clid_len);

					if (is_pd)
						while (!(assigned = assign_pd(iface, a)) &&
								!a->managed_size && ++a->length <= 64);
					else
						assigned = assign_na(iface, a);

					if (a->managed_size && !assigned)
						return -1;
				}
			}

			if (!assigned || iface->ia_addr_len == 0)
				/* Set error status */
				status = (is_pd) ? DHCPV6_STATUS_NOPREFIXAVAIL : DHCPV6_STATUS_NOADDRSAVAIL;
			else if (assigned && !first) {
				size_t handshake_len = 4;
				buf[0] = 0;
				buf[1] = DHCPV6_OPT_RECONF_ACCEPT;
				buf[2] = 0;
				buf[3] = 0;

				if (hdr->msg_type == DHCPV6_MSG_REQUEST) {
					struct dhcpv6_auth_reconfigure auth = {
						htons(DHCPV6_OPT_AUTH),
						htons(sizeof(auth) - 4),
						3, 1, 0,
						{htonl(time(NULL)), htonl(++serial)},
						1,
						{0}
					};
					memcpy(auth.key, a->key, sizeof(a->key));
					memcpy(buf + handshake_len, &auth, sizeof(auth));
					handshake_len += sizeof(auth);
				}

				buf += handshake_len;
				buflen -= handshake_len;
				response_len += handshake_len;

				first = a;
			}

			ia_response_len = append_reply(buf, buflen, status, ia, a, iface, true);

			/* Was only a solicitation: mark binding for removal */
			if (assigned && hdr->msg_type == DHCPV6_MSG_SOLICIT) {
				a->flags &= ~OAF_BOUND;

				if (!(a->flags & OAF_STATIC))
					a->valid_until = now;
			} else if (assigned && hdr->msg_type == DHCPV6_MSG_REQUEST) {
				if (hostname_len > 0) {
					a->hostname = realloc(a->hostname, hostname_len + 1);
					if (a->hostname) {
						memcpy(a->hostname, hostname, hostname_len);
						a->hostname[hostname_len] = 0;
					}
				}
				a->accept_reconf = accept_reconf;
				a->flags |= OAF_BOUND;
				apply_lease(iface, a, true);
			} else if (!assigned && a && a->managed_size == 0) {
				/* Cleanup failed assignment */
				free_dhcpv6_assignment(a);
				a = NULL;
			}
		} else if (hdr->msg_type == DHCPV6_MSG_RENEW ||
				hdr->msg_type == DHCPV6_MSG_RELEASE ||
				hdr->msg_type == DHCPV6_MSG_REBIND ||
				hdr->msg_type == DHCPV6_MSG_DECLINE) {
			if (!a && hdr->msg_type != DHCPV6_MSG_REBIND) {
				status = DHCPV6_STATUS_NOBINDING;
				ia_response_len = append_reply(buf, buflen, status, ia, a, iface, false);
			} else if (hdr->msg_type == DHCPV6_MSG_RENEW ||
					hdr->msg_type == DHCPV6_MSG_REBIND) {
				ia_response_len = append_reply(buf, buflen, status, ia, a, iface, false);
				if (a) {
					a->flags |= OAF_BOUND;
					apply_lease(iface, a, true);
				}
			} else if (hdr->msg_type == DHCPV6_MSG_RELEASE) {
				if (!(a->flags & OAF_STATIC))
					a->valid_until = now - 1;

				a->flags &= ~OAF_BOUND;
				apply_lease(iface, a, false);
			} else if (hdr->msg_type == DHCPV6_MSG_DECLINE && a->length == 128) {
				a->flags &= ~OAF_BOUND;

				if (!(a->flags & OAF_STATIC)) {
					a->clid_len = 0;
					a->valid_until = now + 3600; /* Block address for 1h */
				}
			}
		} else if (hdr->msg_type == DHCPV6_MSG_CONFIRM && ia_addr_present) {
			/* Send NOTONLINK for CONFIRM with addr present so that clients restart connection */
			status = DHCPV6_STATUS_NOTONLINK;
			ia_response_len = append_reply(buf, buflen, status, ia, a, iface, true);
			notonlink = true;
		}

		buf += ia_response_len;
		buflen -= ia_response_len;
		response_len += ia_response_len;
		dhcpv6_log(hdr->msg_type, iface, now, duidbuf, is_pd, a, status);
	}

	if ((hdr->msg_type == DHCPV6_MSG_RELEASE || hdr->msg_type == DHCPV6_MSG_DECLINE || notonlink) &&
			response_len + 6 < buflen) {
		buf[0] = 0;
		buf[1] = DHCPV6_OPT_STATUS;
		buf[2] = 0;
		buf[3] = 2;
		buf[4] = 0;
		buf[5] = (notonlink) ? DHCPV6_STATUS_NOTONLINK : DHCPV6_STATUS_OK;
		response_len += 6;
	}

	dhcpv6_write_statefile();

out:
	return response_len;
}
