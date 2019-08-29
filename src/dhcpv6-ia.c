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

#include <libubox/md5.h>
#include <libubox/usock.h>

#define ADDR_ENTRY_VALID_IA_ADDR(iface, i, m, addrs) \
    ((iface)->dhcpv6_assignall || (i) == (m) || \
     (addrs)[(i)].prefix > 64)

static void dhcpv6_netevent_cb(unsigned long event, struct netevent_handler_info *info);
static void set_border_assignment_size(struct interface *iface, struct dhcp_assignment *b);
static void handle_addrlist_change(struct netevent_handler_info *info);
static void start_reconf(struct dhcp_assignment *a);
static void stop_reconf(struct dhcp_assignment *a);
static void valid_until_cb(struct uloop_timeout *event);

static struct netevent_handler dhcpv6_netevent_handler = { .cb = dhcpv6_netevent_cb, };
static struct uloop_timeout valid_until_timeout = {.cb = valid_until_cb};
static uint32_t serial = 0;
static uint8_t statemd5[16];

int dhcpv6_ia_init(void)
{
	uloop_timeout_set(&valid_until_timeout, 1000);

	netlink_add_netevent_handler(&dhcpv6_netevent_handler);

	return 0;
}

int dhcpv6_ia_setup_interface(struct interface *iface, bool enable)
{
	enable = enable && (iface->dhcpv6 == MODE_SERVER);

	if (enable) {
		struct dhcp_assignment *border;

		if (list_empty(&iface->ia_assignments)) {
			border = alloc_assignment(0);

			if (!border) {
				syslog(LOG_ERR, "Failed to alloc border on %s", iface->name);
				return -1;
			}

			border->length = 64;
			list_add(&border->head, &iface->ia_assignments);
		} else
			border = list_last_entry(&iface->ia_assignments, struct dhcp_assignment, head);

		set_border_assignment_size(iface, border);
	} else {
		struct dhcp_assignment *c;

		while (!list_empty(&iface->ia_assignments)) {
			c = list_first_entry(&iface->ia_assignments, struct dhcp_assignment, head);
			free_assignment(c);
		}
	}

	return 0;
}


static void dhcpv6_netevent_cb(unsigned long event, struct netevent_handler_info *info)
{
	struct interface *iface = info->iface;

	if (!iface || iface->dhcpv6 != MODE_SERVER)
		return;

	switch (event) {
	case NETEV_ADDR6LIST_CHANGE:
		handle_addrlist_change(info);
		break;
	default:
		break;
	}
}


static inline bool valid_prefix_length(const struct dhcp_assignment *a, const uint8_t prefix_length)
{
	return (a->managed_size || a->length > prefix_length);
}

static inline bool valid_addr(const struct odhcpd_ipaddr *addr, time_t now)
{
	return (addr->prefix <= 96 && addr->preferred > (uint32_t)now);
}

static size_t get_preferred_addr(const struct odhcpd_ipaddr *addrs, const size_t addrlen)
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

static int send_reconf(struct dhcp_assignment *assign)
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
	struct interface *iface = assign->iface;

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

static void dhcpv6_ia_free_assignment(struct dhcp_assignment *a)
{
	if (a->managed_sock.fd.registered) {
		ustream_free(&a->managed_sock.stream);
		close(a->managed_sock.fd.fd);
	}

	if (a->reconf_cnt)
		stop_reconf(a);

	free(a->managed);
}

void dhcpv6_ia_enum_addrs(struct interface *iface, struct dhcp_assignment *c,
			  time_t now, dhcpv6_binding_cb_handler_t func, void *arg)
{
	struct odhcpd_ipaddr *addrs = (c->managed) ? c->managed : iface->addr6;
	size_t addrlen = (c->managed) ? (size_t)c->managed_size : iface->addr6_len;
	size_t m = get_preferred_addr(addrs, addrlen);

	for (size_t i = 0; i < addrlen; ++i) {
		struct in6_addr addr;
		uint32_t pref, valid;
		int prefix = c->managed ? addrs[i].prefix : c->length;

		if (!valid_addr(&addrs[i], now))
			continue;

		addr = addrs[i].addr.in6;
		pref = addrs[i].preferred;
		valid = addrs[i].valid;
		if (prefix == 128) {
			if (!ADDR_ENTRY_VALID_IA_ADDR(iface, i, m, addrs))
				continue;

			addr.s6_addr32[3] = htonl(c->assigned);
		} else {
			if (!valid_prefix_length(c, addrs[i].prefix))
				continue;

			addr.s6_addr32[1] |= htonl(c->assigned);
			addr.s6_addr32[2] = addr.s6_addr32[3] = 0;
		}

		if (pref != UINT32_MAX)
			pref -= now;

		if (valid != UINT32_MAX)
			valid -= now;

		func(&addr, prefix, pref, valid, arg);
	}
}

struct write_ctxt {
	FILE *fp;
	md5_ctx_t md5;
	struct dhcp_assignment *c;
	struct interface *iface;
	char *buf;
	int buf_len;
	int buf_idx;
};

static void dhcpv6_write_ia_addr(struct in6_addr *addr, int prefix, _unused uint32_t pref,
				_unused uint32_t valid, void *arg)
{
	struct write_ctxt *ctxt = (struct write_ctxt *)arg;
	char ipbuf[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, addr, ipbuf, sizeof(ipbuf) - 1);

	if (ctxt->c->length == 128 && ctxt->c->hostname &&
	    !(ctxt->c->flags & OAF_BROKEN_HOSTNAME)) {
		fputs(ipbuf, ctxt->fp);

		char b[256];
		if (dn_expand(ctxt->iface->search, ctxt->iface->search + ctxt->iface->search_len,
				ctxt->iface->search, b, sizeof(b)) > 0)
			fprintf(ctxt->fp, "\t%s.%s", ctxt->c->hostname, b);

		fprintf(ctxt->fp, "\t%s\n", ctxt->c->hostname);
		md5_hash(ipbuf, strlen(ipbuf), &ctxt->md5);
		md5_hash(ctxt->c->hostname, strlen(ctxt->c->hostname), &ctxt->md5);
	}

	ctxt->buf_idx += snprintf(ctxt->buf + ctxt->buf_idx,ctxt->buf_len - ctxt->buf_idx,
					"%s/%d ", ipbuf, prefix);
}

void dhcpv6_ia_write_statefile(void)
{
	struct write_ctxt ctxt;

	md5_begin(&ctxt.md5);

	if (config.dhcp_statefile) {
		time_t now = odhcpd_time(), wall_time = time(NULL);
		int fd = open(config.dhcp_statefile, O_CREAT | O_WRONLY | O_CLOEXEC, 0644);
		char leasebuf[512];

		if (fd < 0)
			return;
		int ret;
		ret = lockf(fd, F_LOCK, 0);
		if (ret < 0) {
			close(fd);
			return;
		}
		if (ftruncate(fd, 0) < 0) {}

		ctxt.fp = fdopen(fd, "w");
		if (!ctxt.fp) {
			close(fd);
			return;
		}

		ctxt.buf = leasebuf;
		ctxt.buf_len = sizeof(leasebuf);

		avl_for_each_element(&interfaces, ctxt.iface, avl) {
			if (ctxt.iface->dhcpv6 != MODE_SERVER &&
					ctxt.iface->dhcpv4 != MODE_SERVER)
				continue;

			if (ctxt.iface->dhcpv6 == MODE_SERVER) {
				list_for_each_entry(ctxt.c, &ctxt.iface->ia_assignments, head) {
					if (!(ctxt.c->flags & OAF_BOUND) || ctxt.c->managed_size < 0)
						continue;

					char duidbuf[264];

					odhcpd_hexlify(duidbuf, ctxt.c->clid_data, ctxt.c->clid_len);

					/* iface DUID iaid hostname lifetime assigned length [addrs...] */
					ctxt.buf_idx = snprintf(ctxt.buf, ctxt.buf_len, "# %s %s %x %s%s %ld %x %u ",
								ctxt.iface->ifname, duidbuf, ntohl(ctxt.c->iaid),
								(ctxt.c->flags & OAF_BROKEN_HOSTNAME) ? "broken\\x20" : "",
								(ctxt.c->hostname ? ctxt.c->hostname : "-"),
								(ctxt.c->valid_until > now ?
									(ctxt.c->valid_until - now + wall_time) :
									(INFINITE_VALID(ctxt.c->valid_until) ? -1 : 0)),
								ctxt.c->assigned, (unsigned)ctxt.c->length);

					if (INFINITE_VALID(ctxt.c->valid_until) || ctxt.c->valid_until > now)
						dhcpv6_ia_enum_addrs(ctxt.iface, ctxt.c, now,
									dhcpv6_write_ia_addr, &ctxt);

					ctxt.buf[ctxt.buf_idx - 1] = '\n';
					fwrite(ctxt.buf, 1, ctxt.buf_idx, ctxt.fp);
				}
			}

			if (ctxt.iface->dhcpv4 == MODE_SERVER) {
				struct dhcp_assignment *c;

				list_for_each_entry(c, &ctxt.iface->dhcpv4_assignments, head) {
					if (!(c->flags & OAF_BOUND))
						continue;

					char ipbuf[INET6_ADDRSTRLEN];
					char duidbuf[16];
					odhcpd_hexlify(duidbuf, c->hwaddr, sizeof(c->hwaddr));

					/* iface DUID iaid hostname lifetime assigned length [addrs...] */
					ctxt.buf_idx = snprintf(ctxt.buf, ctxt.buf_len, "# %s %s ipv4 %s%s %ld %x 32 ",
								ctxt.iface->ifname, duidbuf,
								(c->flags & OAF_BROKEN_HOSTNAME) ? "broken\\x20" : "",
								(c->hostname ? c->hostname : "-"),
								(c->valid_until > now ?
									(c->valid_until - now + wall_time) :
									(INFINITE_VALID(c->valid_until) ? -1 : 0)),
								ntohl(c->addr));

					struct in_addr addr = {.s_addr = c->addr};
					inet_ntop(AF_INET, &addr, ipbuf, sizeof(ipbuf) - 1);

					if (c->hostname && !(c->flags & OAF_BROKEN_HOSTNAME)) {
						fputs(ipbuf, ctxt.fp);

						char b[256];
						if (dn_expand(ctxt.iface->search,
								ctxt.iface->search + ctxt.iface->search_len,
								ctxt.iface->search, b, sizeof(b)) > 0)
							fprintf(ctxt.fp, "\t%s.%s", c->hostname, b);

						fprintf(ctxt.fp, "\t%s\n", c->hostname);
						md5_hash(ipbuf, strlen(ipbuf), &ctxt.md5);
						md5_hash(c->hostname, strlen(c->hostname), &ctxt.md5);
					}

					ctxt.buf_idx += snprintf(ctxt.buf + ctxt.buf_idx,
									ctxt.buf_len - ctxt.buf_idx,
									"%s/32 ", ipbuf);
					ctxt.buf[ctxt.buf_idx - 1] = '\n';
					fwrite(ctxt.buf, 1, ctxt.buf_idx, ctxt.fp);
				}
			}
		}

		fclose(ctxt.fp);
	}

	uint8_t newmd5[16];
	md5_end(newmd5, &ctxt.md5);

	if (config.dhcp_cb && memcmp(newmd5, statemd5, sizeof(newmd5))) {
		memcpy(statemd5, newmd5, sizeof(statemd5));
		char *argv[2] = {config.dhcp_cb, NULL};
		if (!vfork()) {
			execv(argv[0], argv);
			_exit(128);
		}
	}
}

static void __apply_lease(struct interface *iface, struct dhcp_assignment *a,
		struct odhcpd_ipaddr *addrs, ssize_t addr_len, bool add)
{
	if (a->length > 64)
		return;

	for (ssize_t i = 0; i < addr_len; ++i) {
		struct in6_addr prefix = addrs[i].addr.in6;
		prefix.s6_addr32[1] |= htonl(a->assigned);
		prefix.s6_addr32[2] = prefix.s6_addr32[3] = 0;
		netlink_setup_route(&prefix, (a->managed_size) ? addrs[i].prefix : a->length,
				iface->ifindex, &a->peer.sin6_addr, 1024, add);
	}
}

static void apply_lease(struct interface *iface, struct dhcp_assignment *a, bool add)
{
	struct odhcpd_ipaddr *addrs = (a->managed) ? a->managed : iface->addr6;
	ssize_t addrlen = (a->managed) ? a->managed_size : (ssize_t)iface->addr6_len;

	__apply_lease(iface, a, addrs, addrlen, add);
}

/* Set border assignment size based on the IPv6 address prefixes */
static void set_border_assignment_size(struct interface *iface, struct dhcp_assignment *b)
{
	time_t now = odhcpd_time();
	int minprefix = -1;

	for (size_t i = 0; i < iface->addr6_len; ++i) {
		if (iface->addr6[i].preferred > (uint32_t)now &&
				iface->addr6[i].prefix < 64 &&
				iface->addr6[i].prefix > minprefix)
			minprefix = iface->addr6[i].prefix;
	}

	if (minprefix > 32 && minprefix <= 64)
		b->assigned = 1U << (64 - minprefix);
	else
		b->assigned = 0;
}

/* More data was received from TCP connection */
static void managed_handle_pd_data(struct ustream *s, _unused int bytes_new)
{
	struct ustream_fd *fd = container_of(s, struct ustream_fd, stream);
	struct dhcp_assignment *c = container_of(fd, struct dhcp_assignment, managed_sock);
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
		free_assignment(c);
	else if (first && !(c->flags & OAF_STATIC))
		c->valid_until = now + 150;
}


/* TCP transmission has ended, either because of success or timeout or other error */
static void managed_handle_pd_done(struct ustream *s)
{
	struct ustream_fd *fd = container_of(s, struct ustream_fd, stream);
	struct dhcp_assignment *c = container_of(fd, struct dhcp_assignment, managed_sock);

	if (!(c->flags & OAF_STATIC))
		c->valid_until = odhcpd_time() + 15;

	c->managed_size = 0;

	if (c->accept_reconf)
		c->reconf_cnt = 1;
}

static bool assign_pd(struct interface *iface, struct dhcp_assignment *assign)
{
	struct dhcp_assignment *c;

	if (iface->dhcpv6_pd_manager[0]) {
		int fd = usock(USOCK_UNIX | USOCK_TCP, iface->dhcpv6_pd_manager, NULL);
		if (fd >= 0) {
			struct pollfd pfd = { .fd = fd, .events = POLLIN };
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
			if (poll(&pfd, 1, 250) < 0) {
				syslog(LOG_ERR, "poll(): %m");
				return false;
			}

			managed_handle_pd_data(&assign->managed_sock.stream, 0);

			if (fcntl(fd, F_GETFL) >= 0 && assign->managed_size > 0)
				return true;
		}

		return false;
	} else if (iface->addr6_len < 1)
		return false;

	/* Try honoring the hint first */
	uint32_t current = 1, asize = (1 << (64 - assign->length)) - 1;
	if (assign->assigned) {
		list_for_each_entry(c, &iface->ia_assignments, head) {
			if (c->length == 128 || c->length == 0)
				continue;

			if (assign->assigned >= current && assign->assigned + asize < c->assigned) {
				list_add_tail(&assign->head, &c->head);

				if (assign->flags & OAF_BOUND)
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

			if (assign->flags & OAF_BOUND)
				apply_lease(iface, assign, true);

			return true;
		}

		if (c->assigned != 0)
			current = (c->assigned + (1 << (64 - c->length)));
	}

	return false;
}

static bool assign_na(struct interface *iface, struct dhcp_assignment *a)
{
	struct dhcp_assignment *c;
	uint32_t seed = 0;

	/* Preconfigured assignment by static lease */
	if (a->assigned) {
		list_for_each_entry(c, &iface->ia_assignments, head) {
			if (c->length == 0)
				continue;

			if (c->assigned > a->assigned || c->length != 128) {
				list_add_tail(&a->head, &c->head);
				return true;
			} else if (c->assigned == a->assigned)
				return false;
		}
	}

	/* Seed RNG with checksum of DUID */
	for (size_t i = 0; i < a->clid_len; ++i)
		seed += a->clid_data[i];
	srand(seed);

	/* Try to assign up to 100x */
	for (size_t i = 0; i < 100; ++i) {
		uint32_t try;
		do try = ((uint32_t)rand()) % 0x0fff; while (try < 0x100);

		if (config_find_lease_by_hostid(try))
			continue;

		list_for_each_entry(c, &iface->ia_assignments, head) {
			if (c->length == 0)
				continue;

			if (c->assigned > try || c->length != 128) {
				a->assigned = try;
				list_add_tail(&a->head, &c->head);
				return true;
			} else if (c->assigned == try)
				break;
		}
	}

	return false;
}

static void handle_addrlist_change(struct netevent_handler_info *info)
{
	struct interface *iface = info->iface;
	struct dhcp_assignment *c, *d, *border = list_last_entry(
			&iface->ia_assignments, struct dhcp_assignment, head);
	struct list_head reassign = LIST_HEAD_INIT(reassign);
	time_t now = odhcpd_time();

	list_for_each_entry(c, &iface->ia_assignments, head) {
		if (c != border && iface->ra_managed == RA_MANAGED_NO_MFLAG
				&& (c->flags & OAF_BOUND))
			__apply_lease(iface, c, info->addrs_old.addrs,
					info->addrs_old.len, false);
	}

	set_border_assignment_size(iface, border);

	list_for_each_entry_safe(c, d, &iface->ia_assignments, head) {
		if (c->clid_len == 0 || (!INFINITE_VALID(c->valid_until) && c->valid_until < now) ||
				c->managed_size)
			continue;

		if (c->length < 128 && (c->assigned == 0 || c->assigned >= border->assigned) && c != border)
			list_move(&c->head, &reassign);
		else if (c != border && (c->flags & OAF_BOUND))
			apply_lease(iface, c, true);

		if (c->accept_reconf && c->reconf_cnt == 0) {
			struct dhcp_assignment *a;

			start_reconf(c);

			/* Leave all other assignments of that client alone */
			list_for_each_entry(a, &iface->ia_assignments, head)
				if (a != c && a->clid_len == c->clid_len &&
						!memcmp(a->clid_data, c->clid_data, a->clid_len))
					a->reconf_cnt = INT_MAX;
		}
	}

	while (!list_empty(&reassign)) {
		c = list_first_entry(&reassign, struct dhcp_assignment, head);
		list_del_init(&c->head);
		if (!assign_pd(iface, c)) {
			c->assigned = 0;
			list_add(&c->head, &iface->ia_assignments);
		}
	}

	dhcpv6_ia_write_statefile();
}

static void reconf_timeout_cb(struct uloop_timeout *event)
{
	struct dhcp_assignment *a = container_of(event, struct dhcp_assignment, reconf_timer);

	if (a->reconf_cnt > 0 && a->reconf_cnt < DHCPV6_REC_MAX_RC) {
		send_reconf(a);
		uloop_timeout_set(&a->reconf_timer,
					DHCPV6_REC_TIMEOUT << a->reconf_cnt);
		a->reconf_cnt++;
	} else
		stop_reconf(a);
}

static void start_reconf(struct dhcp_assignment *a)
{
	uloop_timeout_set(&a->reconf_timer,
				DHCPV6_REC_TIMEOUT << a->reconf_cnt);
	a->reconf_timer.cb = reconf_timeout_cb;
	a->reconf_cnt++;

	send_reconf(a);
}

static void stop_reconf(struct dhcp_assignment *a)
{
	uloop_timeout_cancel(&a->reconf_timer);
	a->reconf_cnt = 0;
	a->reconf_timer.cb = NULL;
}

static void valid_until_cb(struct uloop_timeout *event)
{
	struct interface *iface;
	time_t now = odhcpd_time();

	avl_for_each_element(&interfaces, iface, avl) {
		struct dhcp_assignment *a, *n;

		if (iface->dhcpv6 != MODE_SERVER)
			continue;

		list_for_each_entry_safe(a, n, &iface->ia_assignments, head) {
			if (a->clid_len > 0 && !INFINITE_VALID(a->valid_until) && a->valid_until < now)
				free_assignment(a);
		}
	}
	uloop_timeout_set(event, 1000);
}

static size_t build_ia(uint8_t *buf, size_t buflen, uint16_t status,
		const struct dhcpv6_ia_hdr *ia, struct dhcp_assignment *a,
		struct interface *iface, bool request)
{
	struct dhcpv6_ia_hdr o_ia = {
		.type = ia->type,
		.len = 0,
		.iaid = ia->iaid,
		.t1 = 0,
		.t2 = 0,
	};
	size_t ia_len = sizeof(o_ia);
	time_t now = odhcpd_time();

	if (buflen < ia_len)
		return 0;

	if (status) {
		struct __attribute__((packed)) {
			uint16_t type;
			uint16_t len;
			uint16_t val;
		} o_status = {
			.type = htons(DHCPV6_OPT_STATUS),
			.len = htons(sizeof(o_status) - 4),
			.val = htons(status),
		};

		memcpy(buf + ia_len, &o_status, sizeof(o_status));
		ia_len += sizeof(o_status);

		o_ia.len = htons(ia_len - 4);
		memcpy(buf, &o_ia, sizeof(o_ia));

		return ia_len;
	}

	if (a) {
		uint32_t leasetime;

		if (a->leasetime)
			leasetime = a->leasetime;
		else
			leasetime = iface->dhcpv4_leasetime;

		uint32_t pref = leasetime;
		uint32_t valid = leasetime;

		struct odhcpd_ipaddr *addrs = (a->managed) ? a->managed : iface->addr6;
		size_t addrlen = (a->managed) ? (size_t)a->managed_size : iface->addr6_len;
		size_t m = get_preferred_addr(addrs, addrlen);

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
				struct dhcpv6_ia_prefix o_ia_p = {
					.type = htons(DHCPV6_OPT_IA_PREFIX),
					.len = htons(sizeof(o_ia_p) - 4),
					.preferred = htonl(prefix_pref),
					.valid = htonl(prefix_valid),
					.prefix = (a->managed_size) ? addrs[i].prefix : a->length,
					.addr = addrs[i].addr.in6,
				};

				o_ia_p.addr.s6_addr32[1] |= htonl(a->assigned);
				o_ia_p.addr.s6_addr32[2] = o_ia_p.addr.s6_addr32[3] = 0;

				if ((a->assigned == 0 && a->managed_size == 0) ||
						!valid_prefix_length(a, addrs[i].prefix))
					continue;

				if (buflen < ia_len + sizeof(o_ia_p))
					return 0;

				memcpy(buf + ia_len, &o_ia_p, sizeof(o_ia_p));
				ia_len += sizeof(o_ia_p);
			} else {
				struct dhcpv6_ia_addr o_ia_a = {
					.type = htons(DHCPV6_OPT_IA_ADDR),
					.len = htons(sizeof(o_ia_a) - 4),
					.addr = addrs[i].addr.in6,
					.preferred = htonl(prefix_pref),
					.valid = htonl(prefix_valid)
				};

				o_ia_a.addr.s6_addr32[3] = htonl(a->assigned);

				if (!ADDR_ENTRY_VALID_IA_ADDR(iface, i, m, addrs) ||
						a->assigned == 0)
					continue;

				if (buflen < ia_len + sizeof(o_ia_a))
					return 0;

				memcpy(buf + ia_len, &o_ia_a, sizeof(o_ia_a));
				ia_len += sizeof(o_ia_a);
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

		o_ia.t1 = htonl((pref == UINT32_MAX) ? pref : pref * 5 / 10);
		o_ia.t2 = htonl((pref == UINT32_MAX) ? pref : pref * 8 / 10);

		if (!o_ia.t1)
			o_ia.t1 = htonl(1);

		if (!o_ia.t2)
			o_ia.t2 = htonl(1);
	}

	if (!request) {
		uint8_t *odata, *end = ((uint8_t*)ia) + htons(ia->len) + 4;
		uint16_t otype, olen;

		dhcpv6_for_each_option((uint8_t*)&ia[1], end, otype, olen, odata) {
			struct dhcpv6_ia_prefix *ia_p = (struct dhcpv6_ia_prefix *)&odata[-4];
			struct dhcpv6_ia_addr *ia_a = (struct dhcpv6_ia_addr *)&odata[-4];
			bool found = false;

			if ((otype != DHCPV6_OPT_IA_PREFIX || olen < sizeof(*ia_p) - 4) &&
					(otype != DHCPV6_OPT_IA_ADDR || olen < sizeof(*ia_a) - 4))
				continue;

			if (a) {
				struct odhcpd_ipaddr *addrs = (a->managed) ? a->managed : iface->addr6;
				size_t addrlen = (a->managed) ? (size_t)a->managed_size : iface->addr6_len;

				for (size_t i = 0; i < addrlen; ++i) {
					if (!valid_addr(&addrs[i], now))
						continue;

					struct in6_addr addr = addrs[i].addr.in6;
					if (ia->type == htons(DHCPV6_OPT_IA_PD)) {
						addr.s6_addr32[1] |= htonl(a->assigned);
						addr.s6_addr32[2] = addr.s6_addr32[3] = 0;

						if (!memcmp(&ia_p->addr, &addr, sizeof(addr)) &&
								ia_p->prefix == ((a->managed) ? addrs[i].prefix : a->length))
							found = true;
					} else {
						addr.s6_addr32[3] = htonl(a->assigned);

						if (!memcmp(&ia_a->addr, &addr, sizeof(addr)))
							found = true;
					}
				}
			}

			if (!found) {
				if (otype == DHCPV6_OPT_IA_PREFIX) {
					struct dhcpv6_ia_prefix o_ia_p = {
						.type = htons(DHCPV6_OPT_IA_PREFIX),
						.len = htons(sizeof(o_ia_p) - 4),
						.preferred = 0,
						.valid = 0,
						.prefix = ia_p->prefix,
						.addr = ia_p->addr,
					};

					if (buflen < ia_len + sizeof(o_ia_p))
						return 0;

					memcpy(buf + ia_len, &o_ia_p, sizeof(o_ia_p));
					ia_len += sizeof(o_ia_p);
				} else {
					struct dhcpv6_ia_addr o_ia_a = {
						.type = htons(DHCPV6_OPT_IA_ADDR),
						.len = htons(sizeof(o_ia_a) - 4),
						.addr = ia_a->addr,
						.preferred = 0,
						.valid = 0,
					};

					if (buflen < ia_len + sizeof(o_ia_a))
						continue;

					memcpy(buf + ia_len, &o_ia_a, sizeof(o_ia_a));
					ia_len += sizeof(o_ia_a);
				}
			}
		}
	}

	o_ia.len = htons(ia_len - 4);
	memcpy(buf, &o_ia, sizeof(o_ia));
	return ia_len;
}

struct log_ctxt {
	char *buf;
	int buf_len;
	int buf_idx;
};

static void dhcpv6_log_ia_addr(struct in6_addr *addr, int prefix, _unused uint32_t pref,
				_unused uint32_t valid, void *arg)
{
	struct log_ctxt *ctxt = (struct log_ctxt *)arg;
	char addrbuf[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, addr, addrbuf, sizeof(addrbuf));
	ctxt->buf_idx += snprintf(ctxt->buf + ctxt->buf_idx, ctxt->buf_len - ctxt->buf_idx,
					"%s/%d ", addrbuf, prefix);
}

static void dhcpv6_log(uint8_t msgtype, struct interface *iface, time_t now,
		const char *duidbuf, bool is_pd, struct dhcp_assignment *a, int code)
{
	const char *type = "UNKNOWN";
	const char *status = "UNKNOWN";

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
		struct log_ctxt ctxt = {.buf = leasebuf,
					.buf_len = sizeof(leasebuf),
					.buf_idx = 0 };

		dhcpv6_ia_enum_addrs(iface, a, now, dhcpv6_log_ia_addr, &ctxt);
	}

	syslog(LOG_NOTICE, "DHCPV6 %s %s from %s on %s: %s %s", type, (is_pd) ? "IA_PD" : "IA_NA",
			duidbuf, iface->name, status, leasebuf);
}

static bool dhcpv6_ia_on_link(const struct dhcpv6_ia_hdr *ia, struct dhcp_assignment *a,
		struct interface *iface)
{
	struct odhcpd_ipaddr *addrs = (a && a->managed) ? a->managed : iface->addr6;
	size_t addrlen = (a && a->managed) ? (size_t)a->managed_size : iface->addr6_len;
	time_t now = odhcpd_time();
	uint8_t *odata, *end = ((uint8_t*)ia) + htons(ia->len) + 4;
	uint16_t otype, olen;
	bool onlink = true;

	dhcpv6_for_each_option((uint8_t*)&ia[1], end, otype, olen, odata) {
		struct dhcpv6_ia_prefix *p = (struct dhcpv6_ia_prefix *)&odata[-4];
		struct dhcpv6_ia_addr *n = (struct dhcpv6_ia_addr *)&odata[-4];

		if ((otype != DHCPV6_OPT_IA_PREFIX || olen < sizeof(*p) - 4) &&
				(otype != DHCPV6_OPT_IA_ADDR || olen < sizeof(*n) - 4))
			continue;

		onlink = false;
		for (size_t i = 0; i < addrlen; ++i) {
			if (!valid_addr(&addrs[i], now))
				continue;

			if (ia->type == htons(DHCPV6_OPT_IA_PD)) {
				if (p->prefix < addrs[i].prefix ||
				    odhcpd_bmemcmp(&p->addr, &addrs[i].addr.in6, addrs[i].prefix))
					continue;

			} else if (odhcpd_bmemcmp(&n->addr, &addrs[i].addr.in6, addrs[i].prefix))
				continue;

			onlink = true;
		}

		if (!onlink)
			break;
	}

	return onlink;
}

ssize_t dhcpv6_ia_handle_IAs(uint8_t *buf, size_t buflen, struct interface *iface,
		const struct sockaddr_in6 *addr, const void *data, const uint8_t *end)
{
	struct lease *l;
	struct dhcp_assignment *first = NULL;
	const struct dhcpv6_client_header *hdr = data;
	time_t now = odhcpd_time();
	uint16_t otype, olen, clid_len = 0;
	uint8_t *start = (uint8_t *)&hdr[1], *odata;
	uint8_t *clid_data = NULL, mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	size_t hostname_len = 0, response_len = 0;
	bool notonlink = false, rapid_commit = false, accept_reconf = false;
	char duidbuf[261], hostname[256];

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
		else if (otype == DHCPV6_OPT_RAPID_COMMIT && hdr->msg_type == DHCPV6_MSG_SOLICIT)
			rapid_commit = true;
	}

	if (!clid_data || !clid_len || clid_len > 130)
		goto out;

	l = config_find_lease_by_duid(clid_data, clid_len);
	if (!l)
		l = config_find_lease_by_mac(mac);

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
		struct dhcp_assignment *c, *a = NULL;
		list_for_each_entry(c, &iface->ia_assignments, head) {
			if ((c->clid_len == clid_len && !memcmp(c->clid_data, clid_data, clid_len)) &&
			    c->iaid == ia->iaid && (INFINITE_VALID(c->valid_until) || now < c->valid_until) &&
			    ((is_pd && c->length <= 64) || (is_na && c->length == 128))) {
				a = c;

				/* Reset state */
				if (a->flags & OAF_BOUND)
					apply_lease(iface, a, false);

				stop_reconf(a);
				break;
			}
		}

		if (l && a && a->lease != l) {
			free_assignment(a);
			a = NULL;
		}

		/* Generic message handling */
		uint16_t status = DHCPV6_STATUS_OK;
		if (a && a->managed_size < 0)
			return -1;

		if (hdr->msg_type == DHCPV6_MSG_SOLICIT ||
				hdr->msg_type == DHCPV6_MSG_REQUEST ||
				(hdr->msg_type == DHCPV6_MSG_REBIND && !a)) {
			bool assigned = !!a;

			if (!a) {
				if ((!iface->no_dynamic_dhcp || (l && is_na)) &&
				    (iface->dhcpv6_pd || iface->dhcpv6_na)) {
					/* Create new binding */
					a = alloc_assignment(clid_len);

					if (a) {
						a->clid_len = clid_len;
						memcpy(a->clid_data, clid_data, clid_len);
						a->iaid = ia->iaid;
						a->length = reqlen;
						a->peer = *addr;
						a->assigned = is_na && l ? l->hostid : reqhint;
						/* Set valid time to 0 for static lease indicating */
						/* infinite lifetime otherwise current time        */
						a->valid_until = l ? 0 : now;
						a->dhcp_free_cb = dhcpv6_ia_free_assignment;
						a->iface = iface;
						a->flags = OAF_DHCPV6;

						if (first)
							memcpy(a->key, first->key, sizeof(a->key));
						else
							odhcpd_urandom(a->key, sizeof(a->key));

						if (is_pd && iface->dhcpv6_pd)
							while (!(assigned = assign_pd(iface, a)) &&
							       !a->managed_size && ++a->length <= 64);
						else if (is_na && iface->dhcpv6_na)
							assigned = assign_na(iface, a);

						if (l && assigned) {
							a->flags |= OAF_STATIC;

							if (l->hostname)
								a->hostname = strdup(l->hostname);

							if (l->leasetime)
								a->leasetime = l->leasetime;

							list_add(&a->lease_list, &l->assignments);
							a->lease = l;
						}

						if (a->managed_size && !assigned)
							return -1;
					}
				}
			}

			if (!assigned || iface->addr6_len == 0)
				/* Set error status */
				status = (is_pd) ? DHCPV6_STATUS_NOPREFIXAVAIL : DHCPV6_STATUS_NOADDRSAVAIL;
			else if (hdr->msg_type == DHCPV6_MSG_REQUEST && !dhcpv6_ia_on_link(ia, a, iface)) {
				/* Send NOTONLINK staus for the IA */
				status = DHCPV6_STATUS_NOTONLINK;
				assigned = false;
			} else if (accept_reconf && assigned && !first &&
					hdr->msg_type != DHCPV6_MSG_REBIND) {
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

			ia_response_len = build_ia(buf, buflen, status, ia, a, iface,
							hdr->msg_type == DHCPV6_MSG_REBIND ? false : true);

			/* Was only a solicitation: mark binding for removal */
			if (assigned && hdr->msg_type == DHCPV6_MSG_SOLICIT && !rapid_commit) {
				a->flags &= ~OAF_BOUND;
				a->flags |= OAF_TENTATIVE;

				if (!(a->flags & OAF_STATIC))
					/* Keep tentative assignment around for 60 seconds */
					a->valid_until = now + 60;

			} else if (assigned &&
				   ((hdr->msg_type == DHCPV6_MSG_SOLICIT && rapid_commit) ||
				    hdr->msg_type == DHCPV6_MSG_REQUEST ||
				    hdr->msg_type == DHCPV6_MSG_REBIND)) {
				if ((!(a->flags & OAF_STATIC) || !a->hostname) && hostname_len > 0) {
					a->hostname = realloc(a->hostname, hostname_len + 1);
					if (a->hostname) {
						memcpy(a->hostname, hostname, hostname_len);
						a->hostname[hostname_len] = 0;

						if (odhcpd_valid_hostname(a->hostname))
							a->flags &= ~OAF_BROKEN_HOSTNAME;
						else
							a->flags |= OAF_BROKEN_HOSTNAME;
					}
				}
				a->accept_reconf = accept_reconf;
				a->flags &= ~OAF_TENTATIVE;
				a->flags |= OAF_BOUND;
				apply_lease(iface, a, true);
			} else if (!assigned && a && a->managed_size == 0) {
				/* Cleanup failed assignment */
				free_assignment(a);
				a = NULL;
			}
		} else if (hdr->msg_type == DHCPV6_MSG_RENEW ||
				hdr->msg_type == DHCPV6_MSG_RELEASE ||
				hdr->msg_type == DHCPV6_MSG_REBIND ||
				hdr->msg_type == DHCPV6_MSG_DECLINE) {
			if (!a && hdr->msg_type != DHCPV6_MSG_REBIND) {
				status = DHCPV6_STATUS_NOBINDING;
				ia_response_len = build_ia(buf, buflen, status, ia, a, iface, false);
			} else if (hdr->msg_type == DHCPV6_MSG_RENEW ||
					hdr->msg_type == DHCPV6_MSG_REBIND) {
				ia_response_len = build_ia(buf, buflen, status, ia, a, iface, false);
				if (a) {
					a->flags |= OAF_BOUND;
					apply_lease(iface, a, true);
				}
			} else if (hdr->msg_type == DHCPV6_MSG_RELEASE) {
				if (!(a->flags & OAF_STATIC))
					a->valid_until = now - 1;

				if (a->flags & OAF_BOUND) {
					apply_lease(iface, a, false);
					a->flags &= ~OAF_BOUND;
				}
			} else if (hdr->msg_type == DHCPV6_MSG_DECLINE && a->length == 128) {
				a->flags &= ~OAF_BOUND;

				if (!(a->flags & OAF_STATIC)) {
					memset(a->clid_data, 0, a->clid_len);
					a->valid_until = now + 3600; /* Block address for 1h */
				}
			}
		} else if (hdr->msg_type == DHCPV6_MSG_CONFIRM) {
			if (ia_addr_present && !dhcpv6_ia_on_link(ia, a, iface)) {
				notonlink = true;
				break;
			}

			if (!ia_addr_present || !a || !(a->flags & OAF_BOUND)) {
				response_len = 0;
				goto out;
			}
		}

		buf += ia_response_len;
		buflen -= ia_response_len;
		response_len += ia_response_len;
		dhcpv6_log(hdr->msg_type, iface, now, duidbuf, is_pd, a, status);
	}

	switch (hdr->msg_type) {
	case DHCPV6_MSG_RELEASE:
	case DHCPV6_MSG_DECLINE:
	case DHCPV6_MSG_CONFIRM:
		if (response_len + 6 < buflen) {
			buf[0] = 0;
			buf[1] = DHCPV6_OPT_STATUS;
			buf[2] = 0;
			buf[3] = 2;
			buf[4] = 0;
			buf[5] = (notonlink) ? DHCPV6_STATUS_NOTONLINK : DHCPV6_STATUS_OK;
			response_len += 6;
		}
		break;

	default:
		break;
	}

	dhcpv6_ia_write_statefile();

out:
	return response_len;
}
