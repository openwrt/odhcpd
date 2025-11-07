/*
 * SPDX-FileCopyrightText: 2013 Steven Barth <steven@midlink.org>
 * SPDX-FileCopyrightText: 2013 Hans Dedecker <dedeckeh@gmail.com>
 * SPDX-FileCopyrightText: 2022 Kevin Darbyshire-Bryant <ldir@darbyshire-bryant.me.uk>
 * SPDX-FileCopyrightText: 2024 Paul Donald <newtwen@gmail.com>
 * SPDX-FileCopyrightText: 2024 David Härdeman <david@hardeman.nu>
 *
 * SPDX-License-Identifier: GPL2.0-only
 */

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <libgen.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <resolv.h>

#include <libubox/md5.h>

#include "odhcpd.h"
#include "dhcpv6-ia.h"
#include "statefiles.h"

static uint8_t statemd5[16];

void dhcpv6_ia_enum_addrs(struct interface *iface, struct dhcpv6_lease *c,
			  time_t now, dhcpv6_binding_cb_handler_t func, void *arg)
{
	struct odhcpd_ipaddr *addrs = iface->addr6;
	size_t m = get_preferred_addr(addrs, iface->addr6_len);

	for (size_t i = 0; i < iface->addr6_len; ++i) {
		struct in6_addr addr;
		uint32_t preferred_lt, valid_lt;
		int prefix = c->length;

		if (!valid_addr(&addrs[i], now))
			continue;

		/* Filter Out Prefixes */
		if (ADDR_MATCH_PIO_FILTER(&addrs[i], iface)) {
			char addrbuf[INET6_ADDRSTRLEN];
			info("Address %s filtered out on %s",
			     inet_ntop(AF_INET6, &addrs[i].addr.in6, addrbuf, sizeof(addrbuf)),
			     iface->name);
			continue;
		}

		if (c->flags & OAF_DHCPV6_NA) {
			if (!ADDR_ENTRY_VALID_IA_ADDR(iface, i, m, addrs))
				continue;

			addr = in6_from_prefix_and_iid(&addrs[i], c->assigned_host_id);
		} else {
			if (!valid_prefix_length(c, addrs[i].prefix))
				continue;

			addr = addrs[i].addr.in6;
			addr.s6_addr32[1] |= htonl(c->assigned_subnet_id);
			addr.s6_addr32[2] = addr.s6_addr32[3] = 0;
		}

		preferred_lt = addrs[i].preferred_lt;
		if (preferred_lt > (uint32_t)c->preferred_until)
			preferred_lt = c->preferred_until;

		if (preferred_lt > (uint32_t)c->valid_until)
			preferred_lt = c->valid_until;

		if (preferred_lt != UINT32_MAX)
			preferred_lt -= now;

		valid_lt = addrs[i].valid_lt;
		if (valid_lt > (uint32_t)c->valid_until)
			valid_lt = c->valid_until;

		if (valid_lt != UINT32_MAX)
			valid_lt -= now;

		func(&addr, prefix, preferred_lt, valid_lt, arg);
	}
}

struct write_ctxt {
	FILE *fp;
	md5_ctx_t md5;
	struct dhcpv6_lease *c;
	struct interface *iface;
	char *buf;
	int buf_len;
	int buf_idx;
};

static void dhcpv6_write_ia_addrhosts(struct in6_addr *addr, int prefix, _unused uint32_t pref_lt,
				_unused uint32_t valid_lt, void *arg)
{
	struct write_ctxt *ctxt = (struct write_ctxt *)arg;
	char ipbuf[INET6_ADDRSTRLEN];

	if ((ctxt->c->flags & OAF_DHCPV6_NA) && ctxt->c->hostname &&
	    !(ctxt->c->flags & OAF_BROKEN_HOSTNAME)) {
		inet_ntop(AF_INET6, addr, ipbuf, sizeof(ipbuf) - 1);
		fputs(ipbuf, ctxt->fp);

		char b[256];
		if (dn_expand(ctxt->iface->search, ctxt->iface->search + ctxt->iface->search_len,
				ctxt->iface->search, b, sizeof(b)) > 0)
			fprintf(ctxt->fp, "\t%s.%s", ctxt->c->hostname, b);

		fprintf(ctxt->fp, "\t%s\n", ctxt->c->hostname);
	}
}

static void dhcpv6_write_ia_addr(struct in6_addr *addr, int prefix, _unused uint32_t pref_lt,
				_unused uint32_t valid_lt, void *arg)
{
	struct write_ctxt *ctxt = (struct write_ctxt *)arg;
	char ipbuf[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, addr, ipbuf, sizeof(ipbuf) - 1);

	if ((ctxt->c->flags & OAF_DHCPV6_NA) && ctxt->c->hostname &&
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

static void dhcpv6_ia_write_hostsfile(time_t now)
{
	struct write_ctxt ctxt;

	unsigned hostsfile_strlen = strlen(config.dhcp_hostsfile) + 1;
	unsigned tmp_hostsfile_strlen = hostsfile_strlen + 1; /* space for . */
	char *tmp_hostsfile = alloca(tmp_hostsfile_strlen);

	char *dir_hostsfile;
	char *base_hostsfile;
	char *pdir_hostsfile;
	char *pbase_hostsfile;

	int fd, ret;

	dir_hostsfile = strndup(config.dhcp_hostsfile, hostsfile_strlen);
	base_hostsfile = strndup(config.dhcp_hostsfile, hostsfile_strlen);

	pdir_hostsfile = dirname(dir_hostsfile);
	pbase_hostsfile = basename(base_hostsfile);

	snprintf(tmp_hostsfile, tmp_hostsfile_strlen, "%s/.%s", pdir_hostsfile, pbase_hostsfile);

	free(dir_hostsfile);
	free(base_hostsfile);

	fd = open(tmp_hostsfile, O_CREAT | O_WRONLY | O_CLOEXEC, 0644);
	if (fd < 0)
		return;

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

	avl_for_each_element(&interfaces, ctxt.iface, avl) {
		if (ctxt.iface->dhcpv6 != MODE_SERVER &&
				ctxt.iface->dhcpv4 != MODE_SERVER)
			continue;

		if (ctxt.iface->dhcpv6 == MODE_SERVER) {
			list_for_each_entry(ctxt.c, &ctxt.iface->ia_assignments, head) {
				if (!(ctxt.c->flags & OAF_BOUND))
					continue;

				if (INFINITE_VALID(ctxt.c->valid_until) || ctxt.c->valid_until > now)
					dhcpv6_ia_enum_addrs(ctxt.iface, ctxt.c, now,
							     dhcpv6_write_ia_addrhosts, &ctxt);
			}
		}

		if (ctxt.iface->dhcpv4 == MODE_SERVER) {
			struct dhcpv4_lease *c;

			list_for_each_entry(c, &ctxt.iface->dhcpv4_leases, head) {
				if (!(c->flags & OAF_BOUND))
					continue;

				char ipbuf[INET_ADDRSTRLEN];
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
				}
			}
		}
	}

	fclose(ctxt.fp);

	rename(tmp_hostsfile, config.dhcp_hostsfile);
}

void dhcpv6_ia_write_statefile(void)
{
	struct write_ctxt ctxt;

	md5_begin(&ctxt.md5);

	if (config.dhcp_statefile) {
		unsigned statefile_strlen = strlen(config.dhcp_statefile) + 1;
		unsigned tmp_statefile_strlen = statefile_strlen + 1; /* space for . */
		char *tmp_statefile = alloca(tmp_statefile_strlen);

		char *dir_statefile;
		char *base_statefile;
		char *pdir_statefile;
		char *pbase_statefile;

		time_t now = odhcpd_time(), wall_time = time(NULL);
		int fd, ret;
		char leasebuf[512];

		dir_statefile = strndup(config.dhcp_statefile, statefile_strlen);
		base_statefile = strndup(config.dhcp_statefile, statefile_strlen);

		pdir_statefile = dirname(dir_statefile);
		pbase_statefile = basename(base_statefile);

		snprintf(tmp_statefile, tmp_statefile_strlen, "%s/.%s", pdir_statefile, pbase_statefile);

		free(dir_statefile);
		free(base_statefile);

		fd = open(tmp_statefile, O_CREAT | O_WRONLY | O_CLOEXEC, 0644);
		if (fd < 0)
			return;

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
					if (!(ctxt.c->flags & OAF_BOUND))
						continue;

					char duidbuf[DUID_HEXSTRLEN];

					odhcpd_hexlify(duidbuf, ctxt.c->clid_data, ctxt.c->clid_len);

					/* iface DUID iaid hostname lifetime assigned_host_id length [addrs...] */
					ctxt.buf_idx = snprintf(ctxt.buf, ctxt.buf_len, "# %s %s %x %s%s %"PRId64" ",
								ctxt.iface->ifname, duidbuf, ntohl(ctxt.c->iaid),
								(ctxt.c->flags & OAF_BROKEN_HOSTNAME) ? "broken\\x20" : "",
								(ctxt.c->hostname ? ctxt.c->hostname : "-"),
								(ctxt.c->valid_until > now ?
									(int64_t)(ctxt.c->valid_until - now + wall_time) :
									(INFINITE_VALID(ctxt.c->valid_until) ? -1 : 0)));

					if (ctxt.c->flags & OAF_DHCPV6_NA)
						ctxt.buf_idx += snprintf(ctxt.buf + ctxt.buf_idx, ctxt.buf_len - ctxt.buf_idx,
									 "%" PRIx64" %u ", ctxt.c->assigned_host_id, (unsigned)ctxt.c->length);
					else
						ctxt.buf_idx += snprintf(ctxt.buf + ctxt.buf_idx, ctxt.buf_len - ctxt.buf_idx,
									 "%" PRIx32" %u ", ctxt.c->assigned_subnet_id, (unsigned)ctxt.c->length);

					if (INFINITE_VALID(ctxt.c->valid_until) || ctxt.c->valid_until > now)
						dhcpv6_ia_enum_addrs(ctxt.iface, ctxt.c, now,
									dhcpv6_write_ia_addr, &ctxt);

					ctxt.buf[ctxt.buf_idx - 1] = '\n';
					fwrite(ctxt.buf, 1, ctxt.buf_idx, ctxt.fp);
				}
			}

			if (ctxt.iface->dhcpv4 == MODE_SERVER) {
				struct dhcpv4_lease *c;

				list_for_each_entry(c, &ctxt.iface->dhcpv4_leases, head) {
					if (!(c->flags & OAF_BOUND))
						continue;

					char ipbuf[INET6_ADDRSTRLEN];
					char duidbuf[16];
					odhcpd_hexlify(duidbuf, c->hwaddr, sizeof(c->hwaddr));

					/* iface DUID iaid hostname lifetime assigned length [addrs...] */
					ctxt.buf_idx = snprintf(ctxt.buf, ctxt.buf_len, "# %s %s ipv4 %s%s %"PRId64" %x 32 ",
								ctxt.iface->ifname, duidbuf,
								(c->flags & OAF_BROKEN_HOSTNAME) ? "broken\\x20" : "",
								(c->hostname ? c->hostname : "-"),
								(c->valid_until > now ?
									(int64_t)(c->valid_until - now + wall_time) :
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

		uint8_t newmd5[16];
		md5_end(newmd5, &ctxt.md5);

		rename(tmp_statefile, config.dhcp_statefile);

		if (memcmp(newmd5, statemd5, sizeof(newmd5))) {
			memcpy(statemd5, newmd5, sizeof(statemd5));

			if (config.dhcp_hostsfile)
				dhcpv6_ia_write_hostsfile(now);

			if (config.dhcp_cb) {
				char *argv[2] = {config.dhcp_cb, NULL};
				if (!vfork()) {
					execv(argv[0], argv);
					_exit(128);
				}
			}
		}
	}
}

