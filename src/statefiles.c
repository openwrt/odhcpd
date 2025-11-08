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

void dhcpv6_ia_enum_addrs(struct interface *iface, struct dhcpv6_lease *lease,
			  time_t now, dhcpv6_binding_cb_handler_t func, void *arg)
{
	struct odhcpd_ipaddr *addrs = iface->addr6;
	size_t m = get_preferred_addr(addrs, iface->addr6_len);

	for (size_t i = 0; i < iface->addr6_len; ++i) {
		struct in6_addr addr;
		uint32_t preferred_lt, valid_lt;
		int prefix = lease->length;

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

		if (lease->flags & OAF_DHCPV6_NA) {
			if (!ADDR_ENTRY_VALID_IA_ADDR(iface, i, m, addrs))
				continue;

			addr = in6_from_prefix_and_iid(&addrs[i], lease->assigned_host_id);
		} else {
			if (!valid_prefix_length(lease, addrs[i].prefix))
				continue;

			addr = addrs[i].addr.in6;
			addr.s6_addr32[1] |= htonl(lease->assigned_subnet_id);
			addr.s6_addr32[2] = addr.s6_addr32[3] = 0;
		}

		preferred_lt = addrs[i].preferred_lt;
		if (preferred_lt > (uint32_t)lease->preferred_until)
			preferred_lt = lease->preferred_until;

		if (preferred_lt > (uint32_t)lease->valid_until)
			preferred_lt = lease->valid_until;

		if (preferred_lt != UINT32_MAX)
			preferred_lt -= now;

		valid_lt = addrs[i].valid_lt;
		if (valid_lt > (uint32_t)lease->valid_until)
			valid_lt = lease->valid_until;

		if (valid_lt != UINT32_MAX)
			valid_lt -= now;

		func(lease, &addr, prefix, preferred_lt, valid_lt, arg);
	}
}

struct write_ctxt {
	FILE *fp;
	md5_ctx_t md5;
	struct interface *iface;
	time_t now; // CLOCK_MONOTONIC
	time_t wall_time;
	char *buf;
	int buf_len;
	int buf_idx;
};

static void dhcpv6_write_ia_addrhosts(struct dhcpv6_lease *lease, struct in6_addr *addr, int prefix,
				      _unused uint32_t pref_lt, _unused uint32_t valid_lt, void *arg)
{
	struct write_ctxt *ctxt = (struct write_ctxt *)arg;
	char ipbuf[INET6_ADDRSTRLEN];

	if ((lease->flags & OAF_DHCPV6_NA) && lease->hostname &&
	    !(lease->flags & OAF_BROKEN_HOSTNAME)) {
		inet_ntop(AF_INET6, addr, ipbuf, sizeof(ipbuf) - 1);
		fputs(ipbuf, ctxt->fp);

		char b[256];
		if (dn_expand(ctxt->iface->search, ctxt->iface->search + ctxt->iface->search_len,
				ctxt->iface->search, b, sizeof(b)) > 0)
			fprintf(ctxt->fp, "\t%s.%s", lease->hostname, b);

		fprintf(ctxt->fp, "\t%s\n", lease->hostname);
	}
}

static void dhcpv6_write_ia_addr(struct dhcpv6_lease *lease, struct in6_addr *addr, int prefix,
				 _unused uint32_t pref_lt, _unused uint32_t valid_lt, void *arg)
{
	struct write_ctxt *ctxt = (struct write_ctxt *)arg;
	char ipbuf[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, addr, ipbuf, sizeof(ipbuf) - 1);

	if ((lease->flags & OAF_DHCPV6_NA) && lease->hostname &&
	    !(lease->flags & OAF_BROKEN_HOSTNAME)) {
		fputs(ipbuf, ctxt->fp);

		char b[256];
		if (dn_expand(ctxt->iface->search, ctxt->iface->search + ctxt->iface->search_len,
				ctxt->iface->search, b, sizeof(b)) > 0)
			fprintf(ctxt->fp, "\t%s.%s", lease->hostname, b);

		fprintf(ctxt->fp, "\t%s\n", lease->hostname);
		md5_hash(ipbuf, strlen(ipbuf), &ctxt->md5);
		md5_hash(lease->hostname, strlen(lease->hostname), &ctxt->md5);
	}

	ctxt->buf_idx += snprintf(ctxt->buf + ctxt->buf_idx,ctxt->buf_len - ctxt->buf_idx,
					"%s/%d ", ipbuf, prefix);
}

static void statefiles_write_hosts(time_t now)
{
	struct write_ctxt ctxt;
	size_t tmp_hostsfile_strlen;
	char *tmp_hostsfile;
	int fd;

	if (config.dhcp_hostsdir_fd < 0 || !config.dhcp_hostsfile)
		return;

	tmp_hostsfile_strlen = strlen(config.dhcp_hostsfile) + 2;
	tmp_hostsfile = alloca(tmp_hostsfile_strlen);
	sprintf(tmp_hostsfile, ".%s", config.dhcp_hostsfile);

	fd = openat(config.dhcp_hostsdir_fd, tmp_hostsfile, O_CREAT | O_WRONLY | O_CLOEXEC, 0644);
	if (fd < 0)
		goto err;

	if (lockf(fd, F_LOCK, 0) < 0)
		goto err;

	if (ftruncate(fd, 0) < 0)
		goto err;

	ctxt.fp = fdopen(fd, "w");
	if (!ctxt.fp)
		goto err;

	avl_for_each_element(&interfaces, ctxt.iface, avl) {
		if (ctxt.iface->dhcpv6 == MODE_SERVER) {
			struct dhcpv6_lease *lease;

			list_for_each_entry(lease, &ctxt.iface->ia_assignments, head) {
				if (!(lease->flags & OAF_BOUND))
					continue;

				if (INFINITE_VALID(lease->valid_until) || lease->valid_until > now)
					dhcpv6_ia_enum_addrs(ctxt.iface, lease, now,
							     dhcpv6_write_ia_addrhosts, &ctxt);
			}
		}

		if (ctxt.iface->dhcpv4 == MODE_SERVER) {
			struct dhcpv4_lease *lease;

			list_for_each_entry(lease, &ctxt.iface->dhcpv4_leases, head) {
				if (!(lease->flags & OAF_BOUND))
					continue;

				char ipbuf[INET_ADDRSTRLEN];
				struct in_addr addr = { .s_addr = lease->addr };
				inet_ntop(AF_INET, &addr, ipbuf, sizeof(ipbuf) - 1);

				if (lease->hostname && !(lease->flags & OAF_BROKEN_HOSTNAME)) {
					fputs(ipbuf, ctxt.fp);

					char b[256];

					if (dn_expand(ctxt.iface->search,
							ctxt.iface->search + ctxt.iface->search_len,
							ctxt.iface->search, b, sizeof(b)) > 0)
						fprintf(ctxt.fp, "\t%s.%s", lease->hostname, b);

					fprintf(ctxt.fp, "\t%s\n", lease->hostname);
				}
			}
		}
	}

	fclose(ctxt.fp);
	renameat(config.dhcp_hostsdir_fd, tmp_hostsfile,
		 config.dhcp_hostsdir_fd, config.dhcp_hostsfile);
	return;

err:
	error("Unable to write hostsfile: %m");
	close(fd);
}

static void statefiles_write_dhcpv6_lease(struct write_ctxt *ctxt, struct dhcpv6_lease *lease)
{
	char duidbuf[DUID_HEXSTRLEN];

	odhcpd_hexlify(duidbuf, lease->clid_data, lease->clid_len);

	/* iface DUID iaid hostname lifetime assigned_host_id length [addrs...] */
	ctxt->buf_idx = snprintf(ctxt->buf, ctxt->buf_len, "# %s %s %x %s%s %"PRId64" ",
				 ctxt->iface->ifname, duidbuf, ntohl(lease->iaid),
				 (lease->flags & OAF_BROKEN_HOSTNAME) ? "broken\\x20" : "",
				 (lease->hostname ? lease->hostname : "-"),
				 (lease->valid_until > ctxt->now ?
				  (int64_t)(lease->valid_until - ctxt->now + ctxt->wall_time) :
				  (INFINITE_VALID(lease->valid_until) ? -1 : 0)));

	if (lease->flags & OAF_DHCPV6_NA)
		ctxt->buf_idx += snprintf(ctxt->buf + ctxt->buf_idx,
					  ctxt->buf_len - ctxt->buf_idx,
					  "%" PRIx64" %" PRIu8 " ",
					  lease->assigned_host_id, lease->length);
	else
		ctxt->buf_idx += snprintf(ctxt->buf + ctxt->buf_idx,
					  ctxt->buf_len - ctxt->buf_idx,
					  "%" PRIx32 " %" PRIu8 " ",
					  lease->assigned_subnet_id, lease->length);

	if (INFINITE_VALID(lease->valid_until) || lease->valid_until > ctxt->now)
		dhcpv6_ia_enum_addrs(ctxt->iface, lease, ctxt->now, dhcpv6_write_ia_addr, ctxt);

	ctxt->buf[ctxt->buf_idx - 1] = '\n';
	fwrite(ctxt->buf, 1, ctxt->buf_idx, ctxt->fp);
}

static void statefiles_write_dhcpv4_lease(struct write_ctxt *ctxt, struct dhcpv4_lease *c)
{
	char ipbuf[INET6_ADDRSTRLEN];
	char duidbuf[16];
	odhcpd_hexlify(duidbuf, c->hwaddr, sizeof(c->hwaddr));

	/* iface DUID iaid hostname lifetime assigned length [addrs...] */
	ctxt->buf_idx = snprintf(ctxt->buf, ctxt->buf_len, "# %s %s ipv4 %s%s %"PRId64" %x 32 ",
				 ctxt->iface->ifname, duidbuf,
				 (c->flags & OAF_BROKEN_HOSTNAME) ? "broken\\x20" : "",
				 (c->hostname ? c->hostname : "-"),
				 (c->valid_until > ctxt->now ?
				  (int64_t)(c->valid_until - ctxt->now + ctxt->wall_time) :
				  (INFINITE_VALID(c->valid_until) ? -1 : 0)),
				 ntohl(c->addr));

	struct in_addr addr = {.s_addr = c->addr};
	inet_ntop(AF_INET, &addr, ipbuf, sizeof(ipbuf) - 1);

	if (c->hostname && !(c->flags & OAF_BROKEN_HOSTNAME)) {
		fputs(ipbuf, ctxt->fp);

		char b[256];
		if (dn_expand(ctxt->iface->search,
			      ctxt->iface->search + ctxt->iface->search_len,
			      ctxt->iface->search, b, sizeof(b)) > 0)
			fprintf(ctxt->fp, "\t%s.%s", c->hostname, b);

		fprintf(ctxt->fp, "\t%s\n", c->hostname);
		md5_hash(ipbuf, strlen(ipbuf), &ctxt->md5);
		md5_hash(c->hostname, strlen(c->hostname), &ctxt->md5);
	}

	ctxt->buf_idx += snprintf(ctxt->buf + ctxt->buf_idx,
				  ctxt->buf_len - ctxt->buf_idx,
				  "%s/32 ", ipbuf);
	ctxt->buf[ctxt->buf_idx - 1] = '\n';
	fwrite(ctxt->buf, 1, ctxt->buf_idx, ctxt->fp);
}

static bool statefiles_write_state(time_t now)
{
	char leasebuf[512];
	struct write_ctxt ctxt = {
		.fp = NULL,
		.buf = leasebuf,
		.buf_len = sizeof(leasebuf),
		.now = now,
		.wall_time = time(NULL),
	};
	size_t tmp_statefile_strlen;
	char *tmp_statefile;
	uint8_t newmd5[16];
	int fd;

	if (config.dhcp_statedir_fd < 0 || !config.dhcp_statefile)
		return false;

	tmp_statefile_strlen = strlen(config.dhcp_statefile) + 2;
	tmp_statefile = alloca(tmp_statefile_strlen);
	sprintf(tmp_statefile, ".%s", config.dhcp_statefile);

	fd = openat(config.dhcp_statedir_fd, tmp_statefile, O_CREAT | O_WRONLY | O_CLOEXEC, 0644);
	if (fd < 0)
		goto err;

	if (lockf(fd, F_LOCK, 0) < 0)
		goto err;

	if (ftruncate(fd, 0) < 0)
		goto err;

	ctxt.fp = fdopen(fd, "w");
	if (!ctxt.fp)
		goto err;

	md5_begin(&ctxt.md5);

	avl_for_each_element(&interfaces, ctxt.iface, avl) {
		if (ctxt.iface->dhcpv6 == MODE_SERVER) {
			struct dhcpv6_lease *lease;

			list_for_each_entry(lease, &ctxt.iface->ia_assignments, head)
				if (lease->flags & OAF_BOUND)
					statefiles_write_dhcpv6_lease(&ctxt, lease);
		}

		if (ctxt.iface->dhcpv4 == MODE_SERVER) {
			struct dhcpv4_lease *lease;

			list_for_each_entry(lease, &ctxt.iface->dhcpv4_leases, head)
				if (lease->flags & OAF_BOUND)
					statefiles_write_dhcpv4_lease(&ctxt, lease);
		}
	}

	fclose(ctxt.fp);
	md5_end(newmd5, &ctxt.md5);

	renameat(config.dhcp_statedir_fd, tmp_statefile,
		 config.dhcp_statedir_fd, config.dhcp_statefile);

	if (!memcmp(newmd5, statemd5, sizeof(newmd5)))
		return false;

	memcpy(statemd5, newmd5, sizeof(statemd5));

	return true;

err:
	error("Unable to write statefile: %m");
	close(fd);
	return false;
}

bool statefiles_write()
{
	time_t now = odhcpd_time();

	if (!statefiles_write_state(now))
		return false;

	statefiles_write_hosts(now);

	if (config.dhcp_cb) {
		char *argv[2] = { config.dhcp_cb, NULL };
		if (!vfork()) {
			execv(argv[0], argv);
			_exit(128);
		}
	}

	return true;
}
