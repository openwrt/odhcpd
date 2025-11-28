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
#include <netinet/ether.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <spawn.h>

#include <libubox/md5.h>

#include "odhcpd.h"
#include "dhcpv6-ia.h"
#include "statefiles.h"

static uint8_t statemd5[16];

struct write_ctxt {
	FILE *fp;
	md5_ctx_t md5;
	struct interface *iface;
	time_t now; // CLOCK_MONOTONIC
	time_t wall_time;
};

static FILE *statefiles_open_tmp_file(int dirfd)
{
	int fd;
	FILE *fp;

	if (dirfd < 0)
		return NULL;

	fd = openat(dirfd, ODHCPD_TMP_FILE, O_CREAT | O_WRONLY | O_CLOEXEC, 0644);
	if (fd < 0)
		goto err;

	if (lockf(fd, F_LOCK, 0) < 0)
		goto err;

	if (ftruncate(fd, 0) < 0)
		goto err_del;

	fp = fdopen(fd, "w");
	if (!fp)
		goto err_del;

	return fp;

err_del:
	unlinkat(dirfd, ODHCPD_TMP_FILE, 0);
err:
	close(fd);
	error("Failed to create temporary file: %m");
	return NULL;
}

static void statefiles_finish_tmp_file(int dirfd, FILE **fpp, const char *prefix, const char *suffix)
{
	char *filename;

	if (dirfd < 0 || !fpp || !*fpp || !prefix)
		return;

	if (fflush(*fpp))
		error("Error flushing tmpfile: %m");

	if (fsync(fileno(*fpp)) < 0)
		error("Error synching tmpfile: %m");

	fclose(*fpp);
	*fpp = NULL;

	if (suffix) {
		filename = alloca(strlen(prefix) + strlen(".") + strlen(suffix) + 1);
		sprintf(filename, "%s.%s", prefix, suffix);
	} else {
		filename = alloca(strlen(prefix) + 1);
		sprintf(filename, "%s", prefix);
	}

	renameat(dirfd, ODHCPD_TMP_FILE, dirfd, filename);
}

static void statefiles_write_host(const char *ipbuf, const char *hostname, struct write_ctxt *ctxt)
{
	char exp_dn[DNS_MAX_NAME_LEN];

	if (dn_expand(ctxt->iface->dns_search, ctxt->iface->dns_search + ctxt->iface->dns_search_len,
		      ctxt->iface->dns_search, exp_dn, sizeof(exp_dn)) > 0)
		fprintf(ctxt->fp, "%s\t%s.%s\t%s\n", ipbuf, hostname, exp_dn, hostname);
	else
		fprintf(ctxt->fp, "%s\t%s\n", ipbuf, hostname);
}

static bool statefiles_write_host6(struct write_ctxt *ctxt, struct dhcpv6_lease *lease,
				   struct in6_addr *addr)
{
	char ipbuf[INET6_ADDRSTRLEN];

	if (!lease->hostname || !lease->hostname_valid || !(lease->flags & OAF_DHCPV6_NA))
		return false;

	if (ctxt->fp) {
		inet_ntop(AF_INET6, addr, ipbuf, sizeof(ipbuf));
		statefiles_write_host(ipbuf, lease->hostname, ctxt);
	}

	return true;
}

static void statefiles_write_host6_cb(struct dhcpv6_lease *lease, struct in6_addr *addr, _o_unused uint8_t prefix_len,
				      _o_unused uint32_t pref_lt, _o_unused uint32_t valid_lt, void *arg)
{
	struct write_ctxt *ctxt = (struct write_ctxt *)arg;

	statefiles_write_host6(ctxt, lease, addr);
}

static bool statefiles_write_host4(struct write_ctxt *ctxt, struct dhcpv4_lease *lease)
{
	char ipbuf[INET_ADDRSTRLEN];

	if (!lease->hostname || !lease->hostname_valid)
		return false;

	if (ctxt->fp) {
		inet_ntop(AF_INET, &lease->ipv4, ipbuf, sizeof(ipbuf));
		statefiles_write_host(ipbuf, lease->hostname, ctxt);
	}

	return true;
}

static void statefiles_write_hosts(time_t now)
{
	struct write_ctxt ctxt;

	if (config.dhcp_hostsdir_fd < 0)
		return;

	avl_for_each_element(&interfaces, ctxt.iface, avl) {
		ctxt.fp = statefiles_open_tmp_file(config.dhcp_hostsdir_fd);

		if (ctxt.iface->dhcpv6 == MODE_SERVER) {
			struct dhcpv6_lease *lease;

			list_for_each_entry(lease, &ctxt.iface->ia_assignments, head) {
				if (!lease->bound)
					continue;

				if (!INFINITE_VALID(lease->valid_until) && lease->valid_until <= now)
					continue;

				odhcpd_enum_addr6(ctxt.iface, lease, now,
						  statefiles_write_host6_cb, &ctxt);
			}
		}

		if (ctxt.iface->dhcpv4 == MODE_SERVER) {
			struct dhcpv4_lease *lease;

			avl_for_each_element(&ctxt.iface->dhcpv4_leases, lease, iface_avl) {
				if (!lease->bound)
					continue;

				if (!INFINITE_VALID(lease->valid_until) && lease->valid_until <= now)
					continue;

				statefiles_write_host4(&ctxt, lease);
			}
		}

		statefiles_finish_tmp_file(config.dhcp_hostsdir_fd, &ctxt.fp,
					   ODHCPD_HOSTS_FILE_PREFIX, ctxt.iface->name);
	}
}

static void statefiles_write_state6_addr(struct dhcpv6_lease *lease, struct in6_addr *addr, uint8_t prefix_len,
					 _o_unused uint32_t pref_lt, _o_unused uint32_t valid_lt, void *arg)
{
	struct write_ctxt *ctxt = (struct write_ctxt *)arg;
	char ipbuf[INET6_ADDRSTRLEN];

	if (lease->hostname && lease->hostname_valid && lease->flags & OAF_DHCPV6_NA) {
		md5_hash(addr, sizeof(*addr), &ctxt->md5);
		md5_hash(lease->hostname, strlen(lease->hostname), &ctxt->md5);
	}

	if (!ctxt->fp)
		return;

	inet_ntop(AF_INET6, addr, ipbuf, sizeof(ipbuf));
	fprintf(ctxt->fp, " %s/%" PRIu8, ipbuf, prefix_len);
}

static void statefiles_write_state6(struct write_ctxt *ctxt, struct dhcpv6_lease *lease)
{
	char duidbuf[DUID_HEXSTRLEN];

	if (ctxt->fp) {
		odhcpd_hexlify(duidbuf, lease->duid, lease->duid_len);

		/* # <iface> <hexduid> <hexiaid> <hostname> <valid_until> <assigned_[host|subnet]_id> <pfx_length> [<addrs> ...] */
		fprintf(ctxt->fp,
			"# %s %s %x %s%s %" PRId64 " %" PRIx64 " %" PRIu8,
			ctxt->iface->ifname, duidbuf, ntohl(lease->iaid),
			lease->hostname_valid ? "" : "broken\x20",
			lease->hostname ? lease->hostname : "-",
			(lease->valid_until > ctxt->now ?
			 (int64_t)(lease->valid_until - ctxt->now + ctxt->wall_time) :
			 (INFINITE_VALID(lease->valid_until) ? -1 : 0)),
			(lease->flags & OAF_DHCPV6_NA ?
			 lease->assigned_host_id :
			 (uint64_t)lease->assigned_subnet_id),
			lease->length);
	}

	odhcpd_enum_addr6(ctxt->iface, lease, ctxt->now, statefiles_write_state6_addr, ctxt);

	if (ctxt->fp)
		putc('\n', ctxt->fp);
}

static void statefiles_write_state4(struct write_ctxt *ctxt, struct dhcpv4_lease *lease)
{
	char ipbuf[INET6_ADDRSTRLEN];

	if (lease->hostname && lease->hostname_valid) {
		md5_hash(&lease->ipv4, sizeof(lease->ipv4), &ctxt->md5);
		md5_hash(lease->hostname, strlen(lease->hostname), &ctxt->md5);
	}

	if (!ctxt->fp)
		return;

	inet_ntop(AF_INET, &lease->ipv4, ipbuf, sizeof(ipbuf));

	/* # <iface> <hexhwaddr> "ipv4" <hostname> <valid_until> <hexaddr> "32" <addrstr>"/32" */
	fprintf(ctxt->fp,
		"# %s %s ipv4 %s%s %" PRId64 " %x 32 %s/32\n",
		ctxt->iface->ifname,
		ether_ntoa((struct ether_addr *)lease->hwaddr),
		lease->hostname_valid ? "" : "broken\x20",
		lease->hostname ? lease->hostname : "-",
		(lease->valid_until > ctxt->now ?
		 (int64_t)(lease->valid_until - ctxt->now + ctxt->wall_time) :
		 (INFINITE_VALID(lease->valid_until) ? -1 : 0)),
		ntohl(lease->ipv4.s_addr), ipbuf);
}

/* Returns true if there are changes to be written to the hosts file(s) */
static bool statefiles_write_state(time_t now)
{
	struct write_ctxt ctxt = {
		.fp = NULL,
		.now = now,
		.wall_time = time(NULL),
	};
	uint8_t newmd5[16];

	ctxt.fp = statefiles_open_tmp_file(config.dhcp_statedir_fd);

	md5_begin(&ctxt.md5);

	avl_for_each_element(&interfaces, ctxt.iface, avl) {
		if (ctxt.iface->dhcpv6 == MODE_SERVER) {
			struct dhcpv6_lease *lease;

			list_for_each_entry(lease, &ctxt.iface->ia_assignments, head) {
				if (!lease->bound)
					continue;

				if (!INFINITE_VALID(lease->valid_until) && lease->valid_until <= now)
					continue;

				statefiles_write_state6(&ctxt, lease);
			}
		}

		if (ctxt.iface->dhcpv4 == MODE_SERVER) {
			struct dhcpv4_lease *lease;

			avl_for_each_element(&ctxt.iface->dhcpv4_leases, lease, iface_avl) {
				if (!lease->bound)
					continue;

				if (!INFINITE_VALID(lease->valid_until) && lease->valid_until <= now)
					continue;

				statefiles_write_state4(&ctxt, lease);
			}
		}
	}

	statefiles_finish_tmp_file(config.dhcp_statedir_fd, &ctxt.fp, config.dhcp_statefile, NULL);

	md5_end(newmd5, &ctxt.md5);
	if (!memcmp(newmd5, statemd5, sizeof(newmd5)))
		return false;

	memcpy(statemd5, newmd5, sizeof(statemd5));
	return true;
}

bool statefiles_write()
{
	time_t now = odhcpd_time();

	if (!statefiles_write_state(now))
		return false;

	statefiles_write_hosts(now);

	if (config.dhcp_cb) {
		char *argv[2] = { config.dhcp_cb, NULL };
		pid_t pid;

		posix_spawn(&pid, argv[0], NULL, NULL, argv, environ);
	}

	return true;
}
