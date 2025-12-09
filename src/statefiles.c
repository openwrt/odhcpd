/*
 * SPDX-FileCopyrightText: 2013 Steven Barth <steven@midlink.org>
 * SPDX-FileCopyrightText: 2013 Hans Dedecker <dedeckeh@gmail.com>
 * SPDX-FileCopyrightText: 2022 Kevin Darbyshire-Bryant <ldir@darbyshire-bryant.me.uk>
 * SPDX-FileCopyrightText: 2024 Paul Donald <newtwen@gmail.com>
 * SPDX-FileCopyrightText: 2024 David Härdeman <david@hardeman.nu>
 * SPDX-FileCopyrightText: 2025 Álvaro Fernández Rojas <noltari@gmail.com>
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
#include <json-c/json.h>

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

	if (dirfd < 0 || !fpp || !*fpp)
		return;

	if (!prefix) {
		unlinkat(dirfd, ODHCPD_TMP_FILE, 0);
		fclose(*fpp);
		*fpp = NULL;
		return;
	}

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

#define JSON_LENGTH "length"
#define JSON_PREFIX "prefix"
#define JSON_SLAAC "slaac"
#define JSON_TIME "time"

static inline time_t statefiles_time_from_json(time_t json_time)
{
	time_t ref, now;

	ref = time(NULL);
	now = odhcpd_time();

	if (now > json_time || ref > json_time)
		return 0;

	return json_time + (now - ref);
}

static inline time_t statefiles_time_to_json(time_t config_time)
{
	time_t ref, now;

	ref = time(NULL);
	now = odhcpd_time();

	return config_time + (ref - now);
}

static inline bool statefiles_ra_pio_enabled(struct interface *iface)
{
	return config.ra_piodir_fd >= 0 && iface->ra == MODE_SERVER && !iface->master;
}

static bool statefiles_ra_pio_time(json_object *slaac_json, time_t *slaac_time)
{
	time_t pio_json_time, pio_time;
	json_object *time_json;

	time_json = json_object_object_get(slaac_json, JSON_TIME);
	if (!time_json)
		return true;

	pio_json_time = (time_t) json_object_get_int64(time_json);
	if (!pio_json_time)
		return true;

	pio_time = statefiles_time_from_json(pio_json_time);
	if (!pio_time)
		return false;

	*slaac_time = pio_time;

	return true;
}

static json_object *statefiles_load_ra_pio_json(struct interface *iface)
{
	json_object *json;
	char filename[strlen(ODHCPD_PIO_FILE_PREFIX) + strlen(".") + strlen(iface->ifname) + 1];
	int fd;

	sprintf(filename, "%s.%s", ODHCPD_PIO_FILE_PREFIX, iface->ifname);
	fd = openat(config.ra_piodir_fd, filename, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return NULL;

	json = json_object_from_fd(fd);

	close(fd);

	if (!json)
		error("rfc9096: %s: json read error %s",
		      iface->ifname,
		      json_util_get_last_err());

	return json;
}

void statefiles_read_prefix_information(struct interface *iface)
{
	json_object *json, *slaac_json;
	struct ra_pio *new_pios;
	size_t pio_cnt;
	time_t now;

	if (!statefiles_ra_pio_enabled(iface))
		return;

	json = statefiles_load_ra_pio_json(iface);
	if (!json)
		return;

	slaac_json = json_object_object_get(json, JSON_SLAAC);
	if (!slaac_json) {
		json_object_put(json);
		return;
	}

	now = odhcpd_time();

	pio_cnt = json_object_array_length(slaac_json);
	new_pios = realloc(iface->pios, sizeof(struct ra_pio) * pio_cnt);
	if (!new_pios) {
		json_object_put(json);
		return;
	}

	iface->pios = new_pios;
	iface->pio_cnt = 0;
	for (size_t i = 0; i < pio_cnt; i++) {
		json_object *cur_pio_json, *length_json, *prefix_json;
		const char *pio_str;
		time_t pio_lt = 0;
		struct ra_pio *pio;
		uint8_t pio_len;

		cur_pio_json = json_object_array_get_idx(slaac_json, i);
		if (!cur_pio_json)
			continue;

		if (!statefiles_ra_pio_time(cur_pio_json, &pio_lt))
			continue;

		length_json = json_object_object_get(cur_pio_json, JSON_LENGTH);
		if (!length_json)
			continue;

		prefix_json = json_object_object_get(cur_pio_json, JSON_PREFIX);
		if (!prefix_json)
			continue;

		pio_len = (uint8_t) json_object_get_uint64(length_json);
		pio_str = json_object_get_string(prefix_json);
		pio = &iface->pios[iface->pio_cnt];

		inet_pton(AF_INET6, pio_str, &pio->prefix);
		pio->length = pio_len;
		pio->lifetime = pio_lt;
		info("rfc9096: %s: load %s/%u (%u)",
		     iface->ifname,
		     pio_str,
		     pio_len,
		     ra_pio_lifetime(pio, now));

		iface->pio_cnt++;
	}

	json_object_put(json);

	if (!iface->pio_cnt) {
		free(iface->pios);
		iface->pios = NULL;
	} else if (iface->pio_cnt != pio_cnt) {
		struct ra_pio *tmp;

		tmp = realloc(iface->pios, sizeof(struct ra_pio) * iface->pio_cnt);
		if (tmp)
			iface->pios = tmp;
	}
}

void statefiles_write_prefix_information(struct interface *iface)
{
	struct json_object *json, *slaac_json;
	char ipv6_str[INET6_ADDRSTRLEN];
	time_t now;
	FILE *fp;

	if (!statefiles_ra_pio_enabled(iface))
		return;

	if (!iface->pio_update)
		return;

	fp = statefiles_open_tmp_file(config.ra_piodir_fd);
	if (!fp)
		return;

	now = odhcpd_time();

	json = json_object_new_object();
	if (!json)
		goto out;

	slaac_json = json_object_new_array_ext(iface->pio_cnt);
	if (!slaac_json)
		goto out;

	json_object_object_add(json, JSON_SLAAC, slaac_json);

	for (size_t i = 0; i < iface->pio_cnt; i++) {
		struct json_object *cur_pio_json, *len_json, *pfx_json;
		const struct ra_pio *cur_pio = &iface->pios[i];

		if (ra_pio_expired(cur_pio, now))
			continue;

		cur_pio_json = json_object_new_object();
		if (!cur_pio_json)
			continue;

		inet_ntop(AF_INET6, &cur_pio->prefix, ipv6_str, sizeof(ipv6_str));

		pfx_json = json_object_new_string(ipv6_str);
		if (!pfx_json) {
			json_object_put(cur_pio_json);
			continue;
		}

		len_json = json_object_new_uint64(cur_pio->length);
		if (!len_json) {
			json_object_put(cur_pio_json);
			json_object_put(pfx_json);
			continue;
		}

		json_object_object_add(cur_pio_json, JSON_PREFIX, pfx_json);
		json_object_object_add(cur_pio_json, JSON_LENGTH, len_json);

		if (cur_pio->lifetime) {
			struct json_object *time_json;
			time_t pio_lt;

			pio_lt = statefiles_time_to_json(cur_pio->lifetime);

			time_json = json_object_new_int64(pio_lt);
			if (time_json)
				json_object_object_add(cur_pio_json, JSON_TIME, time_json);
		}

		json_object_array_add(slaac_json, cur_pio_json);
	}

	if (json_object_to_fd(fileno(fp), json, JSON_C_TO_STRING_PLAIN)) {
		error("rfc9096: %s: json write error %s",
		      iface->ifname,
		      json_util_get_last_err());
		goto out;
	}

	statefiles_finish_tmp_file(config.ra_piodir_fd, &fp, ODHCPD_PIO_FILE_PREFIX, iface->ifname);
	iface->pio_update = false;
	warn("rfc9096: %s: piofile updated", iface->ifname);

out:
	json_object_put(json);
	statefiles_finish_tmp_file(config.ra_piodir_fd, &fp, NULL, NULL);
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
			lease->hostname_valid ? "" : "broken\\x20",
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
		lease->hostname_valid ? "" : "broken\\x20",
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

void statefiles_setup_dirfd(const char *path, int *dirfd)
{
	if (!dirfd)
		return;

	if (*dirfd >= 0) {
		close(*dirfd);
		*dirfd = -1;
	}

	if (!path)
		return;

	mkdir_p(strdupa(path), 0755);

	*dirfd = open(path, O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (*dirfd < 0)
		error("Unable to open directory '%s': %m", path);
}
