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
#include "dhcpv4.h"
#include "statefiles.h"

static uint8_t statemd5[16];

struct write_ctxt {
	FILE *fp;
	md5_ctx_t md5;
	struct interface *iface;
	time_t now; // CLOCK_MONOTONIC
	time_t wall_time;
};

static FILE *statefiles_open_file(int dirfd, const char *prefix, const char *suffix)
{
	char filename[strlen(prefix) + strlen(".") + strlen(suffix) + 1];
	int fd;
	FILE *fp;

	if (dirfd < 0)
		return NULL;

	sprintf(filename, "%s.%s", prefix, suffix);

	fd = openat(dirfd, filename, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return NULL;

	if (lockf(fd, F_LOCK, 0) < 0)
		goto err;

	fp = fdopen(fd, "r");
	if (!fp)
		goto err;

	return fp;

err:
	close(fd);
	return NULL;
}

static void statefiles_rm_file(int dirfd, const char *prefix, const char *suffix)
{
	char filename[strlen(prefix) + strlen(".") + strlen(suffix) + 1];

	if (dirfd < 0)
		return;

	sprintf(filename, "%s.%s", prefix, suffix);
	unlinkat(dirfd, filename, 0);
}

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

	if (!lease->hostname || !lease->hostname_valid || lease->type != DHCPV6_IA_NA)
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
		if (ctxt.iface->ignore)
			continue;

		if (ctxt.iface->dhcpv4 != MODE_SERVER && ctxt.iface->dhcpv6 != MODE_SERVER)
			continue;

		ctxt.fp = statefiles_open_tmp_file(config.dhcp_hostsdir_fd);
		if (!ctxt.fp)
			continue;

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

static void statefiles_write_lease6_addr(struct dhcpv6_lease *lease, struct in6_addr *addr, uint8_t prefix_len,
					 _o_unused uint32_t pref_lt, _o_unused uint32_t valid_lt, void *arg)
{
	struct write_ctxt *ctxt = (struct write_ctxt *)arg;
	char ipbuf[INET6_ADDRSTRLEN];

	if (lease->hostname && lease->hostname_valid && lease->type == DHCPV6_IA_NA) {
		md5_hash(addr, sizeof(*addr), &ctxt->md5);
		md5_hash(lease->hostname, strlen(lease->hostname), &ctxt->md5);
	}

	if (!ctxt->fp)
		return;

	inet_ntop(AF_INET6, addr, ipbuf, sizeof(ipbuf));
	fprintf(ctxt->fp, " %s/%" PRIu8, ipbuf, prefix_len);
}

static void statefiles_write_lease6(struct write_ctxt *ctxt, struct dhcpv6_lease *lease)
{
	char duidbuf[DUID_HEXSTRLEN];

	if (ctxt->fp) {
		odhcpd_hexlify(duidbuf, lease->duid, lease->duid_len);

		/* # <iface> <hexduid> <hexiaid> <hostname> <valid_until> <assigned_[host|subnet]_id> <pfx_length> [<addrs> ...] */
		fprintf(ctxt->fp,
			"# %s %s %x %s%s %" PRId64 " %" PRIx64 " %" PRIu8,
			ctxt->iface->ifname, duidbuf, ntohl(lease->iaid),
			lease->hostname && !lease->hostname_valid ? "broken\\x20": "",
			lease->hostname ? lease->hostname : "-",
			(lease->valid_until > ctxt->now ?
			 (int64_t)(lease->valid_until - ctxt->now + ctxt->wall_time) :
			 (INFINITE_VALID(lease->valid_until) ? -1 : 0)),
			lease->type == DHCPV6_IA_NA ?
			lease->assigned_host_id : (uint64_t)lease->assigned_subnet_id,
			lease->type == DHCPV6_IA_NA ?
			128 : lease->prefix_len);
	}

	odhcpd_enum_addr6(ctxt->iface, lease, ctxt->now, statefiles_write_lease6_addr, ctxt);

	if (ctxt->fp)
		putc('\n', ctxt->fp);
}

static void statefiles_write_lease4(struct write_ctxt *ctxt, struct dhcpv4_lease *lease)
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
		ether_ntoa(&lease->macaddr),
		lease->hostname && !lease->hostname_valid ? "broken\\x20" : "",
		lease->hostname ? lease->hostname : "-",
		(lease->valid_until > ctxt->now ?
		 (int64_t)(lease->valid_until - ctxt->now + ctxt->wall_time) :
		 (INFINITE_VALID(lease->valid_until) ? -1 : 0)),
		ntohl(lease->ipv4.s_addr), ipbuf);
}

/* Returns true if there are changes to be written to the hosts file(s) */
static bool statefiles_write_leases(time_t now)
{
	struct write_ctxt ctxt = {
		.fp = NULL,
		.now = now,
		.wall_time = time(NULL),
	};
	uint8_t newmd5[16];

	/* Return value unchecked, continue in order to get the md5 */
	ctxt.fp = statefiles_open_tmp_file(config.dhcp_leasefiledir_fd);

	md5_begin(&ctxt.md5);

	avl_for_each_element(&interfaces, ctxt.iface, avl) {
		if (ctxt.iface->dhcpv6 == MODE_SERVER) {
			struct dhcpv6_lease *lease;

			list_for_each_entry(lease, &ctxt.iface->ia_assignments, head) {
				if (!lease->bound)
					continue;

				if (!INFINITE_VALID(lease->valid_until) && lease->valid_until <= now)
					continue;

				statefiles_write_lease6(&ctxt, lease);
			}
		}

		if (ctxt.iface->dhcpv4 == MODE_SERVER) {
			struct dhcpv4_lease *lease;

			avl_for_each_element(&ctxt.iface->dhcpv4_leases, lease, iface_avl) {
				if (!lease->bound)
					continue;

				if (!INFINITE_VALID(lease->valid_until) && lease->valid_until <= now)
					continue;

				statefiles_write_lease4(&ctxt, lease);
			}
		}
	}

	statefiles_finish_tmp_file(config.dhcp_leasefiledir_fd, &ctxt.fp, config.dhcp_leasefile, NULL);

	md5_end(newmd5, &ctxt.md5);
	if (!memcmp(newmd5, statemd5, sizeof(newmd5)))
		return false;

	memcpy(statemd5, newmd5, sizeof(statemd5));
	return true;
}

#define STATEFILE_VERSION_STR "# STATEFILE_VERSION="
#define STATEFILE_BOOTID_STR "# BOOT_ID="

static time_t
statefiles_double_ts_to_monotime(bool rebooted, int64_t monotime, int64_t time_t_time)
{
	if (!rebooted)
		return (time_t)monotime;
	else if (INFINITE_VALID((time_t)time_t_time))
		return 0;
	else
		return statefiles_time_from_json((time_t)time_t_time);
}

static void
statefiles_read_state6(FILE *fp, struct interface *iface, const char *line,
		       time_t now, bool rebooted)
{
	int lease_type;
	int64_t valid_mono, valid_time_t;
	int64_t preferred_mono, preferred_time_t;
	uint16_t peer_port;
	uint32_t peer_flowinfo;
	char peer_addr_str[INET6_ADDRSTRLEN];
	uint32_t peer_scope_id;
	unsigned bound;
	uint32_t leasetime;
	unsigned hostname_valid;
	char hostname[DNS_MAX_NAME_LEN];
	uint32_t iaid;
	uint16_t duid_len;
	char duidbuf[DUID_HEXSTRLEN];
	uint8_t duid[DUID_MAX_LEN];
	unsigned accept_fr;
	char fr_key_buf[33];
	uint8_t fr_key[16];
	uint64_t assigned_id;
	uint8_t prefix_len;
	size_t ias_cnt;
	unsigned offset;
	int r;

	r = sscanf(line, "dhcpv6 %i %" SCNi64 " %" SCNi64 " %" SCNi64 " %" SCNi64
		" %" SCNu16 " %" SCNu32 " %s %" SCNu32 " %u %" SCNu32
		" %u %s %" SCNu32 " %" SCNu16 " %s %u %s %" SCNu64 " %" SCNu8 " %zu %n",
		&lease_type,
		&valid_mono,
		&valid_time_t,
		&preferred_mono,
		&preferred_time_t,
		/* line */
		&peer_port,
		&peer_flowinfo,
		peer_addr_str,
		&peer_scope_id,
		&bound,
		&leasetime,
		/* line */
		&hostname_valid,
		hostname,
		&iaid,
		&duid_len,
		duidbuf,
		&accept_fr,
		fr_key_buf,
		&assigned_id,
		&prefix_len,
		&ias_cnt,
		&offset);

	debug("Read a dhcpv6 line: result %i, offset %u", r, offset);
	if (r != 21)
		return;

	fprintf(stderr, "Found a stored dhcpv6 lease\n"
		"iface		: %s\n"
		"type		: %i\n"
		"valid_mono	: %" PRIi64 "\n"
		"valid_time_t	: %" PRIi64 "\n"
		"pref_mono	: %" PRIi64 "\n"
		"pref_time_t:	: %" PRIi64 "\n"
		"peer_port	: %" PRIu16 "\n"
		"peer_flowinfo	: %" PRIu32 "\n"
		"peer_addr	: %s\n"
		"peer_scope_id	: %" PRIu32 "\n"
		"bound		: %s\n"
		"leasetime	: %" PRIu32 "\n"
		"valid_hostname	: %s\n"
		"hostname	: %s\n"
		"IAID		: %" PRIu32 "\n"
		"DUID-len	: %" PRIu8 "\n"
		"DUID		: %s\n"
		"Accept FR	: %s\n"
		"FR key		: %s\n"
		"Assiged ID	: %" PRIu64 "\n"
		"Prefix len	: %" PRIu8 "\n"
		"IAS count	: %zu\n",
		iface->ifname,
		lease_type,
		valid_mono,
		valid_time_t,
		preferred_mono,
		preferred_time_t,
		peer_port,
		peer_flowinfo,
		peer_addr_str,
		peer_scope_id,
		bound ? "true" : "false",
		leasetime,
		hostname_valid ? "true" : "false",
		hostname,
		iaid,
		duid_len,
		duidbuf,
		accept_fr ? "true" : "false",
		fr_key_buf,
		assigned_id,
		prefix_len,
		ias_cnt);

	struct dhcpv6_ia ias[ias_cnt];

	for (size_t i = 0; i < ias_cnt; i++) {
		int64_t ias_valid_mono, ias_valid_time_t;
		int64_t ias_preferred_mono, ias_preferred_time_t;
		uint8_t ias_prefix_len;
		char ias_addr[INET6_ADDRSTRLEN];
		unsigned ias_len;
		struct dhcpv6_ia *ia = &ias[i];

		r = sscanf(line + offset, "%" SCNi64 " %" SCNi64 " %" SCNi64 " %" SCNi64 " %" SCNu8 " %s %n",
			   &ias_valid_mono,
			   &ias_valid_time_t,
			   &ias_preferred_mono,
			   &ias_preferred_time_t,
			   &ias_prefix_len,
			   ias_addr,
			   &ias_len);
		debug("IAS sscanf returned %i", r);
		if (r != 6)
			return;

		fprintf(stderr, "IA\n"
			"valid_mono	: %" PRIi64 "\n"
			"valid_time_t	: %" PRIi64 "\n"
			"pref_mono	: %" PRIi64 "\n"
			"pref_time_t:	: %" PRIi64 "\n"
			"prefix_len	: %" PRIu8 "\n"
			"addr		: %s\n"
			"offset		: %u\n",
			ias_valid_mono,
			ias_valid_time_t,
			ias_preferred_mono,
			ias_preferred_time_t,
			ias_prefix_len,
			ias_addr,
			ias_len);

		offset += ias_len;

		ia->preferred_until = statefiles_double_ts_to_monotime(rebooted, ias_valid_mono, ias_valid_time_t);
		ia->valid_until = statefiles_double_ts_to_monotime(rebooted, ias_preferred_mono, ias_preferred_time_t);
		ia->prefix_len = ias_prefix_len;
		if (inet_pton(AF_INET6, ias_addr, &ia->addr) != 1)
			return;
	}

	switch (lease_type) {
	case DHCPV6_IA_NA:
		if (!iface->dhcpv6_na)
			return;
		break;
	case DHCPV6_IA_PD:
		if (!iface->dhcpv6_pd)
			return;
		if (assigned_id > UINT32_MAX)
			return;
		if (prefix_len > 128)
			return;
		break;
	default:
		return;
	}

	time_t valid_until, preferred_until;

	valid_until = statefiles_double_ts_to_monotime(rebooted, valid_mono, valid_time_t);
	preferred_until = statefiles_double_ts_to_monotime(rebooted, preferred_mono, preferred_time_t);

	if (!INFINITE_VALID(valid_until) && valid_until <= now) {
		fprintf(stderr, "Expired\n");
		return;
	}

	struct sockaddr_in6 peer;

	peer.sin6_family = AF_INET6;
	peer.sin6_port = htons(peer_port);
	peer.sin6_flowinfo = peer_flowinfo;
	peer.sin6_scope_id = peer_scope_id;
	if (inet_pton(AF_INET6, peer_addr_str, &peer.sin6_addr) != 1)
		return;

	if (duid_len > DUID_MAX_LEN)
		return;

	if (odhcpd_unhexlify(duid, strlen(duidbuf), duidbuf) != duid_len)
		return;

	if (odhcpd_unhexlify(fr_key, strlen(fr_key_buf), fr_key_buf) != 16)
		return;

	struct dhcpv6_lease *lease;

	lease = dhcpv6_alloc_lease(duid_len);
	if (!lease)
		return;

	lease->ias = malloc(sizeof(ias));
	if (!lease->ias)
		goto err;

	lease->iface = iface;
	lease->peer = peer;
	lease->valid_until = valid_until;
	lease->preferred_until = preferred_until;
	lease->accept_fr_nonce = !!accept_fr;
	memcpy(lease->key, fr_key, sizeof(lease->key));
	memcpy(lease->ias, &ias, sizeof(ias));
	lease->ias_cnt = ias_cnt;
	lease->type = lease_type;
	lease->bound = !!bound;
	lease->leasetime = leasetime;
	lease->hostname = strdup(hostname);
	lease->hostname_valid = !!hostname_valid;
	lease->iaid = iaid;
	lease->duid_len = duid_len;
	memcpy(lease->duid, duid, duid_len);
	lease->lease_cfg = config_find_lease_cfg_by_duid_and_iaid(duid, duid_len, iaid);

	debug("Would insert DHCPv6 lease now");

	if (list_empty(&iface->ia_assignments)) {
		struct dhcpv6_lease *border;
		debug("Adding border");
		border = dhcpv6_alloc_lease(0);
		border->prefix_len = 64;
		list_add(&border->head, &iface->ia_assignments);
	}

	switch (lease_type) {
	case DHCPV6_IA_NA:
		lease->assigned_host_id = assigned_id;
		if (!assign_na(iface, lease))
			goto err;
		break;
	case DHCPV6_IA_PD:
		lease->assigned_subnet_id = (uint32_t)assigned_id;
		lease->prefix_len = prefix_len;
		if (!assign_pd(iface, lease))
			goto err;
		break;
	default:
		goto err;
	}

	if (lease->lease_cfg) {
		if (lease->lease_cfg->leasetime)
			lease->leasetime = lease->lease_cfg->leasetime;
		if (lease->lease_cfg->hostname) {
			free(lease->hostname);
			lease->hostname = strdup(lease->lease_cfg->hostname);
			lease->hostname_valid = true;
		}
		list_add(&lease->lease_cfg_list, &lease->lease_cfg->dhcpv6_leases);
	}

	fprintf(stderr, "Inserted a dhcpv6 lease!\n");
	return;

err:
	dhcpv6_free_lease(lease);
	fprintf(stderr, "Error insering a dhcpv6 lease!\n");
}

static void
statefiles_read_state4(FILE *fp, struct interface *iface, const char *line,
		       time_t now, bool rebooted)
{
	int64_t valid_mono, valid_time_t;
	unsigned bound, hostname_valid, accept_fr;
	uint32_t iaid;
	uint8_t duid_len;
	char ipbuf[INET_ADDRSTRLEN];
	char hostname[DNS_MAX_NAME_LEN];
	char macbuf[ETH_ALEN * 3];
	struct ether_addr macaddr;
	struct in_addr ipaddr;
	char duidbuf[DUID_HEXSTRLEN];
	uint8_t duid[DUID_MAX_LEN];
	char fr_key_buf[33];
	uint8_t fr_key[16];
	struct dhcpv4_lease *lease;
	int r;

	r = sscanf(line, "dhcpv4 %" SCNi64 " %" SCNi64 " %u %s %s %u %s %" SCNu32 " %" SCNu8 " %260s %u %32s",
		   &valid_mono, &valid_time_t, &bound, ipbuf, macbuf,
		   &hostname_valid, hostname, &iaid, &duid_len, duidbuf, &accept_fr, fr_key_buf);
	debug("Read a dhcpv4 record: result %i\n", r);
	if (r != 12)
		return;

	fprintf(stderr, "Found a stored lease\n"
		"iface		: %s\n"
		"valid_mono	: %" PRIi64 "\n"
		"valid_time_t	: %" PRIi64 "\n"
		"bound		: %s\n"
		"IPv4		: %s\n"
		"MAC		: %s\n"
		"valid_hostname	: %s\n"
		"hostname	: %s\n"
		"IAID		: %" PRIu32 "\n"
		"DUID-len	: %" PRIu8 "\n"
		"DUID		: %s\n"
		"Accept FR	: %s\n"
		"FR key:	: %s\n",
		iface->ifname,
		valid_mono,
		valid_time_t,
		bound ? "true" : "false",
		ipbuf,
		macbuf,
		hostname_valid ? "true" : "false",
		hostname,
		iaid,
		duid_len,
		duidbuf,
		accept_fr ? "true" : "false",
		fr_key_buf);

	if (!rebooted)
		valid_mono = (time_t)valid_mono;
	else if (INFINITE_VALID(valid_time_t))
		valid_mono = 0;
	else
		valid_mono = statefiles_time_from_json(valid_time_t);

	if (valid_mono <= now) {
		fprintf(stderr, "Expired\n");
		return;
	}

	if (duid_len > DUID_MAX_LEN)
		return;

	if (odhcpd_unhexlify(duid, strlen(duidbuf), duidbuf) != duid_len)
		return;

	if (odhcpd_unhexlify(fr_key, strlen(fr_key_buf), fr_key_buf) != 16)
		return;

	if (!ether_aton_r(macbuf, &macaddr))
		fprintf(stderr, "incorrect ether addr\n");

	if (inet_pton(AF_INET, ipbuf, &ipaddr) != 1)
		fprintf(stderr, "incorrect ipv4 addr\n");

	lease = dhcpv4_alloc_lease(iface, &macaddr, duid, duid_len, iaid);

	if (duid_len > 0)
		lease->lease_cfg = config_find_lease_cfg_by_duid_and_iaid(duid, duid_len, iaid);

	if (!lease->lease_cfg)
		lease->lease_cfg = config_find_lease_cfg_by_macaddr(&macaddr);

	if (lease->lease_cfg)
		fprintf(stderr, "found a static config\n");
	else
		fprintf(stderr, "found no static cfg\n");

	lease->bound = !!bound;
	lease->valid_until = valid_mono;
	lease->hostname = strdup(hostname);
	lease->hostname_valid = !!hostname_valid;
	lease->accept_fr_nonce = !!accept_fr;
	memcpy(lease->key, fr_key, sizeof(lease->key));

	if (!dhcpv4_insert_lease(iface, lease, ipaddr))
		dhcpv4_free_lease(lease);
	else
		fprintf(stderr, "Inserted a lease!\n");
}

static void statefiles_read_state(struct interface *iface, time_t now)
{
	FILE *fp;
	char line[1024];
	int version;
	char boot_id[BOOT_ID_LEN + 1];
	bool rebooted;

	fp = statefiles_open_file(config.statedir_fd, ODHCPD_STATE_FILE_PREFIX, iface->name);
	if (!fp)
		return;

	if (!fgets(line, sizeof(line), fp) || sscanf(line, "# STATEFILE_VERSION=%u", &version) != 1)
		goto err;

	if (version != ODHCPD_STATE_FILE_VERSION)
		goto err;

	if (!fgets(line, sizeof(line), fp) || sscanf(line, "# BOOT_ID=%36s", boot_id) != 1)
		goto err;

	fprintf(stderr, "Read a file with boot id %s <-> %s\n", boot_id, config.boot_id);
	rebooted = !!strcmp(boot_id, (char *)config.boot_id);
	fprintf(stderr, "Rebooted: %s\n", rebooted ? "true" : "false");

	while (fgets(line, sizeof(line), fp)) {
		if (line[0] == '\0' || line[0] == '#')
			continue;
		else if (!strncmp(line, "dhcpv4 ", strlen("dhcpv4 ")))
			statefiles_read_state4(fp, iface, line, now, rebooted);
		else if (!strncmp(line, "dhcpv6 ", strlen("dhcpv6 ")))
			statefiles_read_state6(fp, iface, line, now, rebooted);
		else
			debug("Unexpected line in statefile: %s", line);
	}

err:
	fclose(fp);
	statefiles_rm_file(config.statedir_fd, ODHCPD_STATE_FILE_PREFIX, iface->name);
}

static void statefiles_write_state4(FILE *fp, struct dhcpv4_lease *lease, time_t now)
{
	char ipbuf[INET_ADDRSTRLEN];
	char duidbuf[DUID_HEXSTRLEN];
	char fr_key_buf[33];
	time_t valid_until_unixtime;

	if (INFINITE_VALID(lease->valid_until))
		valid_until_unixtime = 0;
	else if (lease->valid_until > now)
		valid_until_unixtime = statefiles_time_to_json(lease->valid_until);
	else
		return;

	odhcpd_hexlify(duidbuf, lease->duid, lease->duid_len);
	odhcpd_hexlify(fr_key_buf, lease->key, 16);

	// fmt: "dhcpv4 <valid_until_monotime> <valid_until_unixtime> <bound> <ipv4> <mac> <hostname_valid> <hostname> <iaid> <duid-len> <duid-hex>"
	fprintf(fp, "dhcpv4 %" PRIi64 " %" PRIi64 " %u %s %s %u %s %" PRIu32 " %" PRIu8 " %s %u %s\n",
		(int64_t)lease->valid_until,
		(int64_t)valid_until_unixtime,
		lease->bound,
		inet_ntop(AF_INET, &lease->ipv4, ipbuf, sizeof(ipbuf)),
		ether_ntoa(&lease->macaddr),
		lease->hostname_valid,
		lease->hostname,
		lease->iaid,
		lease->duid_len,
		lease->duid_len ? duidbuf : "-",
		lease->accept_fr_nonce,
		fr_key_buf
		);
}

static void statefiles_write_state6(FILE *fp, struct dhcpv6_lease *lease, time_t now)
{
	char ipbuf[INET6_ADDRSTRLEN];
	char duidbuf[DUID_HEXSTRLEN];
	char fr_key_buf[33];
	time_t valid_until_unixtime, preferred_until_unixtime;

	if (INFINITE_VALID(lease->valid_until))
		valid_until_unixtime = 0;
	else if (lease->valid_until > now)
		valid_until_unixtime = statefiles_time_to_json(lease->valid_until);
	else
		return;

	if (INFINITE_VALID(lease->preferred_until))
		preferred_until_unixtime = 0;
	else if (lease->preferred_until > now)
		preferred_until_unixtime = statefiles_time_to_json(lease->preferred_until);
	else
		return;

	odhcpd_hexlify(duidbuf, lease->duid, lease->duid_len);
	odhcpd_hexlify(fr_key_buf, lease->key, 16);
	uint64_t assigned_id = lease->type == DHCPV6_IA_NA ?
		lease->assigned_host_id : lease->assigned_subnet_id;
	uint8_t prefix_len = lease->type == DHCPV6_IA_NA ?
		128 : lease->prefix_len;



	// fmt: "dhcpv6 <type> <valid_until_monotime> <valid_until_unixtime> <bound> <ipv4> <mac> <hostname_valid> <hostname> <iaid> <duid-len> <duid-hex>"
	fprintf(fp, "dhcpv6 %i %" PRIi64 " %" PRIi64 " %" PRIi64 " %" PRIi64
		" %" PRIu16 " %" PRIu32 " %s %" PRIu32 " %u %" PRIu32
		" %u %s %" PRIu32 " %" PRIu16 " %s %u %s %" PRIu64 " %" PRIu8 " %zu",
		lease->type,
		(int64_t)lease->valid_until,
		(int64_t)valid_until_unixtime,
		(int64_t)lease->preferred_until,
		(int64_t)preferred_until_unixtime,
		/* line */
		ntohs(lease->peer.sin6_port),
		lease->peer.sin6_flowinfo,
		inet_ntop(AF_INET6, &lease->peer.sin6_addr, ipbuf, sizeof(ipbuf)),
		lease->peer.sin6_scope_id,
		lease->bound,
		lease->leasetime,
		/* line */
		lease->hostname_valid,
		lease->hostname,
		lease->iaid,
		lease->duid_len,
		lease->duid_len ? duidbuf : "-",
		lease->accept_fr_nonce,
		fr_key_buf,
		assigned_id,
		prefix_len,
		lease->ias_cnt);

	for (size_t i = 0; i < lease->ias_cnt; i++) {
		struct dhcpv6_ia *ia = &lease->ias[i];

		fprintf(fp, " %" PRIi64 " %" PRIi64 " %" PRIi64 " %" PRIi64 " %" PRIu8 " %s",
			(int64_t)ia->valid_until,
			(int64_t)ia->valid_until,
			(int64_t)ia->preferred_until,
			(int64_t)ia->preferred_until,
			ia->prefix_len,
			inet_ntop(AF_INET6, &ia->addr, ipbuf, sizeof(ipbuf)));
	}

	putc('\n', fp);
}

static void statefiles_write_state(time_t now)
{
	struct interface *iface;
	FILE *fp;

	if (config.statedir_fd < 0)
		return;

	avl_for_each_element(&interfaces, iface, avl) {
		if (iface->ignore)
			continue;

		if (iface->dhcpv4 != MODE_SERVER && iface->dhcpv6 != MODE_SERVER)
			continue;

		fp = statefiles_open_tmp_file(config.statedir_fd);
		if (!fp)
			continue;

		fprintf(fp, "# STATEFILE_VERSION=%i\n", ODHCPD_STATE_FILE_VERSION);
		fprintf(fp, "# BOOT_ID=%s\n", config.boot_id);

		if (iface->dhcpv4 == MODE_SERVER) {
			struct dhcpv4_lease *lease;

			avl_for_each_element(&iface->dhcpv4_leases, lease, iface_avl)
				statefiles_write_state4(fp, lease, now);
		}

		if (iface->dhcpv6 == MODE_SERVER) {
			struct dhcpv6_lease *lease, *border;

			border = list_last_entry(&iface->ia_assignments, struct dhcpv6_lease, head);

			list_for_each_entry(lease, &iface->ia_assignments, head)
				if (lease != border)
					statefiles_write_state6(fp, lease, now);
		}

		statefiles_finish_tmp_file(config.statedir_fd, &fp,
					   ODHCPD_STATE_FILE_PREFIX, iface->name);
	}
}

void statefiles_read(struct interface *iface)
{
	time_t now = odhcpd_time();

	statefiles_read_state(iface, now);
}

bool statefiles_write()
{
	time_t now = odhcpd_time();

	statefiles_write_state(now);

	if (!statefiles_write_leases(now))
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
