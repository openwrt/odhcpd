/*
 * SPDX-FileCopyrightText: 2026 David Härdeman <david@hardeman.nu>
 *
 * SPDX-License-Identifier: GPL2.0-only
 */

/*
 * RFC9686: registering self-generated IPv6 addresses using DHCPv6.
 *
 * Clients inform the server about addresses they configured themselves
 * (e.g. via SLAAC) with ADDR-REG-INFORM messages, one per address, sent from
 * that address. The server records the address and the client's DUID in the
 * interface's databases and acknowledges with an ADDR-REG-REPLY.
 */

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/uio.h>

#include "odhcpd.h"
#include "dhcpv6.h"
#include "dhcpv6-ia.h"

struct reg_match {
	const struct in6_addr *addr6;
	bool found;
};

static void reg_match_cb(struct dhcpv6_lease *lease, struct in6_addr *addr6, uint8_t prefix_len,
			 _o_unused uint32_t pref_lt, _o_unused uint32_t valid_lt, void *arg)
{
	struct reg_match *m = arg;

	if (lease->flags & OAF_DHCPV6_NA) {
		if (IN6_ARE_ADDR_EQUAL(addr6, m->addr6))
			m->found = true;
	} else if (!odhcpd_bmemcmp(addr6, m->addr6, prefix_len)) {
		m->found = true;
	}
}

/* Is addr6 part of a bound lease (of the client with this DUID, if given) */
static bool reg_addr6_in_lease(struct interface *iface, const struct in6_addr *addr6,
			      unsigned int lease_flag, const uint8_t *duid, size_t duid_len,
			      time_t now)
{
	struct reg_match m = { .addr6 = addr6, .found = false };
	struct dhcpv6_lease *a;

	list_for_each_entry(a, &iface->ia_assignments, head) {
		if (!(a->flags & lease_flag) || !a->bound)
			continue;

		if (!INFINITE_VALID(a->valid_until) && a->valid_until <= now)
			continue;

		if (duid && (a->duid_len != duid_len || memcmp(a->duid, duid, duid_len)))
			continue;

		odhcpd_enum_addr6(iface, a, now, reg_match_cb, &m);
		if (m.found)
			return true;
	}

	return false;
}

/* Is addr6 within an on-link prefix (as announced in the PIOs, deprecated or not) */
static bool reg_addr6_on_link(struct interface *iface, const struct in6_addr *addr6, time_t now)
{
	for (size_t i = 0; i < iface->addr6_len; i++) {
		struct odhcpd_ipaddr *a = &iface->addr6[i];

		if (a->prefix_len > 96 || a->valid_lt <= (uint32_t)now ||
		    ADDR_MATCH_PIO_FILTER(a, iface))
			continue;

		if (!odhcpd_bmemcmp(addr6, &a->addr.in6, a->prefix_len < 64 ? 64 : a->prefix_len))
			return true;
	}

	return false;
}

/*
 * Remove expired registrations, and those no longer on-link or delegated,
 * return true if any were removed
 */
bool dhcpv6_reg_timer(struct interface *iface, time_t now)
{
	struct addr6_rec *rec, *tmp;
	bool check = iface->addr6_db_check, changed = false;
	char addr6buf[INET6_ADDRSTRLEN];

	iface->addr6_db_check = false;

	avl_for_each_element_safe(&iface->addr6_db, rec, avl, tmp) {
		const char *why;

		if (!INFINITE_VALID(rec->valid_until) && rec->valid_until < now)
			why = "expired";
		else if (check && !reg_addr6_on_link(iface, &rec->addr6, now) &&
			 !reg_addr6_in_lease(iface, &rec->addr6, OAF_DHCPV6_PD,
					    rec->duid_rec->duid, rec->duid_rec->duid_len, now))
			why = "no longer appropriate";
		else
			continue;

		info("Registration of %s on %s %s", inet_ntop(AF_INET6, &rec->addr6, addr6buf,
		     sizeof(addr6buf)), iface->name, why);
		addr6_rec_del(iface, rec);
		changed = true;
	}

	return changed;
}

/*
 * Get the hostname of a client DUID: from its host section, its Client FQDN
 * option, a DHCPv4 lease with the same MAC, or else "dyn-<DUID>" (in buf)
 */
const char *dhcpv6_reg_hostname(const struct duid_rec *rec, char buf[DHCPV6_REG_HOSTNAME_LEN],
				time_t now)
{
	struct dhcpv4_lease *lease4;
	uint8_t mac[6];
	size_t off;

	if (rec->lease_cfg && rec->lease_cfg->hostname)
		return rec->lease_cfg->hostname;

	if (rec->hostname)
		return rec->hostname;

	if (dhcpv6_duid_to_mac(rec->duid, rec->duid_len, mac)) {
		lease4 = dhcpv4_find_lease_by_hwaddr(rec->iface, mac);
		if (lease4 && lease4->bound && lease4->hostname && lease4->hostname_valid &&
		    (INFINITE_VALID(lease4->valid_until) || lease4->valid_until > now))
			return lease4->hostname;
	}

	/* DNS labels have at most 63 characters */
	off = rec->duid_len > 29 ? rec->duid_len - 29 : 0;
	memcpy(buf, "dyn-", 4);
	odhcpd_hexlify(&buf[4], &rec->duid[off], rec->duid_len - off);

	return buf;
}

static time_t reg_lifetime_to_time(uint32_t lt, time_t now)
{
	/* 0 = infinite */
	return lt == UINT32_MAX ? 0 : now + lt;
}

static void reg_send_reply(struct interface *iface, struct sockaddr_in6 *dest,
			   const struct dhcpv6_client_header *req,
			   const uint8_t *duid, size_t duid_len,
			   const uint8_t *ia_addr_opt, size_t ia_addr_opt_len)
{
	struct dhcpv6_client_header hdr = { .msg_type = DHCPV6_MSG_ADDR_REG_REPLY };
	struct _o_packed {
		uint16_t type;
		uint16_t len;
		uint8_t buf[DUID_MAX_LEN];
	} serverid = { .type = htons(DHCPV6_OPT_SERVERID) },
	  clientid = { .type = htons(DHCPV6_OPT_CLIENTID) };

	memcpy(hdr.transaction_id, req->transaction_id, sizeof(hdr.transaction_id));
	serverid.len = htons(dhcpv6_get_server_duid(iface, serverid.buf));
	clientid.len = htons(duid_len);
	memcpy(clientid.buf, duid, duid_len);

	/*
	 * RFC9686 §4.3 only requires the IA Address, but Android drops replies
	 * without its Client ID
	 */
	struct iovec iov[] = {
		{ &hdr, sizeof(hdr) },
		{ &clientid, DHCPV6_OPT_HDR_SIZE + duid_len },
		{ &serverid, DHCPV6_OPT_HDR_SIZE + ntohs(serverid.len) },
		{ (void *)ia_addr_opt, ia_addr_opt_len },
	};

	/* §4.3: reply to the registered address */
	odhcpd_send(iface->dhcpv6_event.uloop.fd, dest, iov, ARRAY_SIZE(iov), iface);
}

/* Handle a non-relayed ADDR-REG-INFORM message (RFC9686 §4.2) */
void dhcpv6_reg_handle_inform(struct interface *iface, struct sockaddr_in6 *src,
			      const void *data, size_t len)
{
	const struct dhcpv6_client_header *hdr = data;
	const uint8_t *end = (const uint8_t *)data + len;
	uint8_t *duid = NULL, *ia_addr_opt = NULL, *odata;
	uint16_t otype, olen, duid_len = 0, ia_addr_len = 0;
	size_t ia_addr_cnt = 0;
	char hostname[256] = "";
	char addr6buf[INET6_ADDRSTRLEN], duidbuf[DUID_HEXSTRLEN];
	struct dhcpv6_ia_addr ia;
	struct in6_addr addr6;
	uint32_t preferred_lt, valid_lt;
	struct lease_cfg *lease_cfg;
	struct duid_rec *duid_rec;
	struct addr6_rec *rec;
	uint8_t mac[6];
	time_t now = odhcpd_time();
	bool on_link, changed = false;

	if (len < sizeof(*hdr))
		return;

	/* §4.2.1: check the options */
	dhcpv6_for_each_option(&hdr[1], end, otype, olen, odata) {
		switch (otype) {
		case DHCPV6_OPT_CLIENTID:
			duid = odata;
			duid_len = olen;
			break;

		case DHCPV6_OPT_SERVERID:
		case DHCPV6_OPT_ORO:
			debug("Ignoring ADDR-REG-INFORM with option %u on %s", otype, iface->name);
			return;

		case DHCPV6_OPT_IA_ADDR:
			ia_addr_opt = odata - DHCPV6_OPT_HDR_SIZE;
			ia_addr_len = olen;
			ia_addr_cnt++;
			break;

		case DHCPV6_OPT_FQDN:
			dhcpv6_parse_fqdn(odata, olen, hostname);
			break;

		default:
			break;
		}
	}

	if (!duid || duid_len < DUID_MIN_LEN || duid_len > DUID_MAX_LEN) {
		debug("Ignoring ADDR-REG-INFORM without a valid Client Identifier on %s",
		      iface->name);
		return;
	}

	if (ia_addr_cnt != 1 || ia_addr_len < sizeof(ia) - DHCPV6_OPT_HDR_SIZE) {
		debug("Ignoring ADDR-REG-INFORM without exactly one IA Address on %s", iface->name);
		return;
	}

	memcpy(&ia, ia_addr_opt, sizeof(ia));
	addr6 = ia.addr;
	preferred_lt = ntohl(ia.preferred_lt);
	valid_lt = ntohl(ia.valid_lt);
	odhcpd_hexlify(duidbuf, duid, duid_len);
	inet_ntop(AF_INET6, &addr6, addr6buf, sizeof(addr6buf));

	/* §4.2.1: the address must be the source address */
	if (!IN6_ARE_ADDR_EQUAL(&addr6, &src->sin6_addr)) {
		debug("Ignoring ADDR-REG-INFORM for %s from another address on %s",
		      addr6buf, iface->name);
		return;
	}

	/* RFC8415 §21.6: discard addresses with preferred > valid lifetime */
	if (preferred_lt > valid_lt) {
		debug("Ignoring ADDR-REG-INFORM for %s with invalid lifetimes on %s",
		      addr6buf, iface->name);
		return;
	}

	/* Ignore hosts ignored for DHCPv6 */
	lease_cfg = config_find_lease_cfg_by_duid(duid, duid_len);
	if (!lease_cfg && dhcpv6_duid_to_mac(duid, duid_len, mac))
		lease_cfg = config_find_lease_cfg_by_mac(mac);

	if (lease_cfg && lease_cfg->ignore6) {
		debug("Ignoring ADDR-REG-INFORM for %s from ignored host %s on %s",
		      addr6buf, duidbuf, iface->name);
		return;
	}

	/* §4.2.1: on-link, or delegated to the client */
	on_link = reg_addr6_on_link(iface, &addr6, now);
	if (!on_link &&
	    !reg_addr6_in_lease(iface, &addr6, OAF_DHCPV6_PD, duid, duid_len, now)) {
		info("Ignoring ADDR-REG-INFORM for %s from %s: not appropriate to %s",
		     addr6buf, duidbuf, iface->name);
		return;
	}

	/* §4.2.1: not assigned via DHCPv6 */
	if (on_link && reg_addr6_in_lease(iface, &addr6, OAF_DHCPV6_NA, NULL, 0, now)) {
		info("Ignoring ADDR-REG-INFORM for %s from %s: assigned via DHCPv6 on %s",
		     addr6buf, duidbuf, iface->name);
		return;
	}

	rec = addr6_rec_find(iface, &addr6);

	if (valid_lt == 0) {
		/* §4.7: no longer used */
		if (rec && rec->duid_rec->duid_len == duid_len &&
		    !memcmp(rec->duid_rec->duid, duid, duid_len)) {
			info("Address %s no longer registered by %s on %s",
			     addr6buf, duidbuf, iface->name);
			addr6_rec_del(iface, rec);
			changed = true;
		}
		goto reply;
	}

	duid_rec = duid_rec_get(iface, duid, duid_len);
	if (!duid_rec)
		return;

	if (!rec) {
		rec = addr6_rec_add(iface, &addr6, duid_rec);
		if (!rec) {
			duid_rec_put(duid_rec);
			return;
		}

		info("Address %s registered by %s on %s", addr6buf, duidbuf, iface->name);
		changed = true;
	} else if (rec->duid_rec != duid_rec) {
		char olddbuf[DUID_HEXSTRLEN];

		odhcpd_hexlify(olddbuf, rec->duid_rec->duid, rec->duid_rec->duid_len);
		info("Address %s registered by %s on %s, was registered by %s",
		     addr6buf, duidbuf, iface->name, olddbuf);
		addr6_rec_set_duid_rec(rec, duid_rec);
		changed = true;
	} else {
		debug("Address %s registration refreshed by %s on %s",
		      addr6buf, duidbuf, iface->name);
	}

	rec->preferred_until = reg_lifetime_to_time(preferred_lt, now);
	rec->valid_until = reg_lifetime_to_time(valid_lt, now);

	if (hostname[0] && odhcpd_hostname_valid(hostname) &&
	    (!duid_rec->hostname || strcmp(duid_rec->hostname, hostname))) {
		char *tmp = strdup(hostname);

		if (tmp) {
			free(duid_rec->hostname);
			duid_rec->hostname = tmp;
			changed = true;
		}
	}

	duid_rec_put(duid_rec);

reply:
	if (changed)
		iface->update_statefile = true;

	reg_send_reply(iface, src, hdr, duid, duid_len, ia_addr_opt,
		       DHCPV6_OPT_HDR_SIZE + ia_addr_len);
}
