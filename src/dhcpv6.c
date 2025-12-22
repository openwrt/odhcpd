/**
 * Copyright (C) 2012-2013 Steven Barth <steven@midlink.org>
 * Copyright (C) 2018 Hans Dedecker <dedeckeh@gmail.com>
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

#include <errno.h>
#include <unistd.h>
#include <stddef.h>
#include <arpa/inet.h>

#include <libubox/utils.h>

#include "odhcpd.h"
#include "dhcpv6.h"
#include "dhcpv6-pxe.h"
#ifdef DHCPV4_SUPPORT
#include "dhcpv4.h"
#endif

static void relay_client_request(struct sockaddr_in6 *source,
		const void *data, size_t len, struct interface *iface);
static void relay_server_response(uint8_t *data, size_t len);

void handle_ia_addr_reg_inform(struct sockaddr_in6 *source,
		const void *data, size_t len, struct interface *iface);

static void handle_dhcpv6(void *addr, void *data, size_t len,
		struct interface *iface, void *dest);
static void handle_client_request(void *addr, void *data, size_t len,
		struct interface *iface, void *dest_addr);


/* Create socket and register events */
int dhcpv6_init(void)
{
	return dhcpv6_ia_init();
}

int dhcpv6_setup_interface(struct interface *iface, bool enable)
{
	int ret = 0;

	enable = enable && (iface->dhcpv6 != MODE_DISABLED);

	if (iface->dhcpv6_event.uloop.fd >= 0) {
		uloop_fd_delete(&iface->dhcpv6_event.uloop);
		close(iface->dhcpv6_event.uloop.fd);
		iface->dhcpv6_event.uloop.fd = -1;
	}

	/* Configure multicast settings */
	if (enable) {
		struct sockaddr_in6 bind_addr = {AF_INET6, htons(DHCPV6_SERVER_PORT),
					0, IN6ADDR_ANY_INIT, 0};
		struct ipv6_mreq mreq;
		int val = 1;

		iface->dhcpv6_event.uloop.fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
		if (iface->dhcpv6_event.uloop.fd < 0) {
			error("socket(AF_INET6): %m");
			ret = -1;
			goto out;
		}

		/* Basic IPv6 configuration */
		if (setsockopt(iface->dhcpv6_event.uloop.fd, SOL_SOCKET, SO_BINDTODEVICE,
					iface->ifname, strlen(iface->ifname)) < 0) {
			error("setsockopt(SO_BINDTODEVICE): %m");
			ret = -1;
			goto out;
		}

		if (setsockopt(iface->dhcpv6_event.uloop.fd, IPPROTO_IPV6, IPV6_V6ONLY,
					&val, sizeof(val)) < 0) {
			error("setsockopt(IPV6_V6ONLY): %m");
			ret = -1;
			goto out;
		}

		if (setsockopt(iface->dhcpv6_event.uloop.fd, SOL_SOCKET, SO_REUSEADDR,
					&val, sizeof(val)) < 0) {
			error("setsockopt(SO_REUSEADDR): %m");
			ret = -1;
			goto out;
		}

		if (setsockopt(iface->dhcpv6_event.uloop.fd, IPPROTO_IPV6, IPV6_RECVPKTINFO,
					&val, sizeof(val)) < 0) {
			error("setsockopt(IPV6_RECVPKTINFO): %m");
			ret = -1;
			goto out;
		}

		val = DHCPV6_HOP_COUNT_LIMIT;
		if (setsockopt(iface->dhcpv6_event.uloop.fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
					&val, sizeof(val)) < 0) {
			error("setsockopt(IPV6_MULTICAST_HOPS): %m");
			ret = -1;
			goto out;
		}

		val = 0;
		if (setsockopt(iface->dhcpv6_event.uloop.fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
					&val, sizeof(val)) < 0) {
			error("setsockopt(IPV6_MULTICAST_LOOP): %m");
			ret = -1;
			goto out;
		}

		if (bind(iface->dhcpv6_event.uloop.fd, (struct sockaddr*)&bind_addr,
					sizeof(bind_addr)) < 0) {
			error("bind(): %m");
			ret = -1;
			goto out;
		}

		memset(&mreq, 0, sizeof(mreq));
		inet_pton(AF_INET6, ALL_DHCPV6_RELAYS, &mreq.ipv6mr_multiaddr);
		mreq.ipv6mr_interface = iface->ifindex;

		if (setsockopt(iface->dhcpv6_event.uloop.fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
					&mreq, sizeof(mreq)) < 0) {
			error("setsockopt(IPV6_ADD_MEMBERSHIP): %m");
			ret = -1;
			goto out;
		}

		if (iface->dhcpv6 == MODE_SERVER) {
			memset(&mreq, 0, sizeof(mreq));
			inet_pton(AF_INET6, ALL_DHCPV6_SERVERS, &mreq.ipv6mr_multiaddr);
			mreq.ipv6mr_interface = iface->ifindex;

			if (setsockopt(iface->dhcpv6_event.uloop.fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
						&mreq, sizeof(mreq)) < 0) {
				error("setsockopt(IPV6_ADD_MEMBERSHIP): %m");
				ret = -1;
				goto out;
			}
		}

		iface->dhcpv6_event.handle_dgram = handle_dhcpv6;
		odhcpd_register(&iface->dhcpv6_event);
	}

	ret = dhcpv6_ia_setup_interface(iface, enable);

out:
	if (ret < 0 && iface->dhcpv6_event.uloop.fd >= 0) {
		close(iface->dhcpv6_event.uloop.fd);
		iface->dhcpv6_event.uloop.fd = -1;
	}

	return ret;
}

enum {
	IOV_NESTED = 0,
	IOV_DEST,
	IOV_CLIENTID,
	IOV_MAXRT,
#define IOV_STAT IOV_MAXRT
	IOV_RAPID_COMMIT,
	IOV_ADDR_REG_ENABLE,
	IOV_DNS,
	IOV_DNS_ADDR,
	IOV_SEARCH,
	IOV_SEARCH_DOMAIN,
	IOV_PDBUF,
#define	IOV_REFRESH IOV_PDBUF
	IOV_DHCPV6_RAW,
	IOV_NTP,
	IOV_NTP_ADDR,
	IOV_SNTP,
	IOV_SNTP_ADDR,
	IOV_RELAY_MSG,
	IOV_DHCPV4O6_SERVER,
	IOV_DNR,
	IOV_BOOTFILE_URL,
	IOV_POSIX_TZ,
	IOV_POSIX_TZ_STR,
	IOV_TZDB_TZ,
	IOV_TZDB_TZ_STR,
	IOV_CAPT_PORTAL,
	IOV_CAPT_PORTAL_URI,
	IOV_TOTAL
};

static void handle_nested_message(uint8_t *data, size_t len,
				  struct dhcpv6_client_header **c_hdr, uint8_t **opts,
				  uint8_t **end, struct iovec iov[IOV_TOTAL])
{
	struct dhcpv6_relay_header *r_hdr = (struct dhcpv6_relay_header *)data;
	uint16_t otype, olen;
	uint8_t *odata;

	if (iov[IOV_NESTED].iov_base == NULL) {
		iov[IOV_NESTED].iov_base = data;
		iov[IOV_NESTED].iov_len = len;
	}

	if (len < sizeof(struct dhcpv6_client_header))
		return;

	if (r_hdr->msg_type != DHCPV6_MSG_RELAY_FORW) {
		iov[IOV_NESTED].iov_len = data - (uint8_t *)iov[IOV_NESTED].iov_base;
		*c_hdr = (void *)data;
		*opts = (uint8_t *)&(*c_hdr)[1];
		*end = data + len;
		return;
	}

	dhcpv6_for_each_option(r_hdr->options, data + len, otype, olen, odata) {
		if (otype == DHCPV6_OPT_RELAY_MSG) {
			iov[IOV_RELAY_MSG].iov_base = odata + olen;
			iov[IOV_RELAY_MSG].iov_len = (((uint8_t *)iov[IOV_NESTED].iov_base) +
					iov[IOV_NESTED].iov_len) - (odata + olen);
			handle_nested_message(odata, olen, c_hdr, opts, end, iov);
			return;
		}
	}
}


static void update_nested_message(uint8_t *data, size_t len, ssize_t pdiff)
{
	struct dhcpv6_relay_header *hdr = (struct dhcpv6_relay_header*)data;
	if (hdr->msg_type != DHCPV6_MSG_RELAY_FORW)
		return;

	hdr->msg_type = DHCPV6_MSG_RELAY_REPL;

	uint16_t otype, olen;
	uint8_t *odata;
	dhcpv6_for_each_option(hdr->options, data + len, otype, olen, odata) {
		if (otype == DHCPV6_OPT_RELAY_MSG) {
			olen += pdiff;
			odata[-2] = (olen >> 8) & 0xff;
			odata[-1] = olen & 0xff;
			update_nested_message(odata, olen - pdiff, pdiff);
			return;
		}
	}
}

#ifdef DHCPV4_SUPPORT

struct dhcpv4_msg_data {
	uint8_t *msg;
	size_t maxsize;
	ssize_t len;
};

static ssize_t dhcpv6_4o6_send_reply(struct iovec *iov, size_t iov_len,
				     _o_unused struct sockaddr *dest,
				     _o_unused socklen_t dest_len,
				     void *opaque)
{
	struct dhcpv4_msg_data *reply = opaque;
	size_t len = 0;

	for (size_t i = 0; i < iov_len; i++)
		len += iov[i].iov_len;

	if (len > reply->maxsize) {
		error("4o6: reply too large, %zu > %zu", len, reply->maxsize);
		reply->len = -1;
		return -1;
	}

	for (size_t i = 0, off = 0; i < iov_len; i++) {
		memcpy(reply->msg + off, iov[i].iov_base, iov[i].iov_len);
		off += iov[i].iov_len;
	}
	reply->len = len;

	return len;
}

static ssize_t dhcpv6_4o6_query(uint8_t *buf, size_t buflen,
				struct interface *iface,
				const struct sockaddr_in6 *addr,
				const void *data, const uint8_t *end)
{
	const struct dhcpv6_client_header *hdr = data;
	uint16_t otype, olen, msgv4_len = 0;
	uint8_t *msgv4_data = NULL;
	uint8_t *start = (uint8_t *)&hdr[1], *odata;
	struct sockaddr_in addrv4;
	struct dhcpv4_msg_data reply = { .msg = buf, .maxsize = buflen, .len = -1 };

	dhcpv6_for_each_option(start, end, otype, olen, odata) {
		if (otype == DHCPV6_OPT_DHCPV4_MSG) {
			msgv4_data = odata;
			msgv4_len = olen;
		}
	}

	if (!msgv4_data || msgv4_len == 0) {
		error("4o6: missing DHCPv4 message option (%d)", DHCPV6_OPT_DHCPV4_MSG);
		return -1;
	}

	// Dummy IPv4 address
	memset(&addrv4, 0, sizeof(addrv4));
	addrv4.sin_family = AF_INET;
	addrv4.sin_addr.s_addr = INADDR_ANY;
	addrv4.sin_port = htons(DHCPV4_CLIENT_PORT);

	dhcpv4_handle_msg(&addrv4, msgv4_data, msgv4_len,
			  iface, NULL, dhcpv6_4o6_send_reply, &reply);

	return reply.len;
}
#endif	/* DHCPV4_SUPPORT */

/* Simple DHCPv6-server for information requests */
static void handle_client_request(void *addr, void *data, size_t len,
		struct interface *iface, void *dest_addr)
{
	struct dhcpv6_client_header *hdr = data;
	uint8_t *opts = (uint8_t *)&hdr[1], *opts_end = (uint8_t *)data + len;
	bool o_rapid_commit = false;

	if (len < sizeof(*hdr))
		return;

	switch (hdr->msg_type) {
	/* Valid message types for clients */
	case DHCPV6_MSG_SOLICIT:
	case DHCPV6_MSG_REQUEST:
	case DHCPV6_MSG_CONFIRM:
	case DHCPV6_MSG_RENEW:
	case DHCPV6_MSG_REBIND:
	case DHCPV6_MSG_RELEASE:
	case DHCPV6_MSG_DECLINE:
	case DHCPV6_MSG_INFORMATION_REQUEST:
	case DHCPV6_MSG_RELAY_FORW:
#ifdef DHCPV4_SUPPORT
	/* if we include DHCPV4 support, handle this message type */
	case DHCPV6_MSG_DHCPV4_QUERY:
#endif
	case DHCPV6_MSG_ADDR_REG_INFORM:
		break;
	/* Invalid message types for clients i.e. server messages */
	case DHCPV6_MSG_ADVERTISE:
	case DHCPV6_MSG_REPLY:
	case DHCPV6_MSG_RECONFIGURE:
	case DHCPV6_MSG_RELAY_REPL:
#ifndef DHCPV4_SUPPORT
	/* if we omit DHCPV4 support, ignore this client message type */
	case DHCPV6_MSG_DHCPV4_QUERY:
#endif
	case DHCPV6_MSG_DHCPV4_RESPONSE:
	case DHCPV6_MSG_ADDR_REG_REPLY:
	default:
		return;
	}

	debug("Got a DHCPv6-request on %s", iface->name);

	/* RFC9686 - Handle ADDR-REG-INFORM separately */
	if (hdr->msg_type == DHCPV6_MSG_ADDR_REG_INFORM && iface->dhcpv6 == MODE_SERVER) {
		handle_ia_addr_reg_inform((struct sockaddr_in6 *)addr, data, len, iface);
		return;
	}

	/* Construct reply message */
	struct _o_packed {
		uint8_t msg_type;
		uint8_t tr_id[3];
		uint16_t serverid_type;
		uint16_t serverid_length;
		uint8_t serverid_buf[DUID_MAX_LEN];
	} dest = {
		.msg_type = DHCPV6_MSG_REPLY,
		.serverid_type = htons(DHCPV6_OPT_SERVERID),
		.serverid_length = 0,
		.serverid_buf = { 0 },
	};

	if (config.default_duid_len > 0) {
		memcpy(dest.serverid_buf, config.default_duid, config.default_duid_len);
		dest.serverid_length = htons(config.default_duid_len);
	} else {
		uint16_t duid_ll_hdr[] = { htons(DUID_TYPE_LL), htons(ARPHRD_ETHER) };
		memcpy(dest.serverid_buf, duid_ll_hdr, sizeof(duid_ll_hdr));
		odhcpd_get_mac(iface, &dest.serverid_buf[sizeof(duid_ll_hdr)]);
		dest.serverid_length = htons(sizeof(duid_ll_hdr) + ETH_ALEN);
	}

	struct _o_packed {
		uint16_t type;
		uint16_t len;
		uint8_t buf[DUID_MAX_LEN];
	} clientid = {
		.type = htons(DHCPV6_OPT_CLIENTID),
		.len = 0,
		.buf = { 0 },
	};

	struct _o_packed {
		uint16_t type;
		uint16_t len;
		uint32_t value;
	} maxrt = {htons(DHCPV6_OPT_SOL_MAX_RT), htons(sizeof(maxrt) - DHCPV6_OPT_HDR_SIZE),
			htonl(60)};

	struct _o_packed {
		uint16_t type;
		uint16_t len;
	} rapid_commit = {htons(DHCPV6_OPT_RAPID_COMMIT), 0};

	struct _o_packed {
		uint16_t type;
		uint16_t len;
		uint16_t value;
	} stat = {htons(DHCPV6_OPT_STATUS), htons(sizeof(stat) - DHCPV6_OPT_HDR_SIZE),
			htons(DHCPV6_STATUS_USEMULTICAST)};

	struct _o_packed {
		uint16_t type;
		uint16_t len;
		uint32_t value;
	} refresh = {htons(DHCPV6_OPT_INFO_REFRESH), htons(sizeof(uint32_t)),
			htonl(600)};

	struct in6_addr *dns_addrs6 = NULL, dns_addr6;
	size_t dns_addrs6_cnt = 0;

	if (iface->dns_addrs6_cnt > 0) {
		dns_addrs6 = iface->dns_addrs6;
		dns_addrs6_cnt = iface->dns_addrs6_cnt;
	} else if (!odhcpd_get_interface_dns_addr6(iface, &dns_addr6)) {
		dns_addrs6 = &dns_addr6;
		dns_addrs6_cnt = 1;
	}

	struct {
		uint16_t type;
		uint16_t len;
	} dns_hdr = { htons(DHCPV6_OPT_DNS_SERVERS), htons(dns_addrs6_cnt * sizeof(*dns_addrs6)) };

	/* SNTP */
	struct in6_addr *sntp_addr_ptr = iface->dhcpv6_sntp;
	size_t sntp_cnt = 0;
	struct {
		uint16_t type;
		uint16_t len;
	} dhcpv6_sntp;

	/* RFC 4833 - Timezones */
	bool posix_want = false;
	uint8_t *posix_ptr = sys_conf.posix_tz;
	uint16_t posix_len = sys_conf.posix_tz_len;
	/* RFC 4833 - OPTION_NEW_POSIX_TIMEZONE (41)
	 * e.g. EST5EDT4,M3.2.0/02:00,M11.1.0/02:00
	 * Variable-length opaque tz_string blob.
	 */
	struct {
		uint16_t type;
		uint16_t len;
	} posix_tz;

	bool tzdb_want = false;
	uint8_t *tzdb_ptr = sys_conf.tzdb_tz;
	uint16_t tzdb_len = sys_conf.tzdb_tz_len;
	/* RFC 4833 - OPTION_NEW_TZDB_TIMEZONE (42)
	 * e.g. Europe/Zurich
	 * Variable-length opaque tz_name blob.
	 */
	struct {
		uint16_t type;
		uint16_t len;
	} tzdb_tz;

	/* NTP */
	uint8_t *ntp_ptr = iface->dhcpv6_ntp;
	uint16_t ntp_len = iface->dhcpv6_ntp_len;
	size_t ntp_cnt = 0;
	struct {
		uint16_t type;
		uint16_t len;
	} ntp;

	/* DNR */
	struct dhcpv6_dnr {
		uint16_t type;
		uint16_t len;
		uint16_t priority;
		uint16_t adn_len;
		uint8_t body[];
	};
	struct dhcpv6_dnr *dnrs = NULL;
	size_t dnrs_len = 0;

	/* RFC8910 Captive-Portal URI */
	uint8_t *capt_portal_ptr = (uint8_t *)iface->captive_portal_uri;
	size_t capt_portal_len = iface->captive_portal_uri_len;
	struct {
		uint16_t type;
		uint16_t len;
	} capt_portal;

	/* RFC9686 Address Registration Enable option */
	bool addr_reg_enable_want = false;
	struct {
		uint16_t type;
		uint16_t len;
	} addr_reg_enable = {
		htons(DHCPV6_OPT_ADDR_REG_ENABLE),
		0
	};

	/* RFC8910 §2:
	 * DHCP servers MAY send the Captive Portal option without any explicit request
	 * If it is configured, send it.
	 */
	capt_portal.type = htons(DHCPV6_OPT_CAPTIVE_PORTAL);
	capt_portal.len = htons(capt_portal_len);

	uint16_t otype, olen;
	uint8_t *odata;
	uint16_t *reqopts = NULL;
	size_t reqopts_cnt = 0;

	/* FIXME: this should be merged with the second loop further down */
	dhcpv6_for_each_option(opts, opts_end, otype, olen, odata) {
		/* Requested options, array of uint16_t, RFC 8415 §21.7 */
		if (otype == DHCPV6_OPT_ORO) {
			reqopts_cnt = olen / sizeof(uint16_t);
			reqopts = (uint16_t *)odata;
			break;
		}
	}

	/* Requested options */
	for (size_t i = 0; i < reqopts_cnt; i++) {
		uint16_t opt = ntohs(reqopts[i]);

		switch (opt) {
		case DHCPV6_OPT_SNTP_SERVERS:
			sntp_cnt = iface->dhcpv6_sntp_cnt;
			dhcpv6_sntp.type = htons(DHCPV6_OPT_SNTP_SERVERS);
			dhcpv6_sntp.len = htons(sntp_cnt * sizeof(*sntp_addr_ptr));
			break;

		case DHCPV6_OPT_NTP_SERVERS:
			ntp_cnt = iface->dhcpv6_ntp_cnt;
			ntp.type = htons(DHCPV6_OPT_NTP_SERVERS);
			ntp.len = htons(ntp_len);
			break;

		case DHCPV6_OPT_NEW_POSIX_TIMEZONE:
			posix_want = true;
			posix_tz.type = htons(DHCPV6_OPT_NEW_POSIX_TIMEZONE);
			posix_tz.len = htons(posix_len);
			break;

		case DHCPV6_OPT_NEW_TZDB_TIMEZONE:
			tzdb_want = true;
			tzdb_tz.type = htons(DHCPV6_OPT_NEW_TZDB_TIMEZONE);
			tzdb_tz.len = htons(tzdb_len);
			break;

		case DHCPV6_OPT_DNR:
			for (size_t j = 0; j < iface->dnr_cnt; j++) {
				struct dnr_options *dnr = &iface->dnr[j];

				if (dnr->addr6_cnt == 0 && dnr->addr4_cnt > 0)
					continue;

				dnrs_len += sizeof(struct dhcpv6_dnr);
				dnrs_len += dnr->adn_len;

				if (dnr->addr6_cnt > 0 || dnr->svc_len > 0) {
					dnrs_len += sizeof(uint16_t);
					dnrs_len += dnr->addr6_cnt * sizeof(*dnr->addr6);
					dnrs_len += dnr->svc_len;
				}
			}

			dnrs = alloca(dnrs_len);
			uint8_t *pos = (uint8_t *)dnrs;

			for (size_t j = 0; j < iface->dnr_cnt; j++) {
				struct dnr_options *dnr = &iface->dnr[j];
				struct dhcpv6_dnr *d6dnr = (struct dhcpv6_dnr *)pos;
				uint16_t d6dnr_type_be = htons(DHCPV6_OPT_DNR);
				uint16_t d6dnr_len = 2 * sizeof(uint16_t) + dnr->adn_len;
				uint16_t d6dnr_len_be;
				uint16_t d6dnr_priority_be = htons(dnr->priority);
				uint16_t d6dnr_adn_len_be = htons(dnr->adn_len);

				if (dnr->addr6_cnt == 0 && dnr->addr4_cnt > 0)
					continue;

				/* memcpy as the struct is unaligned */
				memcpy(&d6dnr->type, &d6dnr_type_be, sizeof(d6dnr_type_be));
				memcpy(&d6dnr->priority, &d6dnr_priority_be, sizeof(d6dnr_priority_be));
				memcpy(&d6dnr->adn_len, &d6dnr_adn_len_be, sizeof(d6dnr_adn_len_be));

				pos = d6dnr->body;
				memcpy(pos, dnr->adn, dnr->adn_len);
				pos += dnr->adn_len;

				if (dnr->addr6_cnt > 0 || dnr->svc_len > 0) {
					uint16_t addr6_len = dnr->addr6_cnt * sizeof(*dnr->addr6);
					uint16_t addr6_len_be = htons(addr6_len);

					memcpy(pos, &addr6_len_be, sizeof(addr6_len_be));
					pos += sizeof(addr6_len_be);
					memcpy(pos, dnr->addr6, addr6_len);
					pos += addr6_len;
					memcpy(pos, dnr->svc, dnr->svc_len);
					pos += dnr->svc_len;

					d6dnr_len += sizeof(addr6_len_be) + addr6_len + dnr->svc_len;
				}

				d6dnr_len_be = htons(d6dnr_len);
				memcpy(&d6dnr->len, &d6dnr_len_be, sizeof(d6dnr_len_be));
			}
			break;

		case DHCPV6_OPT_ADDR_REG_ENABLE:
			/* RFC9686: Signal address registration support */
			addr_reg_enable_want = true;
			break;
		}
	}

	/* DNS Search options */
	struct {
		uint16_t type;
		uint16_t len;
	} dns_search_hdr = { htons(DHCPV6_OPT_DNS_DOMAIN), htons(iface->dns_search_len) };


	struct _o_packed dhcpv4o6_server {
		uint16_t type;
		uint16_t len;
		struct in6_addr addr;
	} dhcpv4o6_server = {htons(DHCPV6_OPT_4O6_SERVER), htons(sizeof(struct in6_addr)),
			IN6ADDR_ANY_INIT};

	uint8_t pdbuf[512];
	struct iovec iov[IOV_TOTAL] = {
		[IOV_NESTED] = {NULL, 0},
		[IOV_DEST] = {&dest, offsetof(typeof(dest), serverid_buf) + ntohs(dest.serverid_length) },
		[IOV_CLIENTID] = {&clientid, 0},
		[IOV_MAXRT] = {&maxrt, sizeof(maxrt)},
		[IOV_RAPID_COMMIT] = {&rapid_commit, 0},
		[IOV_ADDR_REG_ENABLE] = {&addr_reg_enable, addr_reg_enable_want ? sizeof(addr_reg_enable) : 0},
		[IOV_DNS] = { &dns_hdr, (dns_addrs6_cnt) ? sizeof(dns_hdr) : 0},
		[IOV_DNS_ADDR] = { dns_addrs6, dns_addrs6_cnt * sizeof(*dns_addrs6) },
		[IOV_SEARCH] = { &dns_search_hdr, iface->dns_search_len ? sizeof(dns_search_hdr) : 0 },
		[IOV_SEARCH_DOMAIN] = { iface->dns_search, iface->dns_search_len },
		[IOV_PDBUF] = {pdbuf, 0},
		[IOV_DHCPV6_RAW] = {iface->dhcpv6_raw, iface->dhcpv6_raw_len},
		[IOV_NTP] = {&ntp, (ntp_cnt) ? sizeof(ntp) : 0},
		[IOV_NTP_ADDR] = {ntp_ptr, (ntp_cnt) ? ntp_len : 0},
		[IOV_SNTP] = {&dhcpv6_sntp, (sntp_cnt) ? sizeof(dhcpv6_sntp) : 0},
		[IOV_SNTP_ADDR] = {sntp_addr_ptr, sntp_cnt * sizeof(*sntp_addr_ptr)},
		[IOV_POSIX_TZ] = {&posix_tz, (posix_want) ? sizeof(posix_tz) : 0},
		[IOV_POSIX_TZ_STR] = {posix_ptr, (posix_want) ? posix_len : 0 },
		[IOV_TZDB_TZ] = {&tzdb_tz, (tzdb_want) ? sizeof(tzdb_tz) : 0},
		[IOV_TZDB_TZ_STR] = {tzdb_ptr, (tzdb_want) ? tzdb_len : 0 },
		[IOV_DNR] = {dnrs, dnrs_len},
		[IOV_RELAY_MSG] = {NULL, 0},
		[IOV_DHCPV4O6_SERVER] = {&dhcpv4o6_server, 0},
		[IOV_CAPT_PORTAL] = {&capt_portal, capt_portal_len ? sizeof(capt_portal) : 0},
		[IOV_CAPT_PORTAL_URI] = {capt_portal_ptr, capt_portal_len ? capt_portal_len : 0},
		[IOV_BOOTFILE_URL] = {NULL, 0}
	};

	if (hdr->msg_type == DHCPV6_MSG_RELAY_FORW)
		handle_nested_message(data, len, &hdr, &opts, &opts_end, iov);

	if (!IN6_IS_ADDR_MULTICAST((struct in6_addr *)dest_addr) && iov[IOV_NESTED].iov_len == 0 &&
	    (hdr->msg_type == DHCPV6_MSG_SOLICIT || hdr->msg_type == DHCPV6_MSG_CONFIRM ||
	     hdr->msg_type == DHCPV6_MSG_REBIND || hdr->msg_type == DHCPV6_MSG_INFORMATION_REQUEST))
		return;

	memcpy(dest.tr_id, hdr->transaction_id, sizeof(dest.tr_id));

	/* Go through options and find what we need */
	dhcpv6_for_each_option(opts, opts_end, otype, olen, odata) {
		if (otype == DHCPV6_OPT_CLIENTID && olen <= DUID_MAX_LEN) {
			clientid.len = htons(olen);
			memcpy(clientid.buf, odata, olen);
			iov[IOV_CLIENTID].iov_len = offsetof(typeof(clientid), buf) + olen;
		} else if (otype == DHCPV6_OPT_SERVERID) {
			if (olen != ntohs(dest.serverid_length) ||
			    memcmp(odata, &dest.serverid_buf, olen))
				return; /* Not for us */
		} else if (otype == DHCPV6_OPT_RAPID_COMMIT && hdr->msg_type == DHCPV6_MSG_SOLICIT) {
			iov[IOV_RAPID_COMMIT].iov_len = sizeof(rapid_commit);
			o_rapid_commit = true;
		} else if (otype == DHCPV6_OPT_ORO) {
			for (int i=0; i < olen/2; i++) {
				uint16_t option = ntohs(((uint16_t *)odata)[i]);

				switch (option) {
#ifdef DHCPV4_SUPPORT
				case DHCPV6_OPT_4O6_SERVER:
					if (iface->dhcpv4) {
						/* According to RFC 7341, 7.2. DHCP 4o6 Server Address Option Format:
						 * This option may also carry no IPv6 addresses, which instructs the
						 * client to use the All_DHCP_Relay_Agents_and_Servers multicast address
						 * as the destination address.
						 *
						 * The ISC dhclient logs a missing IPv6 address as an error but seems to
						 * work anyway:
						 * dhcp4-o-dhcp6-server: expecting at least 16 bytes; got 0
						 *
						 * Include the All_DHCP_Relay_Agents_and_Servers multicast address
						 * to make it explicit which address to use. */
						struct dhcpv4o6_server *server = iov[IOV_DHCPV4O6_SERVER].iov_base;

						inet_pton(AF_INET6, ALL_DHCPV6_RELAYS, &server->addr);

						iov[IOV_DHCPV4O6_SERVER].iov_len = sizeof(dhcpv4o6_server);
					}
					break;
#endif /* DHCPV4_SUPPORT */
				default:
					break;
				}
			}
		} else if (otype == DHCPV6_OPT_CLIENT_ARCH) {
			uint16_t arch_code = ntohs(((uint16_t*)odata)[0]);
			ipv6_pxe_serve_boot_url(arch_code, &iov[IOV_BOOTFILE_URL]);
		}
	}

	if (dest.serverid_length == clientid.len && 
	    !memcmp(clientid.buf, dest.serverid_buf, dest.serverid_length)) {
		/* Bail if we are in a network loop where we talk with ourself */
		return;		
	}

	if (!IN6_IS_ADDR_MULTICAST((struct in6_addr *)dest_addr) && iov[IOV_NESTED].iov_len == 0 &&
	    (hdr->msg_type == DHCPV6_MSG_REQUEST || hdr->msg_type == DHCPV6_MSG_RENEW ||
	     hdr->msg_type == DHCPV6_MSG_RELEASE || hdr->msg_type == DHCPV6_MSG_DECLINE)) {
		iov[IOV_STAT].iov_base = &stat;
		iov[IOV_STAT].iov_len = sizeof(stat);

		for (ssize_t i = IOV_STAT + 1; i < IOV_TOTAL; ++i)
			iov[i].iov_len = 0;

		odhcpd_send(iface->dhcpv6_event.uloop.fd, addr, iov, ARRAY_SIZE(iov), iface);
		return;
	}

	if (hdr->msg_type == DHCPV6_MSG_SOLICIT && !o_rapid_commit) {
		dest.msg_type = DHCPV6_MSG_ADVERTISE;
	} else if (hdr->msg_type == DHCPV6_MSG_INFORMATION_REQUEST) {
		iov[IOV_REFRESH].iov_base = &refresh;
		iov[IOV_REFRESH].iov_len = sizeof(refresh);

		/* Return inf max rt option in reply to information request */
		maxrt.type = htons(DHCPV6_OPT_INF_MAX_RT);
	}

#ifdef DHCPV4_SUPPORT
	if (hdr->msg_type == DHCPV6_MSG_DHCPV4_QUERY) {
		struct _o_packed dhcpv4_msg_data {
			uint16_t type;
			uint16_t len;
			uint8_t msg[1];
		} *msg_opt = (struct dhcpv4_msg_data*)pdbuf;
		ssize_t msglen;

		memset(pdbuf, 0, sizeof(pdbuf));

		msglen = dhcpv6_4o6_query(msg_opt->msg, sizeof(pdbuf) - sizeof(*msg_opt) + 1,
						iface, addr, (const void *)hdr, opts_end);
		if (msglen <= 0) {
			error("4o6: query failed");
			return;
		}

		msg_opt->type = htons(DHCPV6_OPT_DHCPV4_MSG);
		msg_opt->len = htons(msglen);
		iov[IOV_PDBUF].iov_len = sizeof(*msg_opt) - 1 + msglen;
		dest.msg_type = DHCPV6_MSG_DHCPV4_RESPONSE;
	} else
#endif	/* DHCPV4_SUPPORT */

	if (hdr->msg_type != DHCPV6_MSG_INFORMATION_REQUEST) {
		ssize_t ialen = dhcpv6_ia_handle_IAs(pdbuf, sizeof(pdbuf), iface, addr, (const void *)hdr, opts_end);

		iov[IOV_PDBUF].iov_len = ialen;
		if (ialen < 0 ||
		    (ialen == 0 && (hdr->msg_type == DHCPV6_MSG_REBIND || hdr->msg_type == DHCPV6_MSG_CONFIRM)))
			return;
	}

	if (iov[IOV_NESTED].iov_len > 0) /* Update length */
		update_nested_message(data, len, iov[IOV_DEST].iov_len + iov[IOV_MAXRT].iov_len +
				      iov[IOV_RAPID_COMMIT].iov_len + iov[IOV_DNS].iov_len +
				      iov[IOV_DNS_ADDR].iov_len + iov[IOV_SEARCH].iov_len +
				      iov[IOV_SEARCH_DOMAIN].iov_len + iov[IOV_PDBUF].iov_len +
				      iov[IOV_ADDR_REG_ENABLE].iov_len +
				      iov[IOV_DHCPV4O6_SERVER].iov_len +
				      iov[IOV_DHCPV6_RAW].iov_len +
				      iov[IOV_NTP].iov_len + iov[IOV_NTP_ADDR].iov_len +
				      iov[IOV_SNTP].iov_len + iov[IOV_SNTP_ADDR].iov_len +
				      iov[IOV_POSIX_TZ].iov_len + iov[IOV_POSIX_TZ_STR].iov_len +
				      iov[IOV_TZDB_TZ].iov_len + iov[IOV_TZDB_TZ_STR].iov_len +
				      iov[IOV_CAPT_PORTAL].iov_len + iov[IOV_CAPT_PORTAL_URI].iov_len +
				      iov[IOV_DNR].iov_len + iov[IOV_BOOTFILE_URL].iov_len -
				      (4 + opts_end - opts));

	debug("Sending a DHCPv6-%s on %s", iov[IOV_NESTED].iov_len ? "relay-reply" : "reply", iface->name);

	odhcpd_send(iface->dhcpv6_event.uloop.fd, addr, iov, ARRAY_SIZE(iov), iface);
}


/* Central DHCPv6-relay handler */
static void handle_dhcpv6(void *addr, void *data, size_t len,
		struct interface *iface, void *dest_addr)
{
	if (iface->dhcpv6 == MODE_SERVER) {
		handle_client_request(addr, data, len, iface, dest_addr);
	} else if (iface->dhcpv6 == MODE_RELAY) {
		if (iface->master)
			relay_server_response(data, len);
		else
			relay_client_request(addr, data, len, iface);
	}
}


/* Relay server response (regular relay server handling) */
static void relay_server_response(uint8_t *data, size_t len)
{
	/* Information we need to gather */
	uint8_t *payload_data = NULL;
	size_t payload_len = 0;
	int32_t ifaceidx = 0;
	struct sockaddr_in6 target = {AF_INET6, htons(DHCPV6_CLIENT_PORT),
		0, IN6ADDR_ANY_INIT, 0};
	uint16_t otype, olen;
	uint8_t *odata, *end = data + len;
	/* Relay DHCPv6 reply from server to client */
	struct dhcpv6_relay_header *h = (void*)data;

	debug("Got a DHCPv6-relay-reply");

	if (len < sizeof(*h) || h->msg_type != DHCPV6_MSG_RELAY_REPL)
		return;

	memcpy(&target.sin6_addr, &h->peer_address, sizeof(struct in6_addr));

	/* Go through options and find what we need */
	dhcpv6_for_each_option(h->options, end, otype, olen, odata) {
		if (otype == DHCPV6_OPT_INTERFACE_ID
				&& olen == sizeof(ifaceidx)) {
			memcpy(&ifaceidx, odata, sizeof(ifaceidx));
		} else if (otype == DHCPV6_OPT_RELAY_MSG) {
			payload_data = odata;
			payload_len = olen;
		}
	}

	/* Invalid interface-id or basic payload */
	struct interface *iface = odhcpd_get_interface_by_index(ifaceidx);
	if (!iface || iface->master || !payload_data || payload_len < 4)
		return;

	bool is_authenticated = false;
	struct in6_addr *dns_addrs6 = NULL;
	size_t dns_addrs6_cnt = 0;

	/* If the payload is relay-reply we have to send to the server port */
	if (payload_data[0] == DHCPV6_MSG_RELAY_REPL) {
		target.sin6_port = htons(DHCPV6_SERVER_PORT);
	} else if (payload_data[0] == DHCPV6_MSG_ADDR_REG_REPLY) {
		/* RFC9686: Forward ADDR-REG-REPLY back to client */
		/* The client address is in the peer_address field of the relay message */
		/* For relayed ADDR-REG-REPLY, just forward as-is to client port */
	} else { /* Go through the payload data */
		struct dhcpv6_client_header *dch = (void*)payload_data;
		end = payload_data + payload_len;

		dhcpv6_for_each_option(&dch[1], end, otype, olen, odata) {
			if (otype == DHCPV6_OPT_DNS_SERVERS && olen >= sizeof(struct in6_addr)) {
				dns_addrs6 = (struct in6_addr*)odata;
				dns_addrs6_cnt = olen / sizeof(struct in6_addr);
			} else if (otype == DHCPV6_OPT_AUTH) {
				is_authenticated = true;
			}
		}
	}

	/* Rewrite DNS servers if requested */
	if (iface->always_rewrite_dns && dns_addrs6 && dns_addrs6_cnt > 0) {
		if (is_authenticated)
			return; /* Impossible to rewrite */

		const struct in6_addr *rewrite = iface->dns_addrs6;
		struct in6_addr addr;
		size_t rewrite_cnt = iface->dns_addrs6_cnt;

		if (rewrite_cnt == 0) {
			if (odhcpd_get_interface_dns_addr6(iface, &addr))
				return; /* Unable to get interface address */

			rewrite = &addr;
			rewrite_cnt = 1;
		}

		/* Copy over any other addresses */
		for (size_t i = 0; i < dns_addrs6_cnt; ++i) {
			size_t j = (i < rewrite_cnt) ? i : rewrite_cnt - 1;
			memcpy(&dns_addrs6[i], &rewrite[j], sizeof(*rewrite));
		}
	}

	struct iovec iov = {payload_data, payload_len};

	debug("Sending a DHCPv6-reply on %s", iface->name);

	odhcpd_send(iface->dhcpv6_event.uloop.fd, &target, &iov, 1, iface);
}

static struct odhcpd_ipaddr *relay_link_address(struct interface *iface)
{
	struct odhcpd_ipaddr *addr = NULL;
	time_t now = odhcpd_time();

	for (size_t i = 0; i < iface->addr6_len; i++) {
		if (iface->addr6[i].valid_lt <= (uint32_t)now)
			continue;

		if (iface->addr6[i].preferred_lt > (uint32_t)now) {
			addr = &iface->addr6[i];
			break;
		}

		if (!addr || (iface->addr6[i].valid_lt > addr->valid_lt))
			addr = &iface->addr6[i];
	}

	return addr;
}

/* Recursively validate ADDR-REG-INFORM messages through relay layers.
 * RFC9686 §4.2.1: The IA Address must match the source address of the
 * original message (peer-address in innermost relay-forward, or source
 * IP if not relayed). Returns true if valid, false if should be discarded. */
static bool validate_addr_reg_inform(const void *data, size_t len,
				      const struct in6_addr *peer_addr)
{
	const struct dhcpv6_relay_header *rh = data;
	const struct dhcpv6_client_header *ch = data;

	if (len < sizeof(struct dhcpv6_client_header))
		return false;

	/* If this is a relay-forward, unwrap and recurse */
	if (rh->msg_type == DHCPV6_MSG_RELAY_FORW) {
		if (len < sizeof(struct dhcpv6_relay_header))
			return false;

		uint16_t otype, olen;
		uint8_t *odata;
		const uint8_t *end = (const uint8_t *)data + len;

		dhcpv6_for_each_option(rh->options, end, otype, olen, odata) {
			if (otype == DHCPV6_OPT_RELAY_MSG) {
				/* Recurse into the inner message with the relay's peer address.
				 * Copy peer_address to a local aligned buffer to avoid 
				 * address-of-packed-member warning. */
				struct in6_addr peer;
				memcpy(&peer, &rh->peer_address, sizeof(peer));
				return validate_addr_reg_inform(odata, olen, &peer);
			}
		}
		/* No relay message option found */
		return false;
	}

	/* We've reached the innermost client message */
	if (ch->msg_type != DHCPV6_MSG_ADDR_REG_INFORM)
		return true; /* Not an ADDR-REG-INFORM, no validation needed */

	/* Validate that IA_ADDR matches peer address */
	uint16_t otype, olen;
	uint8_t *odata;
	const uint8_t *start = (const uint8_t *)&ch[1];
	const uint8_t *end = (const uint8_t *)data + len;

	dhcpv6_for_each_option(start, end, otype, olen, odata) {
		if (otype != DHCPV6_OPT_IA_NA)
			continue;

		struct dhcpv6_ia_hdr *ia = (struct dhcpv6_ia_hdr *)&odata[-4];
		uint8_t *sdata;
		uint16_t stype, slen;

		dhcpv6_for_each_sub_option(&ia[1], odata + olen, stype, slen, sdata) {
			if (stype != DHCPV6_OPT_IA_ADDR || slen < sizeof(struct dhcpv6_ia_addr) - 4)
				continue;

			struct dhcpv6_ia_addr *ia_addr = (struct dhcpv6_ia_addr *)&sdata[-4];
			/* RFC9686 §4.2.1: IA Address must match source/peer address */
			if (memcmp(&ia_addr->addr, peer_addr, sizeof(struct in6_addr)) != 0)
				return false;
		}
	}

	return true;
}

/* Relay client request (regular DHCPv6-relay) */
static void relay_client_request(struct sockaddr_in6 *source,
		const void *data, size_t len, struct interface *iface)
{
	const struct dhcpv6_relay_header *h = data;
	/* Construct our forwarding envelope */
	struct dhcpv6_relay_forward_envelope hdr = {
		.msg_type = DHCPV6_MSG_RELAY_FORW,
		.hop_count = 0,
		.interface_id_type = htons(DHCPV6_OPT_INTERFACE_ID),
		.interface_id_len = htons(sizeof(uint32_t)),
		.relay_message_type = htons(DHCPV6_OPT_RELAY_MSG),
		.relay_message_len = htons(len),
	};
	struct iovec iov[2] = {{&hdr, sizeof(hdr)}, {(void *)data, len}};
	struct interface *c;
	struct odhcpd_ipaddr *ip;
	struct sockaddr_in6 s;

	switch (h->msg_type) {
	/* Valid message types from clients */
	case DHCPV6_MSG_SOLICIT:
	case DHCPV6_MSG_REQUEST:
	case DHCPV6_MSG_CONFIRM:
	case DHCPV6_MSG_RENEW:
	case DHCPV6_MSG_REBIND:
	case DHCPV6_MSG_RELEASE:
	case DHCPV6_MSG_DECLINE:
	case DHCPV6_MSG_INFORMATION_REQUEST:
	case DHCPV6_MSG_RELAY_FORW:
	case DHCPV6_MSG_DHCPV4_QUERY:
	case DHCPV6_MSG_ADDR_REG_INFORM:
		break;
	/* Invalid message types from clients i.e. server messages */
	case DHCPV6_MSG_ADVERTISE:
	case DHCPV6_MSG_REPLY:
	case DHCPV6_MSG_RECONFIGURE:
	case DHCPV6_MSG_RELAY_REPL:
	case DHCPV6_MSG_DHCPV4_RESPONSE:
	case DHCPV6_MSG_ADDR_REG_REPLY:
		return;
	default:
		break;
	}

	debug("Got a DHCPv6-request on %s", iface->name);

	if (h->msg_type == DHCPV6_MSG_RELAY_FORW) { /* handle relay-forward */
		if (h->hop_count >= DHCPV6_HOP_COUNT_LIMIT)
			return; /* Invalid hop count */

		hdr.hop_count = h->hop_count + 1;
	}

	/* RFC9686 §4.2 "fate sharing" or §4.2.1
	 * Validate ADDR-REG-INFORM messages recursively through relay layers.
	 * The IA Address must match the source address of the original message. */
	if (!validate_addr_reg_inform(data, len, &source->sin6_addr)) {
		notice("DHCPv6-relay: Discarding ADDR-REG-INFORM: address does not match source");
		return;
	}

	/* use memcpy here as the destination fields are unaligned */
	memcpy(&hdr.peer_address, &source->sin6_addr, sizeof(struct in6_addr));
	memcpy(&hdr.interface_id_data, &iface->ifindex, sizeof(iface->ifindex));

	/* Detect public IP of slave interface to use as link-address */
	ip = relay_link_address(iface);
	if (ip)
		memcpy(&hdr.link_address, &ip->addr.in6, sizeof(hdr.link_address));

	memset(&s, 0, sizeof(s));
	s.sin6_family = AF_INET6;
	s.sin6_port = htons(DHCPV6_SERVER_PORT);
	inet_pton(AF_INET6, ALL_DHCPV6_SERVERS, &s.sin6_addr);

	avl_for_each_element(&interfaces, c, avl) {
		if (!c->master || c->dhcpv6 != MODE_RELAY)
			continue;

		if (!ip) {
			/* No suitable address! Is the slave not configured yet?
			 * Detect public IP of master interface and use it instead
			 * This is WRONG and probably violates the RFC. However
			 * otherwise we have a hen and egg problem because the
			 * slave-interface cannot be auto-configured. */
			ip = relay_link_address(c);
			if (!ip)
				continue; /* Could not obtain a suitable address */

			memcpy(&hdr.link_address, &ip->addr.in6, sizeof(hdr.link_address));
			ip = NULL;
		}

		debug("Sending a DHCPv6-relay-forward on %s", c->name);

		odhcpd_send(c->dhcpv6_event.uloop.fd, &s, iov, 2, c);
	}
}
