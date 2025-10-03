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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 *
 */

#include <errno.h>
#include <unistd.h>
#include <stddef.h>
#include <resolv.h>
#include <sys/timerfd.h>
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
	IOV_MAXRT,
#define IOV_STAT IOV_MAXRT
	IOV_RAPID_COMMIT,
	IOV_DNS,
	IOV_DNS_ADDR,
	IOV_SEARCH,
	IOV_SEARCH_DOMAIN,
	IOV_PDBUF,
#define	IOV_REFRESH IOV_PDBUF
	IOV_CERID,
	IOV_DHCPV6_RAW,
	IOV_NTP,
	IOV_NTP_ADDR,
	IOV_SNTP,
	IOV_SNTP_ADDR,
	IOV_RELAY_MSG,
	IOV_DHCPV4O6_SERVER,
	IOV_DNR,
	IOV_BOOTFILE_URL,
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

static int send_reply(_unused const void *buf, size_t len,
		      _unused const struct sockaddr *dest, _unused socklen_t dest_len,
		      _unused void *opaque)
{
	struct dhcpv4_msg_data *reply = opaque;

	if (len > reply->maxsize) {
		error("4o6: reply too large, %zu > %zu", len, reply->maxsize);
		reply->len = -1;
	} else {
		memcpy(reply->msg, buf, len);
		reply->len = len;
	}

	return reply->len;
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
			  iface, NULL, send_reply, &reply);

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
	default:
		return;
	}

	debug("Got a DHCPv6-request on %s", iface->name);

	/* Construct reply message */
	struct __attribute__((packed)) {
		uint8_t msg_type;
		uint8_t tr_id[3];
		uint16_t serverid_type;
		uint16_t serverid_length;
		uint16_t duid_type;
		uint16_t hardware_type;
		uint8_t mac[6];
		uint16_t clientid_type;
		uint16_t clientid_length;
		uint8_t clientid_buf[130];
	} dest = {
		.msg_type = DHCPV6_MSG_REPLY,
		.serverid_type = htons(DHCPV6_OPT_SERVERID),
		.serverid_length = htons(10),
		.duid_type = htons(3),
		.hardware_type = htons(1),
		.clientid_type = htons(DHCPV6_OPT_CLIENTID),
		.clientid_buf = {0}
	};
	odhcpd_get_mac(iface, dest.mac);

	struct __attribute__((packed)) {
		uint16_t type;
		uint16_t len;
		uint32_t value;
	} maxrt = {htons(DHCPV6_OPT_SOL_MAX_RT), htons(sizeof(maxrt) - 4),
			htonl(60)};

	struct __attribute__((packed)) {
		uint16_t type;
		uint16_t len;
	} rapid_commit = {htons(DHCPV6_OPT_RAPID_COMMIT), 0};

	struct __attribute__((packed)) {
		uint16_t type;
		uint16_t len;
		uint16_t value;
	} stat = {htons(DHCPV6_OPT_STATUS), htons(sizeof(stat) - 4),
			htons(DHCPV6_STATUS_USEMULTICAST)};

	struct __attribute__((packed)) {
		uint16_t type;
		uint16_t len;
		uint32_t value;
	} refresh = {htons(DHCPV6_OPT_INFO_REFRESH), htons(sizeof(uint32_t)),
			htonl(600)};

	struct in6_addr dns_addr, *dns_addr_ptr = iface->dns;
	size_t dns_cnt = iface->dns_cnt;

	if ((dns_cnt == 0) &&
		!odhcpd_get_interface_dns_addr(iface, &dns_addr)) {
		dns_addr_ptr = &dns_addr;
		dns_cnt = 1;
	}

	struct {
		uint16_t type;
		uint16_t len;
	} dns = {htons(DHCPV6_OPT_DNS_SERVERS), htons(dns_cnt * sizeof(*dns_addr_ptr))};

	/* SNTP */
	struct in6_addr *sntp_addr_ptr = iface->dhcpv6_sntp;
	size_t sntp_cnt = 0;
	struct {
		uint16_t type;
		uint16_t len;
	} dhcpv6_sntp;

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

		case DHCPV6_OPT_DNR:
			for (size_t i = 0; i < iface->dnr_cnt; i++) {
				struct dnr_options *dnr = &iface->dnr[i];

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

			for (size_t i = 0; i < iface->dnr_cnt; i++) {
				struct dnr_options *dnr = &iface->dnr[i];
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
		}
	}

	/* DNS Search options */
	uint8_t search_buf[256], *search_domain = iface->search;
	size_t search_len = iface->search_len;

	if (!search_domain && !res_init() && _res.dnsrch[0] && _res.dnsrch[0][0]) {
		int len = dn_comp(_res.dnsrch[0], search_buf,
				sizeof(search_buf), NULL, NULL);
		if (len > 0) {
			search_domain = search_buf;
			search_len = len;
		}
	}

	struct {
		uint16_t type;
		uint16_t len;
	} search = {htons(DHCPV6_OPT_DNS_DOMAIN), htons(search_len)};


	struct __attribute__((packed)) dhcpv4o6_server {
		uint16_t type;
		uint16_t len;
		struct in6_addr addr;
	} dhcpv4o6_server = {htons(DHCPV6_OPT_4O6_SERVER), htons(sizeof(struct in6_addr)),
			IN6ADDR_ANY_INIT};

	struct dhcpv6_cer_id cerid = {
#ifdef EXT_CER_ID
		.type = htons(EXT_CER_ID),
#endif
		.len = htons(36),
		.addr = iface->dhcpv6_pd_cer,
	};


	uint8_t pdbuf[512];
	struct iovec iov[IOV_TOTAL] = {
		[IOV_NESTED] = {NULL, 0},
		[IOV_DEST] = {&dest, (uint8_t*)&dest.clientid_type - (uint8_t*)&dest},
		[IOV_MAXRT] = {&maxrt, sizeof(maxrt)},
		[IOV_RAPID_COMMIT] = {&rapid_commit, 0},
		[IOV_DNS] = {&dns, (dns_cnt) ? sizeof(dns) : 0},
		[IOV_DNS_ADDR] = {dns_addr_ptr, dns_cnt * sizeof(*dns_addr_ptr)},
		[IOV_SEARCH] = {&search, (search_len) ? sizeof(search) : 0},
		[IOV_SEARCH_DOMAIN] = {search_domain, search_len},
		[IOV_PDBUF] = {pdbuf, 0},
		[IOV_CERID] = {&cerid, 0},
		[IOV_DHCPV6_RAW] = {iface->dhcpv6_raw, iface->dhcpv6_raw_len},
		[IOV_NTP] = {&ntp, (ntp_cnt) ? sizeof(ntp) : 0},
		[IOV_NTP_ADDR] = {ntp_ptr, (ntp_cnt) ? ntp_len : 0},
		[IOV_SNTP] = {&dhcpv6_sntp, (sntp_cnt) ? sizeof(dhcpv6_sntp) : 0},
		[IOV_SNTP_ADDR] = {sntp_addr_ptr, sntp_cnt * sizeof(*sntp_addr_ptr)},
		[IOV_DNR] = {dnrs, dnrs_len},
		[IOV_RELAY_MSG] = {NULL, 0},
		[IOV_DHCPV4O6_SERVER] = {&dhcpv4o6_server, 0},
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
		if (otype == DHCPV6_OPT_CLIENTID && olen <= 130) {
			dest.clientid_length = htons(olen);
			memcpy(dest.clientid_buf, odata, olen);
			iov[IOV_DEST].iov_len += 4 + olen;
		} else if (otype == DHCPV6_OPT_SERVERID) {
			if (olen != ntohs(dest.serverid_length) ||
					memcmp(odata, &dest.duid_type, olen))
				return; /* Not for us */
		} else if (iface->filter_class && otype == DHCPV6_OPT_USER_CLASS) {
			uint8_t *c = odata, *cend = &odata[olen];
			for (; &c[2] <= cend && &c[2 + (c[0] << 8) + c[1]] <= cend; c = &c[2 + (c[0] << 8) + c[1]]) {
				size_t elen = strlen(iface->filter_class);
				if (((((size_t)c[0]) << 8) | c[1]) == elen && !memcmp(&c[2], iface->filter_class, elen))
					return; /* Ignore from homenet */
			}
		} else if (otype == DHCPV6_OPT_IA_PD) {
#ifdef EXT_CER_ID
			iov[IOV_CERID].iov_len = sizeof(cerid);

			if (IN6_IS_ADDR_UNSPECIFIED(&cerid.addr)) {
				struct odhcpd_ipaddr *addrs;
				ssize_t len = netlink_get_interface_addrs(0, true, &addrs);

				for (ssize_t i = 0; i < len; ++i)
					if (IN6_IS_ADDR_UNSPECIFIED(&cerid.addr)
							|| memcmp(&addrs[i].addr, &cerid.addr, sizeof(cerid.addr)) < 0)
						cerid.addr = addrs[i].addr.in6;

				free(addrs);
			}
#endif
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
		struct _packed dhcpv4_msg_data {
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
				      iov[IOV_DHCPV4O6_SERVER].iov_len +
				      iov[IOV_CERID].iov_len + iov[IOV_DHCPV6_RAW].iov_len +
				      iov[IOV_NTP].iov_len + iov[IOV_NTP_ADDR].iov_len +
				      iov[IOV_SNTP].iov_len + iov[IOV_SNTP_ADDR].iov_len +
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
	int otype, olen;
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
	struct in6_addr *dns_ptr = NULL;
	size_t dns_count = 0;

	/* If the payload is relay-reply we have to send to the server port */
	if (payload_data[0] == DHCPV6_MSG_RELAY_REPL) {
		target.sin6_port = htons(DHCPV6_SERVER_PORT);
	} else { /* Go through the payload data */
		struct dhcpv6_client_header *h = (void*)payload_data;
		end = payload_data + payload_len;

		dhcpv6_for_each_option(&h[1], end, otype, olen, odata) {
			if (otype == DHCPV6_OPT_DNS_SERVERS && olen >= 16) {
				dns_ptr = (struct in6_addr*)odata;
				dns_count = olen / 16;
			} else if (otype == DHCPV6_OPT_AUTH) {
				is_authenticated = true;
			}
		}
	}

	/* Rewrite DNS servers if requested */
	if (iface->always_rewrite_dns && dns_ptr && dns_count > 0) {
		if (is_authenticated)
			return; /* Impossible to rewrite */

		const struct in6_addr *rewrite = iface->dns;
		struct in6_addr addr;
		size_t rewrite_cnt = iface->dns_cnt;

		if (rewrite_cnt == 0) {
			if (odhcpd_get_interface_dns_addr(iface, &addr))
				return; /* Unable to get interface address */

			rewrite = &addr;
			rewrite_cnt = 1;
		}

		/* Copy over any other addresses */
		for (size_t i = 0; i < dns_count; ++i) {
			size_t j = (i < rewrite_cnt) ? i : rewrite_cnt - 1;
			memcpy(&dns_ptr[i], &rewrite[j], sizeof(*rewrite));
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
		break;
	/* Invalid message types from clients i.e. server messages */
	case DHCPV6_MSG_ADVERTISE:
	case DHCPV6_MSG_REPLY:
	case DHCPV6_MSG_RECONFIGURE:
	case DHCPV6_MSG_RELAY_REPL:
	case DHCPV6_MSG_DHCPV4_RESPONSE:
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
