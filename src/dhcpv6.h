/**
 * Copyright (C) 2012 Steven Barth <steven@midlink.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License version 2 for more details.
 *
 */

#ifndef _DHCPV6_H_
#define _DHCPV6_H_

#include "odhcpd.h"

#define ALL_DHCPV6_RELAYS "ff02::1:2"

#define ALL_DHCPV6_SERVERS "ff05::1:3"

#define DHCPV6_CLIENT_PORT 546
#define DHCPV6_SERVER_PORT 547

/* RFC8415 */
#define DHCPV6_MSG_SOLICIT 1
#define DHCPV6_MSG_ADVERTISE 2
#define DHCPV6_MSG_REQUEST 3
#define DHCPV6_MSG_CONFIRM 4
#define DHCPV6_MSG_RENEW 5
#define DHCPV6_MSG_REBIND 6
#define DHCPV6_MSG_REPLY 7
#define DHCPV6_MSG_RELEASE 8
#define DHCPV6_MSG_DECLINE 9
#define DHCPV6_MSG_RECONFIGURE 10
#define DHCPV6_MSG_INFORMATION_REQUEST 11
#define DHCPV6_MSG_RELAY_FORW 12
#define DHCPV6_MSG_RELAY_REPL 13
/* RFC7341 */
#define DHCPV6_MSG_DHCPV4_QUERY 20
#define DHCPV6_MSG_DHCPV4_RESPONSE 21

#define DHCPV6_OPT_CLIENTID 1
#define DHCPV6_OPT_SERVERID 2
#define DHCPV6_OPT_IA_NA 3
#define DHCPV6_OPT_IA_ADDR 5
#define DHCPV6_OPT_ORO 6
#define DHCPV6_OPT_STATUS 13
#define DHCPV6_OPT_RELAY_MSG 9
#define DHCPV6_OPT_AUTH 11
#define DHCPV6_OPT_RAPID_COMMIT 14
#define DHCPV6_OPT_USER_CLASS 15
#define DHCPV6_OPT_INTERFACE_ID 18
#define DHCPV6_OPT_RECONF_MSG 19
#define DHCPV6_OPT_RECONF_ACCEPT 20
#define DHCPV6_OPT_DNS_SERVERS 23
#define DHCPV6_OPT_DNS_DOMAIN 24
#define DHCPV6_OPT_IA_PD 25
#define DHCPV6_OPT_IA_PREFIX 26
#define DHCPV6_OPT_SNTP_SERVERS 31
#define DHCPV6_OPT_INFO_REFRESH 32
#define DHCPV6_OPT_FQDN 39
/* RFC 4833 */
#define DHCPV6_OPT_NEW_POSIX_TIMEZONE 41
#define DHCPV6_OPT_NEW_TZDB_TIMEZONE 42

#define DHCPV6_OPT_NTP_SERVERS 56
#define DHCPV6_OPT_BOOTFILE_URL 59
#define DHCPV6_OPT_BOOTFILE_PARAM 60
#define DHCPV6_OPT_CLIENT_ARCH 61
#define DHCPV6_OPT_SOL_MAX_RT 82
#define DHCPV6_OPT_INF_MAX_RT 83
#define DHCPV6_OPT_DHCPV4_MSG 87
#define DHCPV6_OPT_4O6_SERVER 88
/* RFC8910 */
#define DHCPV6_OPT_CAPTIVE_PORTAL 103
#define DHCPV6_OPT_DNR 144

#define DHCPV6_DUID_VENDOR 2

#define DHCPV6_STATUS_OK 0
#define DHCPV6_STATUS_NOADDRSAVAIL 2
#define DHCPV6_STATUS_NOBINDING 3
#define DHCPV6_STATUS_NOTONLINK 4
#define DHCPV6_STATUS_USEMULTICAST 5
#define DHCPV6_STATUS_NOPREFIXAVAIL 6

// I just remembered I have an old one lying around...
#define DHCPV6_ENT_NO 30462
#define DHCPV6_ENT_TYPE 1


#define DHCPV6_HOP_COUNT_LIMIT 32

#define DHCPV6_REC_TIMEOUT	2000 /* msec */
#define DHCPV6_REC_MAX_RC	8

struct dhcpv6_client_header {
	uint8_t msg_type;
	uint8_t transaction_id[3];
} _o_packed;

struct dhcpv6_relay_header {
	uint8_t msg_type;
	uint8_t hop_count;
	struct in6_addr link_address;
	struct in6_addr peer_address;
	uint8_t options[];
} _o_packed;

struct dhcpv6_relay_forward_envelope {
	uint8_t msg_type;
	uint8_t hop_count;
	struct in6_addr link_address;
	struct in6_addr peer_address;
	uint16_t interface_id_type;
	uint16_t interface_id_len;
	uint32_t interface_id_data;
	uint16_t relay_message_type;
	uint16_t relay_message_len;
} _o_packed;

struct dhcpv6_auth_reconfigure {
	uint16_t type;
	uint16_t len;
	uint8_t protocol;
	uint8_t algorithm;
	uint8_t rdm;
	uint32_t replay[2];
	uint8_t reconf_type;
	uint8_t key[16];
} _o_packed;

struct dhcpv6_ia_hdr {
	uint16_t type;
	uint16_t len;
	uint32_t iaid;
	uint32_t t1;
	uint32_t t2;
} _o_packed;

struct dhcpv6_ia_prefix {
	uint16_t type;
	uint16_t len;
	uint32_t preferred_lt;
	uint32_t valid_lt;
	uint8_t prefix_len;
	struct in6_addr addr;
} _o_packed;

struct dhcpv6_ia_addr {
	uint16_t type;
	uint16_t len;
	struct in6_addr addr;
	uint32_t preferred_lt;
	uint32_t valid_lt;
} _o_packed;

struct dhcpv6_cer_id {
	uint16_t type;
	uint16_t len;
	uint16_t reserved;
	uint16_t auth_type;
	uint8_t auth[16];
	struct in6_addr addr;
};

#define dhcpv6_for_each_option(start, end, otype, olen, odata)\
	for (uint8_t *_o = (uint8_t*)(start); _o + 4 <= (end) &&\
		((otype) = _o[0] << 8 | _o[1]) && ((odata) = (void*)&_o[4]) &&\
		((olen) = _o[2] << 8 | _o[3]) + (odata) <= (end); \
		_o += 4 + (_o[2] << 8 | _o[3]))

#endif /* _DHCPV6_H_ */
