/**
 *   Copyright (C) 2012 Steven Barth <steven@midlink.org>
 *   Copyright (C) 2016 Hans Dedecker <dedeckeh@gmail.com>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License version 2
 *   as published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License version 2 for more details.
 *
 */
#pragma once

#define DHCPV4_CLIENT_PORT 68
#define DHCPV4_SERVER_PORT 67

#define DHCPV4_FLAG_BROADCAST  0x8000

#define DHCPV4_MIN_PACKET_SIZE 300

#define DHCPV4_FR_MIN_DELAY	500
#define DHCPV4_FR_MAX_FUZZ	500

enum dhcpv4_op {
	DHCPV4_OP_BOOTREQUEST = 1,
	DHCPV4_OP_BOOTREPLY = 2,
};

// https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml#message-type-53
enum dhcpv4_msg {
	DHCPV4_MSG_DISCOVER		= 1,	 // RFC2132
	DHCPV4_MSG_OFFER		= 2,	 // RFC2132
	DHCPV4_MSG_REQUEST		= 3,	 // RFC2132
	DHCPV4_MSG_DECLINE		= 4,	 // RFC2132
	DHCPV4_MSG_ACK			= 5,	 // RFC2132
	DHCPV4_MSG_NAK			= 6,	 // RFC2132
	DHCPV4_MSG_RELEASE		= 7,	 // RFC2132
	DHCPV4_MSG_INFORM		= 8,	 // RFC2132
	DHCPV4_MSG_FORCERENEW		= 9,	 // RFC3203
	DHCPV4_MSG_LEASEQUERY		= 10,	 // RFC4388
	DHCPV4_MSG_LEASEUNASSIGNED	= 11,	 // RFC4388
	DHCPV4_MSG_LEASEUNKNOWN		= 12,	 // RFC4388
	DHCPV4_MSG_LEASEACTIVE		= 13,	 // RFC4388
	DHCPV4_MSG_BULKLEASEQUERY	= 14,	 // RFC6926
	DHCPV4_MSG_LEASEQUERYDONE	= 15,	 // RFC6926
	DHCPV4_MSG_ACTIVELEASEQUERY	= 16,	 // RFC7724
	DHCPV4_MSG_LEASEQUERYSTATUS	= 17,	 // RFC7724
	DHCPV4_MSG_TLS			= 18,	 // RFC7724
};

enum dhcpv4_opt {
	DHCPV4_OPT_PAD = 0,
	DHCPV4_OPT_NETMASK = 1,
	DHCPV4_OPT_ROUTER = 3,
	DHCPV4_OPT_DNSSERVER = 6,
	DHCPV4_OPT_HOSTNAME = 12,
	DHCPV4_OPT_DOMAIN = 15,
	DHCPV4_OPT_REQUEST = 17,
	DHCPV4_OPT_MTU = 26,
	DHCPV4_OPT_BROADCAST = 28,
	DHCPV4_OPT_NTPSERVER = 42,
	DHCPV4_OPT_IPADDRESS = 50,
	DHCPV4_OPT_LEASETIME = 51,
	DHCPV4_OPT_MESSAGE = 53,
	DHCPV4_OPT_SERVERID = 54,
	DHCPV4_OPT_REQOPTS = 55,
	DHCPV4_OPT_RENEW = 58,
	DHCPV4_OPT_REBIND = 59,
	DHCPV4_OPT_USER_CLASS = 77,
	DHCPV4_OPT_AUTHENTICATION = 90,
	DHCPV4_OPT_SEARCH_DOMAIN = 119,
	DHCPV4_OPT_FORCERENEW_NONCE_CAPABLE = 145,
	DHCPV4_OPT_DNR = 162,
	DHCPV4_OPT_END = 255,
};

struct dhcpv4_message {
	uint8_t op;
	uint8_t htype;
	uint8_t hlen;
	uint8_t hops;
	uint32_t xid;
	uint16_t secs;
	uint16_t flags;
	struct in_addr ciaddr;
	struct in_addr yiaddr;
	struct in_addr siaddr;
	struct in_addr giaddr;
	uint8_t chaddr[16];
	char sname[64];
	char file[128];
	uint32_t cookie;
	uint8_t options[308];
} _packed;

// RFC2131, §3
#define DHCPV4_MAGIC_COOKIE 0x63825363

// RFC3203, §6; RFC3118, §2; RFC6704, §3.1.2
struct dhcpv4_auth_forcerenew {
	uint8_t protocol;
	uint8_t algorithm;
	uint8_t rdm;
	uint32_t replay[2];
	uint8_t type;
	uint8_t key[16];
} _packed;

// https://www.iana.org/assignments/auth-namespaces/auth-namespaces.xhtml#auth-namespaces-1
enum dhcpv4_auth_protocol {
	DHCPV4_AUTH_PROTO_CFG_TOKEN	=	0,	// RFC3118
	DHCPV4_AUTH_PROTO_DELAYED	=	1,	// RFC3118
	DHCPV4_AUTH_PROTO_DELAYED_OBS	=	2,	// RFC8415, Obsolete
	DHCPV4_AUTH_PROTO_RKAP		=	3,	// RFC8415, also RFC6704
	DHCPV4_AUTH_PROTO_SPLIT_DNS	=	4,	// RFC9704
};

// https://www.iana.org/assignments/auth-namespaces/auth-namespaces.xhtml#auth-namespaces-2
enum dhcpv4_auth_algorithm {
	DHCPV4_AUTH_ALG_CFG_TOKEN	=	0,	// RFC3118
	DHCPV4_AUTH_ALG_HMAC_MD5	=	1,	// RFC3118, RFC8415, also RFC6704
};

// https://www.iana.org/assignments/auth-namespaces/auth-namespaces.xhtml#auth-namespaces-2
enum dhcpv4_auth_rdm {
	DHCPV4_AUTH_RDM_MONOTONIC	=	0,	// RFC3118, RFC8415, also RFC6704
};

// RFC6704, §3.1.2 (for DHCPv6: RFC8415, §20.4)
enum dhcpv4_auth_rkap_ai_type {
	DHCPV4_AUTH_RKAP_AI_TYPE_KEY		=	1,
	DHCPV4_AUTH_RKAP_AI_TYPE_MD5_DIGEST	=	2,
};

struct dhcpv4_option {
	uint8_t code;
	uint8_t len;
	uint8_t data[];
};

struct dhcpv4_option_u8 {
	uint8_t code;
	uint8_t len;
	uint8_t data;
};

struct dhcpv4_option_u32 {
	uint8_t code;
	uint8_t len;
	uint32_t data;
} _packed;

/* DNR */
struct dhcpv4_dnr {
	uint16_t len;
	uint16_t priority;
	uint8_t adn_len;
	uint8_t body[];
};


#define dhcpv4_for_each_option(start, end, opt)\
	for (opt = (struct dhcpv4_option*)(start); \
		&opt[1] <= (struct dhcpv4_option*)(end) && \
			&opt->data[opt->len] <= (end); \
		opt = (struct dhcpv4_option*)&opt->data[opt->len])
