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

enum dhcpv4_op {
	DHCPV4_BOOTREQUEST = 1,
	DHCPV4_BOOTREPLY = 2
};

enum dhcpv4_msg {
	DHCPV4_MSG_DISCOVER = 1,
	DHCPV4_MSG_OFFER = 2,
	DHCPV4_MSG_REQUEST = 3,
	DHCPV4_MSG_DECLINE = 4,
	DHCPV4_MSG_ACK = 5,
	DHCPV4_MSG_NAK = 6,
	DHCPV4_MSG_RELEASE = 7,
	DHCPV4_MSG_INFORM = 8,
	DHCPV4_MSG_FORCERENEW = 9,
};

enum dhcpv4_opt {
	DHCPV4_OPT_PAD = 0,
	DHCPV4_OPT_NETMASK = 1,
	DHCPV4_OPT_ROUTER = 3,
	DHCPV4_OPT_DNSSERVER = 6,
	DHCPV4_OPT_DOMAIN = 15,
	DHCPV4_OPT_MTU = 26,
	DHCPV4_OPT_BROADCAST = 28,
	DHCPV4_OPT_NTPSERVER = 42,
	DHCPV4_OPT_LEASETIME = 51,
	DHCPV4_OPT_MESSAGE = 53,
	DHCPV4_OPT_SERVERID = 54,
	DHCPV4_OPT_REQOPTS = 55,
	DHCPV4_OPT_RENEW = 58,
	DHCPV4_OPT_REBIND = 59,
	DHCPV4_OPT_IPADDRESS = 50,
	DHCPV4_OPT_HOSTNAME = 12,
	DHCPV4_OPT_REQUEST = 17,
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
	uint8_t options[312];
};

struct dhcpv4_auth_forcerenew {
	uint8_t protocol;
	uint8_t algorithm;
	uint8_t rdm;
	uint32_t replay[2];
	uint8_t type;
	uint8_t key[16];
} _packed;

struct dhcpv4_option {
	uint8_t type;
	uint8_t len;
	uint8_t data[];
};


#define dhcpv4_for_each_option(start, end, opt)\
	for (opt = (struct dhcpv4_option*)(start); \
		&opt[1] <= (struct dhcpv4_option*)(end) && \
			&opt->data[opt->len] <= (end); \
		opt = (struct dhcpv4_option*)&opt->data[opt->len])
