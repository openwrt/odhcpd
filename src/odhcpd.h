/**
 * Copyright (C) 2012-2013 Steven Barth <steven@midlink.org>
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
 */

#pragma once
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <stdbool.h>
#include <syslog.h>

#include "libubox/blobmsg.h"

#ifndef typeof
#define typeof __typeof
#endif

#ifndef container_of
#define container_of(ptr, type, member) (           \
    (type *)( (char *)ptr - offsetof(type,member) ))
#endif

#include "libubox/list.h"
#include "libubox/uloop.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

// RFC 6106 defines this router advertisement option
#define ND_OPT_ROUTE_INFO 24
#define ND_OPT_RECURSIVE_DNS 25
#define ND_OPT_DNS_SEARCH 31

#define RELAYD_BUFFER_SIZE 8192
#define RELAYD_MAX_PREFIXES 8

#define _unused __attribute__((unused))
#define _packed __attribute__((packed))


#define ALL_IPV6_NODES {{{0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,\
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}}}

#define ALL_IPV6_ROUTERS {{{0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,\
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}}}


struct interface;
extern struct list_head leases;

struct odhcpd_event {
	struct uloop_fd uloop;
	void (*handle_dgram)(void *addr, void *data, size_t len,
			struct interface *iface, void *dest_addr);
};


struct odhcpd_ipaddr {
	struct in6_addr addr;
	uint8_t prefix;
	uint8_t dprefix;
	bool has_class;
	uint16_t class;
	uint32_t preferred;
	uint32_t valid;
};

enum odhcpd_mode {
	RELAYD_DISABLED,
	RELAYD_SERVER,
	RELAYD_RELAY,
	RELAYD_HYBRID
};


struct config {
	bool legacy;
	char *dhcp_cb;
	char *dhcp_statefile;
} config;


struct lease {
	struct list_head head;
	struct in_addr ipaddr;
	uint32_t hostid;
	struct ether_addr mac;
	uint16_t duid_len;
	uint8_t *duid;
	char hostname[];
};


struct interface {
	struct list_head head;

	int ifindex;
	char ifname[IF_NAMESIZE];
	char name[IF_NAMESIZE];

	// Runtime data
	struct uloop_timeout timer_rs;
	struct list_head ia_assignments;
	struct odhcpd_ipaddr ia_addr[8];
	size_t ia_addr_len;
	bool ia_reconf;

	// DHCPv4
	struct odhcpd_event dhcpv6_event;
	struct odhcpd_event dhcpv4_event;
	struct list_head dhcpv4_assignments;

	// Managed PD
	char dhcpv6_pd_manager[128];
	struct in6_addr dhcpv6_pd_cer;

	// Services
	enum odhcpd_mode ra;
	enum odhcpd_mode dhcpv6;
	enum odhcpd_mode ndp;
	enum odhcpd_mode dhcpv4;

	// Config
	bool inuse;
	bool external;
	bool master;
	bool ignore;
	bool always_rewrite_dns;
	bool ra_not_onlink;
	bool no_dynamic_dhcp;

	int learn_routes;
	int default_router;
	int managed;
	int route_preference;

	// DHCPv4
	struct in_addr dhcpv4_start;
	struct in_addr dhcpv4_end;
	struct in_addr *dhcpv4_router;
	size_t dhcpv4_router_cnt;
	struct in_addr *dhcpv4_dns;
	size_t dhcpv4_dns_cnt;
	uint32_t dhcpv4_leasetime;

	// DNS
	struct in6_addr *dns;
	size_t dns_cnt;
	uint8_t *search;
	size_t search_len;

	void *dhcpv6_raw;
	size_t dhcpv6_raw_len;

	char* static_ndp;
	size_t static_ndp_len;

	char *upstream;
	size_t upstream_len;

	char *filter_class;
};

extern struct list_head interfaces;

#define RELAYD_MANAGED_MFLAG	1
#define RELAYD_MANAGED_NO_AFLAG	2


// Exported main functions
int odhcpd_open_rtnl(void);
int odhcpd_register(struct odhcpd_event *event);

ssize_t odhcpd_send(int socket, struct sockaddr_in6 *dest,
		struct iovec *iov, size_t iov_len,
		const struct interface *iface);
ssize_t odhcpd_get_interface_addresses(int ifindex,
		struct odhcpd_ipaddr *addrs, size_t cnt);
struct interface* odhcpd_get_interface_by_name(const char *name);
int odhcpd_get_interface_mtu(const char *ifname);
int odhcpd_get_mac(const struct interface *iface, uint8_t mac[6]);
struct interface* odhcpd_get_interface_by_index(int ifindex);
struct interface* odhcpd_get_master_interface(void);
void odhcpd_urandom(void *data, size_t len);
void odhcpd_setup_route(const struct in6_addr *addr, int prefixlen,
		const struct interface *iface, const struct in6_addr *gw, bool add);

void odhcpd_run(void);
time_t odhcpd_time(void);
ssize_t odhcpd_unhexlify(uint8_t *dst, size_t len, const char *src);
void odhcpd_hexlify(char *dst, const uint8_t *src, size_t len);

int odhcpd_bmemcmp(const void *av, const void *bv, size_t bits);
void odhcpd_bmemcpy(void *av, const void *bv, size_t bits);

int config_parse_interface(void *data, size_t len, const char *iname, bool overwrite);

#ifdef WITH_UBUS
int init_ubus(void);
const char* ubus_get_ifname(const char *name);
void ubus_apply_network(void);
bool ubus_has_prefix(const char *name, const char *ifname);
bool ubus_get_class(const char *ifname, const struct in6_addr *addr, uint16_t *pclass);
#endif


// Exported module initializers
int init_router(void);
int init_dhcpv6(void);
int init_dhcpv4(void);
int init_ndp(void);

int setup_router_interface(struct interface *iface, bool enable);
int setup_dhcpv6_interface(struct interface *iface, bool enable);
int setup_ndp_interface(struct interface *iface, bool enable);
int setup_dhcpv4_interface(struct interface *iface, bool enable);

void odhcpd_reload(void);
