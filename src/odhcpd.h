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
#include <stdbool.h>
#include <syslog.h>

#include <libubox/blobmsg.h>
#include <libubox/list.h>
#include <libubox/uloop.h>
#include <libubox/avl.h>
#include <libubox/ustream.h>
#include <libubox/vlist.h>

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))

// RFC 6106 defines this router advertisement option
#define ND_OPT_ROUTE_INFO 24
#define ND_OPT_RECURSIVE_DNS 25
#define ND_OPT_DNS_SEARCH 31

// RFC 8781 defines PREF64 option
#define ND_OPT_PREF64 38

// RFC 9096 defines recommended option lifetimes configuration values
#define ND_PREFERRED_LIMIT 2700
#define ND_VALID_LIMIT 5400

#define INFINITE_VALID(x) ((x) == 0)

#define _unused __attribute__((unused))
#define _packed __attribute__((packed))

#define ALL_IPV6_NODES "ff02::1"
#define ALL_IPV6_ROUTERS "ff02::2"

#define NTP_SUBOPTION_SRV_ADDR 1
#define NTP_SUBOPTION_MC_ADDR 2
#define NTP_SUBOPTION_SRV_FQDN 3
#define IPV6_ADDR_LEN 16

#define IN6_IS_ADDR_ULA(a) (((a)->s6_addr32[0] & htonl(0xfe000000)) == htonl(0xfc000000))

#define ADDR_MATCH_PIO_FILTER(_addr, iface) (odhcpd_bmemcmp(&(_addr)->addr, \
							    &(iface)->pio_filter_addr, \
							    (iface)->pio_filter_length) != 0 || \
		                             (_addr)->prefix < (iface)->pio_filter_length)

struct interface;
struct nl_sock;
extern struct vlist_tree leases;
extern struct config config;

struct odhcpd_event {
	struct uloop_fd uloop;
	void (*handle_dgram)(void *addr, void *data, size_t len,
			struct interface *iface, void *dest_addr);
	void (*handle_error)(struct odhcpd_event *e, int error);
	void (*recv_msgs)(struct odhcpd_event *e);
};

typedef	int (*send_reply_cb_t)(const void *buf, size_t len,
			       const struct sockaddr *dest, socklen_t dest_len,
			       void *opaque);

typedef void (*dhcpv6_binding_cb_handler_t)(struct in6_addr *addr, int prefix,
					    uint32_t pref, uint32_t valid,
					    void *arg);

union if_addr {
	struct in_addr in;
	struct in6_addr in6;
};

struct netevent_handler_info {
	struct interface *iface;
	union {
		struct {
			union if_addr dst;
			uint8_t dst_len;
			union if_addr gateway;
		} rt;
		struct {
			union if_addr dst;
			uint16_t state;
			uint8_t flags;
		} neigh;
		struct {
			struct odhcpd_ipaddr *addrs;
			size_t len;
		} addrs_old;
		union if_addr addr;
	};
};

enum netevents {
	NETEV_IFINDEX_CHANGE,
	NETEV_ADDR_ADD,
	NETEV_ADDR_DEL,
	NETEV_ADDRLIST_CHANGE,
	NETEV_ADDR6_ADD,
	NETEV_ADDR6_DEL,
	NETEV_ADDR6LIST_CHANGE,
	NETEV_ROUTE6_ADD,
	NETEV_ROUTE6_DEL,
	NETEV_NEIGH6_ADD,
	NETEV_NEIGH6_DEL,
};

struct netevent_handler {
	struct list_head head;
	void (*cb) (unsigned long event, struct netevent_handler_info *info);
};

struct odhcpd_ipaddr {
	union if_addr addr;
	uint8_t prefix;
	uint32_t preferred;
	uint32_t valid;

	union {
		/* ipv6 only */
		struct {
			uint8_t dprefix;
			uint8_t invalid_advertisements;
			bool tentative;
		};

		/* ipv4 only */
		struct in_addr broadcast;
	};
};

enum odhcpd_mode {
	MODE_DISABLED,
	MODE_SERVER,
	MODE_RELAY,
	MODE_HYBRID
};


enum odhcpd_assignment_flags {
	OAF_TENTATIVE		= (1 << 0),
	OAF_BOUND		= (1 << 1),
	OAF_STATIC		= (1 << 2),
	OAF_BROKEN_HOSTNAME	= (1 << 3),
	OAF_DHCPV4		= (1 << 4),
	OAF_DHCPV6_NA		= (1 << 5),
	OAF_DHCPV6_PD		= (1 << 6),
};

struct config {
	bool legacy;
	bool main_dhcpv4;
	char *dhcp_cb;
	char *dhcp_statefile;
	char *dhcp_hostsfile;
	int log_level;
};


struct lease {
	struct vlist_node node;
	struct list_head assignments;
	uint32_t ipaddr;
	uint64_t hostid;
	struct ether_addr mac;
	uint16_t duid_len;
	uint8_t *duid;
	uint32_t leasetime;
	char *hostname;
};

enum {
	LEASE_ATTR_IP,
	LEASE_ATTR_MAC,
	LEASE_ATTR_DUID,
	LEASE_ATTR_HOSTID,
	LEASE_ATTR_LEASETIME,
	LEASE_ATTR_NAME,
	LEASE_ATTR_MAX
};

struct odhcpd_ref_ip;

struct dhcp_assignment {
	struct list_head head;
	struct list_head lease_list;

	void (*dhcp_free_cb)(struct dhcp_assignment *a);

	struct interface *iface;
	struct lease *lease;

	struct sockaddr_in6 peer;
	time_t valid_until;
	time_t preferred_until;

#define fr_timer	reconf_timer
	struct uloop_timeout reconf_timer;
#define accept_fr_nonce accept_reconf
	bool accept_reconf;
#define fr_cnt		reconf_cnt
	int reconf_cnt;
	uint8_t key[16];
	struct odhcpd_ref_ip *fr_ip;

	uint32_t addr;
	union {
		uint64_t assigned_host_id;
		uint32_t assigned_subnet_id;
	};
	uint32_t iaid;
	uint8_t length; // length == 128 -> IA_NA, length <= 64 -> IA_PD

	struct odhcpd_ipaddr *managed;
	ssize_t managed_size;
	struct ustream_fd managed_sock;

	unsigned int flags;
	uint32_t leasetime;
	char *hostname;
	char *reqopts;
#define hwaddr		mac
	uint8_t mac[6];

	uint16_t clid_len;
	uint8_t clid_data[];
};


struct interface {
	struct avl_node avl;

	int ifflags;
	int ifindex;
	char *ifname;
	const char *name;

	// IPv6 runtime data
	struct odhcpd_ipaddr *addr6;
	size_t addr6_len;
	struct odhcpd_ipaddr *invalid_addr6;
	size_t invalid_addr6_len;

	// RA runtime data
	struct odhcpd_event router_event;
	struct uloop_timeout timer_rs;
	uint32_t ra_sent;

	// DHCPv6 runtime data
	struct odhcpd_event dhcpv6_event;
	struct list_head ia_assignments;

	// NDP runtime data
	struct odhcpd_event ndp_event;
	int ndp_ping_fd;

	// IPv4 runtime data
	struct odhcpd_ipaddr *addr4;
	size_t addr4_len;

	// DHCPv4 runtime data
	struct odhcpd_event dhcpv4_event;
	struct list_head dhcpv4_assignments;
	struct list_head dhcpv4_fr_ips;

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
	bool dns_service;

	// NDP
	int learn_routes;

	// RA
	uint8_t ra_flags;
	bool ra_slaac;
	bool ra_not_onlink;
	bool ra_advrouter;
	bool ra_dns;
	uint8_t pref64_length;
	struct in6_addr pref64_addr;
	bool no_dynamic_dhcp;
	bool have_link_local;
	uint8_t pio_filter_length;
	struct in6_addr pio_filter_addr;
	int default_router;
	int route_preference;
	int ra_maxinterval;
	int ra_mininterval;
	int ra_lifetime;
	uint32_t ra_reachabletime;
	uint32_t ra_retranstime;
	uint32_t ra_hoplimit;
	int ra_mtu;
	uint32_t max_preferred_lifetime;
	uint32_t max_valid_lifetime;

	// DHCPv4
	struct in_addr dhcpv4_start;
	struct in_addr dhcpv4_end;
	struct in_addr dhcpv4_start_ip;
	struct in_addr dhcpv4_end_ip;
	struct in_addr dhcpv4_local;
	struct in_addr dhcpv4_bcast;
	struct in_addr dhcpv4_mask;
	struct in_addr *dhcpv4_router;
	size_t dhcpv4_router_cnt;
	struct in_addr *dhcpv4_dns;
	size_t dhcpv4_dns_cnt;
	uint32_t dhcpv4_leasetime;
	bool dhcpv4_forcereconf;

	// DNS
	struct in6_addr *dns;
	size_t dns_cnt;
	uint8_t *search;
	size_t search_len;

	// DHCPV6
	void *dhcpv6_raw;
	size_t dhcpv6_raw_len;
	bool dhcpv6_assignall;
	bool dhcpv6_pd;
	bool dhcpv6_na;
	uint32_t dhcpv6_hostid_len;
	uint32_t dhcpv6_pd_min_len; // minimum delegated prefix length

	char *upstream;
	size_t upstream_len;

	char *filter_class;

	// NTP
	struct in_addr *dhcpv4_ntp;
	size_t dhcpv4_ntp_cnt;
	uint8_t *dhcpv6_ntp;
	uint16_t dhcpv6_ntp_len;
	size_t dhcpv6_ntp_cnt;

	// SNTP
	struct in6_addr *dhcpv6_sntp;
	size_t dhcpv6_sntp_cnt;
};

extern struct avl_tree interfaces;
extern const struct blobmsg_policy lease_attrs[LEASE_ATTR_MAX];

inline static void free_assignment(struct dhcp_assignment *a)
{
	list_del(&a->head);
	list_del(&a->lease_list);

	if (a->dhcp_free_cb)
		a->dhcp_free_cb(a);

	free(a->hostname);
	free(a->reqopts);
	free(a);
}

inline static struct dhcp_assignment *alloc_assignment(size_t extra_len)
{
	struct dhcp_assignment *a = calloc(1, sizeof(*a) + extra_len);

	if (!a)
		return NULL;

	INIT_LIST_HEAD(&a->head);
	INIT_LIST_HEAD(&a->lease_list);

	return a;
}

// Exported main functions
int odhcpd_register(struct odhcpd_event *event);
int odhcpd_deregister(struct odhcpd_event *event);
void odhcpd_process(struct odhcpd_event *event);

ssize_t odhcpd_send(int socket, struct sockaddr_in6 *dest,
		struct iovec *iov, size_t iov_len,
		const struct interface *iface);
int odhcpd_get_interface_dns_addr(const struct interface *iface,
		struct in6_addr *addr);
int odhcpd_get_interface_config(const char *ifname, const char *what);
int odhcpd_get_mac(const struct interface *iface, uint8_t mac[6]);
int odhcpd_get_flags(const struct interface *iface);
struct interface* odhcpd_get_interface_by_index(int ifindex);
int odhcpd_urandom(void *data, size_t len);

void odhcpd_run(void);
time_t odhcpd_time(void);
ssize_t odhcpd_unhexlify(uint8_t *dst, size_t len, const char *src);
void odhcpd_hexlify(char *dst, const uint8_t *src, size_t len);
const char *odhcpd_print_mac(const uint8_t *mac, const size_t len);

int odhcpd_bmemcmp(const void *av, const void *bv, size_t bits);
void odhcpd_bmemcpy(void *av, const void *bv, size_t bits);

int odhcpd_netmask2bitlen(bool v6, void *mask);
bool odhcpd_bitlen2netmask(bool v6, unsigned int bits, void *mask);
bool odhcpd_valid_hostname(const char *name);

int config_parse_interface(void *data, size_t len, const char *iname, bool overwrite);
struct lease *config_find_lease_by_duid(const uint8_t *duid, const uint16_t len);
struct lease *config_find_lease_by_mac(const uint8_t *mac);
struct lease *config_find_lease_by_hostid(const uint64_t hostid);
struct lease *config_find_lease_by_ipaddr(const uint32_t ipaddr);
int set_lease_from_blobmsg(struct blob_attr *ba);

#ifdef WITH_UBUS
int ubus_init(void);
const char* ubus_get_ifname(const char *name);
void ubus_apply_network(void);
bool ubus_has_prefix(const char *name, const char *ifname);
void ubus_bcast_dhcp_event(const char *type, const uint8_t *mac, const size_t mac_len,
		const struct in_addr *addr, const char *name, const char *interface);
#endif

ssize_t dhcpv6_ia_handle_IAs(uint8_t *buf, size_t buflen, struct interface *iface,
		const struct sockaddr_in6 *addr, const void *data, const uint8_t *end);
int dhcpv6_ia_init(void);
int dhcpv6_ia_setup_interface(struct interface *iface, bool enable);
void dhcpv6_ia_enum_addrs(struct interface *iface, struct dhcp_assignment *c, time_t now,
				dhcpv6_binding_cb_handler_t func, void *arg);
void dhcpv6_ia_write_statefile(void);

int netlink_add_netevent_handler(struct netevent_handler *hdlr);
ssize_t netlink_get_interface_addrs(const int ifindex, bool v6,
		struct odhcpd_ipaddr **addrs);
ssize_t netlink_get_interface_linklocal(int ifindex, struct odhcpd_ipaddr **addrs);
int netlink_get_interface_proxy_neigh(int ifindex, const struct in6_addr *addr);
int netlink_setup_route(const struct in6_addr *addr, const int prefixlen,
		const int ifindex, const struct in6_addr *gw,
		const uint32_t metric, const bool add);
int netlink_setup_proxy_neigh(const struct in6_addr *addr,
		const int ifindex, const bool add);
int netlink_setup_addr(struct odhcpd_ipaddr *addr,
		const int ifindex, const bool v6, const bool add);
void netlink_dump_neigh_table(const bool proxy);
void netlink_dump_addr_table(const bool v6);

// Exported module initializers
int netlink_init(void);
int router_init(void);
int dhcpv6_init(void);
int ndp_init(void);
#ifdef DHCPV4_SUPPORT
int dhcpv4_init(void);

int dhcpv4_setup_interface(struct interface *iface, bool enable);
void dhcpv4_handle_msg(void *addr, void *data, size_t len,
		       struct interface *iface, _unused void *dest_addr,
		       send_reply_cb_t send_reply, void *opaque);
#endif
int router_setup_interface(struct interface *iface, bool enable);
int dhcpv6_setup_interface(struct interface *iface, bool enable);
int ndp_setup_interface(struct interface *iface, bool enable);
void reload_services(struct interface *iface);

void odhcpd_reload(void);
