/**
 * Copyright (C) 2012-2013 Steven Barth <steven@midlink.org>
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

#ifndef _ODHCPD_H_
#define _ODHCPD_H_

#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <netinet/ether.h>
#include <stdbool.h>
#include <syslog.h>

#include <libubox/avl.h>
#include <libubox/blobmsg.h>
#include <libubox/list.h>
#include <libubox/uloop.h>
#include <libubox/avl.h>
#include <libubox/ustream.h>
#include <libubox/vlist.h>

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))

/* RFC 1035, §2.3.4, with one extra byte for buffers */
#define DNS_MAX_NAME_LEN 256
#define DNS_MAX_LABEL_LEN 63

// RFC 6106 defines this router advertisement option
#define ND_OPT_ROUTE_INFO 24
#define ND_OPT_RECURSIVE_DNS 25
#define ND_OPT_DNS_SEARCH 31

// RFC 8910 defines captive portal option
#define ND_OPT_CAPTIVE_PORTAL 37

// RFC 8781 defines PREF64 option
#define ND_OPT_PREF64 38

// RFC9096 defines recommended option lifetimes configuration values
#define ND_PREFERRED_LIMIT 2700
#define ND_VALID_LIMIT 5400

// RFC 9463 - Discovery of Network-designated Resolvers (DNR)
#define ND_OPT_DNR 144

#define INFINITE_VALID(x) ((x) == 0)

#ifndef _o_fallthrough
#define _o_fallthrough __attribute__((__fallthrough__))
#endif /* _o_fallthrough */

#ifndef _o_packed
#define _o_packed __attribute__((packed))
#endif /* _o_packed */

#ifndef _o_unused
#define _o_unused __attribute__((unused))
#endif /* _o_unused */

#ifndef _o_noreturn
#define _o_noreturn __attribute__((__noreturn__))
#endif /* _o_noreturn */

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
					     (_addr)->prefix_len < (iface)->pio_filter_length)

struct interface;
struct nl_sock;
extern struct config config;
extern struct sys_conf sys_conf;

void __iflog(int lvl, const char *fmt, ...);
#define debug(fmt, ...) __iflog(LOG_DEBUG, fmt __VA_OPT__(, ) __VA_ARGS__)
#define info(fmt, ...) __iflog(LOG_INFO, fmt __VA_OPT__(, ) __VA_ARGS__)
#define notice(fmt, ...) __iflog(LOG_NOTICE, fmt __VA_OPT__(, ) __VA_ARGS__)
#define warn(fmt, ...) __iflog(LOG_WARNING, fmt __VA_OPT__(, ) __VA_ARGS__)
#define error(fmt, ...) __iflog(LOG_ERR, fmt __VA_OPT__(, ) __VA_ARGS__)
#define critical(fmt, ...) __iflog(LOG_CRIT, fmt __VA_OPT__(, ) __VA_ARGS__)
#define alert(fmt, ...) __iflog(LOG_ALERT, fmt __VA_OPT__(, ) __VA_ARGS__)
#define emergency(fmt, ...) __iflog(LOG_EMERG, fmt __VA_OPT__(, ) __VA_ARGS__)


struct odhcpd_event {
	struct uloop_fd uloop;
	void (*handle_dgram)(void *addr, void *data, size_t len,
			struct interface *iface, void *dest_addr);
	void (*handle_error)(struct odhcpd_event *e, int error);
	void (*recv_msgs)(struct odhcpd_event *e);
};

typedef	ssize_t (*send_reply_cb_t)(struct iovec *iov, size_t iov_len,
				   struct sockaddr *dest, socklen_t dest_len,
				   void *opaque);

union in46_addr {
	struct in_addr in;
	struct in6_addr in6;
};

struct netevent_handler_info {
	struct interface *iface;
	union {
		struct {
			union in46_addr dst;
			uint8_t dst_len;
			union in46_addr gateway;
		} rt;
		struct {
			union in46_addr dst;
			uint16_t state;
			uint8_t flags;
		} neigh;
		struct {
			struct odhcpd_ipaddr *addrs;
			size_t len;
		} addrs_old;
		union in46_addr addr;
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
	union in46_addr addr;
	uint8_t prefix_len;
	uint32_t preferred_lt;
	uint32_t valid_lt;

	union {
		/* IPv6 only */
		struct {
			uint8_t dprefix_len;
			bool tentative;
		};

		/* IPv4 only */
		struct {
			struct in_addr broadcast;
			in_addr_t netmask;
		};
	};
};

enum odhcpd_mode {
	MODE_DISABLED,
	MODE_SERVER,
	MODE_RELAY,
	MODE_HYBRID
};


enum odhcpd_assignment_flags {
	OAF_DHCPV6_NA		= (1 << 0),
	OAF_DHCPV6_PD		= (1 << 1),
};

/* 2-byte type + 128-byte DUID, RFC8415, §11.1 */
#define DUID_MAX_LEN 130
/* In theory, 2 (type only), or 7 (DUID-EN + 1-byte data), but be reasonable */
#define DUID_MIN_LEN 10
#define DUID_HEXSTRLEN (DUID_MAX_LEN * 2 + 1)

enum duid_type {
	DUID_TYPE_LLT = 1,
	DUID_TYPE_EN = 2,
	DUID_TYPE_LL = 3,
	DUID_TYPE_UUID = 4,
};

struct config {
	bool enable_tz;
	bool main_dhcpv4;
	char *dhcp_cb;
	bool use_ubus;

	char *dhcp_statefile;
	int dhcp_statedir_fd;
	char *dhcp_hostsdir;
	int dhcp_hostsdir_fd;

	char *ra_piofolder;
	int ra_piofolder_fd;

	char *uci_cfgdir;
	int log_level;
	bool log_level_cmdline;
	bool log_syslog;

	uint8_t default_duid[DUID_MAX_LEN];
	size_t default_duid_len;
};

struct sys_conf {
	uint8_t *posix_tz;
	size_t posix_tz_len;
	uint8_t *tzdb_tz;
	size_t tzdb_tz_len;
};

struct duid {
	uint8_t len;
	uint8_t id[DUID_MAX_LEN];
	uint32_t iaid;
	bool iaid_set;
};

struct odhcpd_ref_ip;

struct dhcpv4_lease {
	struct avl_node iface_avl;		// struct interface->dhcpv4_leases

	struct interface *iface;		// assignment interface, non-null
	struct lease_cfg *lease_cfg;		// host lease cfg, nullable

	struct in_addr ipv4;			// client IPv4 address
	bool bound;				// the lease has been accepted by the client
	time_t valid_until;			// CLOCK_MONOTONIC time, 0 = inf
	char *hostname;				// client hostname
	bool hostname_valid;			// is the hostname one or more valid DNS labels?
	size_t hwaddr_len;			// hwaddr length
	uint8_t hwaddr[ETH_ALEN];		// hwaddr (only MAC supported)

	// ForceRenew Nonce - RFC6704 §3.1.2
	struct uloop_timeout fr_timer;		// FR message transmission timer
	bool accept_fr_nonce;			// FR client support
	unsigned fr_cnt;			// FR messages sent
	uint8_t key[16];			// FR nonce
	struct odhcpd_ref_ip *fr_ip;		// FR message old serverid/IP

	// RFC4361
	uint32_t iaid;
	uint8_t duid_len;
	uint8_t duid[];
};

struct dhcpv6_lease {
	struct list_head head;
	struct list_head lease_cfg_list;

	struct interface *iface;
	struct lease_cfg *lease_cfg;

	struct sockaddr_in6 peer;
	time_t valid_until;
	time_t preferred_until;

	// ForceRenew Nonce - RFC8415 §20.4, §21.11
	struct uloop_timeout fr_timer;
	bool accept_fr_nonce;
	int fr_cnt;
	uint8_t key[16];

	union {
		uint64_t assigned_host_id;
		uint32_t assigned_subnet_id;
	};
	uint8_t length; // length == 128 -> IA_NA, length <= 64 -> IA_PD

	unsigned int flags;
	bool bound;				// the lease has been accepted by the client
	uint32_t leasetime;
	char *hostname;
	bool hostname_valid;			// is the hostname one or more valid DNS labels?

	uint32_t iaid;
	uint16_t duid_len;
	uint8_t duid[];
};

/* This corresponds to a UCI host section, i.e. a static lease cfg */
struct lease_cfg {
	struct vlist_node node;
	struct list_head dhcpv6_leases;
	struct dhcpv4_lease *dhcpv4_lease;
	struct in_addr ipv4;
	uint64_t hostid;
	size_t mac_count;
	struct ether_addr *macs;
	size_t duid_count;
	struct duid *duids;
	uint32_t leasetime;		// duration of granted leases, UINT32_MAX = inf
	char *hostname;
	bool ignore4;
	bool ignore6;
};

// DNR - RFC9463
struct dnr_options {
	uint16_t priority;

	uint32_t lifetime;
	bool lifetime_set;

	uint8_t *adn;
	uint16_t adn_len;

	struct in_addr *addr4;
	size_t addr4_cnt;
	struct in6_addr *addr6;
	size_t addr6_cnt;

	uint8_t *svc;
	uint16_t svc_len;
};


// RA PIO - RFC9096
struct ra_pio {
	struct {
		struct in6_addr prefix;
		uint8_t length;
	};
	time_t lifetime;
};
#define ra_pio_cmp_len offsetof(struct ra_pio, lifetime)


struct interface {
	struct avl_node avl;

	int ifflags;
	int ifindex;
	char *ifname;
	const char *name;
	uint32_t if_mtu;
	bool update_statefile;

	// IPv6 runtime data
	struct odhcpd_ipaddr *addr6;
	size_t addr6_len;

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
	struct odhcpd_ipaddr *oaddrs4;		// IPv4 addresses assigned to this interface
	size_t oaddrs4_cnt;			// Number of IPv4 addresses assigned to this interface

	// DHCPv4 runtime data
	struct odhcpd_event dhcpv4_event;
	struct avl_tree dhcpv4_leases;
	struct list_head dhcpv4_fr_ips;

	// RFC8910
	char *captive_portal_uri;
	size_t captive_portal_uri_len;

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
	bool ndp_from_link_local;
	struct in6_addr cached_linklocal_addr;
	bool cached_linklocal_valid;

	// RA
	uint8_t ra_flags;
	bool ra_slaac;
	bool ra_not_onlink;
	bool ra_advrouter;
	bool ra_dns;
	uint8_t pref64_length;
	uint8_t pref64_plc;
	uint32_t pref64_prefix[3];
	bool no_dynamic_dhcp;
	bool have_link_local;
	uint8_t pio_filter_length;
	struct in6_addr pio_filter_addr;
	int default_router;
	int route_preference;
	uint32_t ra_maxinterval;
	uint32_t ra_mininterval;
	uint32_t ra_lifetime;
	uint32_t ra_reachabletime;
	uint32_t ra_retranstime;
	uint32_t ra_hoplimit;
	uint32_t ra_mtu;
	uint32_t max_preferred_lifetime;
	uint32_t max_valid_lifetime;

	// DHCP
	uint32_t dhcp_leasetime;

	// DHCPv4
	uint32_t dhcpv4_pool_start;	// Offset to first dynamic address
	uint32_t dhcpv4_pool_end;	// Offset to last dynamic address
	struct in_addr dhcpv4_start_ip;
	struct in_addr dhcpv4_end_ip;
	struct odhcpd_ipaddr dhcpv4_own_ip;
	struct in_addr *dhcpv4_routers;	// IPv4 addresses for routers on this subnet
	size_t dhcpv4_routers_cnt;	// Count of router addresses
	bool dhcpv4_forcereconf;
	uint32_t dhcpv4_v6only_wait;	// V6ONLY_WAIT for the IPv6-only preferred option (RFC8925)

	// DNS
	struct in_addr *dns_addrs4;	// IPv4 DNS server addresses to announce
	size_t dns_addrs4_cnt;		// Count of IPv4 DNS addresses
	struct in6_addr *dns_addrs6;	// IPv6 DNS server addresses to announce
	size_t dns_addrs6_cnt;		// Count of IPv6 DNS addresses
	uint8_t *dns_search;		// DNS domain search list to announce (concatenated)
	size_t dns_search_len;		// Length of the DNS domain search list (bytes)

	// DHCPV6
	void *dhcpv6_raw;
	size_t dhcpv6_raw_len;
	bool dhcpv6_assignall;
	bool dhcpv6_pd;
	bool dhcpv6_pd_preferred;
	bool dhcpv6_na;
	uint32_t dhcpv6_hostid_len;
	uint32_t dhcpv6_pd_min_len; // minimum delegated prefix length

	char *upstream;
	size_t upstream_len;

	// NTP
	struct in_addr *dhcpv4_ntp;
	size_t dhcpv4_ntp_cnt;
	uint8_t *dhcpv6_ntp;
	uint16_t dhcpv6_ntp_len;
	size_t dhcpv6_ntp_cnt;

	// SNTP
	struct in6_addr *dhcpv6_sntp;
	size_t dhcpv6_sntp_cnt;

	// DNR
	struct dnr_options *dnr;
	size_t dnr_cnt;

	// RA PIO - RFC9096
	struct ra_pio *pios;
	size_t pio_cnt;
	bool pio_update;
};

extern struct avl_tree interfaces;

enum {
	LEASE_CFG_ATTR_IPV4,
	LEASE_CFG_ATTR_MAC,
	LEASE_CFG_ATTR_DUID,
	LEASE_CFG_ATTR_HOSTID,
	LEASE_CFG_ATTR_LEASETIME,
	LEASE_CFG_ATTR_NAME,
	LEASE_CFG_ATTR_MAX
};
extern const struct blobmsg_policy lease_cfg_attrs[LEASE_CFG_ATTR_MAX];

inline static bool ra_pio_expired(const struct ra_pio *pio, time_t now)
{
	return pio->lifetime && (now > pio->lifetime);
}

inline static uint32_t ra_pio_lifetime(const struct ra_pio *pio, time_t now)
{
	if (!pio->lifetime || now > pio->lifetime)
		return 0;

	return (uint32_t) (pio->lifetime - now);
}

inline static bool ra_pio_stale(const struct ra_pio *pio)
{
	return !!pio->lifetime;
}

// Exported main functions
int odhcpd_register(struct odhcpd_event *event);
int odhcpd_deregister(struct odhcpd_event *event);
void odhcpd_process(struct odhcpd_event *event);

ssize_t odhcpd_send_with_src(int socket, struct sockaddr_in6 *dest,
		struct iovec *iov, size_t iov_len,
		const struct interface *iface, const struct in6_addr *src_addr);
ssize_t odhcpd_send(int socket, struct sockaddr_in6 *dest,
		struct iovec *iov, size_t iov_len,
		const struct interface *iface);
ssize_t odhcpd_try_send_with_src(int socket, struct sockaddr_in6 *dest,
		struct iovec *iov, size_t iov_len,
		struct interface *iface);
int odhcpd_get_interface_dns_addr6(struct interface *iface,
				   struct in6_addr *dns_addr6);
int odhcpd_get_interface_linklocal_addr(struct interface *iface,
		struct in6_addr *addr);
int odhcpd_get_interface_config(const char *ifname, const char *what);
int odhcpd_get_mac(const struct interface *iface, uint8_t mac[6]);
int odhcpd_get_flags(const struct interface *iface);
struct interface* odhcpd_get_interface_by_index(int ifindex);
void odhcpd_urandom(void *data, size_t len);

int odhcpd_run(void);
time_t odhcpd_time(void);
ssize_t odhcpd_unhexlify(uint8_t *dst, size_t len, const char *src);
void odhcpd_hexlify(char *dst, const uint8_t *src, size_t len);
const char *odhcpd_print_mac(const uint8_t *mac, const size_t len);

int odhcpd_bmemcmp(const void *av, const void *bv, size_t bits);
void odhcpd_bmemcpy(void *av, const void *bv, size_t bits);

typedef void (*odhcpd_enum_addr6_cb_t)(struct dhcpv6_lease *lease,
				       struct in6_addr *addr, uint8_t prefix_len,
				       uint32_t pref, uint32_t valid,
				       void *arg);
void odhcpd_enum_addr6(struct interface *iface, struct dhcpv6_lease *lease,
		       time_t now, odhcpd_enum_addr6_cb_t func, void *arg);
int odhcpd_parse_addr6_prefix(const char *str, struct in6_addr *addr, uint8_t *prefix);
bool odhcpd_hostname_valid(const char *name);

int config_parse_interface(void *data, size_t len, const char *iname, bool overwrite);
struct lease_cfg *config_find_lease_cfg_by_duid_and_iaid(const uint8_t *duid,
							 const uint16_t len,
							 const uint32_t iaid);
struct lease_cfg *config_find_lease_cfg_by_mac(const uint8_t *mac);
struct lease_cfg *config_find_lease_cfg_by_hostid(const uint64_t hostid);
struct lease_cfg *config_find_lease_cfg_by_ipv4(const struct in_addr ipv4);
int config_set_lease_cfg_from_blobmsg(struct blob_attr *ba);
void config_load_ra_pio(struct interface *iface);
void config_save_ra_pio(struct interface *iface);

#ifdef WITH_UBUS
int ubus_init(void);
const char* ubus_get_ifname(const char *name);
void ubus_apply_network(void);
bool ubus_has_prefix(const char *name, const char *ifname);
void ubus_bcast_dhcpv4_event(const char *type, const char *iface,
			     const struct dhcpv4_lease *lease);
#else
static inline int ubus_init(void)
{
	return 0;
}

static inline const char *ubus_get_ifname(const char *name)
{
	return NULL;
}

static inline void ubus_apply_network(void)
{
	return;
}

static inline bool ubus_has_prefix(const char *name, const char *ifname)
{
	return false;
}

static inline
void ubus_bcast_dhcpv4_event(const char *type, const char *iface,
			     const struct dhcpv4_lease *lease)
{
	return;
}
#endif /* WITH_UBUS */

ssize_t dhcpv6_ia_handle_IAs(uint8_t *buf, size_t buflen, struct interface *iface,
		const struct sockaddr_in6 *addr, const void *data, const uint8_t *end);
int dhcpv6_ia_init(void);
int dhcpv6_ia_setup_interface(struct interface *iface, bool enable);
void dhcpv6_free_lease(struct dhcpv6_lease *lease);

int netlink_add_netevent_handler(struct netevent_handler *hdlr);
ssize_t netlink_get_interface_addrs(const int ifindex, bool v6,
				    struct odhcpd_ipaddr **oaddrs);
ssize_t netlink_get_interface_linklocal(int ifindex, struct odhcpd_ipaddr **oaddrs);
int netlink_get_interface_proxy_neigh(int ifindex, const struct in6_addr *addr);
int netlink_setup_route(const struct in6_addr *addr, const int prefixlen,
			const int ifindex, const struct in6_addr *gw,
			const uint32_t metric, const bool add);
int netlink_setup_proxy_neigh(const struct in6_addr *addr,
			      const int ifindex, const bool add);
int netlink_setup_addr(struct odhcpd_ipaddr *oaddr,
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
void dhcpv4_free_lease(struct dhcpv4_lease *a);
bool dhcpv4_setup_interface(struct interface *iface, bool enable);
void dhcpv4_handle_msg(void *addr, void *data, size_t len,
		       struct interface *iface, _o_unused void *dest_addr,
		       send_reply_cb_t send_reply, void *opaque);
#else
static inline bool dhcpv4_setup_interface(struct interface *iface, bool enable) {
	return true;
}

static inline void dhcpv4_free_lease(struct dhcpv4_lease *lease) {
	error("Trying to free IPv4 assignment 0x%p", lease);
}
#endif /* DHCPV4_SUPPORT */

int router_setup_interface(struct interface *iface, bool enable);
int dhcpv6_setup_interface(struct interface *iface, bool enable);
int ndp_setup_interface(struct interface *iface, bool enable);
void reload_services(struct interface *iface);

void odhcpd_reload(void);

#endif /* _ODHCPD_H_ */
