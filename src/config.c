#include <fcntl.h>
#include <resolv.h>
#include <signal.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <libgen.h>
#include <net/if.h>
#include <string.h>
#include <sys/stat.h>
#include <ctype.h>

#include <uci.h>
#include <uci_blob.h>
#include <libubox/utils.h>
#include <libubox/avl.h>
#include <libubox/avl-cmp.h>
#include <libubox/list.h>
#include <libubox/vlist.h>

#include "odhcpd.h"
#include "router.h"
#include "dhcpv6-pxe.h"
#include "dhcpv4.h"
#include "statefiles.h"

static struct blob_buf b;

static int lease_cfg_cmp(const void *k1, const void *k2, void *ptr);
static void lease_cfg_update(struct vlist_tree *tree, struct vlist_node *node_new,
			     struct vlist_node *node_old);

struct vlist_tree lease_cfgs = VLIST_TREE_INIT(lease_cfgs, lease_cfg_cmp,
					       lease_cfg_update, true, false);

AVL_TREE(interfaces, avl_strcmp, false, NULL);
struct config config = {
	.enable_tz = true,
	.main_dhcpv4 = false,
	.dhcp_cb = NULL,
#ifdef WITH_UBUS
	.use_ubus = true,
#else
	.use_ubus = false,
#endif /* WITH_UBUS */
	.dhcp_statefile = NULL,
	.dhcp_statedir_fd = -1,
	.dhcp_hostsdir = NULL,
	.dhcp_hostsdir_fd = -1,
	.ra_piodir = NULL,
	.ra_piodir_fd = -1,
	.uci_cfgdir = NULL,
	.log_level = LOG_WARNING,
	.log_level_cmdline = false,
	.log_syslog = true,
	.default_duid = { 0 },
	.default_duid_len = 0,
};

struct sys_conf sys_conf = {
	.posix_tz = NULL, // "timezone"
	.posix_tz_len = 0,
	.tzdb_tz = NULL, // "zonename"
	.tzdb_tz_len = 0,
};

#define DHCPV4_POOL_LIMIT_DEFAULT	150

#define HOSTID_LEN_MIN	12
#define HOSTID_LEN_MAX	64
#define HOSTID_LEN_DEFAULT HOSTID_LEN_MIN

#define PD_MIN_LEN_MAX (64-2) // must delegate at least 2 bits of prefix

#define OAF_DHCPV6	(OAF_DHCPV6_NA | OAF_DHCPV6_PD)

enum {
	IPV6_PXE_URL,
	IPV6_PXE_ARCH,
	IPV6_PXE_MAX
};

static const struct blobmsg_policy ipv6_pxe_attrs[IPV6_PXE_MAX] = {
	[IPV6_PXE_URL] = {.name = "url", .type = BLOBMSG_TYPE_STRING },
	[IPV6_PXE_ARCH] = {.name = "arch", .type = BLOBMSG_TYPE_INT32 },
};

const struct uci_blob_param_list ipv6_pxe_attr_list = {
	.n_params = IPV6_PXE_MAX,
	.params = ipv6_pxe_attrs,
};

enum {
	IFACE_ATTR_INTERFACE,
	IFACE_ATTR_IFNAME,
	IFACE_ATTR_NETWORKID,
	IFACE_ATTR_DYNAMICDHCP,
	IFACE_ATTR_LEASETIME,
	IFACE_ATTR_DHCPV4_POOL_START,
	IFACE_ATTR_DHCPV4_POOL_LIMIT,
	IFACE_ATTR_MASTER,
	IFACE_ATTR_UPSTREAM,
	IFACE_ATTR_RA,
	IFACE_ATTR_DHCPV4,
	IFACE_ATTR_DHCPV6,
	IFACE_ATTR_NDP,
	IFACE_ATTR_ROUTER,
	IFACE_ATTR_DNS,
	IFACE_ATTR_DNR,
	IFACE_ATTR_DNS_SERVICE,
	IFACE_ATTR_DNS_DOMAIN_SEARCH,
	IFACE_ATTR_DHCPV4_FORCERECONF,
	IFACE_ATTR_DHCPV6_RAW,
	IFACE_ATTR_DHCPV6_ASSIGNALL,
	IFACE_ATTR_DHCPV6_PD_PREFERRED,
	IFACE_ATTR_DHCPV6_PD,
	IFACE_ATTR_DHCPV6_PD_MIN_LEN,
	IFACE_ATTR_DHCPV6_NA,
	IFACE_ATTR_DHCPV6_HOSTID_LEN,
	IFACE_ATTR_RA_DEFAULT,
	IFACE_ATTR_RA_FLAGS,
	IFACE_ATTR_RA_SLAAC,
	IFACE_ATTR_RA_OFFLINK,
	IFACE_ATTR_RA_PREFERENCE,
	IFACE_ATTR_RA_ADVROUTER,
	IFACE_ATTR_RA_MININTERVAL,
	IFACE_ATTR_RA_MAXINTERVAL,
	IFACE_ATTR_RA_LIFETIME,
	IFACE_ATTR_RA_REACHABLETIME,
	IFACE_ATTR_RA_RETRANSTIME,
	IFACE_ATTR_RA_HOPLIMIT,
	IFACE_ATTR_RA_MTU,
	IFACE_ATTR_RA_DNS,
	IFACE_ATTR_RA_PREF64,
	IFACE_ATTR_NDPROXY_ROUTING,
	IFACE_ATTR_NDPROXY_SLAVE,
	IFACE_ATTR_NDP_FROM_LINK_LOCAL,
	IFACE_ATTR_PREFIX_FILTER,
	IFACE_ATTR_MAX_PREFERRED_LIFETIME,
	IFACE_ATTR_MAX_VALID_LIFETIME,
	IFACE_ATTR_NTP,
	IFACE_ATTR_CAPTIVE_PORTAL_URI,
	IFACE_ATTR_IPV6_ONLY_PREFERRED,
	IFACE_ATTR_MAX
};

static const struct blobmsg_policy iface_attrs[IFACE_ATTR_MAX] = {
	[IFACE_ATTR_INTERFACE] = { .name = "interface", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_IFNAME] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_NETWORKID] = { .name = "networkid", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_DYNAMICDHCP] = { .name = "dynamicdhcp", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_LEASETIME] = { .name = "leasetime", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_DHCPV4_POOL_START] = { .name = "start", .type = BLOBMSG_TYPE_INT32 },
	[IFACE_ATTR_DHCPV4_POOL_LIMIT] = { .name = "limit", .type = BLOBMSG_TYPE_INT32 },
	[IFACE_ATTR_MASTER] = { .name = "master", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_UPSTREAM] = { .name = "upstream", .type = BLOBMSG_TYPE_ARRAY },
	[IFACE_ATTR_RA] = { .name = "ra", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_DHCPV4] = { .name = "dhcpv4", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_DHCPV6] = { .name = "dhcpv6", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_NDP] = { .name = "ndp", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_ROUTER] = { .name = "router", .type = BLOBMSG_TYPE_ARRAY },
	[IFACE_ATTR_DNS] = { .name = "dns", .type = BLOBMSG_TYPE_ARRAY },
	[IFACE_ATTR_DNR] = { .name = "dnr", .type = BLOBMSG_TYPE_ARRAY },
	[IFACE_ATTR_DNS_SERVICE] = { .name = "dns_service", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_DNS_DOMAIN_SEARCH] = { .name = "domain", .type = BLOBMSG_TYPE_ARRAY },
	[IFACE_ATTR_DHCPV4_FORCERECONF] = { .name = "dhcpv4_forcereconf", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_DHCPV6_RAW] = { .name = "dhcpv6_raw", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_DHCPV6_ASSIGNALL] = { .name ="dhcpv6_assignall", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_DHCPV6_PD_PREFERRED] = { .name = "dhcpv6_pd_preferred", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_DHCPV6_PD] = { .name = "dhcpv6_pd", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_DHCPV6_PD_MIN_LEN] = { .name = "dhcpv6_pd_min_len", .type = BLOBMSG_TYPE_INT32 },
	[IFACE_ATTR_DHCPV6_NA] = { .name = "dhcpv6_na", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_DHCPV6_HOSTID_LEN] = { .name = "dhcpv6_hostidlength", .type = BLOBMSG_TYPE_INT32 },
	[IFACE_ATTR_RA_DEFAULT] = { .name = "ra_default", .type = BLOBMSG_TYPE_INT32 },
	[IFACE_ATTR_RA_FLAGS] = { .name = "ra_flags", . type = BLOBMSG_TYPE_ARRAY },
	[IFACE_ATTR_RA_SLAAC] = { .name = "ra_slaac", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_RA_OFFLINK] = { .name = "ra_offlink", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_RA_PREFERENCE] = { .name = "ra_preference", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_RA_ADVROUTER] = { .name = "ra_advrouter", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_RA_MININTERVAL] = { .name = "ra_mininterval", .type = BLOBMSG_TYPE_INT32 },
	[IFACE_ATTR_RA_MAXINTERVAL] = { .name = "ra_maxinterval", .type = BLOBMSG_TYPE_INT32 },
	[IFACE_ATTR_RA_LIFETIME] = { .name = "ra_lifetime", .type = BLOBMSG_TYPE_INT32 },
	[IFACE_ATTR_RA_REACHABLETIME] = { .name = "ra_reachabletime", .type = BLOBMSG_TYPE_INT32 },
	[IFACE_ATTR_RA_RETRANSTIME] = { .name = "ra_retranstime", .type = BLOBMSG_TYPE_INT32 },
	[IFACE_ATTR_RA_HOPLIMIT] = { .name = "ra_hoplimit", .type = BLOBMSG_TYPE_INT32 },
	[IFACE_ATTR_RA_MTU] = { .name = "ra_mtu", .type = BLOBMSG_TYPE_INT32 },
	[IFACE_ATTR_RA_DNS] = { .name = "ra_dns", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_RA_PREF64] = { .name = "ra_pref64", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_NDPROXY_ROUTING] = { .name = "ndproxy_routing", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_NDPROXY_SLAVE] = { .name = "ndproxy_slave", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_NDP_FROM_LINK_LOCAL] = { .name = "ndp_from_link_local", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_PREFIX_FILTER] = { .name = "prefix_filter", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_MAX_PREFERRED_LIFETIME] = { .name = "max_preferred_lifetime", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_MAX_VALID_LIFETIME] = { .name = "max_valid_lifetime", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_NTP] = { .name = "ntp", .type = BLOBMSG_TYPE_ARRAY },
	[IFACE_ATTR_CAPTIVE_PORTAL_URI] = { .name = "captive_portal_uri", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_IPV6_ONLY_PREFERRED] = { .name = "ipv6_only_preferred", .type = BLOBMSG_TYPE_INT32 },
};

const struct uci_blob_param_list interface_attr_list = {
	.n_params = IFACE_ATTR_MAX,
	.params = iface_attrs,
};

const struct blobmsg_policy lease_cfg_attrs[LEASE_CFG_ATTR_MAX] = {
	[LEASE_CFG_ATTR_IPV4] = { .name = "ip", .type = BLOBMSG_TYPE_STRING },
	[LEASE_CFG_ATTR_MAC] = { .name = "mac", .type = BLOBMSG_TYPE_ARRAY },
	[LEASE_CFG_ATTR_DUID] = { .name = "duid", .type = BLOBMSG_TYPE_ARRAY },
	[LEASE_CFG_ATTR_HOSTID] = { .name = "hostid", .type = BLOBMSG_TYPE_STRING },
	[LEASE_CFG_ATTR_LEASETIME] = { .name = "leasetime", .type = BLOBMSG_TYPE_STRING },
	[LEASE_CFG_ATTR_NAME] = { .name = "name", .type = BLOBMSG_TYPE_STRING },
};

const struct uci_blob_param_list lease_cfg_attr_list = {
	.n_params = LEASE_CFG_ATTR_MAX,
	.params = lease_cfg_attrs,
};

enum {
	ODHCPD_ATTR_MAINDHCP,
	ODHCPD_ATTR_LEASEFILE,
	ODHCPD_ATTR_LEASETRIGGER,
	ODHCPD_ATTR_LOGLEVEL,
	ODHCPD_ATTR_HOSTSDIR,
	ODHCPD_ATTR_PIODIR,
	ODHCPD_ATTR_ENABLE_TZ,
	ODHCPD_ATTR_MAX
};

static const struct blobmsg_policy odhcpd_attrs[ODHCPD_ATTR_MAX] = {
	[ODHCPD_ATTR_MAINDHCP] = { .name = "maindhcp", .type = BLOBMSG_TYPE_BOOL },
	[ODHCPD_ATTR_LEASEFILE] = { .name = "leasefile", .type = BLOBMSG_TYPE_STRING },
	[ODHCPD_ATTR_LEASETRIGGER] = { .name = "leasetrigger", .type = BLOBMSG_TYPE_STRING },
	[ODHCPD_ATTR_LOGLEVEL] = { .name = "loglevel", .type = BLOBMSG_TYPE_INT32 },
	[ODHCPD_ATTR_HOSTSDIR] = { .name = "hostsdir", .type = BLOBMSG_TYPE_STRING },
	[ODHCPD_ATTR_PIODIR] = { .name = "piodir", .type = BLOBMSG_TYPE_STRING },
	[ODHCPD_ATTR_ENABLE_TZ] = { .name = "enable_tz", .type = BLOBMSG_TYPE_BOOL },
};

const struct uci_blob_param_list odhcpd_attr_list = {
	.n_params = ODHCPD_ATTR_MAX,
	.params = odhcpd_attrs,
};

enum {
	SYSTEM_ATTR_TIMEZONE,
	SYSTEM_ATTR_ZONENAME,
	SYSTEM_ATTR_MAX
};

static const struct blobmsg_policy system_attrs[SYSTEM_ATTR_MAX] = {
	[SYSTEM_ATTR_TIMEZONE] = { .name = "timezone", .type = BLOBMSG_TYPE_STRING },
	[SYSTEM_ATTR_ZONENAME] = { .name = "zonename", .type = BLOBMSG_TYPE_STRING },
};

const struct uci_blob_param_list system_attr_list = {
	.n_params = SYSTEM_ATTR_MAX,
	.params = system_attrs,
};

enum {
	GLOBAL_ATTR_DUID,
	GLOBAL_ATTR_MAX
};

static const struct blobmsg_policy global_attrs[GLOBAL_ATTR_MAX] = {
	[GLOBAL_ATTR_DUID] = { .name = "dhcp_default_duid", .type = BLOBMSG_TYPE_STRING },
};

const struct uci_blob_param_list global_attr_list = {
	.n_params = GLOBAL_ATTR_MAX,
	.params = global_attrs,
};

static const struct { const char *name; uint8_t flag; } ra_flags[] = {
	{ .name = "managed-config", .flag = ND_RA_FLAG_MANAGED },
	{ .name = "other-config", .flag = ND_RA_FLAG_OTHER },
	{ .name = "home-agent", .flag = ND_RA_FLAG_HOME_AGENT },
	{ .name = "none", . flag = 0 },
	{ .name = NULL, },
};

// https://www.iana.org/assignments/dns-svcb/dns-svcb.xhtml
enum svc_param_keys {
	DNR_SVC_MANDATORY,
	DNR_SVC_ALPN,
	DNR_SVC_NO_DEFAULT_ALPN,
	DNR_SVC_PORT,
	DNR_SVC_IPV4HINT,
	DNR_SVC_ECH,
	DNR_SVC_IPV6HINT,
	DNR_SVC_DOHPATH,
	DNR_SVC_OHTTP,
	DNR_SVC_MAX,
};

static const char *svc_param_key_names[DNR_SVC_MAX] = {
	[DNR_SVC_MANDATORY] = "mandatory",
	[DNR_SVC_ALPN] = "alpn",
	[DNR_SVC_NO_DEFAULT_ALPN] = "no-default-alpn",
	[DNR_SVC_PORT] = "port",
	[DNR_SVC_IPV4HINT] = "ipv4hint",
	[DNR_SVC_ECH] = "ech",
	[DNR_SVC_IPV6HINT] = "ipv6hint",
	[DNR_SVC_DOHPATH] = "dohpath",
	[DNR_SVC_OHTTP] = "ohttp",
};

static void set_interface_defaults(struct interface *iface)
{
	iface->ignore = true;
	iface->dhcpv4 = MODE_DISABLED;
	iface->dhcpv6 = MODE_DISABLED;
	iface->ra = MODE_DISABLED;
	iface->ndp = MODE_DISABLED;
	iface->learn_routes = 1;
	iface->ndp_from_link_local = true;
	iface->cached_linklocal_valid = false;
	iface->dhcp_leasetime = 43200;
	iface->max_preferred_lifetime = ND_PREFERRED_LIMIT;
	iface->max_valid_lifetime = ND_VALID_LIMIT;
	iface->captive_portal_uri = NULL;
	iface->dhcpv4_pool_start = 0;
	iface->dhcpv4_pool_end = 0;
	iface->dhcpv6_assignall = true;
	iface->dhcpv6_pd = true;
	iface->dhcpv6_pd_preferred = false;
	iface->dhcpv6_pd_min_len = 0;
	iface->dhcpv6_na = true;
	iface->dhcpv6_hostid_len = HOSTID_LEN_DEFAULT;
	iface->dns_service = true;
	iface->ra_flags = ND_RA_FLAG_OTHER;
	iface->ra_slaac = true;
	iface->ra_maxinterval = 600;
	/*
	 * RFC4861: MinRtrAdvInterval: Default: 0.33 * MaxRtrAdvInterval If
	 * MaxRtrAdvInterval >= 9 seconds; otherwise, the Default is MaxRtrAdvInterval.
	 */
	iface->ra_mininterval = iface->ra_maxinterval/3;
	iface->ra_lifetime = 3 * iface->ra_maxinterval; /* RFC4861: AdvDefaultLifetime: Default: 3 * MaxRtrAdvInterval */
	iface->ra_dns = true;
	iface->pio_update = false;
	iface->update_statefile = true;
}

static void clean_interface(struct interface *iface)
{
	free(iface->dns_addrs4);
	free(iface->dns_addrs6);
	free(iface->dns_search);
	free(iface->upstream);
	free(iface->dhcpv4_routers);
	free(iface->dhcpv6_raw);
	free(iface->dhcpv4_ntp);
	free(iface->dhcpv6_ntp);
	free(iface->dhcpv6_sntp);
	free(iface->captive_portal_uri);
	for (unsigned i = 0; i < iface->dnr_cnt; i++) {
		free(iface->dnr[i].adn);
		free(iface->dnr[i].addr4);
		free(iface->dnr[i].addr6);
		free(iface->dnr[i].svc);
	}
	free(iface->dnr);
	free(iface->pios);
	memset(&iface->ra, 0, sizeof(*iface) - offsetof(struct interface, ra));
	set_interface_defaults(iface);
}

static void close_interface(struct interface *iface)
{
	avl_delete(&interfaces, &iface->avl);

	router_setup_interface(iface, false);
	dhcpv6_setup_interface(iface, false);
	ndp_setup_interface(iface, false);
	dhcpv4_setup_interface(iface, false);

	/* make sure timer is not on the timeouts list before freeing */
	uloop_timeout_cancel(&iface->timer_rs);

	clean_interface(iface);
	free(iface->oaddrs4);
	free(iface->addr6);
	free(iface->ifname);
	free(iface);
}

static int parse_mode(const char *mode)
{
	if (!strcmp(mode, "disabled"))
		return MODE_DISABLED;
	else if (!strcmp(mode, "server"))
		return MODE_SERVER;
	else if (!strcmp(mode, "relay"))
		return MODE_RELAY;
	else if (!strcmp(mode, "hybrid"))
		return MODE_HYBRID;
	else
		return -1;
}

static int parse_ra_flags(uint8_t *flags, struct blob_attr *attr)
{
	struct blob_attr *cur;
	unsigned rem;

	blobmsg_for_each_attr(cur, attr, rem) {
		int i;

		if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING)
			continue;

				if (!blobmsg_check_attr(cur, false))
						continue;

		for (i = 0; ra_flags[i].name; i++) {
			if (!strcmp(ra_flags[i].name, blobmsg_get_string(cur))) {
				*flags |= ra_flags[i].flag;
				break;
			}
		}

		if (!ra_flags[i].name)
			return -1;
	}

	return 0;
}

static void set_global_config(struct uci_section *s)
{
	struct blob_attr *tb[GLOBAL_ATTR_MAX], *c;

	blob_buf_init(&b, 0);
	uci_to_blob(&b, s, &global_attr_list);
	blobmsg_parse(global_attrs, GLOBAL_ATTR_MAX, tb, blob_data(b.head), blob_len(b.head));

	if ((c = tb[GLOBAL_ATTR_DUID])) {
		size_t len = blobmsg_data_len(c) / 2;

		config.default_duid_len = 0;
		if (len >= DUID_MIN_LEN && len <= DUID_MAX_LEN) {
			ssize_t r = odhcpd_unhexlify(config.default_duid, len, blobmsg_get_string(c));
			if (r >= DUID_MIN_LEN)
				config.default_duid_len = r;
		}
	}
}

static void set_config(struct uci_section *s)
{
	struct blob_attr *tb[ODHCPD_ATTR_MAX], *c;

	blob_buf_init(&b, 0);
	uci_to_blob(&b, s, &odhcpd_attr_list);
	blobmsg_parse(odhcpd_attrs, ODHCPD_ATTR_MAX, tb, blob_data(b.head), blob_len(b.head));

	if ((c = tb[ODHCPD_ATTR_MAINDHCP]))
		config.main_dhcpv4 = blobmsg_get_bool(c);

	if ((c = tb[ODHCPD_ATTR_LEASEFILE])) {
		free(config.dhcp_statefile);
		config.dhcp_statefile = strdup(blobmsg_get_string(c));
	}

	if ((c = tb[ODHCPD_ATTR_HOSTSDIR])) {
		free(config.dhcp_hostsdir);
		config.dhcp_hostsdir = strdup(blobmsg_get_string(c));
	}

	if ((c = tb[ODHCPD_ATTR_PIODIR])) {
		free(config.ra_piodir);
		config.ra_piodir = strdup(blobmsg_get_string(c));
	}

	if ((c = tb[ODHCPD_ATTR_LEASETRIGGER])) {
		free(config.dhcp_cb);
		config.dhcp_cb = strdup(blobmsg_get_string(c));
	}

	if ((c = tb[ODHCPD_ATTR_LOGLEVEL])) {
		int log_level = (blobmsg_get_u32(c) & LOG_PRIMASK);

		if (config.log_level != log_level && !config.log_level_cmdline) {
			config.log_level = log_level;
			if (config.log_syslog)
				setlogmask(LOG_UPTO(config.log_level));
			notice("Log level set to %d\n", config.log_level);
		}
	}

	if ((c = tb[ODHCPD_ATTR_ENABLE_TZ]))
		config.enable_tz = blobmsg_get_bool(c);

}

static void sanitize_tz_string(const char *src, uint8_t **dst, size_t *dst_len)
{
	/* replace any spaces with '_' in tz strings. luci, where these strings
	are normally set, (had a bug that) replaced underscores for spaces in the
	names. */

	if (!dst || !dst_len)
		return;

	free(*dst);
	*dst = NULL;
	*dst_len = 0;

	if (!src || !*src)
		return;

	char *copy = strdup(src);
	if (!copy)
		return;

	for (char *p = copy; *p; p++) {
		if (isspace((unsigned char)*p))
			*p = '_';
	}

	*dst = (uint8_t *)copy;
	*dst_len = strlen(copy);
}

static void set_timezone_info_from_uci(struct uci_section *s)
{
	struct blob_attr *tb[SYSTEM_ATTR_MAX], *c;

	blob_buf_init(&b, 0);
	uci_to_blob(&b, s, &system_attr_list);
	blobmsg_parse(system_attrs, SYSTEM_ATTR_MAX, tb, blob_data(b.head), blob_len(b.head));

	if ((c = tb[SYSTEM_ATTR_TIMEZONE]))
		sanitize_tz_string(blobmsg_get_string(c), &sys_conf.posix_tz, &sys_conf.posix_tz_len);

	if ((c = tb[SYSTEM_ATTR_ZONENAME]))
		sanitize_tz_string(blobmsg_get_string(c), &sys_conf.tzdb_tz, &sys_conf.tzdb_tz_len);
}

static uint32_t parse_leasetime(struct blob_attr *c) {
	char *val = blobmsg_get_string(c), *endptr = NULL;
	uint32_t time = strcmp(val, "infinite") ? (uint32_t)strtod(val, &endptr) : UINT32_MAX;

	if (time && endptr && endptr[0]) {
		switch(endptr[0]) {
			case 's': break; /* seconds */
			case 'm': time *= 60; break; /* minutes */
			case 'h': time *= 3600; break; /* hours */
			case 'd': time *= 24 * 3600; break; /* days */
			case 'w': time *= 7 * 24 * 3600; break; /* weeks */
			default: goto err;
		}
	}

	if (time < 60)
		time = 60;

	return time;

err:
	return 0;
}

static void free_lease_cfg(struct lease_cfg *lease_cfg)
{
	if (!lease_cfg)
		return;

	free(lease_cfg->hostname);
	free(lease_cfg);
}

static bool parse_duid(struct duid *duid, struct blob_attr *c)
{
	const char *duid_str = blobmsg_get_string(c);
	size_t duid_str_len = blobmsg_data_len(c) - 1;
	ssize_t duid_len;
	const char *iaid_str;

	/* We support a hex string with either "<DUID>", or "<DUID>%<IAID>" */
	iaid_str = strrchr(duid_str, '%');
	if (iaid_str) {
		size_t iaid_str_len = strlen(++iaid_str);
		char *end;

		/* IAID = uint32, RFC8415, §21.4, §21.5, §21.21 */
		if (iaid_str_len < 1 || iaid_str_len > 2 * sizeof(uint32_t)) {
			error("Invalid IAID length '%s'", iaid_str);
			return false;
		}

		errno = 0;
		duid->iaid = strtoul(iaid_str, &end, 16);
		if (errno || *end != '\0') {
			error("Invalid IAID '%s'", iaid_str);
			return false;
		}

		duid->iaid_set = true;
		duid_str_len -= (iaid_str_len + 1);
	}

	if (duid_str_len < 2 || duid_str_len > DUID_MAX_LEN * 2 || duid_str_len % 2) {
		error("Invalid DUID length '%.*s'", (int)duid_str_len, duid_str);
		return false;
	}

	duid_len = odhcpd_unhexlify(duid->id, duid_str_len / 2, duid_str);
	if (duid_len < 0) {
		error("Invalid DUID '%.*s'", (int)duid_str_len, duid_str);
		return false;
	}

	duid->len = duid_len;
	return true;
}

int config_set_lease_cfg_from_blobmsg(struct blob_attr *ba)
{
	struct blob_attr *tb[LEASE_CFG_ATTR_MAX], *c;
	struct lease_cfg *lease_cfg = NULL;
	int mac_count = 0;
	struct ether_addr *macs;
	int duid_count = 0;
	struct duid *duids;

	blobmsg_parse(lease_cfg_attrs, LEASE_CFG_ATTR_MAX, tb, blob_data(ba), blob_len(ba));

	if ((c = tb[LEASE_CFG_ATTR_MAC])) {
		mac_count = blobmsg_check_array_len(c, BLOBMSG_TYPE_STRING, blob_raw_len(c));
		if (mac_count < 0)
			goto err;
	}

	if ((c = tb[LEASE_CFG_ATTR_DUID])) {
		duid_count = blobmsg_check_array_len(c, BLOBMSG_TYPE_STRING, blob_raw_len(c));
		if (duid_count < 0)
			goto err;
	}

	lease_cfg = calloc_a(sizeof(*lease_cfg),
			     &macs, mac_count * sizeof(*macs),
			     &duids, duid_count * sizeof(*duids));
	if (!lease_cfg)
		goto err;

	if ((c = tb[LEASE_CFG_ATTR_MAC])) {
		struct blob_attr *cur;
		size_t rem;
		int i = 0;

		lease_cfg->mac_count = mac_count;
		lease_cfg->macs = macs;

		blobmsg_for_each_attr(cur, c, rem)
			if (!ether_aton_r(blobmsg_get_string(cur), &lease_cfg->macs[i++]))
				goto err;
	}

	if ((c = tb[LEASE_CFG_ATTR_DUID])) {
		struct blob_attr *cur;
		size_t rem;
		unsigned i = 0;

		lease_cfg->duid_count = duid_count;
		lease_cfg->duids = duids;

		blobmsg_for_each_attr(cur, c, rem)
			if (!parse_duid(&duids[i++], cur))
				goto err;
	}

	if ((c = tb[LEASE_CFG_ATTR_NAME])) {
		if (!odhcpd_hostname_valid(blobmsg_get_string(c)))
			goto err;

		lease_cfg->hostname = strdup(blobmsg_get_string(c));
		if (!lease_cfg->hostname)
			goto err;
	}

	if ((c = tb[LEASE_CFG_ATTR_IPV4])) {
		const char *ip = blobmsg_get_string(c);

		if (!strcmp(ip, "ignore"))
			lease_cfg->ignore4 = true;
		else if (inet_pton(AF_INET, blobmsg_get_string(c), &lease_cfg->ipv4) != 1)
			goto err;
	}

	if ((c = tb[LEASE_CFG_ATTR_HOSTID])) {
		const char *iid = blobmsg_get_string(c);

		if (!strcmp(iid, "ignore")) {
			lease_cfg->ignore6 = true;
		} else {
			errno = 0;
			lease_cfg->hostid = strtoull(blobmsg_get_string(c), NULL, 16);
			if (errno)
				goto err;
		}
	} else {
		uint32_t i4a = ntohl(lease_cfg->ipv4.s_addr) & 0xff;
		lease_cfg->hostid = ((i4a / 100) << 8) | (((i4a % 100) / 10) << 4) | (i4a % 10);
	}

	if ((c = tb[LEASE_CFG_ATTR_LEASETIME])) {
		uint32_t time = parse_leasetime(c);
		if (time == 0)
			goto err;

		lease_cfg->leasetime = time;
	}

	INIT_LIST_HEAD(&lease_cfg->dhcpv6_leases);
	vlist_add(&lease_cfgs, &lease_cfg->node, lease_cfg);
	return 0;

err:
	free_lease_cfg(lease_cfg);
	return -1;
}

static int set_lease_cfg_from_uci(struct uci_section *s)
{
	blob_buf_init(&b, 0);
	uci_to_blob(&b, s, &lease_cfg_attr_list);

	return config_set_lease_cfg_from_blobmsg(b.head);
}

/* Parse NTP Options for DHCPv6 Address */
static int parse_ntp_options(uint16_t *dhcpv6_ntp_len, struct in6_addr addr6, uint8_t **dhcpv6_ntp)
{
	uint16_t sub_opt = 0, sub_len = htons(IPV6_ADDR_LEN);
	uint16_t ntp_len = IPV6_ADDR_LEN + 4;
	uint8_t *ntp;
	size_t pos = *dhcpv6_ntp_len;

	ntp = realloc(*dhcpv6_ntp, pos + ntp_len);
	if (!ntp)
		return -1;

	*dhcpv6_ntp = ntp;

	if (IN6_IS_ADDR_MULTICAST(&addr6))
		sub_opt = htons(NTP_SUBOPTION_MC_ADDR);
	else
		sub_opt = htons(NTP_SUBOPTION_SRV_ADDR);

	memcpy(ntp + pos, &sub_opt, sizeof(sub_opt));
	pos += sizeof(sub_opt);
	memcpy(ntp + pos, &sub_len, sizeof(sub_len));
	pos += sizeof(sub_len);
	memcpy(ntp + pos, &addr6, IPV6_ADDR_LEN);

	*dhcpv6_ntp_len += ntp_len;

	return 0;
}

/* Parse NTP Options for FQDN */
static int parse_ntp_fqdn(uint16_t *dhcpv6_ntp_len, char *fqdn, uint8_t **dhcpv6_ntp)
{
	size_t fqdn_len = strlen(fqdn);
	uint16_t sub_opt = 0, sub_len = 0, ntp_len = 0;
	uint8_t *ntp;
	size_t pos = *dhcpv6_ntp_len;
	uint8_t buf[256] = {0};

	if (fqdn_len > 0 && fqdn[fqdn_len - 1] == '.')
		fqdn[fqdn_len - 1] = 0;

	int len = dn_comp(fqdn, buf, sizeof(buf), NULL, NULL);
	if (len <= 0)
		return -1;

	ntp_len = len + 4;

	ntp = realloc(*dhcpv6_ntp, pos + ntp_len);
	if (!ntp)
		return -1;

	*dhcpv6_ntp = ntp;

	sub_opt = htons(NTP_SUBOPTION_SRV_FQDN);
	sub_len = htons(len);

	memcpy(ntp + pos, &sub_opt, sizeof(sub_opt));
	pos += sizeof(sub_opt);
	memcpy(ntp + pos, &sub_len, sizeof(sub_len));
	pos += sizeof(sub_len);
	memcpy(ntp + pos, buf, len);

	*dhcpv6_ntp_len += ntp_len;

	return 0;
}

/* Parse DNR Options */
static int parse_dnr_str(char *str, struct interface *iface)
{
	struct dnr_options dnr = {0};
	size_t adn_len;
	uint8_t adn_buf[256] = {0};
	char *saveptr1, *saveptr2;

	char *priority;
	priority = strtok_r(str, " \f\n\r\t\v", &saveptr1);
	if (!priority) {
		goto err;
	} else if (sscanf(priority, "%" SCNu16, &dnr.priority) != 1) {
		error("Unable to parse priority '%s'", priority);
		goto err;
	} else if (dnr.priority == 0) {
		error("Invalid priority '%s'", priority);
		goto err;
	}

	char *adn;
	adn = strtok_r(NULL, " \f\n\r\t\v", &saveptr1);
	if (!adn)
		goto err;

	adn_len = strlen(adn);
	if (adn_len > 0 && adn[adn_len - 1] == '.')
		adn[adn_len - 1] = '\0';

	if (adn_len >= sizeof(adn_buf)) {
		error("Hostname '%s' too long", adn);
		goto err;
	}

	adn_len = dn_comp(adn, adn_buf, sizeof(adn_buf), NULL, NULL);
	if (adn_len <= 0) {
		error("Unable to parse hostname '%s'", adn);
		goto err;
	}

	dnr.adn = malloc(adn_len);
	if (!dnr.adn)
		goto err;
	memcpy(dnr.adn, adn_buf, adn_len);
	dnr.adn_len = adn_len;

	char *addrs;
	addrs = strtok_r(NULL, " \f\n\r\t\v", &saveptr1);
	if (!addrs)
		// ADN-Only mode
		goto done;

	for (char *addr = strtok_r(addrs, ",", &saveptr2); addr; addr = strtok_r(NULL, ",", &saveptr2)) {
		struct in6_addr addr6, *tmp6;
		struct in_addr addr4, *tmp4;
		size_t new_sz;

		if (inet_pton(AF_INET6, addr, &addr6) == 1) {
			new_sz = (dnr.addr6_cnt + 1) * sizeof(*dnr.addr6);
			if (new_sz > UINT16_MAX)
				continue;
			tmp6 = realloc(dnr.addr6, new_sz);
			if (!tmp6)
				goto err;
			dnr.addr6 = tmp6;
			memcpy(&dnr.addr6[dnr.addr6_cnt], &addr6, sizeof(*dnr.addr6));
			dnr.addr6_cnt++;

		} else if (inet_pton(AF_INET, addr, &addr4) == 1) {
			new_sz = (dnr.addr4_cnt + 1) * sizeof(*dnr.addr4);
			if (new_sz > UINT8_MAX)
				continue;
			tmp4 = realloc(dnr.addr4, new_sz);
			if (!tmp4)
				goto err;
			dnr.addr4 = tmp4;
			memcpy(&dnr.addr4[dnr.addr4_cnt], &addr4, sizeof(*dnr.addr4));
			dnr.addr4_cnt++;

		} else {
			error("Unable to parse IP address '%s'", addr);
			goto err;
		}
	}

	char *svc_vals[DNR_SVC_MAX] = { NULL, };
	for (char *svc_tok = strtok_r(NULL, " \f\n\r\t\v", &saveptr1); svc_tok; svc_tok = strtok_r(NULL, " \f\n\r\t\v", &saveptr1)) {
		uint16_t svc_id;
		char *svc_key, *svc_val;

		svc_key = strtok_r(svc_tok, "=", &saveptr2);
		svc_val = strtok_r(NULL, "=", &saveptr2);

		if (!strcmp(svc_key, "_lifetime")) {
			uint32_t lifetime;

			if (!svc_val || sscanf(svc_val, "%" SCNu32, &lifetime) != 1) {
				error("Invalid value '%s' for _lifetime", svc_val ? svc_val : "");
				goto err;
			}

			dnr.lifetime = lifetime;
			dnr.lifetime_set = true;
			continue;
		}

		for (svc_id = 0; svc_id < DNR_SVC_MAX; svc_id++)
			if (!strcmp(svc_key, svc_param_key_names[svc_id]))
				break;

		if (svc_id >= DNR_SVC_MAX) {
			error("Invalid SvcParam '%s'", svc_key);
			goto err;
		}

		svc_vals[svc_id] = svc_val ? svc_val : "";
	}

	/* SvcParamKeys must be in increasing order, RFC9460 §2.2 */
	for (uint16_t svc_key = 0; svc_key < DNR_SVC_MAX; svc_key++) {
		uint16_t svc_key_be = ntohs(svc_key);
		uint16_t svc_val_len, svc_val_len_be;
		char *svc_val_str = svc_vals[svc_key];
		uint8_t *tmp;

		if (!svc_val_str)
			continue;

		switch (svc_key) {
		case DNR_SVC_MANDATORY:
			uint16_t mkeys[DNR_SVC_MAX];

			svc_val_len = 0;
			for (char *mkey_str = strtok_r(svc_val_str, ",", &saveptr2); mkey_str; mkey_str = strtok_r(NULL, ",", &saveptr2)) {
				uint16_t mkey;

				for (mkey = 0; mkey < DNR_SVC_MAX; mkey++)
					if (!strcmp(mkey_str, svc_param_key_names[mkey]))
						break;

				if (mkey >= DNR_SVC_MAX || !svc_vals[mkey]) {
					error("Invalid value '%s' for SvcParam 'mandatory'", mkey_str);
					goto err;
				}

				mkeys[svc_val_len++] = ntohs(mkey);
			}

			svc_val_len *= sizeof(uint16_t);
			svc_val_len_be = ntohs(svc_val_len);

			tmp = realloc(dnr.svc, dnr.svc_len + 4 + svc_val_len);
			if (!tmp)
				goto err;

			dnr.svc = tmp;
			memcpy(dnr.svc + dnr.svc_len, &svc_key_be, sizeof(svc_key_be));
			memcpy(dnr.svc + dnr.svc_len + 2, &svc_val_len_be, sizeof(svc_val_len_be));
			memcpy(dnr.svc + dnr.svc_len + 4, mkeys, svc_val_len);
			dnr.svc_len += 4 + svc_val_len;
			break;

		case DNR_SVC_ALPN:
			size_t len_off;

			tmp = realloc(dnr.svc, dnr.svc_len + 4);
			if (!tmp)
				goto err;

			dnr.svc = tmp;
			memcpy(dnr.svc + dnr.svc_len, &svc_key_be, sizeof(svc_key_be));
			/* the length is not known yet */
			len_off = dnr.svc_len + sizeof(svc_key_be);
			dnr.svc_len += 4;

			svc_val_len = 0;
			for (char *alpn_id_str = strtok_r(svc_val_str, ",", &saveptr2); alpn_id_str; alpn_id_str = strtok_r(NULL, ",", &saveptr2)) {
				size_t alpn_id_len;

				alpn_id_len = strlen(alpn_id_str);
				if (alpn_id_len > UINT8_MAX) {
					error("Invalid value '%s' for SvcParam 'alpn'", alpn_id_str);
					goto err;
				}

				tmp = realloc(dnr.svc, dnr.svc_len + 1 + alpn_id_len);
				if (!tmp)
					goto err;
				dnr.svc = tmp;

				dnr.svc[dnr.svc_len] = alpn_id_len;
				memcpy(dnr.svc + dnr.svc_len + 1, alpn_id_str, alpn_id_len);
				dnr.svc_len += 1 + alpn_id_len;
				svc_val_len += 1 + alpn_id_len;
			}

			svc_val_len_be = ntohs(svc_val_len);
			memcpy(dnr.svc + len_off, &svc_val_len_be, sizeof(svc_val_len_be));
			break;

		case DNR_SVC_PORT:
			uint16_t port;

			if (sscanf(svc_val_str, "%" SCNu16, &port) != 1) {
				error("Invalid value '%s' for SvcParam 'port'", svc_val_str);
				goto err;
			}

			port = ntohs(port);
			svc_val_len_be = ntohs(2);

			tmp = realloc(dnr.svc, dnr.svc_len + 6);
			if (!tmp)
				goto err;

			dnr.svc = tmp;
			memcpy(dnr.svc + dnr.svc_len, &svc_key_be, sizeof(svc_key_be));
			memcpy(dnr.svc + dnr.svc_len + 2, &svc_val_len_be, sizeof(svc_val_len_be));
			memcpy(dnr.svc + dnr.svc_len + 4, &port, sizeof(port));
			dnr.svc_len += 6;
			break;

		case DNR_SVC_NO_DEFAULT_ALPN:
		case DNR_SVC_OHTTP:
			if (strlen(svc_val_str) > 0) {
				error("Invalid value '%s' for SvcParam 'port'", svc_val_str);
				goto err;
			}
			_o_fallthrough;

		case DNR_SVC_DOHPATH:
			/* plain string */
			svc_val_len = strlen(svc_val_str);
			svc_val_len_be = ntohs(svc_val_len);
			tmp = realloc(dnr.svc, dnr.svc_len + 4 + svc_val_len);
			if (!tmp)
				goto err;

			dnr.svc = tmp;
			memcpy(dnr.svc + dnr.svc_len, &svc_key_be, sizeof(svc_key_be));
			dnr.svc_len += sizeof(svc_key_be);
			memcpy(dnr.svc + dnr.svc_len, &svc_val_len_be, sizeof(svc_val_len_be));
			dnr.svc_len += sizeof(svc_val_len_be);
			memcpy(dnr.svc + dnr.svc_len, svc_val_str, svc_val_len);
			dnr.svc_len += svc_val_len;
			break;

		case DNR_SVC_ECH:
			error("SvcParam 'ech' is not implemented");
			goto err;

		case DNR_SVC_IPV4HINT:
		case DNR_SVC_IPV6HINT:
			error("SvcParam '%s' is not allowed", svc_param_key_names[svc_key]);
			goto err;
		}
	}

done:
	struct dnr_options *tmp;
	tmp = realloc(iface->dnr, (iface->dnr_cnt + 1) * sizeof(dnr));
	if (!tmp)
		goto err;

	iface->dnr = tmp;
	memcpy(iface->dnr + iface->dnr_cnt, &dnr, sizeof(dnr));
	iface->dnr_cnt++;
	return 0;

err:
	free(dnr.adn);
	free(dnr.addr4);
	free(dnr.addr6);
	free(dnr.svc);
	return -1;
}

static int avl_ipv4_cmp(const void *k1, const void *k2, _o_unused void *ptr)
{
	return memcmp(k1, k2, sizeof(struct in_addr));
}

int config_parse_interface(void *data, size_t len, const char *name, bool overwrite)
{
	struct interface *iface;
	struct blob_attr *tb[IFACE_ATTR_MAX], *c;
	struct odhcpd_ipaddr *oaddrs = NULL;
	ssize_t oaddrs_cnt;
	bool get_addrs = false;
	int mode;
	const char *ifname = NULL;

	blobmsg_parse(iface_attrs, IFACE_ATTR_MAX, tb, data, len);

	if (tb[IFACE_ATTR_INTERFACE])
		name = blobmsg_get_string(tb[IFACE_ATTR_INTERFACE]);

	if (!name)
		return -1;

	iface = avl_find_element(&interfaces, name, iface, avl);
	if (!iface) {
		char *new_name;

		iface = calloc_a(sizeof(*iface), &new_name, strlen(name) + 1);
		if (!iface)
			return -1;

		iface->name = strcpy(new_name, name);
		iface->avl.key = iface->name;
		iface->router_event.uloop.fd = -1;
		iface->dhcpv6_event.uloop.fd = -1;
		iface->ndp_event.uloop.fd = -1;
		iface->ndp_ping_fd = -1;
		iface->dhcpv4_event.uloop.fd = -1;
		INIT_LIST_HEAD(&iface->ia_assignments);
		avl_init(&iface->dhcpv4_leases, avl_ipv4_cmp, false, iface);
		INIT_LIST_HEAD(&iface->dhcpv4_fr_ips);

		set_interface_defaults(iface);

		avl_insert(&interfaces, &iface->avl);
		get_addrs = overwrite = true;
	}

	if (overwrite) {
		if ((c = tb[IFACE_ATTR_IFNAME]))
			ifname = blobmsg_get_string(c);
		else if ((c = tb[IFACE_ATTR_NETWORKID]))
			ifname = blobmsg_get_string(c);
	}

	if (overwrite || !iface->ifname)
		if (config.use_ubus)
			ifname = ubus_get_ifname(name);

	if (!iface->ifname && !ifname)
		goto err;

	if (ifname) {
		free(iface->ifname);
		iface->ifname = strdup(ifname);

		if (!iface->ifname)
			goto err;

		if (!iface->ifindex &&
			(iface->ifindex = if_nametoindex(iface->ifname)) <= 0)
			goto err;

		if ((iface->ifflags = odhcpd_get_flags(iface)) < 0)
			goto err;
	}

	if (get_addrs) {
		oaddrs_cnt = netlink_get_interface_addrs(iface->ifindex,
							 true, &iface->addr6);

		if (oaddrs_cnt > 0)
			iface->addr6_len = oaddrs_cnt;

		oaddrs_cnt = netlink_get_interface_addrs(iface->ifindex,
							 false, &iface->oaddrs4);
		if (oaddrs_cnt > 0)
			iface->oaddrs4_cnt = oaddrs_cnt;
	}

	oaddrs_cnt = netlink_get_interface_linklocal(iface->ifindex, &oaddrs);
	if (oaddrs_cnt > 0) {
		for (ssize_t i = 0; i < oaddrs_cnt; i++) {
			if (!oaddrs[i].tentative) {
				iface->have_link_local = true;
				break;
			}
		}
		free(oaddrs);
	}

	iface->inuse = true;

	if ((c = tb[IFACE_ATTR_DYNAMICDHCP]))
		iface->no_dynamic_dhcp = !blobmsg_get_bool(c);

	if ((c = tb[IFACE_ATTR_LEASETIME])) {
		uint32_t time = parse_leasetime(c);

		if (time > 0)
			iface->dhcp_leasetime = time;
		else
			error("Invalid %s value configured for interface '%s'",
			      iface_attrs[IFACE_ATTR_LEASETIME].name, iface->name);
	}

	if ((c = tb[IFACE_ATTR_MAX_PREFERRED_LIFETIME])) {
		uint32_t time = parse_leasetime(c);

		if (time > 0)
			iface->max_preferred_lifetime = time;
		else
			error("Invalid %s value configured for interface '%s'",
			      iface_attrs[IFACE_ATTR_MAX_PREFERRED_LIFETIME].name, iface->name);
	}

	if ((c = tb[IFACE_ATTR_MAX_VALID_LIFETIME])) {
		uint32_t time = parse_leasetime(c);

		if (time > 0)
			iface->max_valid_lifetime = time;
		else
			error("Invalid %s value configured for interface '%s'",
			      iface_attrs[IFACE_ATTR_MAX_VALID_LIFETIME].name, iface->name);
	}

	if ((c = tb[IFACE_ATTR_DHCPV4_POOL_START])) {
		iface->dhcpv4_pool_start = blobmsg_get_u32(c);
		iface->dhcpv4_pool_end = iface->dhcpv4_pool_start + DHCPV4_POOL_LIMIT_DEFAULT - 1;
	}

	if ((c = tb[IFACE_ATTR_DHCPV4_POOL_LIMIT]))
		iface->dhcpv4_pool_end = iface->dhcpv4_pool_start + blobmsg_get_u32(c) - 1;

	if (iface->dhcpv4_pool_start > UINT16_MAX ||
	    iface->dhcpv4_pool_end > UINT16_MAX ||
	    iface->dhcpv4_pool_start > iface->dhcpv4_pool_end) {
		warn("Invalid DHCPv4 pool range for %s, disabling dynamic leases", iface->name);
		iface->no_dynamic_dhcp = true;
	}

	if ((c = tb[IFACE_ATTR_MASTER]))
		iface->master = blobmsg_get_bool(c);

	if (overwrite && (c = tb[IFACE_ATTR_UPSTREAM])) {
		struct blob_attr *cur;
		unsigned rem;
		char *tmp;

		blobmsg_for_each_attr(cur, c, rem) {
			if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING || !blobmsg_check_attr(cur, false))
				continue;

			tmp = realloc(iface->upstream, iface->upstream_len + blobmsg_data_len(cur));
			if (!tmp)
				goto err;

			iface->upstream = tmp;
			memcpy(iface->upstream + iface->upstream_len, blobmsg_get_string(cur), blobmsg_data_len(cur));
			iface->upstream_len += blobmsg_data_len(cur);
		}
	}

	if ((c = tb[IFACE_ATTR_RA])) {
		if ((mode = parse_mode(blobmsg_get_string(c))) >= 0) {
			iface->ra = mode;

			if (iface->ra != MODE_DISABLED)
				iface->ignore = false;
		} else
			error("Invalid %s mode configured for interface '%s'",
			      iface_attrs[IFACE_ATTR_RA].name, iface->name);
	}

	if ((c = tb[IFACE_ATTR_DHCPV4])) {
		if ((mode = parse_mode(blobmsg_get_string(c))) >= 0) {
			iface->dhcpv4 = config.main_dhcpv4 ? mode : MODE_DISABLED;

			if (iface->dhcpv4 != MODE_DISABLED)
				iface->ignore = false;
		} else
			error("Invalid %s mode configured for interface %s",
			      iface_attrs[IFACE_ATTR_DHCPV4].name, iface->name);
	}

	if ((c = tb[IFACE_ATTR_DHCPV6])) {
		if ((mode = parse_mode(blobmsg_get_string(c))) >= 0) {
			iface->dhcpv6 = mode;

			if (iface->dhcpv6 != MODE_DISABLED)
				iface->ignore = false;
		} else
			error("Invalid %s mode configured for interface '%s'",
			      iface_attrs[IFACE_ATTR_DHCPV6].name, iface->name);
	}

	if ((c = tb[IFACE_ATTR_NDP])) {
		if ((mode = parse_mode(blobmsg_get_string(c))) >= 0) {
			iface->ndp = mode;

			if (iface->ndp != MODE_DISABLED)
				iface->ignore = false;
		} else
			error("Invalid %s mode configured for interface '%s'",
			      iface_attrs[IFACE_ATTR_NDP].name, iface->name);
	}

	if ((c = tb[IFACE_ATTR_ROUTER])) {
		struct blob_attr *cur;
		unsigned rem;

		blobmsg_for_each_attr(cur, c, rem) {
			struct in_addr addr4, *tmp;

			if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING || !blobmsg_check_attr(cur, false))
				continue;

			if (inet_pton(AF_INET, blobmsg_get_string(cur), &addr4) == 1) {
				tmp = realloc(iface->dhcpv4_routers,
					      (iface->dhcpv4_routers_cnt + 1) * sizeof(*iface->dhcpv4_routers));
				if (!tmp)
					goto err;

				iface->dhcpv4_routers = tmp;
				iface->dhcpv4_routers[iface->dhcpv4_routers_cnt++] = addr4;
			} else {
				error("Invalid %s value configured for interface '%s'",
				      iface_attrs[IFACE_ATTR_ROUTER].name, iface->name);
			}
		}
	}

	if ((c = tb[IFACE_ATTR_CAPTIVE_PORTAL_URI])) {
		iface->captive_portal_uri = strdup(blobmsg_get_string(c));
		iface->captive_portal_uri_len = strlen(iface->captive_portal_uri);
		if (iface->captive_portal_uri_len > UINT8_MAX) {
			warn("RFC8910 captive portal URI > %d characters for interface '%s': option via DHCPv4 not possible",
				UINT8_MAX,
				iface->name);
		}
		debug("Set RFC8910 captive portal URI: '%s' for interface '%s'",
			iface->captive_portal_uri, iface->name);
	}

	if ((c = tb[IFACE_ATTR_DNS])) {
		struct blob_attr *cur;
		unsigned rem;

		iface->always_rewrite_dns = true;
		blobmsg_for_each_attr(cur, c, rem) {
			struct in_addr addr4, *tmp4;
			struct in6_addr addr6, *tmp6;

			if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING || !blobmsg_check_attr(cur, false))
				continue;

			if (inet_pton(AF_INET, blobmsg_get_string(cur), &addr4) == 1) {
				if (addr4.s_addr == INADDR_ANY) {
					error("Invalid %s value configured for interface '%s'",
					      iface_attrs[IFACE_ATTR_DNS].name, iface->name);
					continue;
				}

				tmp4 = realloc(iface->dns_addrs4, (iface->dns_addrs4_cnt + 1) *
					       sizeof(*iface->dns_addrs4));
				if (!tmp4)
					goto err;

				iface->dns_addrs4 = tmp4;
				iface->dns_addrs4[iface->dns_addrs4_cnt++] = addr4;

			} else if (inet_pton(AF_INET6, blobmsg_get_string(cur), &addr6) == 1) {
				if (IN6_IS_ADDR_UNSPECIFIED(&addr6)) {
					error("Invalid %s value configured for interface '%s'",
					      iface_attrs[IFACE_ATTR_DNS].name, iface->name);
					continue;
				}

				tmp6 = realloc(iface->dns_addrs6, (iface->dns_addrs6_cnt + 1) *
					       sizeof(*iface->dns_addrs6));
				if (!tmp6)
					goto err;

				iface->dns_addrs6 = tmp6;
				iface->dns_addrs6[iface->dns_addrs6_cnt++] = addr6;

			} else {
				error("Invalid %s value configured for interface '%s'",
				      iface_attrs[IFACE_ATTR_DNS].name, iface->name);
			}
		}
	}

	if ((c = tb[IFACE_ATTR_DNS_SERVICE]))
		iface->dns_service = blobmsg_get_bool(c);

	if ((c = tb[IFACE_ATTR_DNS_DOMAIN_SEARCH])) {
		struct blob_attr *cur;
		unsigned rem;

		blobmsg_for_each_attr(cur, c, rem) {
			uint8_t buf[DNS_MAX_NAME_LEN];
			char *domain;
			size_t domainlen;
			int ds_len;
			uint8_t *tmp;

			if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING || !blobmsg_check_attr(cur, false))
				continue;

			domain = blobmsg_get_string(cur);
			domainlen = strlen(domain);

			if (domainlen > 0 && domain[domainlen - 1] == '.')
				domain[domainlen - 1] = 0;

			ds_len = dn_comp(domain, buf, sizeof(buf), NULL, NULL);
			if (ds_len <= 0) {
				error("Invalid %s value configured for interface '%s'",
				      iface_attrs[IFACE_ATTR_DNS_DOMAIN_SEARCH].name, iface->name);
				continue;
			}

			tmp = realloc(iface->dns_search, iface->dns_search_len + ds_len);
			if (!tmp)
				goto err;

			iface->dns_search = tmp;
			memcpy(&iface->dns_search[iface->dns_search_len], buf, ds_len);
			iface->dns_search_len += ds_len;
		}
	}

	if ((c = tb[IFACE_ATTR_DHCPV4_FORCERECONF]))
		iface->dhcpv4_forcereconf = blobmsg_get_bool(c);

	if ((c = tb[IFACE_ATTR_DHCPV6_RAW])) {
		void *tmp;
		size_t opt_len = blobmsg_data_len(c) / 2;

		tmp = realloc(iface->dhcpv6_raw, opt_len);
		if (!tmp)
			goto err;

		iface->dhcpv6_raw = tmp;
		iface->dhcpv6_raw_len = opt_len;
		odhcpd_unhexlify(iface->dhcpv6_raw, iface->dhcpv6_raw_len, blobmsg_get_string(c));
	}

	if ((c = tb[IFACE_ATTR_DHCPV6_ASSIGNALL]))
		iface->dhcpv6_assignall = blobmsg_get_bool(c);

	if ((c = tb[IFACE_ATTR_DHCPV6_PD_PREFERRED]))
		iface->dhcpv6_pd_preferred = blobmsg_get_bool(c);

	if ((c = tb[IFACE_ATTR_DHCPV6_PD]))
		iface->dhcpv6_pd = blobmsg_get_bool(c);

	if ((c = tb[IFACE_ATTR_DHCPV6_PD_MIN_LEN])) {
		uint32_t pd_min_len = blobmsg_get_u32(c);
		if (pd_min_len > PD_MIN_LEN_MAX)
			iface->dhcpv6_pd_min_len = PD_MIN_LEN_MAX;
		iface->dhcpv6_pd_min_len = pd_min_len;
		if (pd_min_len > PD_MIN_LEN_MAX)
			warn("Clamped invalid %s value configured for interface '%s' to %d",
			     iface_attrs[IFACE_ATTR_DHCPV6_PD_MIN_LEN].name, iface->name, iface->dhcpv6_pd_min_len);
	}

	if ((c = tb[IFACE_ATTR_DHCPV6_NA]))
		iface->dhcpv6_na = blobmsg_get_bool(c);

	if ((c = tb[IFACE_ATTR_DHCPV6_HOSTID_LEN])) {
		uint32_t original_hostid_len, hostid_len;
		original_hostid_len = hostid_len = blobmsg_get_u32(c);

		if (hostid_len < HOSTID_LEN_MIN)
			hostid_len = HOSTID_LEN_MIN;
		else if (hostid_len > HOSTID_LEN_MAX)
			hostid_len = HOSTID_LEN_MAX;

		iface->dhcpv6_hostid_len = hostid_len;

		if (original_hostid_len != hostid_len) {
			warn("Clamped invalid %s value configured for interface '%s' to %d",
			     iface_attrs[IFACE_ATTR_DHCPV6_HOSTID_LEN].name, iface->name, iface->dhcpv6_hostid_len);
		}
	}

	if ((c = tb[IFACE_ATTR_RA_DEFAULT]))
		iface->default_router = blobmsg_get_u32(c);

	if ((c = tb[IFACE_ATTR_RA_FLAGS])) {
		iface->ra_flags = 0;

		if (parse_ra_flags(&iface->ra_flags, c) < 0)
			error("Invalid %s value configured for interface '%s'",
			      iface_attrs[IFACE_ATTR_RA_FLAGS].name, iface->name);
	}

	if ((c = tb[IFACE_ATTR_RA_REACHABLETIME])) {
		uint32_t ra_reachabletime = blobmsg_get_u32(c);

		/* RFC4861 §6.2.1 : AdvReachableTime :
		 * MUST be no greater than 3,600,000 msec
		 */
		iface->ra_reachabletime = ra_reachabletime <= AdvReachableTime ? ra_reachabletime : AdvReachableTime;
		if(ra_reachabletime > AdvReachableTime)
			warn("Clamped invalid %s value configured for interface '%s' to %d",
			     iface_attrs[IFACE_ATTR_RA_REACHABLETIME].name, iface->name, iface->ra_reachabletime);
	}

	if ((c = tb[IFACE_ATTR_RA_RETRANSTIME])) {
		uint32_t ra_retranstime = blobmsg_get_u32(c);

		iface->ra_retranstime = ra_retranstime <= RETRANS_TIMER_MAX ? ra_retranstime : RETRANS_TIMER_MAX;
		if (ra_retranstime > RETRANS_TIMER_MAX)
			warn("Clamped invalid %s value configured for interface '%s' to %d",
			     iface_attrs[IFACE_ATTR_RA_RETRANSTIME].name, iface->name, iface->ra_retranstime);
	}

	if ((c = tb[IFACE_ATTR_RA_HOPLIMIT])) {
		uint32_t ra_hoplimit = blobmsg_get_u32(c);

		/* RFC4861 §6.2.1 : AdvCurHopLimit */
		iface->ra_hoplimit = ra_hoplimit <= AdvCurHopLimit ? ra_hoplimit : AdvCurHopLimit;
		if(ra_hoplimit > AdvCurHopLimit)
			warn("Clamped invalid %s value configured for interface '%s' to %d",
			     iface_attrs[IFACE_ATTR_RA_HOPLIMIT].name, iface->name, iface->ra_hoplimit);
	}

	iface->if_mtu = odhcpd_get_interface_config(iface->ifname, "mtu");
	if ((c = tb[IFACE_ATTR_RA_MTU])) {
		uint32_t original_ra_mtu, ra_mtu;
		original_ra_mtu = ra_mtu = blobmsg_get_u32(c);
		if (ra_mtu < RA_MTU_MIN)
			ra_mtu = RA_MTU_MIN;
		else if (ra_mtu > RA_MTU_MAX)
			ra_mtu = RA_MTU_MAX;
		if (iface->if_mtu && ra_mtu > iface->if_mtu)
			ra_mtu = iface->if_mtu;

		iface->ra_mtu = ra_mtu;

		if (original_ra_mtu != ra_mtu) {
			warn("Clamped invalid %s value configured for interface '%s' to %d",
			     iface_attrs[IFACE_ATTR_RA_MTU].name, iface->name, iface->ra_mtu);
		}
	}

	/* Default RA MTU to the interface MTU if no value is assigned */
	if (!iface->ra_mtu && iface->if_mtu) {
		iface->ra_mtu = iface->if_mtu;
		info("Defaulted %s value for interface '%s' to %d",
		     iface_attrs[IFACE_ATTR_RA_MTU].name, iface->name, iface->ra_mtu);
	}

	if ((c = tb[IFACE_ATTR_RA_SLAAC]))
		iface->ra_slaac = blobmsg_get_bool(c);

	if ((c = tb[IFACE_ATTR_RA_OFFLINK]))
		iface->ra_not_onlink = blobmsg_get_bool(c);

	if ((c = tb[IFACE_ATTR_RA_ADVROUTER]))
		iface->ra_advrouter = blobmsg_get_bool(c);

	/*
	 * RFC4861: MaxRtrAdvInterval: MUST be no less than 4 seconds and no greater than 1800 seconds.
	 * RFC8319: MaxRtrAdvInterval: MUST be no less than 4 seconds and no greater than 65535 seconds.
	 * Default: 600 seconds
	 */
	if ((c = tb[IFACE_ATTR_RA_MAXINTERVAL])){
		uint32_t ra_maxinterval = blobmsg_get_u32(c);
		if (ra_maxinterval < 4)
			ra_maxinterval = 4;
		else if (ra_maxinterval > MaxRtrAdvInterval)
				ra_maxinterval = MaxRtrAdvInterval;
		iface->ra_maxinterval = ra_maxinterval;
	}

	/*
	 * RFC4861: MinRtrAdvInterval: MUST be no less than 3 seconds and no greater than .75 * MaxRtrAdvInterval.
	 * Default: 0.33 * MaxRtrAdvInterval If MaxRtrAdvInterval >= 9 seconds; otherwise, the
	 * Default is MaxRtrAdvInterval.
	 */
	if ((c = tb[IFACE_ATTR_RA_MININTERVAL])){
		uint32_t ra_mininterval = blobmsg_get_u32(c);
		if (ra_mininterval < MinRtrAdvInterval)
			ra_mininterval = MinRtrAdvInterval; // clamp min
		else if (ra_mininterval > (0.75 * iface->ra_maxinterval))
				ra_mininterval = 0.75 * iface->ra_maxinterval; // clamp max
		iface->ra_mininterval = ra_mininterval;
	}

	/*
	 * RFC4861: AdvDefaultLifetime: MUST be either zero or between MaxRtrAdvInterval and 9000 seconds.
	 * RFC8319: AdvDefaultLifetime: MUST be either zero or between MaxRtrAdvInterval and 65535 seconds.
	 * Default: 3 * MaxRtrAdvInterval
	 * i.e. 3 * 65535 => 65535 seconds.
	 */
	if ((c = tb[IFACE_ATTR_RA_LIFETIME])){
		uint32_t ra_lifetime = blobmsg_get_u32(c);
		if (ra_lifetime != 0){
			if (ra_lifetime < iface->ra_maxinterval)
				ra_lifetime = iface->ra_maxinterval; // clamp min
			else if (ra_lifetime > AdvDefaultLifetime)
				ra_lifetime = AdvDefaultLifetime; // clamp max
		}
		iface->ra_lifetime = ra_lifetime;
	}

	if ((c = tb[IFACE_ATTR_RA_DNS]))
		iface->ra_dns = blobmsg_get_bool(c);

	if ((c = tb[IFACE_ATTR_DNR])) {
		struct blob_attr *cur;
		unsigned rem;

		blobmsg_for_each_attr(cur, c, rem) {
			if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING || !blobmsg_check_attr(cur, false))
				continue;

			if (parse_dnr_str(blobmsg_get_string(cur), iface))
				error("Invalid %s value configured for interface '%s'",
				      iface_attrs[IFACE_ATTR_DNR].name, iface->name);
		}
	}

	if ((c = tb[IFACE_ATTR_RA_PREF64])) {
		struct in6_addr addr;

		odhcpd_parse_addr6_prefix(blobmsg_get_string(c),
					  &addr, &iface->pref64_length);

		iface->pref64_prefix[0] = addr.s6_addr32[0];
		switch (iface->pref64_length) {
		case 96:
			iface->pref64_plc = 0;
			iface->pref64_prefix[1] = addr.s6_addr32[1];
			iface->pref64_prefix[2] = addr.s6_addr32[2];
			break;
		case 64:
			iface->pref64_plc = 1;
			iface->pref64_prefix[1] = addr.s6_addr32[1];
			iface->pref64_prefix[2] = 0;
			break;
		case 56:
			iface->pref64_plc = 2;
			iface->pref64_prefix[1] = addr.s6_addr32[1] & htonl(0xffffff00);
			iface->pref64_prefix[2] = 0;
			break;
		case 48:
			iface->pref64_plc = 3;
			iface->pref64_prefix[1] = addr.s6_addr32[1] & htonl(0xffff0000);
			iface->pref64_prefix[2] = 0;
			break;
		case 40:
			iface->pref64_plc = 4;
			iface->pref64_prefix[1] = addr.s6_addr32[1] & htonl(0xff000000);
			iface->pref64_prefix[2] = 0;
			break;
		case 32:
			iface->pref64_plc = 5;
			iface->pref64_prefix[1] = 0;
			iface->pref64_prefix[2] = 0;
			break;
		default:
			warn("Invalid PREF64 prefix size (%d), ignoring ra_pref64 option!",
			     iface->pref64_length);
			iface->pref64_length = 0;
		}
	}

	if ((c = tb[IFACE_ATTR_IPV6_ONLY_PREFERRED])) {
		uint32_t v6only_wait = blobmsg_get_u32(c);

		if (v6only_wait > 0 && v6only_wait < DHCPV4_MIN_V6ONLY_WAIT) {
			warn("Invalid %s value configured for interface '%s', clamped to %d",
			     iface_attrs[IFACE_ATTR_IPV6_ONLY_PREFERRED].name,
			     iface->name, DHCPV4_MIN_V6ONLY_WAIT);
			v6only_wait = DHCPV4_MIN_V6ONLY_WAIT;
		}

		iface->dhcpv4_v6only_wait = v6only_wait;
	}

	if ((c = tb[IFACE_ATTR_RA_PREFERENCE])) {
		const char *prio = blobmsg_get_string(c);

		if (!strcmp(prio, "high"))
			iface->route_preference = 1;
		else if (!strcmp(prio, "low"))
			iface->route_preference = -1;
		else if (!strcmp(prio, "medium") || !strcmp(prio, "default"))
			iface->route_preference = 0;
		else
			error("Invalid %s mode configured for interface '%s'",
			      iface_attrs[IFACE_ATTR_RA_PREFERENCE].name, iface->name);
	}

	if ((c = tb[IFACE_ATTR_NDPROXY_ROUTING]))
		iface->learn_routes = blobmsg_get_bool(c);

	if ((c = tb[IFACE_ATTR_NDPROXY_SLAVE]))
		iface->external = blobmsg_get_bool(c);

	if ((c = tb[IFACE_ATTR_NDP_FROM_LINK_LOCAL]))
		iface->ndp_from_link_local = blobmsg_get_bool(c);

	if ((c = tb[IFACE_ATTR_PREFIX_FILTER]))
		odhcpd_parse_addr6_prefix(blobmsg_get_string(c),
					  &iface->pio_filter_addr,
					  &iface->pio_filter_length);

	if (overwrite && (c = tb[IFACE_ATTR_NTP])) {
		struct blob_attr *cur;
		unsigned rem;

		blobmsg_for_each_attr(cur, c, rem) {
			if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING || !blobmsg_check_attr(cur, false))
				continue;

			char *str = blobmsg_get_string(cur);
			struct in_addr addr4, *tmp4;
			struct in6_addr addr6, *tmp6;

			if (inet_pton(AF_INET, str, &addr4) == 1) {
				if (addr4.s_addr == INADDR_ANY)
					goto err;

				tmp4 = realloc(iface->dhcpv4_ntp, (iface->dhcpv4_ntp_cnt + 1) * sizeof(*iface->dhcpv4_ntp));
				if (!tmp4)
					goto err;

				iface->dhcpv4_ntp = tmp4;
				iface->dhcpv4_ntp[iface->dhcpv4_ntp_cnt++] = addr4;

			} else if (inet_pton(AF_INET6, str, &addr6) == 1) {
				if (IN6_IS_ADDR_UNSPECIFIED(&addr6))
					goto err;

				tmp6 = realloc(iface->dhcpv6_sntp, (iface->dhcpv6_sntp_cnt + 1) * sizeof(*iface->dhcpv6_sntp));
				if (!tmp6)
					goto err;

				iface->dhcpv6_sntp = tmp6;
				iface->dhcpv6_sntp[iface->dhcpv6_sntp_cnt++] = addr6;

				if (!parse_ntp_options(&iface->dhcpv6_ntp_len, addr6, &iface->dhcpv6_ntp))
					iface->dhcpv6_ntp_cnt++;

			} else {
				if (!parse_ntp_fqdn(&iface->dhcpv6_ntp_len, str, &iface->dhcpv6_ntp))
					iface->dhcpv6_ntp_cnt++;
			}
		}
	}

	statefiles_read_prefix_information(iface);

	return 0;

err:
	close_interface(iface);
	return -1;
}

static int set_interface(struct uci_section *s)
{
	blob_buf_init(&b, 0);
	uci_to_blob(&b, s, &interface_attr_list);

	return config_parse_interface(blob_data(b.head), blob_len(b.head), s->e.name, true);
}

static void lease_cfg_delete_dhcpv6_leases(struct lease_cfg *lease_cfg)
{
	struct dhcpv6_lease *lease, *tmp;

	list_for_each_entry_safe(lease, tmp, &lease_cfg->dhcpv6_leases, lease_cfg_list)
		dhcpv6_free_lease(lease);
}

static void lease_cfg_update_leases(struct lease_cfg *lease_cfg)
{
	struct dhcpv4_lease *lease4 = lease_cfg->dhcpv4_lease;
	struct dhcpv6_lease *lease6;

	if (lease4) {
		free(lease4->hostname);
		lease4->hostname = NULL;

		if (lease_cfg->hostname) {
			lease4->hostname = strdup(lease_cfg->hostname);
			lease4->hostname_valid = true;
		}
	}

	list_for_each_entry(lease6, &lease_cfg->dhcpv6_leases, lease_cfg_list) {
		free(lease6->hostname);
		lease6->hostname = NULL;

		if (lease_cfg->hostname) {
			lease6->hostname = strdup(lease_cfg->hostname);
			lease6->hostname_valid = true;
		}

		lease6->leasetime = lease_cfg->leasetime;
	}
}

static int lease_cfg_cmp(const void *k1, const void *k2, _o_unused void *ptr)
{
	const struct lease_cfg *lease_cfg1 = k1, *lease_cfg2 = k2;
	int cmp = 0;

	if (lease_cfg1->duid_count != lease_cfg2->duid_count)
		return lease_cfg1->duid_count - lease_cfg2->duid_count;

	for (size_t i = 0; i < lease_cfg1->duid_count; i++) {
		if (lease_cfg1->duids[i].len != lease_cfg2->duids[i].len)
			return lease_cfg1->duids[i].len - lease_cfg2->duids[i].len;

		if (lease_cfg1->duids[i].len && lease_cfg2->duids[i].len) {
			cmp = memcmp(lease_cfg1->duids[i].id, lease_cfg2->duids[i].id,
				     lease_cfg1->duids[i].len);
			if (cmp)
				return cmp;
		}
	}

	if (lease_cfg1->mac_count != lease_cfg2->mac_count)
		return lease_cfg1->mac_count - lease_cfg2->mac_count;

	for (size_t i = 0; i < lease_cfg1->mac_count; i++) {
		cmp = memcmp(lease_cfg1->macs[i].ether_addr_octet,
			     lease_cfg2->macs[i].ether_addr_octet,
			     sizeof(lease_cfg1->macs[i].ether_addr_octet));
		if (cmp)
			return cmp;
	}

	return 0;
}

static void lease_cfg_change(struct lease_cfg *lease_cfg_old, struct lease_cfg *lease_cfg_new)
{
	bool update = false;

	if ((!!lease_cfg_new->hostname != !!lease_cfg_old->hostname) ||
	    (lease_cfg_new->hostname && strcmp(lease_cfg_new->hostname, lease_cfg_old->hostname))) {
		free(lease_cfg_old->hostname);
		lease_cfg_old->hostname = NULL;

		if (lease_cfg_new->hostname)
			lease_cfg_old->hostname = strdup(lease_cfg_new->hostname);

		update = true;
	}

	if (lease_cfg_old->leasetime != lease_cfg_new->leasetime) {
		lease_cfg_old->leasetime = lease_cfg_new->leasetime;
		update = true;
	}

	if (lease_cfg_old->ipv4.s_addr != lease_cfg_new->ipv4.s_addr) {
		lease_cfg_old->ipv4 = lease_cfg_new->ipv4;
		dhcpv4_free_lease(lease_cfg_old->dhcpv4_lease);
	}

	if (lease_cfg_old->hostid != lease_cfg_new->hostid) {
		lease_cfg_old->hostid = lease_cfg_new->hostid;
		lease_cfg_delete_dhcpv6_leases(lease_cfg_old);
	}

	if (update)
		lease_cfg_update_leases(lease_cfg_old);

	free_lease_cfg(lease_cfg_new);
}

static void lease_cfg_delete(struct lease_cfg *lease_cfg)
{
	dhcpv4_free_lease(lease_cfg->dhcpv4_lease);
	lease_cfg_delete_dhcpv6_leases(lease_cfg);
	free_lease_cfg(lease_cfg);
}

static void lease_cfg_update(_o_unused struct vlist_tree *tree, struct vlist_node *node_new,
			    struct vlist_node *node_old)
{
	struct lease_cfg *lease_cfg_new = container_of(node_new, struct lease_cfg, node);
	struct lease_cfg *lease_cfg_old = container_of(node_old, struct lease_cfg, node);

	if (node_old && node_new)
		lease_cfg_change(lease_cfg_old, lease_cfg_new);
	else if (node_old)
		lease_cfg_delete(lease_cfg_old);
}

/*
 * Either find:
 *  a) a lease cfg with an exact DUID/IAID match; or
 *  b) a lease cfg with a matching DUID and no IAID set
 */
struct lease_cfg *
config_find_lease_cfg_by_duid_and_iaid(const uint8_t *duid, const uint16_t len, const uint32_t iaid)
{
	struct lease_cfg *lease_cfg, *candidate = NULL;

	vlist_for_each_element(&lease_cfgs, lease_cfg, node) {
		for (size_t i = 0; i < lease_cfg->duid_count; i++) {
			if (lease_cfg->duids[i].len != len)
				continue;

			if (memcmp(lease_cfg->duids[i].id, duid, len))
				continue;

			if (!lease_cfg->duids[i].iaid_set) {
				candidate = lease_cfg;
				continue;
			}

			if (lease_cfg->duids[i].iaid == iaid)
				return lease_cfg;
		}
	}

	return candidate;
}

struct lease_cfg *config_find_lease_cfg_by_mac(const uint8_t *mac)
{
	struct lease_cfg *lease_cfg;

	vlist_for_each_element(&lease_cfgs, lease_cfg, node) {
		for (size_t i = 0; i < lease_cfg->mac_count; i++) {
			if (!memcmp(lease_cfg->macs[i].ether_addr_octet, mac,
				    sizeof(lease_cfg->macs[i].ether_addr_octet)))
				return lease_cfg;
		}
	}

	return NULL;
}

struct lease_cfg *config_find_lease_cfg_by_hostid(const uint64_t hostid)
{
	struct lease_cfg *lease_cfg;

	vlist_for_each_element(&lease_cfgs, lease_cfg, node) {
		if (lease_cfg->hostid == hostid)
			return lease_cfg;
	}

	return NULL;
}

struct lease_cfg *config_find_lease_cfg_by_ipv4(const struct in_addr ipv4)
{
	struct lease_cfg *lease_cfg;

	vlist_for_each_element(&lease_cfgs, lease_cfg, node) {
		if (lease_cfg->ipv4.s_addr == ipv4.s_addr)
			return lease_cfg;
	}

	return NULL;
}

void reload_services(struct interface *iface)
{
	if (iface->ifflags & IFF_RUNNING) {
		debug("Enabling services with %s running", iface->ifname);
		router_setup_interface(iface, iface->ra != MODE_DISABLED);
		dhcpv6_setup_interface(iface, iface->dhcpv6 != MODE_DISABLED);
		ndp_setup_interface(iface, iface->ndp != MODE_DISABLED);
		dhcpv4_setup_interface(iface, iface->dhcpv4 != MODE_DISABLED);
	} else {
		debug("Disabling services with %s not running", iface->ifname);
		router_setup_interface(iface, false);
		dhcpv6_setup_interface(iface, false);
		ndp_setup_interface(iface, false);
		dhcpv4_setup_interface(iface, false);
	}
}

static int ipv6_pxe_from_uci(struct uci_section* s)
{
	blob_buf_init(&b, 0);
	uci_to_blob(&b, s, &ipv6_pxe_attr_list);

	void* data = blob_data(b.head);
	size_t len = blob_len(b.head);

	struct blob_attr* tb[IFACE_ATTR_MAX];
	blobmsg_parse(ipv6_pxe_attrs, IPV6_PXE_MAX, tb, data, len);

	if (!tb[IPV6_PXE_URL])
		return -1;

	const char* url = blobmsg_get_string(tb[IPV6_PXE_URL]);

	uint32_t arch = 0xFFFFFFFF;
	if (tb[IPV6_PXE_ARCH])
		arch = blobmsg_get_u32(tb[IPV6_PXE_ARCH]);

	return ipv6_pxe_entry_new(arch, url) ? -1 : 0;
}

void odhcpd_reload(void)
{
	struct uci_context *uci = uci_alloc_context();
	struct interface *master = NULL, *i, *tmp;
	char *uci_dhcp_path = "dhcp";
	char *uci_system_path = "system";
	char *uci_network_path = "network";

	if (!uci)
		return;

	if (config.uci_cfgdir) {
		size_t dlen = strlen(config.uci_cfgdir);

		uci_dhcp_path = alloca(dlen + sizeof("/dhcp"));
		sprintf(uci_dhcp_path, "%s/dhcp", config.uci_cfgdir);
		uci_system_path = alloca(dlen + sizeof("/system"));
		sprintf(uci_system_path, "%s/system", config.uci_cfgdir);
		uci_network_path = alloca(dlen + sizeof("/network"));
		sprintf(uci_network_path, "%s/network", config.uci_cfgdir);
	}

	vlist_update(&lease_cfgs);
	avl_for_each_element(&interfaces, i, avl)
		clean_interface(i);

	struct uci_package *network = NULL;
	if (!uci_load(uci, uci_network_path, &network)) {
		struct uci_element *e;

		/* 0. Global settings */
		uci_foreach_element(&network->sections, e) {
			struct uci_section *s = uci_to_section(e);
			if (!strcmp(s->type, "globals"))
				set_global_config(s);
		}
	}
	uci_unload(uci, network);

	struct uci_package *dhcp = NULL;
	if (!uci_load(uci, uci_dhcp_path, &dhcp)) {
		struct uci_element *e;

		/* 1. General odhcpd settings */
		uci_foreach_element(&dhcp->sections, e) {
			struct uci_section *s = uci_to_section(e);
			if (!strcmp(s->type, "odhcpd"))
				set_config(s);
		}

		/* 2. DHCP pools */
		uci_foreach_element(&dhcp->sections, e) {
			struct uci_section *s = uci_to_section(e);
			if (!strcmp(s->type, "dhcp"))
				set_interface(s);
		}

		/* 3. Static lease cfgs */
		uci_foreach_element(&dhcp->sections, e) {
			struct uci_section* s = uci_to_section(e);
			if (!strcmp(s->type, "host"))
				set_lease_cfg_from_uci(s);
		}

		/* 4. IPv6 PxE */
		ipv6_pxe_clear();
		uci_foreach_element(&dhcp->sections, e) {
			struct uci_section* s = uci_to_section(e);
			if (!strcmp(s->type, "boot6"))
				ipv6_pxe_from_uci(s);
		}
		ipv6_pxe_dump();
	}
	uci_unload(uci, dhcp);

	struct uci_package *system = NULL;
	if (config.enable_tz && !uci_load(uci, uci_system_path, &system)) {
		struct uci_element *e;

		/* 5. System settings */
		uci_foreach_element(&system->sections, e) {
			struct uci_section *s = uci_to_section(e);
			if (!strcmp(s->type, "system"))
				set_timezone_info_from_uci(s);
		}
	}
	uci_unload(uci, system);

	if (config.dhcp_statefile) {
		char *dir = dirname(strdupa(config.dhcp_statefile));
		char *file = basename(config.dhcp_statefile);

		memmove(config.dhcp_statefile, file, strlen(file) + 1);
		statefiles_setup_dirfd(dir, &config.dhcp_statedir_fd);
	} else {
		statefiles_setup_dirfd(NULL, &config.dhcp_statedir_fd);
	}
	statefiles_setup_dirfd(config.dhcp_hostsdir, &config.dhcp_hostsdir_fd);
	statefiles_setup_dirfd(config.ra_piodir, &config.ra_piodir_fd);

	vlist_flush(&lease_cfgs);

	ubus_apply_network();

	bool any_dhcpv6_slave = false, any_ra_slave = false, any_ndp_slave = false;

	/* Test for */
	avl_for_each_element(&interfaces, i, avl) {
		if (i->master)
			continue;

		if (i->dhcpv6 == MODE_HYBRID || i->dhcpv6 == MODE_RELAY)
			any_dhcpv6_slave = true;

		if (i->ra == MODE_HYBRID || i->ra == MODE_RELAY)
			any_ra_slave = true;

		if (i->ndp == MODE_HYBRID || i->ndp == MODE_RELAY)
			any_ndp_slave = true;
	}

	/* Evaluate hybrid mode for master */
	avl_for_each_element(&interfaces, i, avl) {
		if (!i->master)
			continue;

		enum odhcpd_mode hybrid_mode = MODE_DISABLED;

		if (config.use_ubus && !ubus_has_prefix(i->name, i->ifname))
			hybrid_mode = MODE_RELAY;

		if (i->dhcpv6 == MODE_HYBRID)
			i->dhcpv6 = hybrid_mode;

		if (i->dhcpv6 == MODE_RELAY && !any_dhcpv6_slave)
			i->dhcpv6 = MODE_DISABLED;

		if (i->ra == MODE_HYBRID)
			i->ra = hybrid_mode;

		if (i->ra == MODE_RELAY && !any_ra_slave)
			i->ra = MODE_DISABLED;

		if (i->ndp == MODE_HYBRID)
			i->ndp = hybrid_mode;

		if (i->ndp == MODE_RELAY && !any_ndp_slave)
			i->ndp = MODE_DISABLED;

		if (i->dhcpv6 == MODE_RELAY || i->ra == MODE_RELAY || i->ndp == MODE_RELAY)
			master = i;
	}


	avl_for_each_element_safe(&interfaces, i, avl, tmp) {
		if (i->inuse && i->ifflags & IFF_RUNNING) {
			/* Resolve hybrid mode */
			if (i->dhcpv6 == MODE_HYBRID)
				i->dhcpv6 = (master && master->dhcpv6 == MODE_RELAY) ?
						MODE_RELAY : MODE_SERVER;

			if (i->ra == MODE_HYBRID)
				i->ra = (master && master->ra == MODE_RELAY) ?
						MODE_RELAY : MODE_SERVER;

			if (i->ndp == MODE_HYBRID)
				i->ndp = (master && master->ndp == MODE_RELAY) ?
						MODE_RELAY : MODE_DISABLED;

			reload_services(i);
		} else
			close_interface(i);
	}

	uci_free_context(uci);
}

static void signal_reload(_o_unused struct uloop_signal *signal)
{
	odhcpd_reload();
}

int odhcpd_run(void)
{
	static struct uloop_signal sighup = { .signo = SIGHUP, .cb = signal_reload };

	if (config.use_ubus) {
		while (ubus_init()) {
			if (uloop_cancelled)
				return EXIT_FAILURE;
			sleep(1);
		}
	}

	odhcpd_reload();

	/* uloop_init() already handles SIGINT/SIGTERM */
	if (uloop_signal_add(&sighup) < 0)
		return EXIT_FAILURE;

	uloop_run();

	return EXIT_SUCCESS;
}
