#include <fcntl.h>
#include <resolv.h>
#include <signal.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <libgen.h>
#include <net/if.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>

#include <uci.h>
#include <uci_blob.h>
#include <libubox/utils.h>
#include <libubox/avl.h>
#include <libubox/avl-cmp.h>
#include <libubox/list.h>
#include <libubox/vlist.h>

#include "odhcpd.h"
#include "dhcpv6-pxe.h"

static struct blob_buf b;
static int reload_pipe[2] = { -1, -1 };

static int lease_cmp(const void *k1, const void *k2, void *ptr);
static void lease_update(struct vlist_tree *tree, struct vlist_node *node_new,
			 struct vlist_node *node_old);

struct vlist_tree leases = VLIST_TREE_INIT(leases, lease_cmp, lease_update, true, false);
AVL_TREE(interfaces, avl_strcmp, false, NULL);
struct config config = {.legacy = false, .main_dhcpv4 = false,
			.dhcp_cb = NULL, .dhcp_statefile = NULL, .dhcp_hostsfile = NULL,
			.log_level = LOG_WARNING};

#define START_DEFAULT	100
#define LIMIT_DEFAULT	150

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
	IFACE_ATTR_LIMIT,
	IFACE_ATTR_START,
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
	IFACE_ATTR_DOMAIN,
	IFACE_ATTR_FILTER_CLASS,
	IFACE_ATTR_DHCPV4_FORCERECONF,
	IFACE_ATTR_DHCPV6_RAW,
	IFACE_ATTR_DHCPV6_ASSIGNALL,
	IFACE_ATTR_DHCPV6_PD,
	IFACE_ATTR_DHCPV6_PD_MIN_LEN,
	IFACE_ATTR_DHCPV6_NA,
	IFACE_ATTR_DHCPV6_HOSTID_LEN,
	IFACE_ATTR_RA_DEFAULT,
	IFACE_ATTR_RA_MANAGEMENT,
	IFACE_ATTR_RA_FLAGS,
	IFACE_ATTR_RA_SLAAC,
	IFACE_ATTR_RA_OFFLINK,
	IFACE_ATTR_RA_PREFERENCE,
	IFACE_ATTR_RA_ADVROUTER,
	IFACE_ATTR_RA_MININTERVAL,
	IFACE_ATTR_RA_MAXINTERVAL,
	IFACE_ATTR_RA_LIFETIME,
	IFACE_ATTR_RA_USELEASETIME,
	IFACE_ATTR_RA_REACHABLETIME,
	IFACE_ATTR_RA_RETRANSTIME,
	IFACE_ATTR_RA_HOPLIMIT,
	IFACE_ATTR_RA_MTU,
	IFACE_ATTR_RA_DNS,
	IFACE_ATTR_RA_PREF64,
	IFACE_ATTR_PD_MANAGER,
	IFACE_ATTR_PD_CER,
	IFACE_ATTR_NDPROXY_ROUTING,
	IFACE_ATTR_NDPROXY_SLAVE,
	IFACE_ATTR_PREFIX_FILTER,
	IFACE_ATTR_PREFERRED_LIFETIME,
	IFACE_ATTR_NTP,
	IFACE_ATTR_MAX
};

static const struct blobmsg_policy iface_attrs[IFACE_ATTR_MAX] = {
	[IFACE_ATTR_INTERFACE] = { .name = "interface", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_IFNAME] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_NETWORKID] = { .name = "networkid", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_DYNAMICDHCP] = { .name = "dynamicdhcp", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_LEASETIME] = { .name = "leasetime", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_START] = { .name = "start", .type = BLOBMSG_TYPE_INT32 },
	[IFACE_ATTR_LIMIT] = { .name = "limit", .type = BLOBMSG_TYPE_INT32 },
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
	[IFACE_ATTR_DOMAIN] = { .name = "domain", .type = BLOBMSG_TYPE_ARRAY },
	[IFACE_ATTR_FILTER_CLASS] = { .name = "filter_class", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_DHCPV4_FORCERECONF] = { .name = "dhcpv4_forcereconf", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_DHCPV6_RAW] = { .name = "dhcpv6_raw", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_DHCPV6_ASSIGNALL] = { .name ="dhcpv6_assignall", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_DHCPV6_PD] = { .name = "dhcpv6_pd", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_DHCPV6_PD_MIN_LEN] = { .name = "dhcpv6_pd_min_len", .type = BLOBMSG_TYPE_INT32 },
	[IFACE_ATTR_DHCPV6_NA] = { .name = "dhcpv6_na", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_DHCPV6_HOSTID_LEN] = { .name = "dhcpv6_hostidlength", .type = BLOBMSG_TYPE_INT32 },
	[IFACE_ATTR_PD_MANAGER] = { .name = "pd_manager", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_PD_CER] = { .name = "pd_cer", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_RA_DEFAULT] = { .name = "ra_default", .type = BLOBMSG_TYPE_INT32 },
	[IFACE_ATTR_RA_MANAGEMENT] = { .name = "ra_management", .type = BLOBMSG_TYPE_INT32 },
	[IFACE_ATTR_RA_FLAGS] = { .name = "ra_flags", . type = BLOBMSG_TYPE_ARRAY },
	[IFACE_ATTR_RA_SLAAC] = { .name = "ra_slaac", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_RA_OFFLINK] = { .name = "ra_offlink", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_RA_PREFERENCE] = { .name = "ra_preference", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_RA_ADVROUTER] = { .name = "ra_advrouter", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_RA_MININTERVAL] = { .name = "ra_mininterval", .type = BLOBMSG_TYPE_INT32 },
	[IFACE_ATTR_RA_MAXINTERVAL] = { .name = "ra_maxinterval", .type = BLOBMSG_TYPE_INT32 },
	[IFACE_ATTR_RA_LIFETIME] = { .name = "ra_lifetime", .type = BLOBMSG_TYPE_INT32 },
	[IFACE_ATTR_RA_USELEASETIME] = { .name = "ra_useleasetime", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_RA_REACHABLETIME] = { .name = "ra_reachabletime", .type = BLOBMSG_TYPE_INT32 },
	[IFACE_ATTR_RA_RETRANSTIME] = { .name = "ra_retranstime", .type = BLOBMSG_TYPE_INT32 },
	[IFACE_ATTR_RA_HOPLIMIT] = { .name = "ra_hoplimit", .type = BLOBMSG_TYPE_INT32 },
	[IFACE_ATTR_RA_MTU] = { .name = "ra_mtu", .type = BLOBMSG_TYPE_INT32 },
	[IFACE_ATTR_RA_DNS] = { .name = "ra_dns", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_RA_PREF64] = { .name = "ra_pref64", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_NDPROXY_ROUTING] = { .name = "ndproxy_routing", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_NDPROXY_SLAVE] = { .name = "ndproxy_slave", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_PREFIX_FILTER] = { .name = "prefix_filter", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_PREFERRED_LIFETIME] = { .name = "preferred_lifetime", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_NTP] = { .name = "ntp", .type = BLOBMSG_TYPE_ARRAY },
};

static const struct uci_blob_param_info iface_attr_info[IFACE_ATTR_MAX] = {
	[IFACE_ATTR_UPSTREAM] = { .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_DNS] = { .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_DOMAIN] = { .type = BLOBMSG_TYPE_STRING },
};

const struct uci_blob_param_list interface_attr_list = {
	.n_params = IFACE_ATTR_MAX,
	.params = iface_attrs,
	.info = iface_attr_info,
};

const struct blobmsg_policy lease_attrs[LEASE_ATTR_MAX] = {
	[LEASE_ATTR_IP] = { .name = "ip", .type = BLOBMSG_TYPE_STRING },
	[LEASE_ATTR_MAC] = { .name = "mac", .type = BLOBMSG_TYPE_STRING },
	[LEASE_ATTR_DUID] = { .name = "duid", .type = BLOBMSG_TYPE_STRING },
	[LEASE_ATTR_HOSTID] = { .name = "hostid", .type = BLOBMSG_TYPE_STRING },
	[LEASE_ATTR_LEASETIME] = { .name = "leasetime", .type = BLOBMSG_TYPE_STRING },
	[LEASE_ATTR_NAME] = { .name = "name", .type = BLOBMSG_TYPE_STRING },
};

const struct uci_blob_param_list lease_attr_list = {
	.n_params = LEASE_ATTR_MAX,
	.params = lease_attrs,
};

enum {
	ODHCPD_ATTR_LEGACY,
	ODHCPD_ATTR_MAINDHCP,
	ODHCPD_ATTR_LEASEFILE,
	ODHCPD_ATTR_LEASETRIGGER,
	ODHCPD_ATTR_LOGLEVEL,
	ODHCPD_ATTR_HOSTSFILE,
	ODHCPD_ATTR_MAX
};

static const struct blobmsg_policy odhcpd_attrs[ODHCPD_ATTR_MAX] = {
	[ODHCPD_ATTR_LEGACY] = { .name = "legacy", .type = BLOBMSG_TYPE_BOOL },
	[ODHCPD_ATTR_MAINDHCP] = { .name = "maindhcp", .type = BLOBMSG_TYPE_BOOL },
	[ODHCPD_ATTR_LEASEFILE] = { .name = "leasefile", .type = BLOBMSG_TYPE_STRING },
	[ODHCPD_ATTR_LEASETRIGGER] = { .name = "leasetrigger", .type = BLOBMSG_TYPE_STRING },
	[ODHCPD_ATTR_LOGLEVEL] = { .name = "loglevel", .type = BLOBMSG_TYPE_INT32 },
	[ODHCPD_ATTR_HOSTSFILE] = { .name = "hostsfile", .type = BLOBMSG_TYPE_STRING },
};

const struct uci_blob_param_list odhcpd_attr_list = {
	.n_params = ODHCPD_ATTR_MAX,
	.params = odhcpd_attrs,
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
	iface->dhcp_leasetime = 43200;
	iface->preferred_lifetime = 604800; /* rfc4861#section-6.2.1: AdvPreferredLifetime 7 days */
	iface->dhcpv4_start.s_addr = htonl(START_DEFAULT);
	iface->dhcpv4_end.s_addr = htonl(START_DEFAULT + LIMIT_DEFAULT - 1);
	iface->dhcpv6_assignall = true;
	iface->dhcpv6_pd = true;
	iface->dhcpv6_pd_min_len = 0;
	iface->dhcpv6_na = true;
	iface->dhcpv6_hostid_len = HOSTID_LEN_DEFAULT;
	iface->dns_service = true;
	iface->ra_flags = ND_RA_FLAG_OTHER;
	iface->ra_slaac = true;
	iface->ra_maxinterval = 600;
	iface->ra_mininterval = iface->ra_maxinterval/3;
	iface->ra_lifetime = -1;
	iface->ra_dns = true;
}

static void clean_interface(struct interface *iface)
{
	free(iface->dns);
	free(iface->search);
	free(iface->upstream);
	free(iface->dhcpv4_router);
	free(iface->dhcpv4_dns);
	free(iface->dhcpv6_raw);
	free(iface->filter_class);
	free(iface->dhcpv4_ntp);
	free(iface->dhcpv6_ntp);
	free(iface->dhcpv6_sntp);
	for (unsigned i = 0; i < iface->dnr_cnt; i++) {
		free(iface->dnr[i].adn);
		free(iface->dnr[i].addr4);
		free(iface->dnr[i].addr6);
		free(iface->dnr[i].svc);
	}
	free(iface->dnr);
	memset(&iface->ra, 0, sizeof(*iface) - offsetof(struct interface, ra));
	set_interface_defaults(iface);
}

static void close_interface(struct interface *iface)
{
	avl_delete(&interfaces, &iface->avl);

	router_setup_interface(iface, false);
	dhcpv6_setup_interface(iface, false);
	ndp_setup_interface(iface, false);
#ifdef DHCPV4_SUPPORT
	dhcpv4_setup_interface(iface, false);
#endif

	/* make sure timer is not on the timeouts list before freeing */
	uloop_timeout_cancel(&iface->timer_rs);

	clean_interface(iface);
	free(iface->addr4);
	free(iface->addr6);
	free(iface->invalid_addr6);
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

static void set_config(struct uci_section *s)
{
	struct blob_attr *tb[ODHCPD_ATTR_MAX], *c;

	blob_buf_init(&b, 0);
	uci_to_blob(&b, s, &odhcpd_attr_list);
	blobmsg_parse(odhcpd_attrs, ODHCPD_ATTR_MAX, tb, blob_data(b.head), blob_len(b.head));

	if ((c = tb[ODHCPD_ATTR_LEGACY]))
		config.legacy = blobmsg_get_bool(c);

	if ((c = tb[ODHCPD_ATTR_MAINDHCP]))
		config.main_dhcpv4 = blobmsg_get_bool(c);

	if ((c = tb[ODHCPD_ATTR_LEASEFILE])) {
		free(config.dhcp_statefile);
		config.dhcp_statefile = strdup(blobmsg_get_string(c));
	}

	if ((c = tb[ODHCPD_ATTR_HOSTSFILE])) {
		free(config.dhcp_hostsfile);
		config.dhcp_hostsfile = strdup(blobmsg_get_string(c));
	}

	if ((c = tb[ODHCPD_ATTR_LEASETRIGGER])) {
		free(config.dhcp_cb);
		config.dhcp_cb = strdup(blobmsg_get_string(c));
	}

	if ((c = tb[ODHCPD_ATTR_LOGLEVEL])) {
		int log_level = (blobmsg_get_u32(c) & LOG_PRIMASK);

		if (config.log_level != log_level) {
			config.log_level = log_level;
			setlogmask(LOG_UPTO(config.log_level));
		}
	}
}

static double parse_leasetime(struct blob_attr *c) {
	char *val = blobmsg_get_string(c), *endptr = NULL;
	double time = strcmp(val, "infinite") ? strtod(val, &endptr) : UINT32_MAX;

	if (time && endptr && endptr[0]) {
		if (endptr[0] == 's')
			time *= 1;
		else if (endptr[0] == 'm')
			time *= 60;
		else if (endptr[0] == 'h')
			time *= 3600;
		else if (endptr[0] == 'd')
			time *= 24 * 3600;
		else if (endptr[0] == 'w')
			time *= 7 * 24 * 3600;
		else
			goto err;
	}

	if (time < 60)
		time = 60;

	return time;

err:
	return -1;
}

static void free_lease(struct lease *l)
{
	free(l->hostname);
	free(l);
}


int set_lease_from_blobmsg(struct blob_attr *ba)
{
	struct blob_attr *tb[LEASE_ATTR_MAX], *c;
	struct lease *l;
	size_t duidlen = 0;
	uint8_t *duid;

	blobmsg_parse(lease_attrs, LEASE_ATTR_MAX, tb, blob_data(ba), blob_len(ba));

	if ((c = tb[LEASE_ATTR_DUID]))
		duidlen = (blobmsg_data_len(c) - 1) / 2;

	l = calloc_a(sizeof(*l), &duid, duidlen);
	if (!l)
		goto err;

	if ((c = tb[LEASE_ATTR_MAC]))
		if (!ether_aton_r(blobmsg_get_string(c), &l->mac))
			goto err;

	if ((c = tb[LEASE_ATTR_DUID])) {
		ssize_t len;

		l->duid = duid;
		len = odhcpd_unhexlify(l->duid, duidlen, blobmsg_get_string(c));

		if (len < 0)
			goto err;

		l->duid_len = len;
	}

	if ((c = tb[LEASE_ATTR_NAME])) {
		l->hostname = strdup(blobmsg_get_string(c));
		if (!l->hostname || !odhcpd_valid_hostname(l->hostname))
			goto err;
	}

	if ((c = tb[LEASE_ATTR_IP]))
		if (inet_pton(AF_INET, blobmsg_get_string(c), &l->ipaddr) < 0)
			goto err;

	if ((c = tb[LEASE_ATTR_HOSTID])) {
		errno = 0;
		l->hostid = strtoull(blobmsg_get_string(c), NULL, 16);
		if (errno)
			goto err;
	} else {
		uint32_t i4a = ntohl(l->ipaddr) & 0xff;
		l->hostid = ((i4a / 100) << 8) | (((i4a % 100) / 10) << 4) | (i4a % 10);
	}

	if ((c = tb[LEASE_ATTR_LEASETIME])) {
		double time = parse_leasetime(c);
		if (time < 0)
			goto err;

		l->leasetime = time;
	}

	INIT_LIST_HEAD(&l->assignments);
	vlist_add(&leases, &l->node, l);
	return 0;

err:
	if (l)
		free_lease(l);

	return -1;
}

static int set_lease_from_uci(struct uci_section *s)
{
	blob_buf_init(&b, 0);
	uci_to_blob(&b, s, &lease_attr_list);

	return set_lease_from_blobmsg(b.head);
}

/* Parse NTP Options for DHCPv6 Address */
static int parse_ntp_options(uint16_t *dhcpv6_ntp_len, struct in6_addr addr6, uint8_t **dhcpv6_ntp)
{
	uint16_t sub_opt = 0, sub_len = htons(IPV6_ADDR_LEN);
	uint16_t ntp_len = IPV6_ADDR_LEN + 4;
	uint8_t *ntp = *dhcpv6_ntp;
	size_t pos = *dhcpv6_ntp_len;

	ntp = realloc(ntp, pos + ntp_len);
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
	uint8_t *ntp = *dhcpv6_ntp;
	size_t pos = *dhcpv6_ntp_len;
	uint8_t buf[256] = {0};

	if (fqdn_len > 0 && fqdn[fqdn_len - 1] == '.')
		fqdn[fqdn_len - 1] = 0;

	int len = dn_comp(fqdn, buf, sizeof(buf), NULL, NULL);
	if (len <= 0)
		return -1;

	ntp_len = len + 4;

	ntp = realloc(ntp, pos + ntp_len);
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
		syslog(LOG_ERR, "Unable to parse priority '%s'", priority);
		goto err;
	} else if (dnr.priority == 0) {
		syslog(LOG_ERR, "Invalid priority '%s'", priority);
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
		syslog(LOG_ERR, "Hostname '%s' too long", adn);
		goto err;
	}

	adn_len = dn_comp(adn, adn_buf, sizeof(adn_buf), NULL, NULL);
	if (adn_len <= 0) {
		syslog(LOG_ERR, "Unable to parse hostname '%s'", adn);
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
			syslog(LOG_ERR, "Unable to parse IP address '%s'", addr);
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
				syslog(LOG_ERR, "Invalid value '%s' for _lifetime", svc_val ? svc_val : "");
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
			syslog(LOG_ERR, "Invalid SvcParam '%s'", svc_key);
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
					syslog(LOG_ERR, "Invalid value '%s' for SvcParam 'mandatory'", mkey_str);
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
					syslog(LOG_ERR, "Invalid value '%s' for SvcParam 'alpn'", alpn_id_str);
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
				syslog(LOG_ERR, "Invalid value '%s' for SvcParam 'port'", svc_val_str);
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
			/* fall through */

		case DNR_SVC_OHTTP:
			if (strlen(svc_val_str) > 0) {
				syslog(LOG_ERR, "Invalid value '%s' for SvcParam 'port'", svc_val_str);
				goto err;
			}
			/* fall through */

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
			syslog(LOG_ERR, "SvcParam 'ech' is not implemented");
			goto err;

		case DNR_SVC_IPV4HINT:
			/* fall through */

		case DNR_SVC_IPV6HINT:
			syslog(LOG_ERR, "SvcParam '%s' is not allowed", svc_param_key_names[svc_key]);
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

int config_parse_interface(void *data, size_t len, const char *name, bool overwrite)
{
	struct odhcpd_ipaddr *addrs = NULL;
	struct interface *iface;
	struct blob_attr *tb[IFACE_ATTR_MAX], *c;
	ssize_t addrs_len;
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
		INIT_LIST_HEAD(&iface->dhcpv4_assignments);
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

#ifdef WITH_UBUS
	if (overwrite || !iface->ifname)
		ifname = ubus_get_ifname(name);
#endif

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
		addrs_len = netlink_get_interface_addrs(iface->ifindex,
						true, &iface->addr6);

		if (addrs_len > 0)
			iface->addr6_len = addrs_len;

		addrs_len = netlink_get_interface_addrs(iface->ifindex,
						false, &iface->addr4);
		if (addrs_len > 0)
			iface->addr4_len = addrs_len;
	}

	addrs_len = netlink_get_interface_linklocal(iface->ifindex, &addrs);
	if (addrs_len > 0) {
		for (ssize_t i = 0; i < addrs_len; i++) {
			if (!addrs[i].tentative) {
				iface->have_link_local = true;
				break;
			}
		}
		free(addrs);
	}

	iface->inuse = true;

	if ((c = tb[IFACE_ATTR_DYNAMICDHCP]))
		iface->no_dynamic_dhcp = !blobmsg_get_bool(c);

	if ((c = tb[IFACE_ATTR_LEASETIME])) {
		double time = parse_leasetime(c);

		if (time >= 0)
			iface->dhcp_leasetime = time;
		else
			syslog(LOG_ERR, "Invalid %s value configured for interface '%s'",
					iface_attrs[IFACE_ATTR_LEASETIME].name, iface->name);

	}

	if ((c = tb[IFACE_ATTR_PREFERRED_LIFETIME])) {
		double time = parse_leasetime(c);

		if (time >= 0)
			iface->preferred_lifetime = time;
		else
			syslog(LOG_ERR, "Invalid %s value configured for interface '%s'",
					iface_attrs[IFACE_ATTR_PREFERRED_LIFETIME].name, iface->name);

	}

	if ((c = tb[IFACE_ATTR_START])) {
		iface->dhcpv4_start.s_addr = htonl(blobmsg_get_u32(c));
		iface->dhcpv4_end.s_addr = htonl(ntohl(iface->dhcpv4_start.s_addr) +
							LIMIT_DEFAULT - 1);

		if (config.main_dhcpv4 && config.legacy)
			iface->dhcpv4 = MODE_SERVER;
	}

	if ((c = tb[IFACE_ATTR_LIMIT]))
		iface->dhcpv4_end.s_addr = htonl(ntohl(iface->dhcpv4_start.s_addr) +
							blobmsg_get_u32(c) - 1);

	if ((c = tb[IFACE_ATTR_MASTER]))
		iface->master = blobmsg_get_bool(c);

	if (overwrite && (c = tb[IFACE_ATTR_UPSTREAM])) {
		struct blob_attr *cur;
		unsigned rem;

		blobmsg_for_each_attr(cur, c, rem) {
			if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING || !blobmsg_check_attr(cur, false))
				continue;

			iface->upstream = realloc(iface->upstream,
					iface->upstream_len + blobmsg_data_len(cur));
			if (!iface->upstream)
				goto err;

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
			syslog(LOG_ERR, "Invalid %s mode configured for interface '%s'",
					iface_attrs[IFACE_ATTR_RA].name, iface->name);
	}

	if ((c = tb[IFACE_ATTR_DHCPV4])) {
		if ((mode = parse_mode(blobmsg_get_string(c))) >= 0) {
			if (config.main_dhcpv4) {
				iface->dhcpv4 = mode;

				if (iface->dhcpv4 != MODE_DISABLED)
					iface->ignore = false;
			}
		} else
			syslog(LOG_ERR, "Invalid %s mode configured for interface %s",
					iface_attrs[IFACE_ATTR_DHCPV4].name, iface->name);
	}

	if ((c = tb[IFACE_ATTR_DHCPV6])) {
		if ((mode = parse_mode(blobmsg_get_string(c))) >= 0) {
			iface->dhcpv6 = mode;

			if (iface->dhcpv6 != MODE_DISABLED)
				iface->ignore = false;
		} else
			syslog(LOG_ERR, "Invalid %s mode configured for interface '%s'",
					iface_attrs[IFACE_ATTR_DHCPV6].name, iface->name);
	}

	if ((c = tb[IFACE_ATTR_NDP])) {
		if ((mode = parse_mode(blobmsg_get_string(c))) >= 0) {
			iface->ndp = mode;

			if (iface->ndp != MODE_DISABLED)
				iface->ignore = false;
		} else
			syslog(LOG_ERR, "Invalid %s mode configured for interface '%s'",
					iface_attrs[IFACE_ATTR_NDP].name, iface->name);
	}

	if ((c = tb[IFACE_ATTR_ROUTER])) {
		struct blob_attr *cur;
		unsigned rem;

		blobmsg_for_each_attr(cur, c, rem) {
			struct in_addr addr4;

			if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING || !blobmsg_check_attr(cur, false))
				continue;

			if (inet_pton(AF_INET, blobmsg_get_string(cur), &addr4) == 1) {
				iface->dhcpv4_router = realloc(iface->dhcpv4_router,
						(++iface->dhcpv4_router_cnt) * sizeof(*iface->dhcpv4_router));
				if (!iface->dhcpv4_router)
					goto err;

				iface->dhcpv4_router[iface->dhcpv4_router_cnt - 1] = addr4;
			} else
				syslog(LOG_ERR, "Invalid %s value configured for interface '%s'",
						iface_attrs[IFACE_ATTR_ROUTER].name, iface->name);
		}
	}

	if ((c = tb[IFACE_ATTR_DNS])) {
		struct blob_attr *cur;
		unsigned rem;

		iface->always_rewrite_dns = true;
		blobmsg_for_each_attr(cur, c, rem) {
			struct in_addr addr4;
			struct in6_addr addr6;

			if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING || !blobmsg_check_attr(cur, false))
				continue;

			if (inet_pton(AF_INET, blobmsg_get_string(cur), &addr4) == 1) {
				if (addr4.s_addr == INADDR_ANY) {
					syslog(LOG_ERR, "Invalid %s value configured for interface '%s'",
							iface_attrs[IFACE_ATTR_DNS].name, iface->name);

					continue;
				}

				iface->dhcpv4_dns = realloc(iface->dhcpv4_dns,
						(++iface->dhcpv4_dns_cnt) * sizeof(*iface->dhcpv4_dns));
				if (!iface->dhcpv4_dns)
					goto err;

				iface->dhcpv4_dns[iface->dhcpv4_dns_cnt - 1] = addr4;
			} else if (inet_pton(AF_INET6, blobmsg_get_string(cur), &addr6) == 1) {
				if (IN6_IS_ADDR_UNSPECIFIED(&addr6)) {
					syslog(LOG_ERR, "Invalid %s value configured for interface '%s'",
							iface_attrs[IFACE_ATTR_DNS].name, iface->name);

					continue;
				}

				iface->dns = realloc(iface->dns,
						(++iface->dns_cnt) * sizeof(*iface->dns));
				if (!iface->dns)
					goto err;

				iface->dns[iface->dns_cnt - 1] = addr6;
			} else
				syslog(LOG_ERR, "Invalid %s value configured for interface '%s'",
						iface_attrs[IFACE_ATTR_DNS].name, iface->name);
		}
	}

	if ((c = tb[IFACE_ATTR_DNS_SERVICE]))
		iface->dns_service = blobmsg_get_bool(c);

	if ((c = tb[IFACE_ATTR_DOMAIN])) {
		struct blob_attr *cur;
		unsigned rem;

		blobmsg_for_each_attr(cur, c, rem) {
			uint8_t buf[256];
			char *domain = blobmsg_get_string(cur);
			size_t domainlen = strlen(domain);
			int len;

			if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING || !blobmsg_check_attr(cur, false))
				continue;

			domain = blobmsg_get_string(cur);
			domainlen = strlen(domain);

			if (domainlen > 0 && domain[domainlen - 1] == '.')
				domain[domainlen - 1] = 0;

			len = dn_comp(domain, buf, sizeof(buf), NULL, NULL);
			if (len <= 0) {
				syslog(LOG_ERR, "Invalid %s value configured for interface '%s'",
						iface_attrs[IFACE_ATTR_DOMAIN].name, iface->name);

				continue;
			}

			iface->search = realloc(iface->search, iface->search_len + len);
			if (!iface->search)
				goto err;

			memcpy(&iface->search[iface->search_len], buf, len);
			iface->search_len += len;
		}
	}

	if ((c = tb[IFACE_ATTR_FILTER_CLASS])) {
		iface->filter_class = realloc(iface->filter_class, blobmsg_data_len(c) + 1);
		memcpy(iface->filter_class, blobmsg_get_string(c), blobmsg_data_len(c) + 1);
	}

	if ((c = tb[IFACE_ATTR_DHCPV4_FORCERECONF]))
		iface->dhcpv4_forcereconf = blobmsg_get_bool(c);

	if ((c = tb[IFACE_ATTR_DHCPV6_RAW])) {
		iface->dhcpv6_raw_len = blobmsg_data_len(c) / 2;
		iface->dhcpv6_raw = realloc(iface->dhcpv6_raw, iface->dhcpv6_raw_len);
		odhcpd_unhexlify(iface->dhcpv6_raw, iface->dhcpv6_raw_len, blobmsg_get_string(c));
	}

	if ((c = tb[IFACE_ATTR_DHCPV6_ASSIGNALL]))
		iface->dhcpv6_assignall = blobmsg_get_bool(c);

	if ((c = tb[IFACE_ATTR_DHCPV6_PD]))
		iface->dhcpv6_pd = blobmsg_get_bool(c);

	if ((c = tb[IFACE_ATTR_DHCPV6_PD_MIN_LEN])) {
		uint32_t pd_min_len = blobmsg_get_u32(c);
		if (pd_min_len != 0 && pd_min_len <= PD_MIN_LEN_MAX)
			iface->dhcpv6_pd_min_len = pd_min_len;
		else
			syslog(LOG_ERR, "Invalid %s value configured for interface '%s'",
					iface_attrs[IFACE_ATTR_DHCPV6_PD_MIN_LEN].name, iface->name);
	}

	if ((c = tb[IFACE_ATTR_DHCPV6_NA]))
		iface->dhcpv6_na = blobmsg_get_bool(c);

	if ((c = tb[IFACE_ATTR_DHCPV6_HOSTID_LEN])) {
		uint32_t hostid_len = blobmsg_get_u32(c);

		if (hostid_len >= HOSTID_LEN_MIN && hostid_len <= HOSTID_LEN_MAX)
			iface->dhcpv6_hostid_len = hostid_len;
		else
			syslog(LOG_ERR, "Invalid %s value configured for interface '%s'",
				iface_attrs[IFACE_ATTR_DHCPV6_HOSTID_LEN].name, iface->name);

	}

	if ((c = tb[IFACE_ATTR_RA_DEFAULT]))
		iface->default_router = blobmsg_get_u32(c);

	/* IFACE_ATTR_RA_MANAGEMENT aka ra_management is deprecated since 2019 */
	if (!tb[IFACE_ATTR_RA_FLAGS] && !tb[IFACE_ATTR_RA_SLAAC] &&
		(c = tb[IFACE_ATTR_RA_MANAGEMENT])) {
		switch (blobmsg_get_u32(c)) {
		case 0:
			iface->ra_flags = ND_RA_FLAG_OTHER;
			iface->ra_slaac = true;
			break;
		case 1:
			iface->ra_flags = ND_RA_FLAG_OTHER|ND_RA_FLAG_MANAGED;
			iface->ra_slaac = true;
			break;
		case 2:
			iface->ra_flags = ND_RA_FLAG_OTHER|ND_RA_FLAG_MANAGED;
			iface->ra_slaac = false;
			break;
		default:
			break;
		}
	}

	if ((c = tb[IFACE_ATTR_RA_FLAGS])) {
		iface->ra_flags = 0;

		if (parse_ra_flags(&iface->ra_flags, c) < 0)
			syslog(LOG_ERR, "Invalid %s value configured for interface '%s'",
					iface_attrs[IFACE_ATTR_RA_FLAGS].name, iface->name);
	}

	if ((c = tb[IFACE_ATTR_RA_REACHABLETIME])) {
		uint32_t ra_reachabletime = blobmsg_get_u32(c);

		if (ra_reachabletime <= 3600000)
			iface->ra_reachabletime = ra_reachabletime;
		else
			syslog(LOG_ERR, "Invalid %s value configured for interface '%s'",
					iface_attrs[IFACE_ATTR_RA_REACHABLETIME].name, iface->name);
	}

	if ((c = tb[IFACE_ATTR_RA_RETRANSTIME])) {
		uint32_t ra_retranstime = blobmsg_get_u32(c);

		if (ra_retranstime <= 60000)
			iface->ra_retranstime = ra_retranstime;
		else
			syslog(LOG_ERR, "Invalid %s value configured for interface '%s'",
					iface_attrs[IFACE_ATTR_RA_RETRANSTIME].name, iface->name);
	}

	if ((c = tb[IFACE_ATTR_RA_HOPLIMIT])) {
		uint32_t ra_hoplimit = blobmsg_get_u32(c);

		if (ra_hoplimit <= 255)
			iface->ra_hoplimit = ra_hoplimit;
		else
			syslog(LOG_ERR, "Invalid %s value configured for interface '%s'",
					iface_attrs[IFACE_ATTR_RA_HOPLIMIT].name, iface->name);
	}

	if ((c = tb[IFACE_ATTR_RA_MTU])) {
		uint32_t ra_mtu = blobmsg_get_u32(c);

		if (ra_mtu >= 1280 || ra_mtu <= 65535)
			iface->ra_mtu = ra_mtu;
		else
			syslog(LOG_ERR, "Invalid %s value configured for interface '%s'",
					iface_attrs[IFACE_ATTR_RA_MTU].name, iface->name);
	}

	if ((c = tb[IFACE_ATTR_RA_SLAAC]))
		iface->ra_slaac = blobmsg_get_bool(c);

	if ((c = tb[IFACE_ATTR_RA_OFFLINK]))
		iface->ra_not_onlink = blobmsg_get_bool(c);

	if ((c = tb[IFACE_ATTR_RA_ADVROUTER]))
		iface->ra_advrouter = blobmsg_get_bool(c);

	if ((c = tb[IFACE_ATTR_RA_MININTERVAL]))
		iface->ra_mininterval =  blobmsg_get_u32(c);

	if ((c = tb[IFACE_ATTR_RA_MAXINTERVAL]))
		iface->ra_maxinterval = blobmsg_get_u32(c);

	if ((c = tb[IFACE_ATTR_RA_LIFETIME]))
		iface->ra_lifetime = blobmsg_get_u32(c);

	if ((c = tb[IFACE_ATTR_RA_USELEASETIME]))
		iface->ra_useleasetime = blobmsg_get_bool(c);

	if ((c = tb[IFACE_ATTR_RA_DNS]))
		iface->ra_dns = blobmsg_get_bool(c);

	if ((c = tb[IFACE_ATTR_DNR])) {
		struct blob_attr *cur;
		unsigned rem;

		blobmsg_for_each_attr(cur, c, rem) {
			if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING || !blobmsg_check_attr(cur, false))
				continue;

			if (parse_dnr_str(blobmsg_get_string(cur), iface))
				syslog(LOG_ERR, "Invalid %s value configured for interface '%s'",
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
			syslog(LOG_WARNING, "Invalid PREF64 prefix size (%d), "
			       "ignoring ra_pref64 option!", iface->pref64_length);
			iface->pref64_length = 0;
		}
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
			syslog(LOG_ERR, "Invalid %s mode configured for interface '%s'",
					iface_attrs[IFACE_ATTR_RA_PREFERENCE].name, iface->name);
	}

	if ((c = tb[IFACE_ATTR_PD_MANAGER]))
		strncpy(iface->dhcpv6_pd_manager, blobmsg_get_string(c),
				sizeof(iface->dhcpv6_pd_manager) - 1);

	if ((c = tb[IFACE_ATTR_PD_CER]) &&
			inet_pton(AF_INET6, blobmsg_get_string(c), &iface->dhcpv6_pd_cer) < 1)
		syslog(LOG_ERR, "Invalid %s value configured for interface '%s'",
				iface_attrs[IFACE_ATTR_PD_CER].name, iface->name);

	if ((c = tb[IFACE_ATTR_NDPROXY_ROUTING]))
		iface->learn_routes = blobmsg_get_bool(c);

	if ((c = tb[IFACE_ATTR_NDPROXY_SLAVE]))
		iface->external = blobmsg_get_bool(c);

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
			struct in_addr addr4;
			struct in6_addr addr6;

			if (inet_pton(AF_INET, str, &addr4) == 1) {
				if (addr4.s_addr == INADDR_ANY)
					goto err;

				iface->dhcpv4_ntp = realloc(iface->dhcpv4_ntp,
						(++iface->dhcpv4_ntp_cnt) * sizeof(*iface->dhcpv4_ntp));
				if (!iface->dhcpv4_ntp)
					goto err;

				iface->dhcpv4_ntp[iface->dhcpv4_ntp_cnt - 1] = addr4;
			} else if (inet_pton(AF_INET6, str, &addr6) == 1) {
				if (IN6_IS_ADDR_UNSPECIFIED(&addr6))
					goto err;

				iface->dhcpv6_sntp = realloc(iface->dhcpv6_sntp,
						(++iface->dhcpv6_sntp_cnt) * sizeof(*iface->dhcpv6_sntp));
				if (!iface->dhcpv6_sntp)
					goto err;

				iface->dhcpv6_sntp[iface->dhcpv6_sntp_cnt - 1] = addr6;

				if (!parse_ntp_options(&iface->dhcpv6_ntp_len, addr6, &iface->dhcpv6_ntp))
					iface->dhcpv6_ntp_cnt++;
			} else {
				if (!parse_ntp_fqdn(&iface->dhcpv6_ntp_len, str, &iface->dhcpv6_ntp))
					iface->dhcpv6_ntp_cnt++;
			}
		}
	}

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

static void lease_delete_assignments(struct lease *l, bool v6)
{
	struct dhcp_assignment *a, *tmp;
	unsigned int flag = v6 ? OAF_DHCPV6 : OAF_DHCPV4;

	list_for_each_entry_safe(a, tmp, &l->assignments, lease_list) {
		if (a->flags & flag)
			free_assignment(a);
	}
}

static void lease_update_assignments(struct lease *l)
{
	struct dhcp_assignment *a;

	list_for_each_entry(a, &l->assignments, lease_list) {
		if (a->hostname)
			free(a->hostname);
		a->hostname = NULL;

		if (l->hostname)
			a->hostname = strdup(l->hostname);

		a->leasetime = l->leasetime;
	}
}

static int lease_cmp(const void *k1, const void *k2, _unused void *ptr)
{
	const struct lease *l1 = k1, *l2 = k2;
	int cmp = 0;

	if (l1->duid_len != l2->duid_len)
		return l1->duid_len - l2->duid_len;

	if (l1->duid_len && l2->duid_len)
		cmp = memcmp(l1->duid, l2->duid, l1->duid_len);

	if (cmp)
		return cmp;

	return memcmp(l1->mac.ether_addr_octet, l2->mac.ether_addr_octet,
				sizeof(l1->mac.ether_addr_octet));
}

static void lease_change_config(struct lease *l_old, struct lease *l_new)
{
	bool update = false;

	if ((!!l_new->hostname != !!l_old->hostname) ||
		(l_new->hostname && strcmp(l_new->hostname, l_old->hostname))) {
		free(l_old->hostname);
		l_old->hostname = NULL;

		if (l_new->hostname)
			l_old->hostname = strdup(l_new->hostname);

		update = true;
	}

	if (l_old->leasetime != l_new->leasetime) {
		l_old->leasetime = l_new->leasetime;
		update = true;
	}

	if (l_old->ipaddr != l_new->ipaddr) {
		l_old->ipaddr = l_new->ipaddr;
		lease_delete_assignments(l_old, false);
	}

	if (l_old->hostid != l_new->hostid) {
		l_old->hostid = l_new->hostid;
		lease_delete_assignments(l_old, true);
	}

	if (update)
		lease_update_assignments(l_old);

	free_lease(l_new);
}

static void lease_delete(struct lease *l)
{
	struct dhcp_assignment *a, *tmp;

	list_for_each_entry_safe(a, tmp, &l->assignments, lease_list)
		free_assignment(a);

	free_lease(l);
}

static void lease_update(_unused struct vlist_tree *tree, struct vlist_node *node_new,
			 struct vlist_node *node_old)
{
	struct lease *lease_new = container_of(node_new, struct lease, node);
	struct lease *lease_old = container_of(node_old, struct lease, node);

	if (node_old && node_new)
		lease_change_config(lease_old, lease_new);
	else if (node_old)
		lease_delete(lease_old);
}

struct lease *config_find_lease_by_duid(const uint8_t *duid, const uint16_t len)
{
	struct lease *l;

	vlist_for_each_element(&leases, l, node) {
		if (l->duid_len == len && !memcmp(l->duid, duid, len))
			return l;
	}

	return NULL;
}

struct lease *config_find_lease_by_mac(const uint8_t *mac)
{
	struct lease *l;

	vlist_for_each_element(&leases, l, node) {
		if (!memcmp(l->mac.ether_addr_octet, mac,
				sizeof(l->mac.ether_addr_octet)))
			return l;
	}

	return NULL;
}

struct lease *config_find_lease_by_hostid(const uint64_t hostid)
{
	struct lease *l;

	vlist_for_each_element(&leases, l, node) {
		if (l->hostid == hostid)
			return l;
	}

	return NULL;
}

struct lease *config_find_lease_by_ipaddr(const uint32_t ipaddr)
{
	struct lease *l;

	vlist_for_each_element(&leases, l, node) {
		if (l->ipaddr == ipaddr)
			return l;
	}

	return NULL;
}

void reload_services(struct interface *iface)
{
	if (iface->ifflags & IFF_RUNNING) {
		syslog(LOG_DEBUG, "Enabling services with %s running", iface->ifname);
		router_setup_interface(iface, iface->ra != MODE_DISABLED);
		dhcpv6_setup_interface(iface, iface->dhcpv6 != MODE_DISABLED);
		ndp_setup_interface(iface, iface->ndp != MODE_DISABLED);
#ifdef DHCPV4_SUPPORT
		dhcpv4_setup_interface(iface, iface->dhcpv4 != MODE_DISABLED);
#endif
	} else {
		syslog(LOG_DEBUG, "Disabling services with %s not running", iface->ifname);
		router_setup_interface(iface, false);
		dhcpv6_setup_interface(iface, false);
		ndp_setup_interface(iface, false);
#ifdef DHCPV4_SUPPORT
		dhcpv4_setup_interface(iface, false);
#endif
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

	if (!uci)
		return;

	vlist_update(&leases);
	avl_for_each_element(&interfaces, i, avl)
		clean_interface(i);

	struct uci_package *dhcp = NULL;
	if (!uci_load(uci, "dhcp", &dhcp)) {
		struct uci_element *e;

		/* 1. Global settings */
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

		/* 3. Static leases */
		uci_foreach_element(&dhcp->sections, e) {
			struct uci_section* s = uci_to_section(e);
			if (!strcmp(s->type, "host"))
				set_lease_from_uci(s);
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

	if (config.dhcp_statefile) {
		char *path = strdup(config.dhcp_statefile);

		mkdir_p(dirname(path), 0755);
		free(path);
	}

	vlist_flush(&leases);

#ifdef WITH_UBUS
	ubus_apply_network();
#endif

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
#ifdef WITH_UBUS
		if (!ubus_has_prefix(i->name, i->ifname))
			hybrid_mode = MODE_RELAY;
#endif

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

	uci_unload(uci, dhcp);
	uci_free_context(uci);
}

static void handle_signal(int signal)
{
	char b[1] = {0};

	if (signal == SIGHUP) {
		if (write(reload_pipe[1], b, sizeof(b)) < 0) {}
	} else
		uloop_end();
}

static void reload_cb(struct uloop_fd *u, _unused unsigned int events)
{
	char b[512];
	if (read(u->fd, b, sizeof(b)) < 0) {}

	odhcpd_reload();
}

static struct uloop_fd reload_fd = { .fd = -1, .cb = reload_cb };

void odhcpd_run(void)
{
	if (pipe2(reload_pipe, O_NONBLOCK | O_CLOEXEC) < 0) {}

	reload_fd.fd = reload_pipe[0];
	uloop_fd_add(&reload_fd, ULOOP_READ);

	signal(SIGTERM, handle_signal);
	signal(SIGINT, handle_signal);
	signal(SIGHUP, handle_signal);

#ifdef WITH_UBUS
	while (ubus_init())
		sleep(1);
#endif

	odhcpd_reload();
	uloop_run();
}
