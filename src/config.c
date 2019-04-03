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

static struct blob_buf b;
static int reload_pipe[2];

static int lease_cmp(const void *k1, const void *k2, void *ptr);
static void lease_update(struct vlist_tree *tree, struct vlist_node *node_new,
			 struct vlist_node *node_old);

struct vlist_tree leases = VLIST_TREE_INIT(leases, lease_cmp, lease_update, true, false);
AVL_TREE(interfaces, avl_strcmp, false, NULL);
struct config config = {.legacy = false, .main_dhcpv4 = false,
			.dhcp_cb = NULL, .dhcp_statefile = NULL,
			.log_level = LOG_INFO};

enum {
	IFACE_ATTR_INTERFACE,
	IFACE_ATTR_IFNAME,
	IFACE_ATTR_NETWORKID,
	IFACE_ATTR_DYNAMICDHCP,
	IFACE_ATTR_IGNORE,
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
	IFACE_ATTR_DOMAIN,
	IFACE_ATTR_FILTER_CLASS,
	IFACE_ATTR_DHCPV4_FORCERECONF,
	IFACE_ATTR_DHCPV6_RAW,
	IFACE_ATTR_DHCPV6_ASSIGNALL,
	IFACE_ATTR_DHCPV6_PD,
	IFACE_ATTR_DHCPV6_NA,
	IFACE_ATTR_RA_DEFAULT,
	IFACE_ATTR_RA_MANAGEMENT,
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
	IFACE_ATTR_PD_MANAGER,
	IFACE_ATTR_PD_CER,
	IFACE_ATTR_NDPROXY_ROUTING,
	IFACE_ATTR_NDPROXY_SLAVE,
	IFACE_ATTR_PREFIX_FILTER,
	IFACE_ATTR_MAX
};

static const struct blobmsg_policy iface_attrs[IFACE_ATTR_MAX] = {
	[IFACE_ATTR_INTERFACE] = { .name = "interface", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_IFNAME] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_NETWORKID] = { .name = "networkid", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_DYNAMICDHCP] = { .name = "dynamicdhcp", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_IGNORE] = { .name = "ignore", .type = BLOBMSG_TYPE_BOOL },
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
	[IFACE_ATTR_DOMAIN] = { .name = "domain", .type = BLOBMSG_TYPE_ARRAY },
	[IFACE_ATTR_FILTER_CLASS] = { .name = "filter_class", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_DHCPV4_FORCERECONF] = { .name = "dhcpv4_forcereconf", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_DHCPV6_RAW] = { .name = "dhcpv6_raw", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_DHCPV6_ASSIGNALL] = { .name ="dhcpv6_assignall", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_DHCPV6_PD] = { .name = "dhcpv6_pd", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_DHCPV6_NA] = { .name = "dhcpv6_na", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_PD_MANAGER] = { .name = "pd_manager", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_PD_CER] = { .name = "pd_cer", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_RA_DEFAULT] = { .name = "ra_default", .type = BLOBMSG_TYPE_INT32 },
	[IFACE_ATTR_RA_MANAGEMENT] = { .name = "ra_management", .type = BLOBMSG_TYPE_INT32 },
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
	[IFACE_ATTR_NDPROXY_ROUTING] = { .name = "ndproxy_routing", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_NDPROXY_SLAVE] = { .name = "ndproxy_slave", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_PREFIX_FILTER] = { .name = "prefix_filter", .type = BLOBMSG_TYPE_STRING },
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

enum {
	LEASE_ATTR_IP,
	LEASE_ATTR_MAC,
	LEASE_ATTR_DUID,
	LEASE_ATTR_HOSTID,
	LEASE_ATTR_LEASETIME,
	LEASE_ATTR_NAME,
	LEASE_ATTR_MAX
};

static const struct blobmsg_policy lease_attrs[LEASE_ATTR_MAX] = {
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
	ODHCPD_ATTR_MAX
};

static const struct blobmsg_policy odhcpd_attrs[ODHCPD_ATTR_MAX] = {
	[ODHCPD_ATTR_LEGACY] = { .name = "legacy", .type = BLOBMSG_TYPE_BOOL },
	[ODHCPD_ATTR_MAINDHCP] = { .name = "maindhcp", .type = BLOBMSG_TYPE_BOOL },
	[ODHCPD_ATTR_LEASEFILE] = { .name = "leasefile", .type = BLOBMSG_TYPE_STRING },
	[ODHCPD_ATTR_LEASETRIGGER] = { .name = "leasetrigger", .type = BLOBMSG_TYPE_STRING },
	[ODHCPD_ATTR_LOGLEVEL] = { .name = "loglevel", .type = BLOBMSG_TYPE_INT32 },
};

const struct uci_blob_param_list odhcpd_attr_list = {
	.n_params = ODHCPD_ATTR_MAX,
	.params = odhcpd_attrs,
};

static int mkdir_p(char *dir, mode_t mask)
{
	char *l = strrchr(dir, '/');
	int ret;

	if (!l)
		return 0;

	*l = '\0';

	if (mkdir_p(dir, mask))
		return -1;

	*l = '/';

	ret = mkdir(dir, mask);
	if (ret && errno == EEXIST)
		return 0;

	if (ret)
		syslog(LOG_ERR, "mkdir(%s, %d) failed: %m\n", dir, mask);

	return ret;
}

static void set_interface_defaults(struct interface *iface)
{
	iface->learn_routes = 1;
	iface->dhcpv4_leasetime = 43200;
	iface->dhcpv6_assignall = true;
	iface->dhcpv6_pd = true;
	iface->dhcpv6_na = true;
	iface->ra_managed = RA_MANAGED_MFLAG;
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

	clean_interface(iface);
	free(iface->addr4);
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

static int set_lease(struct uci_section *s)
{
	struct blob_attr *tb[LEASE_ATTR_MAX], *c;
	struct lease *l;
	size_t duidlen = 0;
	uint8_t *duid;

	blob_buf_init(&b, 0);
	uci_to_blob(&b, s, &lease_attr_list);
	blobmsg_parse(lease_attrs, LEASE_ATTR_MAX, tb, blob_data(b.head), blob_len(b.head));

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
		l->hostid = strtoul(blobmsg_get_string(c), NULL, 16);
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

int config_parse_interface(void *data, size_t len, const char *name, bool overwrite)
{
	struct interface *iface;
	struct blob_attr *tb[IFACE_ATTR_MAX], *c;
	bool get_addrs = false;

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
		iface->dhcpv4_event.uloop.fd = -1;
		set_interface_defaults(iface);

		avl_insert(&interfaces, &iface->avl);
		get_addrs = overwrite = true;
	}

	const char *ifname = NULL;
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
	}

	if (get_addrs) {
		ssize_t len = netlink_get_interface_addrs(iface->ifindex,
						true, &iface->addr6);

		if (len > 0)
			iface->addr6_len = len;

		len = netlink_get_interface_addrs(iface->ifindex,
						false, &iface->addr4);
		if (len > 0)
			iface->addr4_len = len;
	}

	iface->inuse = true;

	if ((c = tb[IFACE_ATTR_DYNAMICDHCP]))
		iface->no_dynamic_dhcp = !blobmsg_get_bool(c);

	if (overwrite && (c = tb[IFACE_ATTR_IGNORE]))
		iface->ignore = blobmsg_get_bool(c);

	if ((c = tb[IFACE_ATTR_LEASETIME])) {
		double time = parse_leasetime(c);
		if (time < 0)
			goto err;

		iface->dhcpv4_leasetime = time;
	}

	if ((c = tb[IFACE_ATTR_START])) {
		iface->dhcpv4_start.s_addr = htonl(blobmsg_get_u32(c));

		if (config.main_dhcpv4 && config.legacy)
			iface->dhcpv4 = MODE_SERVER;
	}

	if ((c = tb[IFACE_ATTR_LIMIT]))
		iface->dhcpv4_end.s_addr = htonl(
				ntohl(iface->dhcpv4_start.s_addr) + blobmsg_get_u32(c));

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

	int mode;
	if ((c = tb[IFACE_ATTR_RA])) {
		if ((mode = parse_mode(blobmsg_get_string(c))) >= 0)
			iface->ra = mode;
		else
			goto err;
	}

	if ((c = tb[IFACE_ATTR_DHCPV4])) {
		if ((mode = parse_mode(blobmsg_get_string(c))) >= 0) {
			if (config.main_dhcpv4)
				iface->dhcpv4 = mode;
		}
		else
			goto err;
	}

	if ((c = tb[IFACE_ATTR_DHCPV6])) {
		if ((mode = parse_mode(blobmsg_get_string(c))) >= 0)
			iface->dhcpv6 = mode;
		else
			goto err;
	}

	if ((c = tb[IFACE_ATTR_NDP])) {
		if ((mode = parse_mode(blobmsg_get_string(c))) >= 0)
			iface->ndp = mode;
		else
			goto err;
	}

	if ((c = tb[IFACE_ATTR_ROUTER])) {
		struct blob_attr *cur;
		unsigned rem;

		blobmsg_for_each_attr(cur, c, rem) {
			if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING || !blobmsg_check_attr(cur, false))
				continue;

			struct in_addr addr4;
			if (inet_pton(AF_INET, blobmsg_get_string(cur), &addr4) == 1) {
				iface->dhcpv4_router = realloc(iface->dhcpv4_router,
						(++iface->dhcpv4_router_cnt) * sizeof(*iface->dhcpv4_router));
				if (!iface->dhcpv4_router)
					goto err;

				iface->dhcpv4_router[iface->dhcpv4_router_cnt - 1] = addr4;
			} else
				goto err;
		}
	}

	if ((c = tb[IFACE_ATTR_DNS])) {
		struct blob_attr *cur;
		unsigned rem;

		iface->always_rewrite_dns = true;
		blobmsg_for_each_attr(cur, c, rem) {
			if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING || !blobmsg_check_attr(cur, false))
				continue;

			struct in_addr addr4;
			struct in6_addr addr6;
			if (inet_pton(AF_INET, blobmsg_get_string(cur), &addr4) == 1) {
				if (addr4.s_addr == INADDR_ANY)
					goto err;

				iface->dhcpv4_dns = realloc(iface->dhcpv4_dns,
						(++iface->dhcpv4_dns_cnt) * sizeof(*iface->dhcpv4_dns));
				if (!iface->dhcpv4_dns)
					goto err;

				iface->dhcpv4_dns[iface->dhcpv4_dns_cnt - 1] = addr4;
			} else if (inet_pton(AF_INET6, blobmsg_get_string(cur), &addr6) == 1) {
				if (IN6_IS_ADDR_UNSPECIFIED(&addr6))
					goto err;

				iface->dns = realloc(iface->dns,
						(++iface->dns_cnt) * sizeof(*iface->dns));
				if (!iface->dns)
					goto err;

				iface->dns[iface->dns_cnt - 1] = addr6;
			} else
				goto err;
		}
	}

	if ((c = tb[IFACE_ATTR_DOMAIN])) {
		struct blob_attr *cur;
		unsigned rem;

		blobmsg_for_each_attr(cur, c, rem) {
			if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING || !blobmsg_check_attr(cur, false))
				continue;

			uint8_t buf[256];
			char *domain = blobmsg_get_string(cur);
			size_t domainlen = strlen(domain);
			if (domainlen > 0 && domain[domainlen - 1] == '.')
				domain[domainlen - 1] = 0;

			int len = dn_comp(domain, buf, sizeof(buf), NULL, NULL);
			if (len <= 0)
				goto err;

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

	if ((c = tb[IFACE_ATTR_DHCPV6_NA]))
		iface->dhcpv6_na = blobmsg_get_bool(c);

	if ((c = tb[IFACE_ATTR_RA_DEFAULT]))
		iface->default_router = blobmsg_get_u32(c);

	if ((c = tb[IFACE_ATTR_RA_MANAGEMENT]))
		iface->ra_managed = blobmsg_get_u32(c);

	if ((c = tb[IFACE_ATTR_RA_REACHABLETIME])) {
		uint32_t ra_reachabletime = blobmsg_get_u32(c);
		if (ra_reachabletime > 3600000)
			goto err;

		iface->ra_reachabletime = ra_reachabletime;
	}

	if ((c = tb[IFACE_ATTR_RA_RETRANSTIME])) {
		uint32_t ra_retranstime = blobmsg_get_u32(c);
		if (ra_retranstime > 60000)
			goto err;

		iface->ra_retranstime = ra_retranstime;
	}

	if ((c = tb[IFACE_ATTR_RA_HOPLIMIT])) {
		uint32_t ra_hoplimit = blobmsg_get_u32(c);
		if (ra_hoplimit > 255)
			goto err;

		iface->ra_hoplimit = ra_hoplimit;
	}

	if ((c = tb[IFACE_ATTR_RA_MTU])) {
		uint32_t ra_mtu = blobmsg_get_u32(c);
		if (ra_mtu < 1280 || ra_mtu > 65535)
			goto err;

		iface->ra_mtu = ra_mtu;
	}

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

	if ((c = tb[IFACE_ATTR_RA_PREFERENCE])) {
		const char *prio = blobmsg_get_string(c);

		if (!strcmp(prio, "high"))
			iface->route_preference = 1;
		else if (!strcmp(prio, "low"))
			iface->route_preference = -1;
		else if (!strcmp(prio, "medium") || !strcmp(prio, "default"))
			iface->route_preference = 0;
		else
			goto err;
	}

	if ((c = tb[IFACE_ATTR_PD_MANAGER]))
		strncpy(iface->dhcpv6_pd_manager, blobmsg_get_string(c),
				sizeof(iface->dhcpv6_pd_manager) - 1);

	if ((c = tb[IFACE_ATTR_PD_CER]) &&
			inet_pton(AF_INET6, blobmsg_get_string(c), &iface->dhcpv6_pd_cer) < 1)
		goto err;

	if ((c = tb[IFACE_ATTR_NDPROXY_ROUTING]))
		iface->learn_routes = blobmsg_get_bool(c);

	if ((c = tb[IFACE_ATTR_NDPROXY_SLAVE]))
		iface->external = blobmsg_get_bool(c);

	if ((c = tb[IFACE_ATTR_PREFIX_FILTER])) {
		const char *str = blobmsg_get_string(c);
		char *astr = malloc(strlen(str) + 1);
		char *delim;
		int l;

		if (!astr || !strcpy(astr, str) ||
				(delim = strchr(astr, '/')) == NULL || (*(delim++) = 0) ||
				sscanf(delim, "%i", &l) == 0 || l > 128 ||
				inet_pton(AF_INET6, astr, &iface->pio_filter_addr) == 0)
			iface->pio_filter_length = 0;
		else
			iface->pio_filter_length = l;

		if (astr)
			free(astr);
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
	struct dhcp_assignment *a;

	list_for_each_entry(a, &l->assignments, lease_list)
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

struct lease *config_find_lease_by_hostid(const uint32_t hostid)
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
		uci_foreach_element(&dhcp->sections, e) {
			struct uci_section *s = uci_to_section(e);
			if (!strcmp(s->type, "host"))
				set_lease(s);
			else if (!strcmp(s->type, "odhcpd"))
				set_config(s);
		}

		uci_foreach_element(&dhcp->sections, e) {
			struct uci_section *s = uci_to_section(e);
			if (!strcmp(s->type, "dhcp"))
				set_interface(s);
		}
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
		if (i->inuse) {
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

			router_setup_interface(i, !i->ignore || i->ra != MODE_DISABLED);
			dhcpv6_setup_interface(i, !i->ignore || i->dhcpv6 != MODE_DISABLED);
			ndp_setup_interface(i, !i->ignore || i->ndp != MODE_DISABLED);
#ifdef DHCPV4_SUPPORT
			dhcpv4_setup_interface(i, !i->ignore || i->dhcpv4 != MODE_DISABLED);
#endif
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

static struct uloop_fd reload_fd = { .cb = reload_cb };

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
