#include <fcntl.h>
#include <resolv.h>
#include <signal.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <uci.h>
#include <uci_blob.h>

#include "odhcpd.h"

static struct blob_buf b;
static int reload_pipe[2];
struct list_head leases = LIST_HEAD_INIT(leases);
struct list_head interfaces = LIST_HEAD_INIT(interfaces);
struct config config = {false, NULL, NULL};

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
	IFACE_ATTR_DNS,
	IFACE_ATTR_DOMAIN,
	IFACE_ATTR_RA_DEFAULT,
	IFACE_ATTR_RA_MANAGEMENT,
	IFACE_ATTR_RA_OFFLINK,
	IFACE_ATTR_RA_PREFERENCE,
	IFACE_ATTR_NDPROXY_ROUTING,
	IFACE_ATTR_NDPROXY_SLAVE,
	IFACE_ATTR_NDPROXY_STATIC,
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
	[IFACE_ATTR_DNS] = { .name = "dns", .type = BLOBMSG_TYPE_ARRAY },
	[IFACE_ATTR_DOMAIN] = { .name = "domain", .type = BLOBMSG_TYPE_ARRAY },
	[IFACE_ATTR_RA_DEFAULT] = { .name = "ra_default", .type = BLOBMSG_TYPE_INT32 },
	[IFACE_ATTR_RA_MANAGEMENT] = { .name = "ra_management", .type = BLOBMSG_TYPE_INT32 },
	[IFACE_ATTR_RA_OFFLINK] = { .name = "ra_offlink", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_RA_PREFERENCE] = { .name = "ra_preference", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_NDPROXY_ROUTING] = { .name = "ndproxy_routing", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_NDPROXY_SLAVE] = { .name = "ndproxy_slave", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_NDPROXY_STATIC] = { .name = "ndproxy_static", .type = BLOBMSG_TYPE_ARRAY },
};

static const struct uci_blob_param_info iface_attr_info[IFACE_ATTR_MAX] = {
	[IFACE_ATTR_UPSTREAM] = { .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_DNS] = { .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_DOMAIN] = { .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_NDPROXY_STATIC] = { .type = BLOBMSG_TYPE_STRING },
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
	LEASE_ATTR_NAME,
	LEASE_ATTR_MAX
};


static const struct blobmsg_policy lease_attrs[LEASE_ATTR_MAX] = {
	[LEASE_ATTR_IP] = { .name = "ip", .type = BLOBMSG_TYPE_STRING },
	[LEASE_ATTR_MAC] = { .name = "mac", .type = BLOBMSG_TYPE_STRING },
	[LEASE_ATTR_DUID] = { .name = "duid", .type = BLOBMSG_TYPE_STRING },
	[LEASE_ATTR_HOSTID] = { .name = "hostid", .type = BLOBMSG_TYPE_STRING },
	[LEASE_ATTR_NAME] = { .name = "name", .type = BLOBMSG_TYPE_STRING },
};


const struct uci_blob_param_list lease_attr_list = {
	.n_params = LEASE_ATTR_MAX,
	.params = lease_attrs,
};


enum {
	ODHCPD_ATTR_MAINDHCP,
	ODHCPD_ATTR_LEASEFILE,
	ODHCPD_ATTR_LEASETRIGGER,
	ODHCPD_ATTR_MAX
};


static const struct blobmsg_policy odhcpd_attrs[LEASE_ATTR_MAX] = {
	[ODHCPD_ATTR_MAINDHCP] = { .name = "maindhcp", .type = BLOBMSG_TYPE_BOOL },
	[ODHCPD_ATTR_LEASEFILE] = { .name = "leasefile", .type = BLOBMSG_TYPE_STRING },
	[ODHCPD_ATTR_LEASETRIGGER] = { .name = "leasetrigger", .type = BLOBMSG_TYPE_STRING },
};


const struct uci_blob_param_list odhcpd_attr_list = {
	.n_params = ODHCPD_ATTR_MAX,
	.params = odhcpd_attrs,
};


static struct interface* get_interface(const char *name)
{
	struct interface *c;
	list_for_each_entry(c, &interfaces, head)
		if (!strcmp(c->name, name))
			return c;
	return NULL;
}


static void clean_interface(struct interface *iface)
{
	free(iface->dns);
	free(iface->search);
	free(iface->upstream);
	free(iface->static_ndp);
	free(iface->dhcpv4_dns);
	memset(&iface->ra, 0, sizeof(*iface) - offsetof(struct interface, ra));
}


static void close_interface(struct interface *iface)
{
	if (iface->head.next)
		list_del(&iface->head);

	setup_router_interface(iface, false);
	setup_dhcpv6_interface(iface, false);
	setup_ndp_interface(iface, false);
	setup_dhcpv4_interface(iface, false);

	clean_interface(iface);
	free(iface);
}


static int parse_mode(const char *mode)
{
	if (!strcmp(mode, "disabled")) {
		return RELAYD_DISABLED;
	} else if (!strcmp(mode, "server")) {
		return RELAYD_SERVER;
	} else if (!strcmp(mode, "relay")) {
		return RELAYD_RELAY;
	} else if (!strcmp(mode, "hybrid")) {
		return RELAYD_HYBRID;
	} else {
		return -1;
	}
}


static void set_config(struct uci_section *s)
{
	struct blob_attr *tb[ODHCPD_ATTR_MAX], *c;

	blob_buf_init(&b, 0);
	uci_to_blob(&b, s, &odhcpd_attr_list);
	blobmsg_parse(odhcpd_attrs, ODHCPD_ATTR_MAX, tb, blob_data(b.head), blob_len(b.head));

	if ((c = tb[ODHCPD_ATTR_MAINDHCP]))
		config.legacy = blobmsg_get_bool(c);

	if ((c = tb[ODHCPD_ATTR_LEASEFILE])) {
		free(config.dhcp_statefile);
		config.dhcp_statefile = strdup(blobmsg_get_string(c));
	}

	if ((c = tb[ODHCPD_ATTR_LEASETRIGGER])) {
		free(config.dhcp_cb);
		config.dhcp_cb = strdup(blobmsg_get_string(c));
	}
}


static int set_lease(struct uci_section *s)
{
	struct blob_attr *tb[LEASE_ATTR_MAX], *c;

	blob_buf_init(&b, 0);
	uci_to_blob(&b, s, &lease_attr_list);
	blobmsg_parse(lease_attrs, LEASE_ATTR_MAX, tb, blob_data(b.head), blob_len(b.head));

	size_t hostlen = 1;
	if ((c = tb[LEASE_ATTR_NAME]))
		hostlen = blobmsg_data_len(c);

	struct lease *lease = calloc(1, sizeof(*lease) + hostlen);
	if (!lease)
		goto err;

	if (hostlen > 1)
		memcpy(lease->hostname, blobmsg_get_string(c), hostlen);

	if ((c = tb[LEASE_ATTR_IP]))
		if (inet_pton(AF_INET, blobmsg_get_string(c), &lease->ipaddr) < 0)
			goto err;

	if ((c = tb[LEASE_ATTR_MAC]))
		if (!ether_aton_r(blobmsg_get_string(c), &lease->mac))
			goto err;

	if ((c = tb[LEASE_ATTR_DUID])) {
		size_t duidlen = (blobmsg_data_len(c) - 1) / 2;
		lease->duid = malloc(duidlen);
		if (!lease->duid)
			goto err;

		ssize_t len = odhcpd_unhexlify(lease->duid,
				duidlen, blobmsg_get_string(c));

		if (len < 0)
			goto err;

		lease->duid_len = len;
	}

	if ((c = tb[LEASE_ATTR_HOSTID]))
		if (odhcpd_unhexlify((uint8_t*)&lease->hostid, sizeof(lease->hostid),
				blobmsg_get_string(c)) < 0)
			goto err;

	list_add(&lease->head, &leases);
	return 0;

err:
	if (lease) {
		free(lease->duid);
		free(lease);
	}
	return -1;
}


int config_parse_interface(void *data, size_t len, const char *name, bool overwrite)
{
	struct blob_attr *tb[IFACE_ATTR_MAX], *c;
	blobmsg_parse(iface_attrs, IFACE_ATTR_MAX, tb, data, len);

	if (tb[IFACE_ATTR_INTERFACE])
		name = blobmsg_get_string(tb[IFACE_ATTR_INTERFACE]);

	if (!name)
		return -1;

	struct interface *iface = get_interface(name);
	if (!iface) {
		iface = calloc(1, sizeof(*iface));
		if (!iface)
			return -1;

		strncpy(iface->name, name, sizeof(iface->name) - 1);
		list_add(&iface->head, &interfaces);
	}

	const char *ifname = NULL;
#ifdef WITH_UBUS
	if (overwrite || !iface->ifname[0])
		ifname = ubus_get_ifname(name);
#endif

	if (overwrite) {
		if ((c = tb[IFACE_ATTR_IFNAME]))
			ifname = blobmsg_get_string(c);
		else if ((c = tb[IFACE_ATTR_NETWORKID]))
			ifname = blobmsg_get_string(c);
	}

	if (!iface->ifname[0] && !ifname)
		return -1;

	if (ifname)
		strncpy(iface->ifname, ifname, sizeof(iface->ifname) - 1);

	if ((iface->ifindex = if_nametoindex(iface->ifname)) <= 0)
		return -1;

	iface->inuse = true;

	if ((c = tb[IFACE_ATTR_DYNAMICDHCP]))
		iface->no_dynamic_dhcp = !blobmsg_get_bool(c);

	if (overwrite && (c = tb[IFACE_ATTR_IGNORE]))
		iface->ignore = blobmsg_get_bool(c);

	if ((c = tb[IFACE_ATTR_LEASETIME])) {
		char *val = blobmsg_get_string(c), *endptr;
		double time = strtod(val, &endptr);
		if (time && endptr[0]) {
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

		if (time >= 60)
			iface->dhcpv4_leasetime = time;
	}

	if ((c = tb[IFACE_ATTR_START])) {
		iface->dhcpv4_start.s_addr = htonl(blobmsg_get_u32(c));

		if (config.legacy)
			iface->dhcpv4 = RELAYD_SERVER;
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
			if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING || !blobmsg_check_attr(cur, NULL))
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
		if ((mode = parse_mode(blobmsg_get_string(c))) >= 0)
			iface->dhcpv4 = mode;
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

	if ((c = tb[IFACE_ATTR_DNS])) {
		struct blob_attr *cur;
		unsigned rem;

		iface->always_rewrite_dns = true;
		blobmsg_for_each_attr(cur, c, rem) {
			if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING || !blobmsg_check_attr(cur, NULL))
				continue;

			struct in_addr addr4;
			struct in6_addr addr6;
			if (inet_pton(AF_INET, blobmsg_get_string(cur), &addr4) == 1) {
				iface->dhcpv4_dns = realloc(iface->dhcpv4_dns,
						(++iface->dhcpv4_dns_cnt) * sizeof(*iface->dhcpv4_dns));
				if (!iface->dhcpv4_dns)
					goto err;

				iface->dhcpv4_dns[iface->dhcpv4_dns_cnt - 1] = addr4;
			} else if (inet_pton(AF_INET6, blobmsg_get_string(cur), &addr6) == 1) {
				iface->dns = realloc(iface->dns,
						(++iface->dns_cnt) * sizeof(*iface->dns));
				if (!iface->dns)
					goto err;

				iface->dns[iface->dns_cnt - 1] = addr6;
			} else {
				goto err;
			}
		}
	}

	if ((c = tb[IFACE_ATTR_DOMAIN])) {
		struct blob_attr *cur;
		unsigned rem;

		blobmsg_for_each_attr(cur, c, rem) {
			if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING || !blobmsg_check_attr(cur, NULL))
				continue;

			uint8_t buf[256];
			int len = dn_comp(blobmsg_get_string(cur), buf, sizeof(buf), NULL, NULL);
			if (len <= 0)
				goto err;

			iface->search = realloc(iface->search, iface->search_len + len);
			if (!iface->search)
				goto err;

			memcpy(&iface->search[iface->search_len], buf, len);
			iface->search_len += len;
		}
	}

	if ((c = tb[IFACE_ATTR_RA_DEFAULT]))
		iface->default_router = blobmsg_get_u32(c);

	if ((c = tb[IFACE_ATTR_RA_MANAGEMENT]))
		iface->managed = blobmsg_get_u32(c);
	else
		iface->managed = 1;

	if ((c = tb[IFACE_ATTR_RA_OFFLINK]))
		iface->ra_not_onlink = blobmsg_get_bool(c);

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

	if ((c = tb[IFACE_ATTR_NDPROXY_ROUTING]))
		iface->learn_routes = blobmsg_get_bool(c);
	else
		iface->learn_routes = true;

	if ((c = tb[IFACE_ATTR_NDPROXY_SLAVE]))
		iface->external = blobmsg_get_bool(c);

	if ((c = tb[IFACE_ATTR_NDPROXY_STATIC])) {
		struct blob_attr *cur;
		unsigned rem;

		blobmsg_for_each_attr(cur, c, rem) {
			if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING || !blobmsg_check_attr(cur, NULL))
				continue;

			int len = blobmsg_data_len(cur);
			iface->static_ndp = realloc(iface->static_ndp, iface->static_ndp_len + len);
			if (!iface->static_ndp)
				goto err;

			memcpy(&iface->static_ndp[iface->static_ndp_len], blobmsg_get_string(cur), len);
			iface->static_ndp_len += len;
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


void odhcpd_reload(void)
{
	struct uci_context *uci = uci_alloc_context();
	struct lease *l;
	list_for_each_entry(l, &leases, head) {
		list_del(&l->head);
		free(l->duid);
		free(l);
	}

	struct interface *master = NULL, *i, *n;

	if (!uci)
		return;

	list_for_each_entry(i, &interfaces, head)
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


#ifdef WITH_UBUS
	ubus_apply_network();
#endif

	bool any_dhcpv6_slave = false, any_ra_slave = false, any_ndp_slave = false;

	// Test for
	list_for_each_entry(i, &interfaces, head) {
		if (i->master)
			continue;

		if (i->dhcpv6 == RELAYD_HYBRID || i->dhcpv6 == RELAYD_RELAY)
			any_dhcpv6_slave = true;

		if (i->ra == RELAYD_HYBRID || i->ra == RELAYD_RELAY)
			any_ra_slave = true;

		if (i->ndp == RELAYD_HYBRID || i->ndp == RELAYD_RELAY)
			any_ndp_slave = true;
	}

	// Evaluate hybrid mode for master
	list_for_each_entry(i, &interfaces, head) {
		if (!i->master)
			continue;

		enum odhcpd_mode hybrid_mode = RELAYD_DISABLED;
#ifdef WITH_UBUS
		if (!ubus_has_prefix(i->name, i->ifname))
			hybrid_mode = RELAYD_RELAY;
#endif

		if (i->dhcpv6 == RELAYD_HYBRID)
			i->dhcpv6 = hybrid_mode;

		if (i->dhcpv6 == RELAYD_RELAY && !any_dhcpv6_slave)
			i->dhcpv6 = RELAYD_DISABLED;

		if (i->ra == RELAYD_HYBRID)
			i->ra = hybrid_mode;

		if (i->ra == RELAYD_RELAY && !any_ra_slave)
			i->ra = RELAYD_DISABLED;

		if (i->ndp == RELAYD_HYBRID)
			i->ndp = hybrid_mode;

		if (i->ndp == RELAYD_RELAY && !any_ndp_slave)
			i->ndp = RELAYD_DISABLED;

		if (i->dhcpv6 == RELAYD_RELAY || i->ra == RELAYD_RELAY || i->ndp == RELAYD_RELAY)
			master = i;
	}


	list_for_each_entry_safe(i, n, &interfaces, head) {
		if (i->inuse) {
			// Resolve hybrid mode
			if (i->dhcpv6 == RELAYD_HYBRID)
				i->dhcpv6 = (master && master->dhcpv6 == RELAYD_RELAY) ?
						RELAYD_RELAY : RELAYD_SERVER;

			if (i->ra == RELAYD_HYBRID)
				i->ra = (master && master->ra == RELAYD_RELAY) ?
						RELAYD_RELAY : RELAYD_SERVER;

			if (i->ndp == RELAYD_HYBRID)
				i->ndp = (master && master->ndp == RELAYD_RELAY) ?
						RELAYD_RELAY : RELAYD_DISABLED;

			setup_router_interface(i, true);
			setup_dhcpv6_interface(i, true);
			setup_ndp_interface(i, true);
			setup_dhcpv4_interface(i, true);
		} else {
			close_interface(i);
		}
	}

	uci_unload(uci, dhcp);
	uci_free_context(uci);
}


static void handle_signal(int signal)
{
	char b[1] = {0};
	if (signal == SIGHUP)
		write(reload_pipe[1], b, sizeof(b));
	else
		uloop_end();
}



static void reload_cb(struct uloop_fd *u, _unused unsigned int events)
{
	char b[512];
	read(u->fd, b, sizeof(b));
	odhcpd_reload();
}

static struct uloop_fd reload_fd = { .cb = reload_cb };

void odhcpd_run(void)
{
	pipe2(reload_pipe, O_NONBLOCK | O_CLOEXEC);
	reload_fd.fd = reload_pipe[0];
	uloop_fd_add(&reload_fd, ULOOP_READ);

	signal(SIGTERM, handle_signal);
	signal(SIGINT, handle_signal);
	signal(SIGHUP, handle_signal);

#ifdef WITH_UBUS
	while (init_ubus())
		sleep(1);
#endif

	odhcpd_reload();
	uloop_run();
}

