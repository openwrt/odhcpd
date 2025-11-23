#include <libubus.h>
#include <libubox/uloop.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inttypes.h>

#include <libubox/utils.h>

#include "odhcpd.h"
#include "dhcpv6.h"
#include "dhcpv4.h"
#include "statefiles.h"

static struct ubus_context *ubus = NULL;
static struct ubus_subscriber netifd;
static struct blob_buf b;
static struct blob_attr *dump = NULL;
static uint32_t objid = 0;
static struct ubus_request req_dump = { .list = LIST_HEAD_INIT(req_dump.list) };

#ifdef DHCPV4_SUPPORT
static int handle_dhcpv4_leases(struct ubus_context *ctx, _o_unused struct ubus_object *obj,
		struct ubus_request_data *req, _o_unused const char *method,
		_o_unused struct blob_attr *msg)
{
	struct interface *iface;
	time_t now = odhcpd_time();
	void *a;

	blob_buf_init(&b, 0);
	a = blobmsg_open_table(&b, "device");

	avl_for_each_element(&interfaces, iface, avl) {
		if (iface->dhcpv4 != MODE_SERVER)
			continue;

		void *i = blobmsg_open_table(&b, iface->ifname);
		void *j = blobmsg_open_array(&b, "leases");
		struct dhcpv4_lease *c;

		avl_for_each_element(&iface->dhcpv4_leases, c, iface_avl) {
			if (!INFINITE_VALID(c->valid_until) && c->valid_until < now)
				continue;

			void *m, *l = blobmsg_open_table(&b, NULL);
			char *buf = blobmsg_alloc_string_buffer(&b, "mac", sizeof(c->hwaddr) * 2 + 1);

			odhcpd_hexlify(buf, c->hwaddr, sizeof(c->hwaddr));
			blobmsg_add_string_buffer(&b);

			if (c->duid_len > 0) {
				buf = blobmsg_alloc_string_buffer(&b, "duid", DUID_HEXSTRLEN + 1);
				odhcpd_hexlify(buf, c->duid, c->duid_len);
				blobmsg_add_string_buffer(&b);
				blobmsg_add_u32(&b, "iaid", ntohl(c->iaid));
			}

			blobmsg_add_string(&b, "hostname", (c->hostname) ? c->hostname : "");
			blobmsg_add_u8(&b, "accept-reconf", c->accept_fr_nonce);

			m = blobmsg_open_array(&b, "flags");
			if (c->flags & OAF_BOUND)
				blobmsg_add_string(&b, NULL, "bound");

			if (c->flags & OAF_STATIC)
				blobmsg_add_string(&b, NULL, "static");

			if (!c->hostname_valid)
				blobmsg_add_string(&b, NULL, "broken-hostname");
			blobmsg_close_array(&b, m);

			buf = blobmsg_alloc_string_buffer(&b, "address", INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &c->ipv4, buf, INET_ADDRSTRLEN);
			blobmsg_add_string_buffer(&b);

			blobmsg_add_u32(&b, "valid", INFINITE_VALID(c->valid_until) ?
						(uint32_t)-1 : (uint32_t)(c->valid_until - now));

			blobmsg_close_table(&b, l);
		}

		blobmsg_close_array(&b, j);
		blobmsg_close_table(&b, i);
	}

	blobmsg_close_table(&b, a);
	ubus_send_reply(ctx, req, b.head);

	return 0;
}
#endif /* DHCPV4_SUPPORT */

static void dhcpv6_blobmsg_ia_addr(_o_unused struct dhcpv6_lease *lease, struct in6_addr *addr, uint8_t prefix_len,
				   uint32_t pref_lt, uint32_t valid_lt, _o_unused void *arg)
{
	void *a	= blobmsg_open_table(&b, NULL);
	char *buf = blobmsg_alloc_string_buffer(&b, "address", INET6_ADDRSTRLEN);

	inet_ntop(AF_INET6, addr, buf, INET6_ADDRSTRLEN);
	blobmsg_add_string_buffer(&b);
	blobmsg_add_u32(&b, "preferred-lifetime",
			pref_lt == UINT32_MAX ? (uint32_t)-1 : pref_lt);
	blobmsg_add_u32(&b, "valid-lifetime",
			valid_lt == UINT32_MAX ? (uint32_t)-1 : valid_lt);

	if (prefix_len != 128)
		blobmsg_add_u32(&b, "prefix-length", prefix_len);

	blobmsg_close_table(&b, a);
}

static int handle_dhcpv6_leases(_o_unused struct ubus_context *ctx, _o_unused struct ubus_object *obj,
		_o_unused struct ubus_request_data *req, _o_unused const char *method,
		_o_unused struct blob_attr *msg)
{
	struct interface *iface;
	time_t now = odhcpd_time();
	void *dev_tbl;

	blob_buf_init(&b, 0);
	dev_tbl = blobmsg_open_table(&b, "device");

	avl_for_each_element(&interfaces, iface, avl) {
		if (iface->dhcpv6 != MODE_SERVER)
			continue;

		void *i = blobmsg_open_table(&b, iface->ifname);
		void *j = blobmsg_open_array(&b, "leases");

		struct dhcpv6_lease *a, *border;

		border = list_last_entry(&iface->ia_assignments, struct dhcpv6_lease, head);

		list_for_each_entry(a, &iface->ia_assignments, head) {
			if (a == border || (!INFINITE_VALID(a->valid_until) &&
						a->valid_until < now))
				continue;

			void *m, *l = blobmsg_open_table(&b, NULL);
			char *buf = blobmsg_alloc_string_buffer(&b, "duid", DUID_HEXSTRLEN + 1);

			odhcpd_hexlify(buf, a->duid, a->duid_len);
			blobmsg_add_string_buffer(&b);

			blobmsg_add_u32(&b, "iaid", ntohl(a->iaid));
			blobmsg_add_string(&b, "hostname", (a->hostname) ? a->hostname : "");
			blobmsg_add_u8(&b, "accept-reconf", a->accept_fr_nonce);
			if (a->flags & OAF_DHCPV6_NA)
				blobmsg_add_u64(&b, "assigned", a->assigned_host_id);
			else
				blobmsg_add_u16(&b, "assigned", a->assigned_subnet_id);

			m = blobmsg_open_array(&b, "flags");
			if (a->flags & OAF_BOUND)
				blobmsg_add_string(&b, NULL, "bound");

			if (a->flags & OAF_STATIC)
				blobmsg_add_string(&b, NULL, "static");
			blobmsg_close_array(&b, m);

			m = blobmsg_open_array(&b, a->flags & OAF_DHCPV6_NA ? "ipv6-addr": "ipv6-prefix");
			odhcpd_enum_addr6(iface, a, now, dhcpv6_blobmsg_ia_addr, NULL);
			blobmsg_close_array(&b, m);

			blobmsg_add_u32(&b, "valid", INFINITE_VALID(a->valid_until) ?
						(uint32_t)-1 : (uint32_t)(a->valid_until - now));

			blobmsg_close_table(&b, l);
		}

		blobmsg_close_array(&b, j);
		blobmsg_close_table(&b, i);
	}

	blobmsg_close_table(&b, dev_tbl);
	ubus_send_reply(ctx, req, b.head);

	return 0;
}

static int handle_ra_pio(_o_unused struct ubus_context *ctx, _o_unused struct ubus_object *obj,
		_o_unused struct ubus_request_data *req, _o_unused const char *method,
		_o_unused struct blob_attr *msg)
{
	char ipv6_str[INET6_ADDRSTRLEN];
	time_t now = odhcpd_time();
	struct interface *iface;
	void *interfaces_blob;

	blob_buf_init(&b, 0);

	interfaces_blob = blobmsg_open_table(&b, "interfaces");

	avl_for_each_element(&interfaces, iface, avl) {
		void *interface_blob;

		if (iface->ra != MODE_SERVER)
			continue;

		interface_blob = blobmsg_open_array(&b, iface->ifname);

		for (size_t i = 0; i < iface->pio_cnt; i++) {
			struct ra_pio *cur_pio = &iface->pios[i];
			void *cur_pio_blob;
			uint32_t pio_lt;
			bool pio_stale;

			if (ra_pio_expired(cur_pio, now))
				continue;

			cur_pio_blob = blobmsg_open_table(&b, NULL);

			pio_lt = ra_pio_lifetime(cur_pio, now);
			pio_stale = ra_pio_stale(cur_pio);

			inet_ntop(AF_INET6, &cur_pio->prefix, ipv6_str, sizeof(ipv6_str));

			if (pio_lt)
				blobmsg_add_u32(&b, "lifetime", pio_lt);
			blobmsg_add_string(&b, "prefix", ipv6_str);
			blobmsg_add_u16(&b, "length", cur_pio->length);
			blobmsg_add_u8(&b, "stale", pio_stale);

			blobmsg_close_table(&b, cur_pio_blob);
		}

		blobmsg_close_array(&b, interface_blob);
	}

	blobmsg_close_table(&b, interfaces_blob);

	ubus_send_reply(ctx, req, b.head);

	return 0;
}

static int handle_add_lease_cfg(_o_unused struct ubus_context *ctx, _o_unused struct ubus_object *obj,
				_o_unused struct ubus_request_data *req, _o_unused const char *method,
				struct blob_attr *msg)
{
	if (!config_set_lease_cfg_from_blobmsg(msg))
		return UBUS_STATUS_OK;

	return UBUS_STATUS_INVALID_ARGUMENT;
}

static struct ubus_method main_object_methods[] = {
#ifdef DHCPV4_SUPPORT
	{ .name = "ipv4leases", .handler = handle_dhcpv4_leases },
#endif /* DHCPV4_SUPPORT */
	{ .name = "ipv6leases", .handler = handle_dhcpv6_leases },
	{ .name = "ipv6ra", .handler = handle_ra_pio },
	UBUS_METHOD("add_lease", handle_add_lease_cfg, lease_cfg_attrs),
};

static struct ubus_object_type main_object_type =
	UBUS_OBJECT_TYPE("dhcp", main_object_methods);

static struct ubus_object main_object = {
	.name = "dhcp",
	.type = &main_object_type,
	.methods = main_object_methods,
	.n_methods = ARRAY_SIZE(main_object_methods),
};


enum {
	DUMP_ATTR_INTERFACE,
	DUMP_ATTR_MAX
};

static const struct blobmsg_policy dump_attrs[DUMP_ATTR_MAX] = {
	[DUMP_ATTR_INTERFACE] = { .name = "interface", .type = BLOBMSG_TYPE_ARRAY },
};


enum {
	IFACE_ATTR_INTERFACE,
	IFACE_ATTR_IFNAME,
	IFACE_ATTR_UP,
	IFACE_ATTR_DATA,
	IFACE_ATTR_PREFIX,
	IFACE_ATTR_ADDRESS,
	IFACE_ATTR_MAX,
};

static const struct blobmsg_policy iface_attrs[IFACE_ATTR_MAX] = {
	[IFACE_ATTR_INTERFACE] = { .name = "interface", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_IFNAME] = { .name = "l3_device", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_UP] = { .name = "up", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_DATA] = { .name = "data", .type = BLOBMSG_TYPE_TABLE },
	[IFACE_ATTR_PREFIX] = { .name = "ipv6-prefix", .type = BLOBMSG_TYPE_ARRAY },
	[IFACE_ATTR_ADDRESS] = { .name = "ipv6-address", .type = BLOBMSG_TYPE_ARRAY },
};

static void handle_dump(_o_unused struct ubus_request *req, _o_unused int type, struct blob_attr *msg)
{
	struct blob_attr *tb[DUMP_ATTR_MAX];
	blobmsg_parse(dump_attrs, DUMP_ATTR_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[DUMP_ATTR_INTERFACE])
		return;

	free(dump);
	dump = blob_memdup(tb[DUMP_ATTR_INTERFACE]);
	odhcpd_reload();
}


static void update_netifd(bool subscribe)
{
	if (subscribe)
		ubus_subscribe(ubus, &netifd, objid);

	ubus_abort_request(ubus, &req_dump);
	blob_buf_init(&b, 0);

	if (!ubus_invoke_async(ubus, objid, "dump", b.head, &req_dump)) {
		req_dump.data_cb = handle_dump;
		ubus_complete_request_async(ubus, &req_dump);
	}
}


static int handle_update(_o_unused struct ubus_context *ctx, _o_unused struct ubus_object *obj,
		_o_unused struct ubus_request_data *req, _o_unused const char *method,
		struct blob_attr *msg)
{
	struct blob_attr *tb[IFACE_ATTR_MAX];
	struct interface *c;
	bool update = true;

	blobmsg_parse(iface_attrs, IFACE_ATTR_MAX, tb, blob_data(msg), blob_len(msg));
	const char *interface = (tb[IFACE_ATTR_INTERFACE]) ?
			blobmsg_get_string(tb[IFACE_ATTR_INTERFACE]) : "";

	avl_for_each_element(&interfaces, c, avl) {
		if (!strcmp(interface, c->name) && c->ignore) {
			update = false;
			break;
		}
	}

	if (update)
		update_netifd(false);

	return 0;
}


void ubus_apply_network(void)
{
	struct blob_attr *a;
	unsigned rem;

	if (!dump)
		return;

	blobmsg_for_each_attr(a, dump, rem) {
		struct blob_attr *tb[IFACE_ATTR_MAX];
		blobmsg_parse(iface_attrs, IFACE_ATTR_MAX, tb, blobmsg_data(a), blobmsg_data_len(a));

		if (!tb[IFACE_ATTR_INTERFACE] || !tb[IFACE_ATTR_DATA])
			continue;

		const char *interface = (tb[IFACE_ATTR_INTERFACE]) ?
				blobmsg_get_string(tb[IFACE_ATTR_INTERFACE]) : "";

		bool matched = false;
		struct interface *c, *tmp;
		avl_for_each_element_safe(&interfaces, c, avl, tmp) {
			char *f = memmem(c->upstream, c->upstream_len,
					interface, strlen(interface) + 1);
			bool cmatched = !strcmp(interface, c->name);
			matched |= cmatched;

			if (!cmatched && (!c->upstream_len || !f || (f != c->upstream && f[-1] != 0)))
				continue;

			if (!c->ignore)
				config_parse_interface(blobmsg_data(tb[IFACE_ATTR_DATA]),
						blobmsg_data_len(tb[IFACE_ATTR_DATA]), c->name, false);
		}

		if (!matched)
			config_parse_interface(blobmsg_data(tb[IFACE_ATTR_DATA]),
					blobmsg_data_len(tb[IFACE_ATTR_DATA]), interface, false);
	}
}


enum {
	OBJ_ATTR_ID,
	OBJ_ATTR_PATH,
	OBJ_ATTR_MAX
};

static const struct blobmsg_policy obj_attrs[OBJ_ATTR_MAX] = {
	[OBJ_ATTR_ID] = { .name = "id", .type = BLOBMSG_TYPE_INT32 },
	[OBJ_ATTR_PATH] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
};

void ubus_bcast_dhcpv4_event(const char *type, const char *iface,
			     const struct dhcpv4_lease *lease)
{
	char ipv4_str[INET_ADDRSTRLEN];

	if (!ubus || !main_object.has_subscribers || !iface)
		return;

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "interface", iface);
	blobmsg_add_string(&b, "ipv4", inet_ntop(AF_INET, &lease->ipv4, ipv4_str, sizeof(ipv4_str)));
	blobmsg_add_string(&b, "mac", odhcpd_print_mac(lease->hwaddr, sizeof(lease->hwaddr)));
	if (lease->hostname)
		blobmsg_add_string(&b, "hostname", lease->hostname);
	if (lease->duid_len > 0) {
		char *buf = blobmsg_alloc_string_buffer(&b, "duid", DUID_HEXSTRLEN + 1);
		odhcpd_hexlify(buf, lease->duid, lease->duid_len);
		blobmsg_add_string_buffer(&b);
		blobmsg_add_u32(&b, "iaid", lease->iaid);
	}

	ubus_notify(ubus, &main_object, type, b.head, -1);
}

static void handle_event(_o_unused struct ubus_context *ctx,
			 _o_unused struct ubus_event_handler *ev,
			 _o_unused const char *type, struct blob_attr *msg)
{
	struct blob_attr *tb[OBJ_ATTR_MAX];
	blobmsg_parse(obj_attrs, OBJ_ATTR_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[OBJ_ATTR_ID] || !tb[OBJ_ATTR_PATH])
		return;

	if (strcmp(blobmsg_get_string(tb[OBJ_ATTR_PATH]), "network.interface"))
		return;

	objid = blobmsg_get_u32(tb[OBJ_ATTR_ID]);
	update_netifd(true);
}

static struct ubus_event_handler event_handler = { .cb = handle_event };


const char* ubus_get_ifname(const char *name)
{
	struct blob_attr *c;
	unsigned rem;

	if (!dump)
		return NULL;

	blobmsg_for_each_attr(c, dump, rem) {
		struct blob_attr *tb[IFACE_ATTR_MAX];
		blobmsg_parse(iface_attrs, IFACE_ATTR_MAX, tb, blobmsg_data(c), blobmsg_data_len(c));

		if (!tb[IFACE_ATTR_INTERFACE] || strcmp(name,
				blobmsg_get_string(tb[IFACE_ATTR_INTERFACE])))
			continue;

		if (tb[IFACE_ATTR_IFNAME])
			return blobmsg_get_string(tb[IFACE_ATTR_IFNAME]);
	}

	return NULL;
}


bool ubus_has_prefix(const char *name, const char *ifname)
{
	struct blob_attr *c, *cur;
	unsigned rem;

	if (!dump)
		return false;

	blobmsg_for_each_attr(c, dump, rem) {
		struct blob_attr *tb[IFACE_ATTR_MAX];
		blobmsg_parse(iface_attrs, IFACE_ATTR_MAX, tb, blobmsg_data(c), blobmsg_data_len(c));

		if (!tb[IFACE_ATTR_INTERFACE] || !tb[IFACE_ATTR_IFNAME])
			continue;

		if (strcmp(name, blobmsg_get_string(tb[IFACE_ATTR_INTERFACE])) ||
				strcmp(ifname, blobmsg_get_string(tb[IFACE_ATTR_IFNAME])))
			continue;

		if ((cur = tb[IFACE_ATTR_PREFIX])) {
			if (blobmsg_type(cur) != BLOBMSG_TYPE_ARRAY || !blobmsg_check_attr(cur, false))
				continue;

			struct blob_attr *d;
			unsigned drem;
			blobmsg_for_each_attr(d, cur, drem) {
				return true;
			}
		}
	}

	return false;
}


int ubus_init(void)
{
	if (!(ubus = ubus_connect(NULL))) {
		error("Unable to connect to ubus: %m");
		return -1;
	}

	netifd.cb = handle_update;
	ubus_register_subscriber(ubus, &netifd);

	ubus_add_uloop(ubus);
	ubus_add_object(ubus, &main_object);
	ubus_register_event_handler(ubus, &event_handler, "ubus.object.add");
	if (!ubus_lookup_id(ubus, "network.interface", &objid))
		update_netifd(true);

	return 0;
}

