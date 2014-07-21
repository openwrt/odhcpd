#include <syslog.h>
#include <libubus.h>
#include <libubox/uloop.h>
#include <arpa/inet.h>

#include "odhcpd.h"
#include "dhcpv6.h"
#include "dhcpv4.h"


static struct ubus_context *ubus = NULL;
static struct ubus_subscriber netifd;
static struct blob_buf b;
static struct blob_attr *dump = NULL;
static uint32_t objid = 0;
static struct ubus_request req_dump = { .list = LIST_HEAD_INIT(req_dump.list) };


static int handle_dhcpv4_leases(struct ubus_context *ctx, _unused struct ubus_object *obj,
		struct ubus_request_data *req, _unused const char *method,
		_unused struct blob_attr *msg)
{
	blob_buf_init(&b, 0);
	void *a = blobmsg_open_table(&b, "device");
	time_t now = odhcpd_time();

	struct interface *iface;
	list_for_each_entry(iface, &interfaces, head) {
		if (iface->dhcpv4 != RELAYD_SERVER)
			continue;

		void *i = blobmsg_open_table(&b, iface->ifname);
		void *j = blobmsg_open_array(&b, "leases");

		struct dhcpv4_assignment *lease;
		list_for_each_entry(lease, &iface->dhcpv4_assignments, head) {
			if (lease->valid_until < now)
				continue;

			void *l = blobmsg_open_table(&b, NULL);

			char *buf = blobmsg_alloc_string_buffer(&b, "mac", 13);
			odhcpd_hexlify(buf, lease->hwaddr, sizeof(lease->hwaddr));
			blobmsg_add_string_buffer(&b);

			blobmsg_add_string(&b, "hostname", lease->hostname);

			buf = blobmsg_alloc_string_buffer(&b, "ip", INET_ADDRSTRLEN);
			struct in_addr addr = {htonl(lease->addr)};
			inet_ntop(AF_INET, &addr, buf, INET_ADDRSTRLEN);
			blobmsg_add_string_buffer(&b);

			blobmsg_add_u32(&b, "valid", now - lease->valid_until);

			blobmsg_close_table(&b, l);
		}

		blobmsg_close_array(&b, j);
		blobmsg_close_table(&b, i);
	}

	blobmsg_close_table(&b, a);
	ubus_send_reply(ctx, req, b.head);
	return 0;
}


static int handle_dhcpv6_leases(_unused struct ubus_context *ctx, _unused struct ubus_object *obj,
		_unused struct ubus_request_data *req, _unused const char *method,
		_unused struct blob_attr *msg)
{
	blob_buf_init(&b, 0);
	void *a = blobmsg_open_table(&b, "device");
	time_t now = odhcpd_time();

	struct interface *iface;
	list_for_each_entry(iface, &interfaces, head) {
		if (iface->dhcpv6 != RELAYD_SERVER)
			continue;

		void *i = blobmsg_open_table(&b, iface->ifname);
		void *j = blobmsg_open_array(&b, "leases");

		struct dhcpv6_assignment *lease;
		list_for_each_entry(lease, &iface->ia_assignments, head) {
			if (lease->valid_until < now)
				continue;

			void *l = blobmsg_open_table(&b, NULL);

			char *buf = blobmsg_alloc_string_buffer(&b, "duid", 264);
			odhcpd_hexlify(buf, lease->clid_data, lease->clid_len);
			blobmsg_add_string_buffer(&b);

			blobmsg_add_u32(&b, "iaid", ntohl(lease->iaid));
			blobmsg_add_string(&b, "hostname", (lease->hostname) ? lease->hostname : "");
			blobmsg_add_u32(&b, "assigned", lease->assigned);
			blobmsg_add_u32(&b, "length", lease->length);

			void *m = blobmsg_open_array(&b, "ipv6");
			struct in6_addr addr;
			for (size_t i = 0; i < iface->ia_addr_len; ++i) {
				if (iface->ia_addr[i].prefix > 64)
					continue;

				addr = iface->ia_addr[i].addr;
				if (lease->length == 128)
					addr.s6_addr32[3] = htonl(lease->assigned);
				else
					addr.s6_addr32[1] |= htonl(lease->assigned);

				char *c = blobmsg_alloc_string_buffer(&b, NULL, INET6_ADDRSTRLEN);
				inet_ntop(AF_INET6, &addr, c, INET6_ADDRSTRLEN);
				blobmsg_add_string_buffer(&b);
			}
			blobmsg_close_table(&b, m);

			blobmsg_add_u32(&b, "valid", now - lease->valid_until);

			blobmsg_close_table(&b, l);
		}

		blobmsg_close_array(&b, j);
		blobmsg_close_table(&b, i);
	}

	blobmsg_close_table(&b, a);
	ubus_send_reply(ctx, req, b.head);
	return 0;
}


static struct ubus_method main_object_methods[] = {
	{.name = "ipv4leases", .handler = handle_dhcpv4_leases},
	{.name = "ipv6leases", .handler = handle_dhcpv6_leases},
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

static void handle_dump(_unused struct ubus_request *req, _unused int type, struct blob_attr *msg)
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
	if (!ubus_invoke_async(ubus, objid, "dump", NULL, &req_dump)) {
		req_dump.data_cb = handle_dump;
		ubus_complete_request_async(ubus, &req_dump);
	}
}


static int handle_update(_unused struct ubus_context *ctx, _unused struct ubus_object *obj,
		_unused struct ubus_request_data *req, _unused const char *method,
		struct blob_attr *msg)
{
	struct blob_attr *tb[IFACE_ATTR_MAX];
	blobmsg_parse(iface_attrs, IFACE_ATTR_MAX, tb, blob_data(msg), blob_len(msg));

	const char *interface = (tb[IFACE_ATTR_INTERFACE]) ?
			blobmsg_get_string(tb[IFACE_ATTR_INTERFACE]) : "";
	const char *ifname = (tb[IFACE_ATTR_IFNAME]) ?
			blobmsg_get_string(tb[IFACE_ATTR_IFNAME]) : "";

	struct interface *c, *iface = NULL;
	list_for_each_entry(c, &interfaces, head)
		if (!strcmp(interface, c->name) || !strcmp(ifname, c->ifname))
			iface = c;

	if (iface && iface->ignore)
		return 0;

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
		const char *ifname = (tb[IFACE_ATTR_IFNAME]) ?
				blobmsg_get_string(tb[IFACE_ATTR_IFNAME]) : "";

		bool matched = false;
		struct interface *c, *n;
		list_for_each_entry_safe(c, n, &interfaces, head) {
			char *f = memmem(c->upstream, c->upstream_len,
					interface, strlen(interface) + 1);
			bool cmatched = !strcmp(interface, c->name) || !strcmp(ifname, c->ifname);
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


static void handle_event(_unused struct ubus_context *ctx, _unused struct ubus_event_handler *ev,
                _unused const char *type, struct blob_attr *msg)
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
		return NULL;

	blobmsg_for_each_attr(c, dump, rem) {
		struct blob_attr *tb[IFACE_ATTR_MAX];
		blobmsg_parse(iface_attrs, IFACE_ATTR_MAX, tb, blobmsg_data(c), blobmsg_data_len(c));

		if (!tb[IFACE_ATTR_INTERFACE] || !tb[IFACE_ATTR_IFNAME])
			continue;

		if (strcmp(name, blobmsg_get_string(tb[IFACE_ATTR_INTERFACE])) ||
				strcmp(ifname, blobmsg_get_string(tb[IFACE_ATTR_IFNAME])))
			continue;

		if ((cur = tb[IFACE_ATTR_PREFIX])) {
			if (blobmsg_type(cur) != BLOBMSG_TYPE_ARRAY || !blobmsg_check_attr(cur, NULL))
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


enum {
	ADDR_ATTR_ADDR,
	ADDR_ATTR_CLASS,
	ADDR_ATTR_MAX
};

static const struct blobmsg_policy addr_attrs[ADDR_ATTR_MAX] = {
	[ADDR_ATTR_ADDR] = { .name = "address", .type = BLOBMSG_TYPE_STRING },
	[ADDR_ATTR_CLASS] = { .name = "class", .type = BLOBMSG_TYPE_STRING },
};

bool ubus_get_class(const char *ifname, const struct in6_addr *addr, uint16_t *pclass)
{
	struct blob_attr *c, *cur;
	unsigned rem;

	if (!dump)
		return false;

	blobmsg_for_each_attr(c, dump, rem) {
		struct blob_attr *tb[IFACE_ATTR_MAX];
		blobmsg_parse(iface_attrs, IFACE_ATTR_MAX, tb, blobmsg_data(c), blobmsg_data_len(c));

		if (!tb[IFACE_ATTR_IFNAME])
			continue;

		if (strcmp(ifname, blobmsg_get_string(tb[IFACE_ATTR_IFNAME])))
			continue;

		if ((cur = tb[IFACE_ATTR_ADDRESS])) {
			if (blobmsg_type(cur) != BLOBMSG_TYPE_ARRAY || !blobmsg_check_attr(cur, NULL))
				continue;

			struct blob_attr *d;
			unsigned drem;
			blobmsg_for_each_attr(d, cur, drem) {
				struct blob_attr *t[ADDR_ATTR_MAX];
				blobmsg_parse(addr_attrs, ADDR_ATTR_MAX, t, blobmsg_data(d), blobmsg_data_len(d));

				if (!t[ADDR_ATTR_ADDR] || !t[ADDR_ATTR_CLASS])
					continue;

				const char *addrs = blobmsg_get_string(t[ADDR_ATTR_ADDR]);
				const char *class = blobmsg_get_string(t[ADDR_ATTR_CLASS]);

				struct in6_addr ip6addr;
				inet_pton(AF_INET6, addrs, &ip6addr);

				if (IN6_ARE_ADDR_EQUAL(&ip6addr, addr)) {
					*pclass = atoi(class);
					return true;
				}
			}
		}

		return false;
	}

	return false;
}


int init_ubus(void)
{
	if (!(ubus = ubus_connect(NULL))) {
		syslog(LOG_ERR, "Unable to connect to ubus: %s", strerror(errno));
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

