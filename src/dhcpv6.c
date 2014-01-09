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
 *
 */

#include <errno.h>
#include <unistd.h>
#include <stddef.h>
#include <resolv.h>
#include <sys/timerfd.h>

#include "odhcpd.h"
#include "dhcpv6.h"


static void relay_client_request(struct sockaddr_in6 *source,
		const void *data, size_t len, struct interface *iface);
static void relay_server_response(uint8_t *data, size_t len);

static void handle_dhcpv6(void *addr, void *data, size_t len,
		struct interface *iface);
static void handle_client_request(void *addr, void *data, size_t len,
		struct interface *iface);



// Create socket and register events
int init_dhcpv6(void)
{
	dhcpv6_ia_init();
	return 0;
}


int setup_dhcpv6_interface(struct interface *iface, bool enable)
{
	if (iface->dhcpv6_event.uloop.fd > 0) {
		uloop_fd_delete(&iface->dhcpv6_event.uloop);
		close(iface->dhcpv6_event.uloop.fd);
		iface->dhcpv6_event.uloop.fd = -1;
	}

	// Configure multicast settings
	if (enable && iface->dhcpv6 && !iface->master) {
		int sock = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
		if (sock < 0) {
			syslog(LOG_ERR, "Failed to create DHCPv6 server socket: %s",
					strerror(errno));
			return -1;
		}

		// Basic IPv6 configuration
		setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, iface->ifname, strlen(iface->ifname));

		int val = 1;
		setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val));
		setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
		setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &val, sizeof(val));

		val = DHCPV6_HOP_COUNT_LIMIT;
		setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &val, sizeof(val));

		val = 0;
		setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &val, sizeof(val));

		struct sockaddr_in6 bind_addr = {AF_INET6, htons(DHCPV6_SERVER_PORT),
					0, IN6ADDR_ANY_INIT, 0};

		if (bind(sock, (struct sockaddr*)&bind_addr, sizeof(bind_addr))) {
			syslog(LOG_ERR, "Failed to open DHCPv6 server socket: %s",
					strerror(errno));
			return -1;
		}

		struct ipv6_mreq relay = {ALL_DHCPV6_RELAYS, iface->ifindex};
		struct ipv6_mreq server = {ALL_DHCPV6_SERVERS, iface->ifindex};
		setsockopt(sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &relay, sizeof(relay));

		if (iface->dhcpv6 == RELAYD_SERVER)
			setsockopt(sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &server, sizeof(server));

		iface->dhcpv6_event.uloop.fd = sock;
		iface->dhcpv6_event.handle_dgram = handle_dhcpv6;
		odhcpd_register(&iface->dhcpv6_event);
	}

	return setup_dhcpv6_ia_interface(iface, enable);
}


static void handle_nested_message(uint8_t *data, size_t len,
		uint8_t **opts, uint8_t **end, struct iovec iov[6])
{
	struct dhcpv6_relay_header *hdr = (struct dhcpv6_relay_header*)data;
	if (iov[0].iov_base == NULL) {
		iov[0].iov_base = data;
		iov[0].iov_len = len;
	}

	if (len < sizeof(struct dhcpv6_client_header))
		return;

	if (hdr->msg_type != DHCPV6_MSG_RELAY_FORW) {
		iov[0].iov_len = data - (uint8_t*)iov[0].iov_base;
		struct dhcpv6_client_header *hdr = (void*)data;
		*opts = (uint8_t*)&hdr[1];
		*end = data + len;
		return;
	}

	uint16_t otype, olen;
	uint8_t *odata;
	dhcpv6_for_each_option(hdr->options, data + len, otype, olen, odata) {
		if (otype == DHCPV6_OPT_RELAY_MSG) {
			iov[7].iov_base = odata + olen;
			iov[7].iov_len = (((uint8_t*)iov[0].iov_base) + iov[0].iov_len)
					- (odata + olen);
			handle_nested_message(odata, olen, opts, end, iov);
			return;
		}
	}
}


static void update_nested_message(uint8_t *data, size_t len, ssize_t pdiff)
{
	struct dhcpv6_relay_header *hdr = (struct dhcpv6_relay_header*)data;
	if (hdr->msg_type != DHCPV6_MSG_RELAY_FORW)
		return;

	hdr->msg_type = DHCPV6_MSG_RELAY_REPL;

	uint16_t otype, olen;
	uint8_t *odata;
	dhcpv6_for_each_option(hdr->options, data + len, otype, olen, odata) {
		if (otype == DHCPV6_OPT_RELAY_MSG) {
			olen += pdiff;
			odata[-2] = (olen >> 8) & 0xff;
			odata[-1] = olen & 0xff;
			update_nested_message(odata, olen - pdiff, pdiff);
			return;
		}
	}
}


// Simple DHCPv6-server for information requests
static void handle_client_request(void *addr, void *data, size_t len,
		struct interface *iface)
{
	struct dhcpv6_client_header *hdr = data;
	if (len < sizeof(*hdr))
		return;

	syslog(LOG_NOTICE, "Got DHCPv6 request");

	// Construct reply message
	struct __attribute__((packed)) {
		uint8_t msg_type;
		uint8_t tr_id[3];
		uint16_t serverid_type;
		uint16_t serverid_length;
		uint16_t duid_type;
		uint16_t hardware_type;
		uint8_t mac[6];
		uint16_t clientid_type;
		uint16_t clientid_length;
		uint8_t clientid_buf[130];
	} dest = {
		.msg_type = DHCPV6_MSG_REPLY,
		.serverid_type = htons(DHCPV6_OPT_SERVERID),
		.serverid_length = htons(10),
		.duid_type = htons(3),
		.hardware_type = htons(1),
		.clientid_type = htons(DHCPV6_OPT_CLIENTID),
		.clientid_buf = {0}
	};
	odhcpd_get_mac(iface, dest.mac);

	struct __attribute__((packed)) {
		uint16_t type;
		uint16_t len;
		uint16_t value;
	} stat = {htons(DHCPV6_OPT_STATUS), htons(sizeof(stat) - 4),
			htons(DHCPV6_STATUS_NOADDRSAVAIL)};

	struct __attribute__((packed)) {
		uint16_t type;
		uint16_t len;
		uint32_t value;
	} refresh = {htons(DHCPV6_OPT_INFO_REFRESH), htons(sizeof(uint32_t)),
			htonl(600)};

	struct odhcpd_ipaddr ipaddr;
	struct in6_addr *dns_addr = iface->dns;
	size_t dns_cnt = iface->dns_cnt;

	if (dns_cnt == 0 && odhcpd_get_interface_addresses(iface->ifindex, &ipaddr, 1) == 1) {
		dns_addr = &ipaddr.addr;
		dns_cnt = 1;
	}

	struct {
		uint16_t type;
		uint16_t len;
	} dns = {htons(DHCPV6_OPT_DNS_SERVERS), htons(dns_cnt * sizeof(*dns_addr))};



	// DNS Search options
	uint8_t search_buf[256], *search_domain = iface->search;
	size_t search_len = iface->search_len;

	if (!search_domain && !res_init() && _res.dnsrch[0] && _res.dnsrch[0][0]) {
		int len = dn_comp(_res.dnsrch[0], search_buf,
				sizeof(search_buf), NULL, NULL);
		if (len > 0) {
			search_domain = search_buf;
			search_len = len;
		}
	}

	struct {
		uint16_t type;
		uint16_t len;
	} search = {htons(DHCPV6_OPT_DNS_DOMAIN), htons(search_len)};



	uint8_t pdbuf[512];
	struct iovec iov[] = {{NULL, 0},
			{&dest, (uint8_t*)&dest.clientid_type - (uint8_t*)&dest},
			{&dns, (dns_cnt) ? sizeof(dns) : 0},
			{dns_addr, dns_cnt * sizeof(*dns_addr)},
			{&search, (search_len) ? sizeof(search) : 0},
			{search_domain, search_len},
			{pdbuf, 0},
			{NULL, 0}};

	uint8_t *opts = (uint8_t*)&hdr[1], *opts_end = (uint8_t*)data + len;
	if (hdr->msg_type == DHCPV6_MSG_RELAY_FORW)
		handle_nested_message(data, len, &opts, &opts_end, iov);

	memcpy(dest.tr_id, &opts[-3], sizeof(dest.tr_id));

	if (opts[-4] == DHCPV6_MSG_ADVERTISE || opts[-4] == DHCPV6_MSG_REPLY || opts[-4] == DHCPV6_MSG_RELAY_REPL)
		return;

	if (opts[-4] == DHCPV6_MSG_SOLICIT) {
		dest.msg_type = DHCPV6_MSG_ADVERTISE;
	} else if (opts[-4] == DHCPV6_MSG_INFORMATION_REQUEST) {
		iov[6].iov_base = &refresh;
		iov[6].iov_len = sizeof(refresh);
	}

	// Go through options and find what we need
	uint16_t otype, olen;
	uint8_t *odata;
	dhcpv6_for_each_option(opts, opts_end, otype, olen, odata) {
		if (otype == DHCPV6_OPT_CLIENTID && olen <= 130) {
			dest.clientid_length = htons(olen);
			memcpy(dest.clientid_buf, odata, olen);
			iov[1].iov_len += 4 + olen;
		} else if (otype == DHCPV6_OPT_SERVERID) {
			if (olen != ntohs(dest.serverid_length) ||
					memcmp(odata, &dest.duid_type, olen))
				return; // Not for us
		}
	}

	if (opts[-4] != DHCPV6_MSG_INFORMATION_REQUEST) {
		iov[6].iov_len = dhcpv6_handle_ia(pdbuf, sizeof(pdbuf), iface, addr, &opts[-4], opts_end);
		if (iov[6].iov_len == 0 && opts[-4] == DHCPV6_MSG_REBIND)
			return;
	}

	if (iov[0].iov_len > 0) // Update length
		update_nested_message(data, len, iov[1].iov_len + iov[2].iov_len +
				iov[3].iov_len + iov[4].iov_len + iov[5].iov_len +
				iov[6].iov_len - (4 + opts_end - opts));

	odhcpd_send(iface->dhcpv6_event.uloop.fd, addr, iov, ARRAY_SIZE(iov), iface);
}


// Central DHCPv6-relay handler
static void handle_dhcpv6(void *addr, void *data, size_t len,
		struct interface *iface)
{
	if (iface->dhcpv6 == RELAYD_SERVER) {
		handle_client_request(addr, data, len, iface);
	} else if (iface->dhcpv6 == RELAYD_RELAY) {
		if (iface->master)
			relay_server_response(data, len);
		else
			relay_client_request(addr, data, len, iface);
	}
}


// Relay server response (regular relay server handling)
static void relay_server_response(uint8_t *data, size_t len)
{
	// Information we need to gather
	uint8_t *payload_data = NULL;
	size_t payload_len = 0;
	int32_t ifaceidx = 0;
	struct sockaddr_in6 target = {AF_INET6, htons(DHCPV6_CLIENT_PORT),
		0, IN6ADDR_ANY_INIT, 0};

	syslog(LOG_NOTICE, "Got a DHCPv6-reply");

	int otype, olen;
	uint8_t *odata, *end = data + len;

	// Relay DHCPv6 reply from server to client
	struct dhcpv6_relay_header *h = (void*)data;
	if (len < sizeof(*h) || h->msg_type != DHCPV6_MSG_RELAY_REPL)
		return;

	memcpy(&target.sin6_addr, &h->peer_address,
			sizeof(struct in6_addr));

	// Go through options and find what we need
	dhcpv6_for_each_option(h->options, end, otype, olen, odata) {
		if (otype == DHCPV6_OPT_INTERFACE_ID
				&& olen == sizeof(ifaceidx)) {
			memcpy(&ifaceidx, odata, sizeof(ifaceidx));
		} else if (otype == DHCPV6_OPT_RELAY_MSG) {
			payload_data = odata;
			payload_len = olen;
		}
	}

	// Invalid interface-id or basic payload
	struct interface *iface = odhcpd_get_interface_by_index(ifaceidx);
	if (!iface || iface->master || !payload_data || payload_len < 4)
		return;

	bool is_authenticated = false;
	struct in6_addr *dns_ptr = NULL;
	size_t dns_count = 0;

	// If the payload is relay-reply we have to send to the server port
	if (payload_data[0] == DHCPV6_MSG_RELAY_REPL) {
		target.sin6_port = htons(DHCPV6_SERVER_PORT);
	} else { // Go through the payload data
		struct dhcpv6_client_header *h = (void*)payload_data;
		end = payload_data + payload_len;

		dhcpv6_for_each_option(&h[1], end, otype, olen, odata) {
			if (otype == DHCPV6_OPT_DNS_SERVERS && olen >= 16) {
				dns_ptr = (struct in6_addr*)odata;
				dns_count = olen / 16;
			} else if (otype == DHCPV6_OPT_AUTH) {
				is_authenticated = true;
			}
		}
	}

	// Rewrite DNS servers if requested
	if (iface->always_rewrite_dns && dns_ptr && dns_count > 0) {
		if (is_authenticated)
			return; // Impossible to rewrite

		struct odhcpd_ipaddr ip;
		const struct in6_addr *rewrite = iface->dns;
		size_t rewrite_cnt = iface->dns_cnt;

		if (rewrite_cnt == 0) {
			if (odhcpd_get_interface_addresses(iface->ifindex, &ip, 1) < 1)
				return; // Unable to get interface address

			rewrite = &ip.addr;
			rewrite_cnt = 1;
		}

		// Copy over any other addresses
		for (size_t i = 0; i < dns_count; ++i) {
			size_t j = (i < rewrite_cnt) ? i : rewrite_cnt - 1;
			memcpy(&dns_ptr[i], &rewrite[j], sizeof(*rewrite));
		}
	}

	struct iovec iov = {payload_data, payload_len};
	odhcpd_send(iface->dhcpv6_event.uloop.fd, &target, &iov, 1, iface);
}


// Relay client request (regular DHCPv6-relay)
static void relay_client_request(struct sockaddr_in6 *source,
		const void *data, size_t len, struct interface *iface)
{
	struct interface *master = odhcpd_get_master_interface();
	const struct dhcpv6_relay_header *h = data;
	if (!master || master->dhcpv6 != RELAYD_RELAY ||
			h->msg_type == DHCPV6_MSG_RELAY_REPL ||
			h->msg_type == DHCPV6_MSG_RECONFIGURE ||
			h->msg_type == DHCPV6_MSG_REPLY ||
			h->msg_type == DHCPV6_MSG_ADVERTISE)
		return; // Invalid message types for client

	syslog(LOG_NOTICE, "Got a DHCPv6-request");

	// Construct our forwarding envelope
	struct dhcpv6_relay_forward_envelope hdr = {
		.msg_type = DHCPV6_MSG_RELAY_FORW,
		.hop_count = 0,
		.interface_id_type = htons(DHCPV6_OPT_INTERFACE_ID),
		.interface_id_len = htons(sizeof(uint32_t)),
		.relay_message_type = htons(DHCPV6_OPT_RELAY_MSG),
		.relay_message_len = htons(len),
	};

	if (h->msg_type == DHCPV6_MSG_RELAY_FORW) { // handle relay-forward
		if (h->hop_count >= DHCPV6_HOP_COUNT_LIMIT)
			return; // Invalid hop count
		else
			hdr.hop_count = h->hop_count + 1;
	}

	// use memcpy here as the destination fields are unaligned
	uint32_t ifindex = iface->ifindex;
	memcpy(&hdr.peer_address, &source->sin6_addr, sizeof(struct in6_addr));
	memcpy(&hdr.interface_id_data, &ifindex, sizeof(ifindex));

	// Detect public IP of slave interface to use as link-address
	struct odhcpd_ipaddr ip;
	if (odhcpd_get_interface_addresses(iface->ifindex, &ip, 1) < 1) {
		// No suitable address! Is the slave not configured yet?
		// Detect public IP of master interface and use it instead
		// This is WRONG and probably violates the RFC. However
		// otherwise we have a hen and egg problem because the
		// slave-interface cannot be auto-configured.
		if (odhcpd_get_interface_addresses(master->ifindex, &ip, 1) < 1)
			return; // Could not obtain a suitable address
	}
	memcpy(&hdr.link_address, &ip.addr, sizeof(hdr.link_address));

	struct sockaddr_in6 dhcpv6_servers = {AF_INET6,
			htons(DHCPV6_SERVER_PORT), 0, ALL_DHCPV6_SERVERS, 0};
	struct iovec iov[2] = {{&hdr, sizeof(hdr)}, {(void*)data, len}};
	odhcpd_send(iface->dhcpv6_event.uloop.fd, &dhcpv6_servers, iov, 2, master);
}
