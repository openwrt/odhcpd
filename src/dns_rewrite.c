/**
 * Copyright (C) 2026 odhcpd contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License v2 as published by
 * the Free Software Foundation.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netinet/icmp6.h>
#include <stdlib.h>
#include <string.h>

#include "dns_rewrite.h"

#define ND_OPT_RECURSIVE_DNS 25
#define ND_OPT_DNS_SEARCH 31
#define DHCPV6_OPT_DNS_DOMAIN 24

#define PACKED __attribute__((packed))

struct dhcpv6_client_header {
	uint8_t msg_type;
	uint8_t transaction_id[3];
} PACKED;

struct ra_dns_option {
	uint8_t type;
	uint8_t len;
	uint16_t reserved;
	uint32_t lifetime;
	uint8_t data[];
} PACKED;

static int copy_packet(const uint8_t *packet, size_t packet_len,
		uint8_t **result, size_t *result_len)
{
	uint8_t *copy;

	if (!packet || !result || !result_len)
		return -EINVAL;

	copy = malloc(packet_len ? packet_len : 1);
	if (!copy)
		return -ENOMEM;

	if (packet_len)
		memcpy(copy, packet, packet_len);

	*result = copy;
	*result_len = packet_len;
	return 0;
}

int odhcpd_rewrite_ra_dnssl(const uint8_t *packet, size_t packet_len,
		const uint8_t *search, size_t search_len, uint32_t fallback_lifetime,
		uint8_t **result, size_t *result_len)
{
	const uint8_t *cursor, *end;
	size_t removed_len = 0, option_len, new_len;
	uint32_t dnssl_lifetime = 0, rdnss_lifetime = 0;
	uint8_t *output, *write;

	if (!packet || !result || !result_len || (search_len && !search))
		return -EINVAL;

	*result = NULL;
	*result_len = 0;

	if (!search_len)
		return copy_packet(packet, packet_len, result, result_len);

	if (packet_len < sizeof(struct nd_router_advert) ||
	    search_len > RA_DNSSL_MAX_SEARCH_LEN)
		return -EINVAL;

	end = packet + packet_len;
	cursor = packet + sizeof(struct nd_router_advert);
	while (cursor < end) {
		const struct ra_dns_option *opt;
		size_t len;
		uint32_t lifetime;

		if ((size_t)(end - cursor) < 2 || cursor[1] == 0)
			return -EINVAL;

		len = (size_t)cursor[1] * 8;
		if (len > (size_t)(end - cursor))
			return -EINVAL;

		opt = (const struct ra_dns_option *)cursor;
		if (opt->type == ND_OPT_DNS_SEARCH) {
			if (len < sizeof(*opt))
				return -EINVAL;
			removed_len += len;
			lifetime = ntohl(opt->lifetime);
			if (lifetime > dnssl_lifetime)
				dnssl_lifetime = lifetime;
		} else if (opt->type == ND_OPT_RECURSIVE_DNS) {
			if (len < sizeof(*opt))
				return -EINVAL;
			lifetime = ntohl(opt->lifetime);
			if (lifetime > rdnss_lifetime)
				rdnss_lifetime = lifetime;
		}

		cursor += len;
	}

	if (search_len > SIZE_MAX - 7)
		return -EOVERFLOW;
	option_len = sizeof(struct ra_dns_option) + ((search_len + 7) & ~(size_t)7);
	if (option_len > UINT8_MAX * 8U || packet_len < removed_len ||
	    packet_len - removed_len > SIZE_MAX - option_len)
		return -EOVERFLOW;

	new_len = packet_len - removed_len + option_len;
	output = calloc(1, new_len);
	if (!output)
		return -ENOMEM;

	memcpy(output, packet, sizeof(struct nd_router_advert));
	write = output + sizeof(struct nd_router_advert);
	cursor = packet + sizeof(struct nd_router_advert);
	while (cursor < end) {
		size_t len = (size_t)cursor[1] * 8;

		if (cursor[0] != ND_OPT_DNS_SEARCH) {
			memcpy(write, cursor, len);
			write += len;
		}
		cursor += len;
	}

	struct ra_dns_option *dnssl = (struct ra_dns_option *)write;
	dnssl->type = ND_OPT_DNS_SEARCH;
	dnssl->len = option_len / 8;
	dnssl->reserved = 0;
	dnssl->lifetime = htonl(dnssl_lifetime ? dnssl_lifetime :
					 (rdnss_lifetime ? rdnss_lifetime : fallback_lifetime));
	memcpy(dnssl->data, search, search_len);

	*result = output;
	*result_len = new_len;
	return 0;
}

int odhcpd_rewrite_dhcpv6_domain(const uint8_t *packet, size_t packet_len,
		const uint8_t *search, size_t search_len, bool authenticated,
		uint8_t **result, size_t *result_len)
{
	const uint8_t *cursor, *end;
	size_t removed_len = 0, new_len;
	uint8_t *output, *write;

	if (!packet || !result || !result_len || (search_len && !search))
		return -EINVAL;

	*result = NULL;
	*result_len = 0;

	if (!search_len)
		return copy_packet(packet, packet_len, result, result_len);

	if (packet_len < sizeof(struct dhcpv6_client_header) || search_len > UINT16_MAX)
		return -EINVAL;

	end = packet + packet_len;
	cursor = packet + sizeof(struct dhcpv6_client_header);
	while (cursor < end) {
		uint16_t type, len;

		if ((size_t)(end - cursor) < 4)
			return -EINVAL;

		memcpy(&type, cursor, sizeof(type));
		memcpy(&len, cursor + 2, sizeof(len));
		type = ntohs(type);
		len = ntohs(len);
		if ((size_t)(end - cursor - 4) < len)
			return -EINVAL;

		if (type == DHCPV6_OPT_DNS_DOMAIN)
			removed_len += 4 + len;
		cursor += 4 + len;
	}

	if (authenticated)
		return -EPERM;

	if (packet_len < removed_len || packet_len - removed_len > SIZE_MAX - 4 - search_len)
		return -EOVERFLOW;

	new_len = packet_len - removed_len + 4 + search_len;
	output = malloc(new_len);
	if (!output)
		return -ENOMEM;

	memcpy(output, packet, sizeof(struct dhcpv6_client_header));
	write = output + sizeof(struct dhcpv6_client_header);
	cursor = packet + sizeof(struct dhcpv6_client_header);
	while (cursor < end) {
		uint16_t type, len;

		memcpy(&type, cursor, sizeof(type));
		memcpy(&len, cursor + 2, sizeof(len));
		type = ntohs(type);
		len = ntohs(len);
		if (type != DHCPV6_OPT_DNS_DOMAIN) {
			memcpy(write, cursor, 4 + len);
			write += 4 + len;
		}
		cursor += 4 + len;
	}

	uint16_t type = htons(DHCPV6_OPT_DNS_DOMAIN);
	uint16_t len = htons((uint16_t)search_len);
	memcpy(write, &type, sizeof(type));
	memcpy(write + 2, &len, sizeof(len));
	memcpy(write + 4, search, search_len);

	*result = output;
	*result_len = new_len;
	return 0;
}
