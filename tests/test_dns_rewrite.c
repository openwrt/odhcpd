#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/icmp6.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dns_rewrite.h"

#define ND_OPT_RECURSIVE_DNS 25
#define ND_OPT_DNS_SEARCH 31
#define DHCPV6_OPT_DNS_DOMAIN 24

static const uint8_t speedport_domain[] = {
	9, 's', 'p', 'e', 'e', 'd', 'p', 'o', 'r', 't',
	2, 'i', 'p', 0,
};

static const uint8_t local_domain[] = {
	11, 'g', 'a', 's', 'c', 'h', 'l', 'e', 'r', 'l', 'a', 'n',
	2, 'd', 'e', 0,
};

static const uint8_t second_domain[] = {
	4, 'h', 'o', 'm', 'e',
	7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
	3, 'n', 'e', 't', 0,
};

static void append_ra_option(uint8_t *packet, size_t *packet_len, uint8_t type,
		const uint8_t *data, size_t data_len, uint32_t lifetime)
{
	size_t option_len = 8 + ((data_len + 7) & ~(size_t)7);
	uint32_t lifetime_be = htonl(lifetime);

	packet[*packet_len] = type;
	packet[*packet_len + 1] = option_len / 8;
	memset(packet + *packet_len + 2, 0, option_len - 2);
	memcpy(packet + *packet_len + 4, &lifetime_be, sizeof(lifetime_be));
	if (data_len)
		memcpy(packet + *packet_len + 8, data, data_len);
	*packet_len += option_len;
}

static void append_ra_raw_option(uint8_t *packet, size_t *packet_len, uint8_t type,
		const uint8_t *data, size_t data_len)
{
	size_t option_len = 2 + data_len;

	assert(option_len % 8 == 0 && option_len / 8 <= UINT8_MAX);
	packet[*packet_len] = type;
	packet[*packet_len + 1] = option_len / 8;
	memcpy(packet + *packet_len + 2, data, data_len);
	*packet_len += option_len;
}

static void append_dhcpv6_option(uint8_t *packet, size_t *packet_len,
		uint16_t type, const uint8_t *data, size_t data_len)
{
	uint16_t type_be = htons(type);
	uint16_t len_be = htons(data_len);

	assert(data_len <= UINT16_MAX);
	memcpy(packet + *packet_len, &type_be, sizeof(type_be));
	memcpy(packet + *packet_len + 2, &len_be, sizeof(len_be));
	if (data_len)
		memcpy(packet + *packet_len + 4, data, data_len);
	*packet_len += 4 + data_len;
}

static const uint8_t *find_ra_option(const uint8_t *packet, size_t packet_len,
		uint8_t type, size_t *option_len, unsigned *count)
{
	const uint8_t *found = NULL;
	const uint8_t *cursor = packet + sizeof(struct nd_router_advert);
	const uint8_t *end = packet + packet_len;

	*count = 0;
	while (cursor < end) {
		size_t len = (size_t)cursor[1] * 8;

		assert(len >= 8 && len <= (size_t)(end - cursor));
		if (cursor[0] == type) {
			found = cursor;
			*option_len = len;
			(*count)++;
		}
		cursor += len;
	}
	return found;
}

static const uint8_t *find_dhcpv6_option(const uint8_t *packet, size_t packet_len,
		uint16_t wanted_type, size_t *option_len, unsigned *count)
{
	const uint8_t *found = NULL;
	const uint8_t *cursor = packet + 4;
	const uint8_t *end = packet + packet_len;

	*count = 0;
	while (cursor < end) {
		uint16_t type, len;

		assert((size_t)(end - cursor) >= 4);
		memcpy(&type, cursor, sizeof(type));
		memcpy(&len, cursor + 2, sizeof(len));
		type = ntohs(type);
		len = ntohs(len);
		assert((size_t)(end - cursor - 4) >= len);
		if (type == wanted_type) {
			found = cursor;
			*option_len = 4 + len;
			(*count)++;
		}
		cursor += 4 + len;
	}
	return found;
}

static uint32_t ra_option_lifetime(const uint8_t *option)
{
	uint32_t lifetime;

	memcpy(&lifetime, option + 4, sizeof(lifetime));
	return ntohl(lifetime);
}

static void test_ra_passthrough_without_local_domain(void)
{
	uint8_t packet[128] = {0};
	size_t packet_len = sizeof(struct nd_router_advert);
	uint8_t *result = NULL;
	size_t result_len = 0;

	append_ra_option(packet, &packet_len, ND_OPT_DNS_SEARCH,
			speedport_domain, sizeof(speedport_domain), 180);
	assert(odhcpd_rewrite_ra_dnssl(packet, packet_len, NULL, 0, 900,
			&result, &result_len) == 0);
	assert(result_len == packet_len);
	assert(memcmp(result, packet, packet_len) == 0);
	assert(result != packet);
	free(result);
}

static void test_ra_replaces_all_domains_and_preserves_options(void)
{
	uint8_t packet[256] = {0};
	size_t packet_len = sizeof(struct nd_router_advert);
	uint8_t source_lladdr[6] = {0, 1, 2, 3, 4, 5};
	uint8_t dns_addr[16] = {0xfd, 0xce};
	uint8_t *result = NULL;
	size_t result_len = 0, option_len = 0;
	unsigned count = 0;
	const uint8_t *dnssl, *source;

	append_ra_raw_option(packet, &packet_len, ND_OPT_SOURCE_LINKADDR,
			source_lladdr, sizeof(source_lladdr));
	append_ra_option(packet, &packet_len, ND_OPT_RECURSIVE_DNS,
			dns_addr, sizeof(dns_addr), 180);
	append_ra_option(packet, &packet_len, ND_OPT_DNS_SEARCH,
			speedport_domain, sizeof(speedport_domain), 180);
	append_ra_option(packet, &packet_len, ND_OPT_DNS_SEARCH,
			second_domain, sizeof(second_domain), 300);

	assert(odhcpd_rewrite_ra_dnssl(packet, packet_len, local_domain,
			sizeof(local_domain), 900, &result, &result_len) == 0);
	dnssl = find_ra_option(result, result_len, ND_OPT_DNS_SEARCH,
			&option_len, &count);
	assert(dnssl && count == 1);
	assert(option_len == 8 + sizeof(local_domain));
	assert(ra_option_lifetime(dnssl) == 300);
	assert(memcmp(dnssl + 8, local_domain, sizeof(local_domain)) == 0);

	source = find_ra_option(result, result_len, ND_OPT_SOURCE_LINKADDR,
			&option_len, &count);
	assert(source && count == 1 && option_len == 8);
	assert(memcmp(source + 2, source_lladdr, sizeof(source_lladdr)) == 0);
	assert(memcmp(packet + sizeof(struct nd_router_advert), source, 8) == 0);
	free(result);
}

static void test_ra_adds_domain_and_selects_lifetime(void)
{
	uint8_t packet[128] = {0};
	size_t packet_len = sizeof(struct nd_router_advert);
	uint8_t dns_addr[16] = {0xfd, 0xce};
	uint8_t *result = NULL;
	size_t result_len = 0, option_len = 0;
	unsigned count = 0;
	const uint8_t *dnssl;

	append_ra_option(packet, &packet_len, ND_OPT_RECURSIVE_DNS,
			dns_addr, sizeof(dns_addr), 180);
	assert(odhcpd_rewrite_ra_dnssl(packet, packet_len, local_domain,
			sizeof(local_domain), 900, &result, &result_len) == 0);
	dnssl = find_ra_option(result, result_len, ND_OPT_DNS_SEARCH,
			&option_len, &count);
	assert(dnssl && count == 1 && ra_option_lifetime(dnssl) == 180);
	free(result);

	packet_len = sizeof(struct nd_router_advert);
	assert(odhcpd_rewrite_ra_dnssl(packet, packet_len, local_domain,
			sizeof(local_domain), 900, &result, &result_len) == 0);
	dnssl = find_ra_option(result, result_len, ND_OPT_DNS_SEARCH,
			&option_len, &count);
	assert(dnssl && count == 1 && ra_option_lifetime(dnssl) == 900);
	free(result);
}

static void test_ra_padding_and_per_interface_results(void)
{
	uint8_t packet[128] = {0};
	size_t packet_len = sizeof(struct nd_router_advert);
	uint8_t short_domain[] = {1, 'x', 0};
	uint8_t *first = NULL, *second = NULL;
	size_t first_len = 0, second_len = 0, option_len = 0;
	unsigned count = 0;
	const uint8_t *dnssl;

	append_ra_option(packet, &packet_len, ND_OPT_DNS_SEARCH,
			speedport_domain, sizeof(speedport_domain), 180);
	assert(odhcpd_rewrite_ra_dnssl(packet, packet_len, short_domain,
			sizeof(short_domain), 900, &first, &first_len) == 0);
	assert(odhcpd_rewrite_ra_dnssl(packet, packet_len, local_domain,
			sizeof(local_domain), 900, &second, &second_len) == 0);
	assert(first_len != second_len);
	assert(memcmp(packet + sizeof(struct nd_router_advert) + 8,
			speedport_domain, sizeof(speedport_domain)) == 0);

	dnssl = find_ra_option(first, first_len, ND_OPT_DNS_SEARCH,
			&option_len, &count);
	assert(dnssl && option_len == 16);
	assert(memcmp(dnssl + 8, short_domain, sizeof(short_domain)) == 0);
	for (size_t i = 8 + sizeof(short_domain); i < option_len; i++)
		assert(dnssl[i] == 0);
	free(first);
	free(second);
}

static void test_multiple_local_domains_keep_their_order(void)
{
	uint8_t packet[128] = {0};
	uint8_t search[sizeof(local_domain) + sizeof(second_domain)];
	size_t packet_len = sizeof(struct nd_router_advert);
	uint8_t *result = NULL;
	size_t result_len = 0, option_len = 0;
	unsigned count = 0;
	const uint8_t *dnssl;

	memcpy(search, local_domain, sizeof(local_domain));
	memcpy(search + sizeof(local_domain), second_domain, sizeof(second_domain));
	append_ra_option(packet, &packet_len, ND_OPT_DNS_SEARCH,
			speedport_domain, sizeof(speedport_domain), 180);

	assert(odhcpd_rewrite_ra_dnssl(packet, packet_len, search, sizeof(search),
			900, &result, &result_len) == 0);
	dnssl = find_ra_option(result, result_len, ND_OPT_DNS_SEARCH,
			&option_len, &count);
	assert(dnssl && count == 1);
	assert(memcmp(dnssl + 8, search, sizeof(search)) == 0);
	free(result);
}

static void test_ra_rejects_malformed_and_oversized_input(void)
{
	uint8_t packet[64] = {0};
	uint8_t oversized[RA_DNSSL_MAX_SEARCH_LEN + 1] = {0};
	size_t packet_len = sizeof(struct nd_router_advert) + 8;
	uint8_t *result = NULL;
	size_t result_len = 0;

	packet[sizeof(struct nd_router_advert)] = ND_OPT_DNS_SEARCH;
	packet[sizeof(struct nd_router_advert) + 1] = 0;
	assert(odhcpd_rewrite_ra_dnssl(packet, packet_len, local_domain,
			sizeof(local_domain), 900, &result, &result_len) == -EINVAL);
	assert(!result && result_len == 0);

	packet[sizeof(struct nd_router_advert) + 1] = 2;
	assert(odhcpd_rewrite_ra_dnssl(packet, packet_len, local_domain,
			sizeof(local_domain), 900, &result, &result_len) == -EINVAL);
	assert(odhcpd_rewrite_ra_dnssl(packet, sizeof(struct nd_router_advert),
			oversized, sizeof(oversized), 900, &result, &result_len) == -EINVAL);
}

static void test_dhcpv6_passthrough_and_rewrite(void)
{
	uint8_t packet[256] = {7, 0xaa, 0xbb, 0xcc};
	size_t packet_len = 4;
	uint8_t server_id[] = {1, 2, 3, 4};
	uint8_t *result = NULL;
	size_t result_len = 0, option_len = 0;
	unsigned count = 0;
	const uint8_t *domain, *other;

	append_dhcpv6_option(packet, &packet_len, 2, server_id, sizeof(server_id));
	append_dhcpv6_option(packet, &packet_len, DHCPV6_OPT_DNS_DOMAIN,
			speedport_domain, sizeof(speedport_domain));
	append_dhcpv6_option(packet, &packet_len, DHCPV6_OPT_DNS_DOMAIN,
			second_domain, sizeof(second_domain));

	assert(odhcpd_rewrite_dhcpv6_domain(packet, packet_len, NULL, 0, false,
			&result, &result_len) == 0);
	assert(result_len == packet_len && memcmp(result, packet, packet_len) == 0);
	free(result);

	assert(odhcpd_rewrite_dhcpv6_domain(packet, packet_len, local_domain,
			sizeof(local_domain), false, &result, &result_len) == 0);
	assert(memcmp(result, packet, 4) == 0);
	domain = find_dhcpv6_option(result, result_len, DHCPV6_OPT_DNS_DOMAIN,
			&option_len, &count);
	assert(domain && count == 1 && option_len == 4 + sizeof(local_domain));
	assert(memcmp(domain + 4, local_domain, sizeof(local_domain)) == 0);
	other = find_dhcpv6_option(result, result_len, 2, &option_len, &count);
	assert(other && count == 1 && option_len == 8);
	assert(memcmp(other + 4, server_id, sizeof(server_id)) == 0);
	free(result);
}

static void test_dhcpv6_adds_domain_and_rejects_unsafe_packets(void)
{
	uint8_t packet[64] = {7, 1, 2, 3};
	size_t packet_len = 4;
	uint8_t value[] = {42};
	uint8_t *result = NULL;
	size_t result_len = 0, option_len = 0;
	unsigned count = 0;
	const uint8_t *domain;

	append_dhcpv6_option(packet, &packet_len, 2, value, sizeof(value));
	assert(odhcpd_rewrite_dhcpv6_domain(packet, packet_len, local_domain,
			sizeof(local_domain), false, &result, &result_len) == 0);
	domain = find_dhcpv6_option(result, result_len, DHCPV6_OPT_DNS_DOMAIN,
			&option_len, &count);
	assert(domain && count == 1);
	free(result);

	assert(odhcpd_rewrite_dhcpv6_domain(packet, packet_len, local_domain,
			sizeof(local_domain), true, &result, &result_len) == -EPERM);
	packet[6] = 0xff;
	packet[7] = 0xff;
	assert(odhcpd_rewrite_dhcpv6_domain(packet, packet_len, local_domain,
			sizeof(local_domain), false, &result, &result_len) == -EINVAL);
}

int main(void)
{
	test_ra_passthrough_without_local_domain();
	test_ra_replaces_all_domains_and_preserves_options();
	test_ra_adds_domain_and_selects_lifetime();
	test_ra_padding_and_per_interface_results();
	test_multiple_local_domains_keep_their_order();
	test_ra_rejects_malformed_and_oversized_input();
	test_dhcpv6_passthrough_and_rewrite();
	test_dhcpv6_adds_domain_and_rejects_unsafe_packets();
	puts("dns_rewrite tests passed");
	return 0;
}
