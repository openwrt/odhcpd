/**
 * Copyright (C) 2026 odhcpd contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License v2 as published by
 * the Free Software Foundation.
 */

#ifndef _DNS_REWRITE_H_
#define _DNS_REWRITE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* An RA option is at most 255 8-byte units. The DNSSL header uses 8 bytes. */
#define RA_DNSSL_MAX_SEARCH_LEN (UINT8_MAX * 8U - 8U)

int odhcpd_rewrite_ra_dnssl(const uint8_t *packet, size_t packet_len,
		const uint8_t *search, size_t search_len, uint32_t fallback_lifetime,
		uint8_t **result, size_t *result_len);

int odhcpd_rewrite_dhcpv6_domain(const uint8_t *packet, size_t packet_len,
		const uint8_t *search, size_t search_len, bool authenticated,
		uint8_t **result, size_t *result_len);

#endif
