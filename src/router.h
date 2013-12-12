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
 */

#pragma once
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>

struct icmpv6_opt {
	uint8_t type;
	uint8_t len;
};

struct nd_opt_slla {
	uint8_t type;
	uint8_t len;
	uint8_t addr[6];
};

struct nd_opt_recursive_dns {
	uint8_t type;
	uint8_t len;
	uint8_t pad;
	uint8_t pad2;
	uint32_t lifetime;
};

#define icmpv6_for_each_option(opt, start, end)\
	for (opt = (struct icmpv6_opt *)(start);\
	((void *)opt < (void *)end) && \
	(void *)((uint8_t *)opt + (opt->len << 3)) <= (void *)(end); \
	opt = (struct icmpv6_opt *)((uint8_t *)opt + (opt->len << 3)))

#define MaxRtrAdvInterval 600
#define MinRtrAdvInterval (MaxRtrAdvInterval / 3)
#define MaxValidTime 7200
#define MaxPreferredTime  (3 * MaxRtrAdvInterval)

#define ND_RA_FLAG_PROXY	0x4
#define ND_RA_PREF_HIGH	(1 << 3)
#define ND_RA_PREF_LOW		(3 << 3)
