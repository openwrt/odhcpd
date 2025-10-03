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
	uint8_t data[6];
};


#define icmpv6_for_each_option(opt, start, end)\
	for (opt = (struct icmpv6_opt*)(start);\
	(void*)(opt + 1) <= (void*)(end) && opt->len > 0 &&\
	(void*)(opt + opt->len) <= (void*)(end); opt += opt->len)


#define MaxInitialRtrAdvInterval	16
#define MaxInitialRtAdvs		3
/* RFC8319 §4
	This document updates §4.2 and 6.2.1 of [RFC4861] to change
	the following router configuration variables.

	In §6.2.1, inside the paragraph that defines
	MaxRtrAdvInterval, change 1800 to 65535 seconds.

	In §6.2.1, inside the paragraph that defines
	AdvDefaultLifetime, change 9000 to 65535 seconds.
*/
#define MaxRtrAdvInterval				65535
#define MinRtrAdvInterval				3
#define AdvDefaultLifetime				65535
/* RFC8319 §4
	This document updates §4.2 and 6.2.1 of [RFC4861] to change
	the following router configuration variables.

	In §4.2, inside the paragraph that defines Router Lifetime,
	change 9000 to 65535 seconds.

	Note: this is 16 bit Router Lifetime field in RA packets
*/
#define RouterLifetime					65535

#define ND_RA_FLAG_PROXY		0x4
#define ND_RA_PREF_HIGH			(1 << 3)
#define ND_RA_PREF_LOW			(3 << 3)
