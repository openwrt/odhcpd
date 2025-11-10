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
/* RFC9096 defines recommended option lifetimes configuration values
	ND_PREFERRED_LIMIT 2700
	ND_VALID_LIMIT 5400

	RFC9096  §3.4
	CE routers SHOULD set the "Router Lifetime" of Router Advertisement
	(RA) messages to ND_PREFERRED_LIMIT.

	Note: while the RFC recommends SHOULD of ND_PREFERRED_LIMIT, this
	define is used to cap values to a sane ceiling, i.e. ND_VALID_LIMIT.
*/
#define RouterLifetime					5400
/* RFC4861 §6.2.1 : AdvReachableTime :
 * MUST be no greater than 3,600,000 msec
 */
#define AdvReachableTime				3600000
/* RFC4861 §6.2.1 : AdvCurHopLimit
	The value should be set to the current
	diameter of the Internet.  The value zero means
	unspecified (by this router).

	Note: this value is an 8 bit int, so max 255.
*/
#define AdvCurHopLimit					255
/* RFC4861 §10 - constants
	Node constants:
		RETRANS_TIMER                 1,000 milliseconds
*/
#define RETRANS_TIMER_MAX				60000
/* RFC2460 §5
   IPv6 requires that every link in the internet have an MTU of 1280
   octets or greater.
*/
#define RA_MTU_MIN						1280
#define RA_MTU_MAX						65535

#define ND_RA_FLAG_PROXY		0x4
#define ND_RA_PREF_HIGH			(1 << 3)
#define ND_RA_PREF_LOW			(3 << 3)

/* RFC9762 DHCPv6 PD Availability - Preferred Flag
 * use this until it is defined in netinet/icmp6.h
 */
#define ND_OPT_PI_FLAG_PD_PREFERRED		0x10
