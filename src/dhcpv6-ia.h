/**
 * Copyright (C) 2013 Steven Barth <steven@midlink.org>
 * Copyright (C) 2016 Hans Dedecker <dedeckeh@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License v2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 */

#ifndef _DHCPV6_IA_H_
#define _DHCPV6_IA_H_

#define ADDR_ENTRY_VALID_IA_ADDR(iface, i, m, addrs) \
	((iface)->dhcpv6_assignall || \
	 (i) == (m) || \
	 (addrs)[(i)].prefix_len > 64)

size_t get_preferred_addr(const struct odhcpd_ipaddr *addrs, const size_t addrlen);

struct in6_addr in6_from_prefix_and_iid(const struct odhcpd_ipaddr *prefix, uint64_t iid);

static inline bool valid_prefix_length(const struct dhcpv6_lease *a, const uint8_t prefix_length)
{
	return a->length > prefix_length;
}

static inline bool valid_addr(const struct odhcpd_ipaddr *addr, time_t now)
{
	return (addr->prefix_len <= 96 && addr->valid_lt > (uint32_t)now && addr->preferred_lt > (uint32_t)now);
}

#endif /* _DHCPV6_IA_H_ */
