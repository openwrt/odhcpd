/*
 * SPDX-FileCopyrightText: 2024 David Härdeman <david@hardeman.nu>
 *
 * SPDX-License-Identifier: GPL2.0-only
 */

#ifndef _STATEFILES_H_
#define _STATEFILES_H_

void dhcpv6_ia_enum_addrs(struct interface *iface, struct dhcpv6_lease *lease,
			  time_t now, dhcpv6_binding_cb_handler_t func, void *arg);

void dhcpv6_ia_write_statefile(void);

#endif /* _STATEFILES_H_ */
