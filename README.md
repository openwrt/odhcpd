# odhcpd - Embedded DHCP/DHCPv6/RA Server & Relay

## Abstract

odhcpd is a daemon for serving and relaying IP management protocols to
configure clients and downstream routers. It tries to follow the RFC 6204
requirements for IPv6 home routers.

odhcpd provides server services for DHCP, RA, stateless and stateful DHCPv6,
prefix delegation and can be used to relay RA, DHCPv6 and NDP between routed
(non-bridged) interfaces in case no delegated prefixes are available.


## Features

1. Router Discovery support (solicitations and advertisements) with 2 modes:
   * server: RD server for slave interfaces
     * automatic detection of prefixes, delegated prefix and default routes, MTU
     * automatic reannouncement when changes to prefixes or routes occur

   * relay: RD relay between master and slave interfaces
     * support for rewriting announced DNS-server addresses in relay mode

2. DHCPv6-support with 2 modes of operation
   * server: stateless, stateful and PD-server mode
     * stateless and stateful address assignment
     * prefix delegation support
     * dynamic reconfiguration in case prefixes change
     * hostname detection and hosts-files creation

   * relay: mostly standards-compliant DHCPv6-relay
     * support for rewriting announced DNS-server addresses

3. DHCPv4-support
   * server: stateless and stateful mode

4. Proxy for Neighbor Discovery messages (solicitations and advertisements)
   * support for auto-learning routes to the local routing table
   * support for marking interfaces "external" not proxying NDP for them
     and only serving NDP for DAD and for traffic to the router itself
     [Warning: you should provide additional firewall rules for security]

5. IPv6 PxE Support


## Compiling

odhcpd uses cmake:
* To prepare a Makefile use: `cmake .`
* To build / install use: `make` / `make install` afterwards.
* To build DEB or RPM packages use: `make package` afterwards.


## Configuration

odhcpd uses a UCI configuration file in `/etc/config/dhcp` for configuration
and may also receive information from ubus


### Section of type odhcpd

| Option	| Type	|Default| Description |
| :------------ | :---- | :----	| :---------- |
| maindhcp	| bool	| 0	| Use odhcpd as the main DHCPv4 service |
| leasefile	| string|	| DHCPv4/6 lease file |
| leasetrigger	| string|	| Lease trigger script |
| hostsdir	| string|	| DHCPv4/v6 hostfile directory (one file per interface will be created) |
| loglevel	|integer| 6	| Syslog level priority (0-7) |
| piodir	|string |	| Directory to store IPv6 prefix information (to detect stale prefixes, see RFC9096, §3.5) |
| enable_tz |bool | 1 | Toggle whether RFC4833 timezone information is sent to clients, if set in system  |


### Sections of type dhcp (configure DHCP / DHCPv6 / RA / NDP service)

| Option		| Type	|Default| Description |
| :-------------------- | :---- | :---- | :---------- |
| interface		|string	|`<name of UCI section>`| logical OpenWrt interface |
| ifname		|string	|`<resolved from logical>`| physical network interface |
| networkid		|string	|same as ifname| compat. alias for ifname |
| master		|bool	| 0	| is a master interface for relaying |
| ra			|string	|disabled| Router Advert service [disabled\|server\|relay\|hybrid] |
| dhcpv6		|string	|disabled| DHCPv6 service [disabled\|server\|relay\|hybrid] |
| dhcpv4		|string	|disabled| DHCPv4 service [disabled\|server] |
| ndp			|string	|disabled| Neighbor Discovery Proxy [disabled\|relay\|hybrid] |
| dynamicdhcp		|bool	| 1	| Dynamically create leases for DHCPv4 and DHCPv6 |
| dhcpv4_forcereconf	|bool	| 0	| Force reconfiguration by sending force renew message even if the client did not include the force renew nonce capability option (RFC6704) |
| dhcpv6_assignall	|bool	| 1	| Assign all viable DHCPv6 addresses in statefull mode; if disabled only the DHCPv6 address having the longest preferred lifetime is assigned |
| dhcpv6_hostidlength	|integer| 12	| Host ID length of dynamically created leases, allowed values: 12 - 64 (bits). |
| dhcpv6_na		|bool	| 1	| DHCPv6 stateful addressing hands out IA_NA - Internet Address - Network Address |
| dhcpv6_pd		|bool	| 1	| DHCPv6 stateful addressing hands out IA_PD - Internet Address - Prefix Delegation (PD) |
| dhcpv6_pd_preferred   |bool | 0 | Set the DHCPv6-PD Preferred (P) flag in outgoing ICMPv6 RA message PIOs (RFC9762); requires `dhcpv6` and `dhcpv6_pd`. |
| dhcpv6_pd_min_len	|integer| -	| Minimum prefix length to delegate with IA_PD (value is adjusted if needed to be greater than the interface prefix length).  Range [1,62] |
| router		|list	|`<local address>`| IPv4 addresses of routers on a given subnet (provided via DHCPv4, should be in order of preference) |
| dns			|list	|`<local address>`| DNS servers to announce, accepts IPv4 and IPv6 |
| dnr			|list	|disabled| Encrypted DNS servers to announce, `<priority> <domain name> [<comma separated IP addresses> <SvcParams (key=value)>...]` |
| dns_service		|bool	| 1	| Announce the address of interface as DNS service if the list of dns is empty |
| domain		|list	|`<local search domain>`| Search domains to announce |
| leasetime		|string	| 12h	| DHCPv4 address leasetime |
| start			|integer| 100	| DHCPv4 pool start |
| limit			|integer| 150	| DHCPv4 pool size |
| max_preferred_lifetime|string	| 45m	| Upper limit for the preferred lifetime for a prefix |
| max_valid_lifetime	|string	| 90m	| Upper limit for the valid lifetime for a prefix |
| ra_default		|integer| 0	| Override default route - 0: default, 1: ignore no public address, 2: ignore all |
| ra_flags		|list	|other-config| List of RA flags to be advertised in RA messages [managed-config\|other-config\|home-agent\|none] |
| ra_slaac		|bool	| 1	| Advertise that prefixes (which are <= 64 bits long) on this interface can be used for SLAAC (the "A" flag in the PIO, RFC4861, §4.6.2) |
| ra_advrouter		|bool   | 0	| Advertise the IPv6 address of this router in RA messages (the "R" flag in the PIO, RFC6275, §7.2) |
| ra_offlink		|bool	| 0	| Announce prefixes off-link |
| ra_preference		|string	| medium| Route(r) preference [medium\|high\|low] |
| ra_maxinterval	|integer| 600	| Maximum time allowed between sending unsolicited RA |
| ra_mininterval	|integer| 200	| Minimum time allowed between sending unsolicited RA |
| ra_lifetime		|integer| 2700	| Value to be placed in Router Lifetime field of RA. Not recommended to be more than 2700 (RFC9096). |
| ra_reachabletime	|integer| 0	| Reachable Time in milliseconds to be advertised in RA messages |
| ra_retranstime	|integer| 0	| Retransmit Time in milliseconds to be advertised in RA messages |
| ra_hoplimit		|integer| 0	| Current hoplimit to be advertised in RA messages |
| ra_mtu		|integer| -	| MTU to be advertised in RA messages |
| ra_dns		|bool	| 1	| Announce DNS configuration in RA messages (RFC8106) |
| ra_pref64		|string	| -	| Announce PREF64 option for NAT64 prefix (RFC8781) [IPv6 prefix] |
| ndproxy_routing	|bool	| 1	| Learn routes from NDP |
| ndproxy_slave		|bool	| 0	| NDProxy external slave |
| ndp_from_link_local	|bool	| 1	| Use link-local source addresses for NDP operations (RFC 4861, §4.2 compliance) and macOS compatibility |
| prefix_filter		|string	|`::/0`	| Only advertise on-link prefixes within the provided IPv6 prefix; others are filtered out. [IPv6 prefix] |
| ntp			|list	|`<local address>`| NTP servers to announce accepts IPv4 and IPv6 |
| upstream		|list	| -	| A list of interfaces which can be used as a source of configuration information (e.g. for NTP servers, if not set explicitly). |
| captive_portal_uri |string | no  | The API URI to be sent in RFC8910 captive portal options, via DHCPv4, DHCPv6, and ICMPv6 RA. |
| ipv6_only_preferred   |integer| 0 | Indicate that IPv6-only mode is preferred (RFC8925) [V6ONLY_WAIT time in seconds] |

[//]: # "dhcpv6_raw - string - not documented, may change when generic DHCPv4/DHCPv6 options are added"


### Sections of type host (static leases)
| Option		| Type	|Default| Description |
| :-------------------- | :---- | :---- | :---------- |
| ip			|string	|(none) | IPv4 host address or `ignore` to ignore any DHCPv4 request from this host |
| mac			|list\|string|(none) | HexadecimalMACaddress(es) |
| duid			|list\|string|(none) | Hexadecimal DUID(s), or DUID%IAID(s) |
| hostid		|string	|(none)	| IPv6 tokenised IID or `ignore` to ignore any DHCPv6 request from this host |
| name			|string	|(none) | Hostname |
| leasetime		|string	|(none) | DHCPv4/v6leasetime |


### Sections of type boot6
| Option	| Type	|Required|Description |
| :------------ | :---- | :----	| :---------- |
| url		|string	| yes	| e.g. `tftp://[fd11::1]/pxe.efi` |
| arch		|integer| no	| the arch code. `07` is EFI. If not present, this boot6 will be the default. |

odhcpd also uses the UCI configuration file `/etc/config/network` for configuration
of the following options:

### Section of type globals
| Option            | Type	|Required|Description |
| :----------------	| :---- | :----	| :---------- |
| dhcp_default_duid |string | no	| The DUID to use to identify the DHCPv6 server to clients. |


### System variables for Timezone options (uci system.system)
| Option  | Type  |Required|Description |
| :------------ | :---- | :---- | :---------- |
| timezone   |string | no | e.g. `EST5EDT4,M3.2.0/02:00,M11.1.0/02:00` |
| zonename    |string| no  | e.g. `Europe/Zurich` |


## ubus Interface

odhcpd currently exposes the following methods under the `dhcp` object path:

| Method	| Arguments	| Description |
| :------------ | :------------ | :---------- |
| `ipv4leases`  | `none`	| Lists all currently active DHCPv4 leases per interface |
| `ipv6leases`	| `none`	| Lists all currently active DHCPv6 leases per interface |
| `ipv6ra`	| `none`	| Lists announced IPv6 prefixes per interface |
| `add_lease`	| options as in the cfg `host` section | Creates a new static lease, the arguments need to be formatted as a valid JSON string |

These can be called by running e.g. `ubus call dhcp ipv6leases` on your OpenWrt
device.

odhcpd currently broadcasts the following events via ubus:

| Name		| Parameters			| Description	|
| :------------ | :----------------------------	| :------------ |
| `dhcp.ack`	| `mac,ip,name,interface`	| A new DHCPv4 lease has been created |
| `dhcp.release`| `mac,ip,name,interface`	| A DHCPv4 lease has been released by a client |
| `dhcp.expire`	| `mac,ip,name,interface`	| A DHCPv4 lease has expired |

These can be observed by running e.g. `ubus listen dhcp` on your OpenWrt device.
