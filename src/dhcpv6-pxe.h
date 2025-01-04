#pragma once

#include <unistd.h>
#include <stddef.h>

// The detail is hidden except for dhcpv6-pxe.c
struct ipv6_pxe_entry;

const struct ipv6_pxe_entry* ipv6_pxe_entry_new(uint32_t arch, const char* url);
const struct ipv6_pxe_entry* ipv6_pxe_of_arch(uint16_t arch);
void ipv6_pxe_serve_boot_url(uint16_t arch, struct iovec* iov);
void ipv6_pxe_dump(void);
void ipv6_pxe_clear(void);
