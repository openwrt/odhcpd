#include <unistd.h>
#include <stddef.h>

#include <libubox/list.h>

#include "dhcpv6.h"
#include "dhcpv6-pxe.h"

struct ipv6_pxe_entry {
	struct list_head list;	// List head for linking
	uint32_t arch;

	// Ready to send
	struct __attribute__((packed)) {
		uint16_t type;		// In network endianess
		uint16_t len;		// In network endianess, without /0
		char payload[];		// Null-terminated here
	} bootfile_url;
};

static struct ipv6_pxe_entry* ipv6_pxe_default = NULL;
LIST_HEAD(ipv6_pxe_list);

const struct ipv6_pxe_entry* ipv6_pxe_entry_new(uint32_t arch, const char* url) {
	size_t url_len = strlen(url);
	struct ipv6_pxe_entry* ipe = malloc(sizeof(struct ipv6_pxe_entry) + url_len + 1);
	if (!ipe)
		return NULL;

	memcpy(ipe->bootfile_url.payload, url, url_len + 1);
	ipe->bootfile_url.len = htons(url_len);
	ipe->bootfile_url.type = htons(DHCPV6_OPT_BOOTFILE_URL);

	if (arch == 0xFFFFFFFF) {
		ipv6_pxe_default = ipe;
	}
	else {
		ipe->arch = arch;
		list_add(&ipe->list, &ipv6_pxe_list);
	}

	return ipe;
}

const struct ipv6_pxe_entry* ipv6_pxe_of_arch(uint16_t arch) {
	struct ipv6_pxe_entry* entry;
	list_for_each_entry(entry, &ipv6_pxe_list, list) {
		if (arch == entry->arch)
			return entry;
	}

	return ipv6_pxe_default;
}

void ipv6_pxe_serve_boot_url(uint16_t arch, struct iovec* iov) {
	const struct ipv6_pxe_entry* entry = ipv6_pxe_of_arch(arch);

	if (entry == NULL) {
		// No IPv6 PxE bootfile defined
		iov->iov_base = NULL;
		iov->iov_len = 0;
	}
	else {
		iov->iov_base = (void*)&(entry->bootfile_url);
		iov->iov_len = 4 + ntohs(entry->bootfile_url.len);
		syslog(LOG_INFO, "Serve IPv6 PxE, arch = %d, url = %s", arch, entry->bootfile_url.payload);
	}
}

void ipv6_pxe_dump(void) {
	struct ipv6_pxe_entry* entry;
	int count = 0;

	if (ipv6_pxe_default)
		count++;

	list_for_each_entry(entry, &ipv6_pxe_list, list) {
		count++;
	}

	if (count) {
		syslog(LOG_INFO, "IPv6 PxE URLs:\n");

		list_for_each_entry(entry, &ipv6_pxe_list, list) {
			syslog(LOG_INFO, "    arch %04d = %s\n", entry->arch, entry->bootfile_url.payload);
		}

		if (ipv6_pxe_default)
			syslog(LOG_INFO, "    Default   = %s\n", ipv6_pxe_default->bootfile_url.payload);
	}
}

void ipv6_pxe_clear(void) {
	struct ipv6_pxe_entry* entry, * temp;
	list_for_each_entry_safe(entry, temp, &ipv6_pxe_list, list) {
		list_del(&entry->list);
		free(entry);
	}

	if (ipv6_pxe_default) {
		free(ipv6_pxe_default);
		ipv6_pxe_default = NULL;
	}
}
