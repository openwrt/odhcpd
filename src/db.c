/*
 * SPDX-FileCopyrightText: 2026 David Härdeman <david@hardeman.nu>
 *
 * SPDX-License-Identifier: GPL2.0-only
 */

/*
 * Per-interface database:
 *
 *  - iface->addr6_db: IPv6 addresses in use by clients
 *  - iface->duid_db: DUIDs in use by clients
 */

#include <stdlib.h>
#include <string.h>

#include "odhcpd.h"

static int addr6_db_cmp(const void *k1, const void *k2, _o_unused void *ptr)
{
	return memcmp(k1, k2, sizeof(struct in6_addr));
}

/* Key: duid_len, DUID */
static int duid_db_cmp(const void *k1, const void *k2, _o_unused void *ptr)
{
	const uint8_t *d1 = k1, *d2 = k2;

	if (d1[0] != d2[0])
		return d1[0] - d2[0];

	return memcmp(&d1[1], &d2[1], d1[0]);
}

void db_init_iface(struct interface *iface)
{
	avl_init(&iface->addr6_db, addr6_db_cmp, false, NULL);
	avl_init(&iface->duid_db, duid_db_cmp, false, NULL);
}

struct duid_rec *duid_rec_find(struct interface *iface, const uint8_t *duid, size_t len)
{
	uint8_t key[1 + DUID_MAX_LEN];
	struct duid_rec *rec;

	if (len < DUID_MIN_LEN || len > DUID_MAX_LEN)
		return NULL;

	key[0] = len;
	memcpy(&key[1], duid, len);

	return avl_find_element(&iface->duid_db, key, rec, avl);
}

/* Get/create a DUID record */
struct duid_rec *duid_rec_get(struct interface *iface, const uint8_t *duid, size_t len)
{
	struct duid_rec *rec = duid_rec_find(iface, duid, len);

	if (rec) {
		rec->refcnt++;
		return rec;
	}

	if (len < DUID_MIN_LEN || len > DUID_MAX_LEN)
		return NULL;

	rec = calloc(1, sizeof(*rec) + len);
	if (!rec)
		return NULL;

	rec->iface = iface;
	rec->refcnt = 1;
	INIT_LIST_HEAD(&rec->addr6_recs);
	INIT_LIST_HEAD(&rec->lease_cfg_list);
	rec->duid_len = len;
	memcpy(rec->duid, duid, len);
	rec->avl.key = &rec->duid_len;

	if (avl_insert(&iface->duid_db, &rec->avl)) {
		free(rec);
		return NULL;
	}

	config_link_duid_rec(rec);

	return rec;
}

void duid_rec_put(struct duid_rec *rec)
{
	if (!rec || --rec->refcnt > 0)
		return;

	avl_delete(&rec->iface->duid_db, &rec->avl);
	list_del(&rec->lease_cfg_list);
	free(rec->hostname);
	free(rec);
}

struct addr6_rec *addr6_rec_find(struct interface *iface, const struct in6_addr *addr6)
{
	struct addr6_rec *rec;

	return avl_find_element(&iface->addr6_db, addr6, rec, avl);
}

/* Add an address to a DUID record */
struct addr6_rec *addr6_rec_add(struct interface *iface, const struct in6_addr *addr6,
				struct duid_rec *duid_rec)
{
	struct addr6_rec *rec = calloc(1, sizeof(*rec));

	if (!rec)
		return NULL;

	rec->addr6 = *addr6;
	rec->avl.key = &rec->addr6;

	if (avl_insert(&iface->addr6_db, &rec->avl)) {
		free(rec);
		return NULL;
	}

	duid_rec->refcnt++;
	rec->duid_rec = duid_rec;
	list_add_tail(&rec->duid_rec_list, &duid_rec->addr6_recs);

	return rec;
}

/* Move an address to another DUID record */
void addr6_rec_set_duid_rec(struct addr6_rec *rec, struct duid_rec *duid_rec)
{
	struct duid_rec *old = rec->duid_rec;

	if (old == duid_rec)
		return;

	duid_rec->refcnt++;
	rec->duid_rec = duid_rec;
	list_move_tail(&rec->duid_rec_list, &duid_rec->addr6_recs);
	duid_rec_put(old);
}

void addr6_rec_del(struct interface *iface, struct addr6_rec *rec)
{
	avl_delete(&iface->addr6_db, &rec->avl);
	list_del(&rec->duid_rec_list);
	duid_rec_put(rec->duid_rec);
	free(rec);
}

/* Delete the addresses of a DUID record (which may free it), return the count */
size_t duid_rec_del_addr6s(struct duid_rec *rec)
{
	struct addr6_rec *a, *tmp;
	size_t cnt = 0;

	rec->refcnt++;
	list_for_each_entry_safe(a, tmp, &rec->addr6_recs, duid_rec_list) {
		addr6_rec_del(rec->iface, a);
		cnt++;
	}
	duid_rec_put(rec);

	return cnt;
}

/* Delete the addresses within a prefix, return the count */
size_t addr6_db_del_prefix(struct interface *iface, const struct in6_addr *prefix, uint8_t len)
{
	struct addr6_rec *rec, *next;
	struct in6_addr start = IN6ADDR_ANY_INIT;
	size_t cnt = 0;

	if (len > 128)
		return 0;

	/* The lowest address in the prefix */
	memcpy(&start, prefix, len / 8);
	if (len % 8)
		start.s6_addr[len / 8] = prefix->s6_addr[len / 8] & (0xff << (8 - len % 8));

	if (avl_is_empty(&iface->addr6_db))
		return 0;

	rec = avl_find_ge_element(&iface->addr6_db, &start, rec, avl);
	while (rec && !odhcpd_bmemcmp(&rec->addr6, &start, len)) {
		next = avl_is_last(&iface->addr6_db, &rec->avl) ?
			NULL : avl_next_element(rec, avl);
		addr6_rec_del(iface, rec);
		rec = next;
		cnt++;
	}

	return cnt;
}

/* Delete all records of an interface */
void db_flush_iface(struct interface *iface)
{
	struct addr6_rec *rec, *tmp;

	avl_for_each_element_safe(&iface->addr6_db, rec, avl, tmp)
		addr6_rec_del(iface, rec);
}
