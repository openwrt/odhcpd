/*
 * SPDX-FileCopyrightText: 2024 David Härdeman <david@hardeman.nu>
 *
 * SPDX-License-Identifier: GPL2.0-only
 */

#ifndef _STATEFILES_H_
#define _STATEFILES_H_

#define ODHCPD_HOSTS_FILE_PREFIX "odhcpd.hosts"
#define ODHCPD_TMP_FILE ".odhcpd.tmp"

bool statefiles_write(void);

void statefiles_setup_dirfd(const char *path, int *dirfdp);

#endif /* _STATEFILES_H_ */
