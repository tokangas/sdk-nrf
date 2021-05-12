/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef LTELC_SHELL_PDN_H
#define LTELC_SHELL_PDN_H
#include <shell/shell.h>
#include <modem/pdn.h>

void ltelc_shell_pdn_init(const struct shell *shell);

int ltelc_shell_pdn_connect(const struct shell *shell, const char *apn_name,
			    const char *family_str);
int ltelc_shell_pdn_disconnect(const struct shell *shell, int pdn_cid);

int ltelc_family_str_to_pdn_lib_family(enum pdn_fam *ret_fam, const char *family);
const char *ltelc_pdn_lib_family_to_string(enum pdn_fam pdn_family, char *out_fam_str);

#endif /* LTELC_SHELL_PDN_H */
