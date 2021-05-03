/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef LTELC_SHELL_PDN_H
#define LTELC_SHELL_PDN_H
#include <shell/shell.h>

int ltelc_shell_pdn_connect(
	const struct shell *shell, const char *apn_name, const char *family_str);
int ltelc_shell_pdn_disconnect(const struct shell *shell, int pdn_cid);
void ltelc_shell_pdn_init(const struct shell *shell);

#endif /* LTELC_SHELL_PDN_H */
