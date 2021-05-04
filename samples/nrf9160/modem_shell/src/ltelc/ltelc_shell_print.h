/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef LTELC_SHELL_PRINT_H
#define LTELC_SHELL_PRINT_H

#include <shell/shell.h>
#include <modem/lte_lc.h>

void ltelc_shell_print_reg_status(const struct shell *shell,
				  enum lte_lc_nw_reg_status reg_status);

void ltelc_shell_print_modem_sleep_notif(const struct shell *shell, const struct lte_lc_evt *const evt);
const char *ltelc_shell_funmode_to_string(int funmode, char *out_str_buff);
const char *ltelc_shell_sysmode_to_string(int sysmode, char *out_str_buff);
const char *ltelc_shell_sysmode_preferred_to_string(int sysmode_preference, char *out_str_buff);
const char *ltelc_shell_sysmode_currently_active_to_string(int actmode, char *out_str_buff);

#endif /* LTELC_SHELL_PRINT_H */
