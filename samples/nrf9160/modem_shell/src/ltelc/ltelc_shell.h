/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef LTELC_SHELL_H
#define LTELC_SHELL_H
#include <shell/shell.h>
#include <modem/lte_lc.h>

int ltelc_shell(const struct shell *shell, size_t argc, char **argv);

const char *ltelc_shell_sysmode_to_string(int sysmode, char *out_str_buff);
const char *ltelc_shell_sysmode_preferred_to_string(
	int sysmode_preference, char *out_str_buff);
int ltelc_shell_get_and_print_current_system_modes(const struct shell *shell,
	enum lte_lc_system_mode *sys_mode_current,
	enum lte_lc_system_mode_preference *sys_mode_preferred,
	enum lte_lc_lte_mode *currently_active_mode);
const char *ltelc_shell_sysmode_currently_active_to_string(
	int actmode, char *out_str_buff);


#endif /* LTELC_SHELL_H */
