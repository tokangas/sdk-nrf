/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef LTELC_SHELL_H
#define LTELC_SHELL_H
#include <shell/shell.h>

int ltelc_shell(const struct shell *shell, size_t argc, char **argv);

const char *ltelc_shell_sysmode_to_string(int sysmode, char *out_str_buff);
void ltelc_shell_print_current_system_modes(const struct shell *shell);
const char *ltelc_shell_sysmode_currently_active_to_string(
	int actmode, char *out_str_buff);


#endif /* LTELC_SHELL_H */
