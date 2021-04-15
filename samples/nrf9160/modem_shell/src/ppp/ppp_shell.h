/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef PPP_SHELL_H
#define PPP_SHELL_H

#if defined (CONFIG_MOSH_PPP)
#include <shell/shell.h>
int ppp_shell_cmd(const struct shell *shell, size_t argc, char **argv);
#endif

#endif /* PPP_SHELL_H */
