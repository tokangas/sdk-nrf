/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <shell/shell.h>
#include <modem/at_cmd.h>

static int app_cmd_at(const struct shell *shell, size_t argc, char **argv)
{
	int err;
	char response[256];

	err = at_cmd_write(argv[1], response, sizeof(response), NULL);
	if (err) {
		shell_error(shell, "ERROR");
		return -EINVAL;
	}

	shell_print(shell, "%sOK", response);

	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(app_cmds,
	SHELL_CMD_ARG(at, NULL, "Execute an AT command.", app_cmd_at, 2, 0),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(app, &app_cmds,
		   "Commands for controlling the FOTA sample application",
		   NULL);
