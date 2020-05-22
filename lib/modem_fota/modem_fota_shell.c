/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <stdlib.h>
#include <shell/shell.h>
#include "modem_fota_internal.h"

static int fota_cmd_interval_set(const struct shell *shell, size_t argc,
		char **argv)
{
	u32_t interval;

	interval = strtoul(argv[1], NULL, 10);

	if (interval == 0) {
		shell_error(shell, "set: invalid interval value");
		return -EINVAL;
	}

	set_update_check_interval(interval);

	return 0;
}

static int fota_cmd_interval_reset(const struct shell *shell, size_t argc,
		char **argv)
{
	reset_update_check_interval();

	return 0;
}

static int fota_cmd_server_set(const struct shell *shell, size_t argc,
		char **argv)
{
	u32_t port;

	port = strtoul(argv[2], NULL, 10);

	if (port == 0 || port > USHRT_MAX) {
		shell_error(shell, "set: invalid port number");
		return -EINVAL;
	}

	set_dm_server_host(argv[1]);
	set_dm_server_port(port);

	return 0;
}

static int fota_cmd_server_reset(const struct shell *shell, size_t argc,
		char **argv)
{
	reset_dm_server_host();
	reset_dm_server_port();

	return 0;
}

static int fota_cmd_disable(const struct shell *shell, size_t argc, char **argv)
{
	if (!is_fota_enabled()) {
		shell_error(shell, "disable: FOTA already disabled");
		return -ENOEXEC;
	}

	disable_fota();

	return 0;
}

static int fota_cmd_enable(const struct shell *shell, size_t argc, char **argv)
{
	if (is_fota_enabled()) {
		shell_error(shell, "enable: FOTA already enabled");
		return -ENOEXEC;
	}

	enable_fota();

	return 0;
}

static int fota_cmd_status(const struct shell *shell, size_t argc, char **argv)
{
	u32_t time_to_check;

	shell_print(shell, "FOTA %s",
		    is_fota_enabled() ? "enabled" : "disabled");
	time_to_check = get_time_to_next_update_check();
	if (time_to_check > 0)
		shell_print(shell, "Time until next update check: %d seconds",
			    time_to_check);
	else
		shell_print(shell, "Next update check not scheduled or no " \
				   "network time");
	shell_print(shell, "Update check interval: %d minutes",
		    get_update_check_interval());
	shell_print(shell, "DM server host: %s", get_dm_server_host());
	shell_print(shell, "DM server port: %d", get_dm_server_port());

	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(fota_interval_cmds,
	SHELL_CMD_ARG(set, NULL,
		      "'fota interval set <value in minutes>' overrides the " \
		      "configured firmware update check interval.",
		      fota_cmd_interval_set, 2, 0),
	SHELL_CMD_ARG(reset, NULL,
		      "Restore the configured firmware update check interval.",
		      fota_cmd_interval_reset, 1, 0),
	SHELL_SUBCMD_SET_END
);

SHELL_STATIC_SUBCMD_SET_CREATE(fota_server_cmds,
	SHELL_CMD_ARG(set, NULL,
		      "'fota server set <host> <port>' overrides the " \
		      "configured Device Management server hostname and " \
		      "port number.",
		      fota_cmd_server_set, 3, 0),
	SHELL_CMD_ARG(reset, NULL,
		      "Restore the configured Device Management server " \
		      "hostname and port number.",
		      fota_cmd_server_reset, 1, 0),
	SHELL_SUBCMD_SET_END
);

SHELL_STATIC_SUBCMD_SET_CREATE(fota_cmds,
	SHELL_CMD(interval, &fota_interval_cmds,
		  "Change the firmware update check interval.", NULL),
	SHELL_CMD(server, &fota_server_cmds,
		  "Change the Device Management server hostname and " \
		  "port number.", NULL),
	SHELL_CMD(disable, NULL, "Disable FOTA.", fota_cmd_disable),
	SHELL_CMD(enable, NULL, "Enable FOTA.", fota_cmd_enable),
	SHELL_CMD(status, NULL, "Show FOTA status.", fota_cmd_status),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(fota, &fota_cmds,
		   "Commands for controlling the FOTA Client", NULL);
