/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <shell/shell.h>
#include <modem/at_cmd.h>

#include "icmp_ping.h"
#include "socket.h"

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
static int cmd_icmp_ping(const struct shell *shell, size_t argc, char **argv)
{ 
#ifdef RM_JH	
	shell_print(shell, "argc = %d", argc);
	for (size_t cnt = 0; cnt < argc; cnt++) {
		shell_print(shell, "  argv[%d] = %s", cnt, argv[cnt]);
	}
#endif	
	if (argc > 1) {
        char *target_name = argv[1];
		icmp_ping_start(shell, target_name);
	}

	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(app_data_cmds,
	SHELL_CMD(start, NULL, "'app data start [interval in seconds]' starts "
		               "periodic UDP data sending. The default "
		               "interval is 10 seconds.", app_cmd_data_start),
	SHELL_CMD(stop, NULL, "Stop periodic UDP data sending.",
		  app_cmd_data_stop),
	SHELL_SUBCMD_SET_END
);

SHELL_STATIC_SUBCMD_SET_CREATE(sock_cmds,
	SHELL_CMD(send, NULL, "'app data start [interval in seconds]' starts "
		               "send data", tcp_cmd_send_data),
	SHELL_CMD(stop, NULL, "Stop periodic UDP data sending.",
		  sc_cmd_data_stop),
	SHELL_SUBCMD_SET_END
);

SHELL_STATIC_SUBCMD_SET_CREATE(app_cmds,
	SHELL_CMD(data, &app_data_cmds, "Send periodic UDP data over default "
					"APN.", NULL),
	SHELL_CMD(ping, NULL, "'ft ping [target host name]' does an ICMP ping.\n No other hooks: work very much in progress", cmd_icmp_ping),
	SHELL_CMD(sock, &sock_cmds, "Send periodic UDP data over default "
					"APN.", NULL),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_ARG_REGISTER(at, NULL,
		   "Execute an AT command.",
		   app_cmd_at,
		   2,
		   0);

SHELL_CMD_REGISTER(ft, &app_cmds,
		   "Commands for controlling the FT application",
		   NULL);

SHELL_CMD_REGISTER(sock, &sock_cmds,
		   "Commands for controlling the FT application",
		   NULL);
