/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */
#include <stdlib.h>

#include <shell/shell.h>
#include <modem/at_cmd.h>

#include "icmp_ping.h"
#include "socket.h"

//b_jh
#include <sys/select.h>
#include "iperf/iperf_api.h"

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
	if (argc < 4 || argc > 6) {
		shell_error(shell, "wrong amount of arguments");
		return -1;
	}
	
#ifdef RM_JH
	shell_print(shell, "argc = %d", argc);
	for (size_t cnt = 0; cnt < argc; cnt++) {
		shell_print(shell, "  argv[%d] = %s", cnt, argv[cnt]);
	}
#endif

	//USAGE: ping <target_name> <payload_length> <timeout_in_msecs>[ <count>[ <interval_in_msecs>]]
	if (argc > 1) {
		char *target_name = argv[1];
		int length = 0;
		int timeout = ICMP_PARAM_TIMEOUT_DEFAULT;
		int count = ICMP_PARAM_COUNT_DEFAULT;
		int interval = ICMP_PARAM_INTERVAL_DEFAULT;

		if (strlen(target_name) > ICMP_MAX_URL) {
			shell_error(shell, "too long target_name");
			return -1;
		}

		length = atoi(argv[2]);
		if (length == 0) {
			shell_warn(
				shell,
				"length not an integer (> 0), defaulting to zero length payload");
		}
		if (length > ICMP_MAX_LEN) {
			shell_error(shell, "Payload size exceeds the limit %d",
				    ICMP_MAX_LEN);
			return -1;
		}

		timeout = atoi(argv[3]);
		if (timeout == 0) {
			shell_warn(
				shell,
				"timeout not an integer (> 0), defaulting to %d msecs",
				ICMP_PARAM_TIMEOUT_DEFAULT);
		}
		if (argc > 4) {
			/* Optional arguments: */
			count = atoi(argv[4]);
			if (count == 0) {
				shell_warn(
					shell,
					"count not an integer (> 0), defaulting to %d",
					ICMP_PARAM_COUNT_DEFAULT);
				count = ICMP_PARAM_COUNT_DEFAULT;
			}
			if (argc == 6) {
				interval = atoi(argv[5]);
				if (interval == 0) {
					shell_warn(
						shell,
						"interval not an integer (> 0), defaulting to %d",
						ICMP_PARAM_INTERVAL_DEFAULT);
					interval = ICMP_PARAM_INTERVAL_DEFAULT;
				}
			}
		}
		icmp_ping_start(shell, target_name, length, timeout, count,
				interval);
	}
	return 0;
}
#define PING_USAGE_STR                                                         \
	"USAGE: ping <target_name> <payload_length> <timeout_in_msecs>[ <count>[ <interval_in_msecs>]]"

#if defined (CONFIG_FTA_IPERF3)	
static int cmd_iperf3(const struct shell *shell, size_t argc, char **argv)
{
	int return_value = iperf_main(argc, argv);
	return return_value;
}
#endif

SHELL_STATIC_SUBCMD_SET_CREATE(
	sock_cmds,
	SHELL_CMD_ARG(
		connect, NULL,
		"Open and connect socket. "
		"4 arguments should be given:\n"
		"address family, domain, ip address, port.\n"
		"E.g., sock connect af_inet sock_stream \"5.189.130.26\" 20180",
		socket_connect_shell, 5, 1),
	SHELL_CMD_ARG(send, NULL, "Send data.", socket_send_shell, 2, 3),
	SHELL_CMD_ARG(close, NULL, "Close socket.", socket_close_shell, 2, 0),
	SHELL_CMD(list, NULL, "List opened sockets.", socket_list_shell),
	SHELL_SUBCMD_SET_END);

SHELL_STATIC_SUBCMD_SET_CREATE(
	app_cmds,
	SHELL_CMD(ping, NULL, PING_USAGE_STR, cmd_icmp_ping),
	SHELL_CMD(sock, &sock_cmds,
		  "Perform socket related network operations.", NULL),
	SHELL_SUBCMD_SET_END);

SHELL_CMD_ARG_REGISTER(at, NULL, "Execute an AT command.", app_cmd_at, 2, 0);

SHELL_CMD_REGISTER(ft, &app_cmds, "Commands for controlling the FT application",
		   NULL);

#if defined (CONFIG_FTA_IPERF3)	
SHELL_CMD_REGISTER(iperf3, NULL, 
"iperf3 usage",
cmd_iperf3);
#endif
SHELL_CMD_REGISTER(sock, &sock_cmds,
		   "Commands for controlling the FT application", NULL);
SHELL_CMD_ARG_REGISTER(ping, NULL, PING_USAGE_STR, cmd_icmp_ping, 3,
		       SHELL_OPT_ARG_CHECK_SKIP);
