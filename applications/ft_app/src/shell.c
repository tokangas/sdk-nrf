/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */
#include <stdlib.h>

#include <shell/shell.h>
#include <modem/at_cmd.h>
#include <modem/at_notif.h>
#include <modem/lte_lc.h>
#if defined (CONFIG_FTA_PING)
#include "ping/icmp_ping_shell.h"
#endif
#if defined (CONFIG_FTA_SOCK)
#include "sock_shell.h"
#endif
#if defined (CONFIG_POSIX_API)
#include <sys/select.h>
#else
#if !defined (CONFIG_NET_SOCKETS_POSIX_NAMES)
#include <posix/sys/select.h>
#endif
#endif
#if defined (CONFIG_FTA_IPERF3)
#include "iperf/iperf_api.h"
#endif
#if defined (CONFIG_FTA_LTELC)
#include "ltelc_shell.h"
#endif
#if defined (CONFIG_FTA_CURL)	
#include "fta_curl.h"
#endif
#if defined (CONFIG_FTA_GNSS)
#include "gnss/gnss_shell.h"
#endif

const struct shell* shell_global;

const char at_usage_str[] =
	"Usage: at <command>\n"
	"\n"
	"<command> is AT command or one of the following:\n"
	"  events_enable     Enable AT event handler which prints AT notifications\n"
	"  events_disable    Disable AT event handler\n"
	"  help              Show this usage\n"
	"\n"
	"Examples:\n"
	"\n"
	"Send AT command to query network status with:\n"
	"  at at+cereg?\n"
	"\n"
	"Send AT command to query neightbour cells:\n"
	"  at at%NBRGRSRP\n"
	"\n"
	"AT command:\n"
	"  at events_enable\n"
	;

void at_cmd_handler(void *context, const char *response)
{
	const struct shell *shell = context;
	shell_print(shell, "AT event handler: %s", response);
}

static void at_print_usage()
{
	shell_print(shell_global, "%s", at_usage_str);
}

static int app_cmd_at(const struct shell *shell, size_t argc, char **argv)
{
	int err;
	char response[CONFIG_AT_CMD_RESPONSE_MAX_LEN + 1];

	if (argc < 2) {
		at_print_usage();
		return 0;
	}

	char* command = argv[1];

	shell_global = shell;

	if (!strcmp(command, "events_enable")) {
		int err = at_notif_register_handler((void*)shell, at_cmd_handler);
		if (err == 0) {
			shell_print(shell, "AT command event handler registered successfully");
		} else {
			shell_print(shell, "AT command event handler registeration failed, err=%d", err);
		}
	} else if (!strcmp(command, "events_disable")) {
		at_notif_deregister_handler((void*)shell, at_cmd_handler);
		shell_print(shell, "AT command event handler deregistered successfully");
	} else if (!strcmp(command, "help")) {
		shell_print(shell, "%s", at_usage_str);
	} else {
		err = at_cmd_write(command, response, sizeof(response), NULL);
		if (err) {
			shell_error(shell, "ERROR");
			return -EINVAL;
		}

		shell_print(shell, "%sOK", response);
	}

	return 0;
}


#if defined (CONFIG_FTA_IPERF3)	
static int cmd_iperf3(const struct shell *shell, size_t argc, char **argv)
{
	(void)iperf_main(argc, argv);
	return 0;
}
#endif

#if defined (CONFIG_FTA_CURL)	
static int cmd_curl(const struct shell *shell, size_t argc, char **argv)
{
	(void)curl_tool_main(argc, argv);
	shell_print(shell, "\nDONE");
	return 0;
}
SHELL_CMD_REGISTER(curl, NULL, "For curl usage, just type \"curl --manual\"", cmd_curl);
#endif

SHELL_CMD_REGISTER(at, NULL, "Execute an AT command.", app_cmd_at);

#if defined (CONFIG_FTA_SOCK)
SHELL_CMD_REGISTER(sock, NULL,
	"Commands for socket operations such as connect and send.",
	sock_shell);
#endif

#if defined (CONFIG_FTA_PING)
SHELL_CMD_REGISTER(ping, NULL, "For ping usage, just type \"ping\"", icmp_ping_shell);
#endif

#if defined (CONFIG_FTA_LTELC)
SHELL_CMD_REGISTER(ltelc, NULL,
	"Commands for LTE link controlling and status information.",
	ltelc_shell);
#endif

#if defined (CONFIG_FTA_IPERF3)
SHELL_CMD_REGISTER(iperf3, NULL, "For iperf3 usage, just type \"iperf3 --manual\"", cmd_iperf3);
#endif

#if defined (CONFIG_FTA_GNSS)
SHELL_CMD_REGISTER(gnss, NULL,
	"Commands for controlling GNSS.",
	gnss_shell);
#endif
