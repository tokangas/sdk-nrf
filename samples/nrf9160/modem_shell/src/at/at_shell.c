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
#if defined (CONFIG_FTA_LTELC)
#include "ltelc_shell.h"
#endif
#if defined (CONFIG_FTA_CURL)	
#include "fta_curl.h"
#endif
#if defined (CONFIG_FTA_GNSS)
#include "gnss/gnss_shell.h"
#endif

extern const struct shell* shell_global;

static const char at_usage_str[] =
	"Usage: at <command>\n"
	"\n"
	"<command> is AT command or one of the following:\n"
	"  events_enable     Enable AT event handler which prints AT notifications\n"
	"  events_disable    Disable AT event handler\n"
	"  help              Show this usage\n"
	"\n"
	"Examples:\n"
	"\n"
	"  Send AT command to query network status with:\n"
	"    at at+cereg?\n"
	"\n"
	"  Send AT command to query neightbour cells:\n"
	"    at at%NBRGRSRP\n"
	"\n"
	"  Enable AT command events:\n"
	"    at events_enable\n"
	"\n"
	"  Disable AT command events:\n"
	"    at events_disable\n"
	;

static void at_cmd_handler(void *context, const char *response)
{
	const struct shell *shell = context;
	shell_print(shell, "AT event handler: %s", response);
}

static void at_print_usage()
{
	shell_print(shell_global, "%s", at_usage_str);
}

int at_shell(const struct shell *shell, size_t argc, char **argv)
{
	int err;
	char response[CONFIG_AT_CMD_RESPONSE_MAX_LEN + 1];
	shell_global = shell;

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
