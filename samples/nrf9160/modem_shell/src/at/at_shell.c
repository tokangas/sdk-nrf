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
#if defined (CONFIG_MOSH_PING)
#include "ping/icmp_ping_shell.h"
#endif
#if defined (CONFIG_MOSH_SOCK)
#include "sock_shell.h"
#endif
#if defined (CONFIG_POSIX_API)
#include <sys/select.h>
#else
#if !defined (CONFIG_NET_SOCKETS_POSIX_NAMES)
#include <posix/sys/select.h>
#endif
#endif
#if defined (CONFIG_MOSH_LTELC)
#include "ltelc_shell.h"
#endif
#if defined (CONFIG_MOSH_CURL)	
#include "fta_curl.h"
#endif
#if defined (CONFIG_MOSH_GNSS)
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

static void at_print_error_info(enum at_cmd_state state, int error)
{
	switch (state)
	{
	case AT_CMD_ERROR:
		shell_error(shell_global, "ERROR: %d", error);
		break;
	case AT_CMD_ERROR_CMS:
		shell_error(shell_global, "CMS ERROR: %d", error);
		break;
	case AT_CMD_ERROR_CME:
		shell_error(shell_global, "CME ERROR: %d", error);
		break;
	case AT_CMD_ERROR_QUEUE:
		shell_error(shell_global, "QUEUE ERROR: %d", error);
		break;
	case AT_CMD_ERROR_WRITE:
		shell_error(shell_global, "AT CMD SOCKET WRITE ERROR: %d", error);
		break;
	case AT_CMD_ERROR_READ:
		shell_error(shell_global, "AT CMD SOCKET READ ERROR: %d", error);
		break;
	case AT_CMD_NOTIFICATION:
		shell_error(shell_global, "AT CMD NOTIFICATION: %d", error);
		break;
	default:
		break;
	}
}

int at_shell(const struct shell *shell, size_t argc, char **argv)
{
	int err;
	char response[CONFIG_AT_CMD_RESPONSE_MAX_LEN + 1];
	shell_global = shell;
	enum at_cmd_state state = AT_CMD_OK;

	if (argc < 2) {
		at_print_usage();
		return 0;
	}

	char* command = argv[1];

	shell_global = shell;

	if (!strcmp(command, "events_enable")) {
		int err = at_notif_register_handler(
			(void*)shell, at_cmd_handler);
		if (err == 0) {
			shell_print(shell, "AT command event handler registered successfully");
		} else {
			shell_print(
				shell,
				"AT command event handler registeration failed, err=%d",
				err);
		}
	} else if (!strcmp(command, "events_disable")) {
		at_notif_deregister_handler((void*)shell, at_cmd_handler);
		shell_print(shell, "AT command event handler deregistered successfully");
	} else if (!strcmp(command, "help")) {
		shell_print(shell, "%s", at_usage_str);
	} else {
		err = at_cmd_write(command, response, sizeof(response), &state);
		if (state != AT_CMD_OK) {
			at_print_error_info(state, err);
			return -EINVAL;
		}

		shell_print(shell, "%sOK", response);
	}

	return 0;
}
