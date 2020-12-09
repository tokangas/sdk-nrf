/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <zephyr.h>
#include <stdio.h>

#include <shell/shell.h>

#include "ppp_ctrl.h"
#include "ppp_shell.h"

#if defined (CONFIG_FTA_PPP)
#include <net/promiscuous.h>

typedef enum {
	PPP_CMD_START = 0,
	PPP_CMD_STOP
} ppp_shell_command;

typedef struct {
	ppp_shell_command command;
} ppp_shell_cmd_args_t;

static ppp_shell_cmd_args_t ppp_cmd_args;

const char ppp_cmd_usage_str[] =
	"Usage: ppp <command> [options]\n"
	"\n"
	"<command> is one of the following:\n"
	"  help:                    Show this message\n"
	"  start:                   Set carrier ON and start PPP\n"
	"  stop:                    Set carrier OFF and stop PPP\n"
	"\n"
	"Options for 'pp' command:\n"
	"\n"
	;
static void ppp_shell_print_usage(const struct shell *shell)
{
	shell_print(shell, "%s", ppp_cmd_usage_str);
}

static void ppp_shell_cmd_defaults_set(ppp_shell_cmd_args_t *ppp_cmd_args)
{
	memset(ppp_cmd_args, 0, sizeof(ppp_shell_cmd_args_t));
}

int ppp_shell_cmd(const struct shell *shell, size_t argc, char **argv)
{	
	int ret = 0;

	ppp_shell_cmd_defaults_set(&ppp_cmd_args);

	if (argc < 2) {
		goto show_usage;
	}

	if (strcmp(argv[1], "start") == 0) {
		ppp_cmd_args.command = PPP_CMD_START;
	} else if (strcmp(argv[1], "stop") == 0) {
		ppp_cmd_args.command = PPP_CMD_STOP;
	} else if (strcmp(argv[1], "help") == 0) {
        goto show_usage;
	} else {
		shell_error(shell, "Unsupported command=%s\n", argv[1]);
		ret = -EINVAL;
		goto show_usage;
	}

	switch (ppp_cmd_args.command) {
		case PPP_CMD_START:
			ret = ppp_ctrl_start(shell);
			if (ret <= 0)
				shell_print(shell, "PPP started\n");
			else
				shell_print(shell, "PPP cannot be started: %d\n", ret);

			break;
		case PPP_CMD_STOP:
			ppp_shell_set_ppp_carrier_off();
			break;
	}

	return 0;

show_usage:
	ppp_shell_print_usage(shell);
	return 0;
}

#endif
