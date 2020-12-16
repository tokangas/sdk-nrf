/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <shell/shell.h>
#include <assert.h>
#include <strings.h>
#include <stdio.h>

#include "sms.h"
#include "fta_defines.h"
#include "utils/freebsd-getopt/getopt.h"

// Maximum length of the data that can be specified with -d option
#define SMS_MAX_MESSAGE_LEN 200

typedef enum {
	SMS_CMD_SEND = 0,
	SMS_CMD_RECV,
	SMS_CMD_HELP
} sms_command;

extern const struct shell* shell_global;

const char sms_usage_str[] =
	"Usage: sock <command> [options]\n"
	"\n"
	"<command> is one of the following:\n"
	"  send:    Send SMS message. Mandatory options: -m, -n\n"
	"\n"
	"Options for 'send' command:\n"
	"  -m, --message [str]       Data to be sent. Cannot be used with -l option.\n"
	"  -n, --number, [str]       Length of undefined data in bytes. This can be used when testing\n"
	"                            with bigger data amounts. Cannot be used with -d or -e option.\n"
	"\n"
	"Options for 'help' command:\n"
	"  -v, --verbose, [bool]     Show examples\n"
	;

const char sms_usage_example_str[] =
	"Examples:\n"
	"\n"
	"TODO\n"
	;

/* Specifying the expected options (both long and short): */
static struct option long_options[] = {
    {"message",        required_argument, 0,  'm' },
    {"number",         required_argument, 0,  'n' },
    {0,                0,                 0,   0  }
};

static void sms_print_usage()
{
	shell_print(shell_global, "%s", sms_usage_str);
}

static int sms_help(bool verbose) {
	sms_print_usage();
	if (verbose) {
		shell_print(shell_global, "%s", sms_usage_example_str);
	}
	return 0;
}

int sms_shell(const struct shell *shell, size_t argc, char **argv)
{
	int err = 0;
	shell_global = shell;
	// Before parsing the command line, reset getopt index to the start of the arguments
	optind = 1;

	if (argc < 2) {
		sms_print_usage();
		return 0;
	}

	// Command = argv[1]
	sms_command command;
	if (!strcmp(argv[1], "send")) {
		command = SMS_CMD_SEND;
	} else if (!strcmp(argv[1], "recv")) {
		command = SMS_CMD_RECV;
		shell_error(shell, "recv command not implemented yet\n");
	} else {
		shell_error(shell, "Unsupported command=%s\n", argv[1]);
		sms_print_usage();
		return -EINVAL;
	}
	// Increase getopt command line parsing index not to handle command
	optind++;

	// Variables for command line arguments
	char arg_number[SMS_MAX_MESSAGE_LEN+1];// = SMS_NUMBER_NONE;
	char arg_message[SMS_MAX_MESSAGE_LEN+1];
	bool arg_verbose = false;

	memset(arg_message, 0, SMS_MAX_MESSAGE_LEN+1);

	// Parse command line
	int flag = 0;
	while ((flag = getopt_long(argc, argv, "m:n:", long_options, NULL)) != -1) {
		int send_data_len = 0;

		switch (flag) {
		case 'n': // Phone number
			strcpy(arg_number, optarg);
			break;
		case 'm': // Message text
			send_data_len = strlen(optarg);
			if (send_data_len > SMS_MAX_MESSAGE_LEN) {
				shell_error(shell, "Data length %d exceeded. Maximum is %d. Given data: %s",
					send_data_len, SMS_MAX_MESSAGE_LEN, optarg);
				return -EINVAL;
			}
			strcpy(arg_message, optarg);
			break;
		case 'v': // Start monitoring received data
			arg_verbose = true;
			break;
		}
	}

	// Run given command with it's arguments
	switch (command) {
		case SMS_CMD_SEND:
			err = sms_send(arg_number, arg_message);
			break;
		case SMS_CMD_RECV:
			//err = sms_recv();
			break;
		case SMS_CMD_HELP:
			err = sms_help(arg_verbose);
			break;
		default:
			shell_error(shell, "Internal error. Unknown socket command=%d", command);
			err = -EINVAL;
			break;
	}

	return err;
}
