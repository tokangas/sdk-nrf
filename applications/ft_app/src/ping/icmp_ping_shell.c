/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <stdlib.h>
#include <zephyr.h>

#include <shell/shell.h>

#include "utils/freebsd-getopt/getopt.h"

#include "icmp_ping.h"
#include "icmp_ping_shell.h"

#define PING_USAGE_STR                                                         \
	"USAGE: ping <target_name> <payload_length> <timeout_in_msecs>[ <count>[ <interval_in_msecs>]]"

static const char icmp_ping_shell_cmd_usage_str[] =
	"Usage: ping [optional options] -d destination\n"
	"\n"
	"mandatory options:\n"
	"  -d destination, [str]   name or ip address\n"
	"optional options:\n"
	"  -t timeout,     [int]   ping timeout in msecs\n"
	"  -c count,       [int]   the number of times to send the ping request\n"
	"  -i interval,    [int]   an interval between successive packet transmissions.\n"
	"  -l length,      [int]   payload length to be sent\n"
	"  -I interface,   [str]   use this option to bind pinging to specific APN.\n"
	"  -h,             [bool]  shows this information.\n"
	;

static void icmp_ping_shell_usage_print(const struct shell *shell)
{
	shell_print(shell, "%s", icmp_ping_shell_cmd_usage_str);
}
static void icmp_ping_shell_cmd_defaults_set(icmp_ping_shell_cmd_argv_t *ping_args)
{
    memset(ping_args, 0, sizeof(icmp_ping_shell_cmd_argv_t));
    //ping_args->dest = NULL;
    ping_args->count = ICMP_PARAM_COUNT_DEFAULT;
    ping_args->interval = ICMP_PARAM_INTERVAL_DEFAULT;
    ping_args->timeout = ICMP_PARAM_TIMEOUT_DEFAULT;
    ping_args->len = ICMP_PARAM_LENGTH_DEFAULT;
}
/*****************************************************************************/
int icmp_ping_shell(const struct shell *shell, size_t argc, char **argv)
{
    icmp_ping_shell_cmd_argv_t ping_args;
    int flag, dest_len;

    icmp_ping_shell_cmd_defaults_set(&ping_args);

	if (argc < 3) {
		goto show_usage;
	}

	//start from the 1st argument
	optind = 1;

	while ((flag = getopt(argc, argv, "d:t:c:i:I:l:h")) != -1) {
		switch (flag) {
		case 'd': //destination
            dest_len = strlen(optarg);
            if (dest_len > ICMP_MAX_URL) {
			    shell_error(shell, "too long destination name");
                goto show_usage;
            }
			strcpy(ping_args.target_name, optarg);
			break;
		case 't': //timeout
			ping_args.timeout = atoi(optarg);
            if (ping_args.timeout == 0) {
                shell_warn(
                    shell,
                    "timeout not an integer (> 0), defaulting to %d msecs",
                    ICMP_PARAM_TIMEOUT_DEFAULT);
                ping_args.timeout = ICMP_PARAM_TIMEOUT_DEFAULT;
            }            
            break;
		case 'c': //count
			ping_args.count = atoi(optarg);
			if (ping_args.count == 0) {
				shell_warn(
					shell,
					"count not an integer (> 0), defaulting to %d",
					ICMP_PARAM_COUNT_DEFAULT);
                ping_args.timeout = ICMP_PARAM_COUNT_DEFAULT;
              }            
            break;
		case 'i': //interval
			ping_args.interval = atoi(optarg);
			if (ping_args.interval == 0) {
				shell_warn(
					shell,
					"interval not an integer (> 0), defaulting to %d",
					ICMP_PARAM_INTERVAL_DEFAULT);
				ping_args.interval = ICMP_PARAM_INTERVAL_DEFAULT;
			}
            break;
		case 'l': //payload length
			ping_args.len = atoi(optarg);
            if (ping_args.len > ICMP_MAX_LEN) {
                shell_error(shell, "Payload size exceeds the limit %d", ICMP_MAX_LEN);
                goto show_usage;
            }
            break;
		case 'h': //help
        default:
            goto show_usage;
            break;
        }
    }

    /* Check that all mandatory args were given: */
    if (ping_args.target_name == NULL) {
            shell_error(shell, "-d destination, MUST be given. See usage:");
            goto show_usage;
    } else {
        /* All good, start the ping: */
		return icmp_ping_start(shell, &ping_args);
    }

show_usage:
	icmp_ping_shell_usage_print(shell);
	return -1;
}
