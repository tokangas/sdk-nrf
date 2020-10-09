/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <stdlib.h>
#include <zephyr.h>

#include <shell/shell.h>

#include "utils/freebsd-getopt/getopt.h"

#include "ltelc_api.h"

#include "icmp_ping.h"
#include "icmp_ping_shell.h"

static const char icmp_ping_shell_cmd_usage_str[] =
	"Usage: ping [optional options] -d destination\n"
	"\n"
	"mandatory options:\n"
	"  -d destination, [str]   name or ip address\n"
	"optional options:\n"
	"  -t timeout,       [int]   ping timeout in msecs\n"
	"  -c count,         [int]   the number of times to send the ping request\n"
	"  -i interval,      [int]   an interval between successive packet transmissions.\n"
	"  -l length,        [int]   payload length to be sent\n"
	"  -I interface CID, [str]   use this option to bind pinging to specific CID, see ltelc cmd for interfaces.\n"
	"  -6,               [bool]  force IPv6 usage, e.g. with dual stack interfaces\n"
	"  -h,               [bool]  shows this information.\n"
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
    ping_args->cid = FTA_ARG_NOT_SET;
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

	while ((flag = getopt(argc, argv, "d:t:c:i:I:l:h6")) != -1) {
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
		case 'I': //PDN CID
			ping_args.cid = atoi(optarg);
			if (ping_args.cid == 0) {
				shell_warn(
					shell,
					"CID not an integer (> 0), default context used");
                ping_args.cid = FTA_ARG_NOT_SET;
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
		case '6': //force ipv6
            ping_args.force_ipv6 = true;
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
        /* All good for args, get the current connection info and start the ping: */
        int ret = 0;
  	    pdp_context_info_array_t pdp_context_info_tbl;

        ret = ltelc_api_default_pdp_context_read(&pdp_context_info_tbl);
        if (ret) {
            shell_error(shell, "cannot read current connection info: %d", ret);
            return -1;
        }
        else {
            if (pdp_context_info_tbl.size > 0) {

                /* Default context: */
                if (ping_args.cid == FTA_ARG_NOT_SET) {
                    ping_args.current_pdp_type = pdp_context_info_tbl.array[0].pdp_type;
                    ping_args.current_sin4 = pdp_context_info_tbl.array[0].sin4;
                    ping_args.current_sin6 = pdp_context_info_tbl.array[0].sin6;
                }
                else {
                    /* Find PDP context info for requested CID: */
                    int i;
                    bool found = false;

                    for (i = 0; i < pdp_context_info_tbl.size; i++) {
                        if (pdp_context_info_tbl.array[i].cid == ping_args.cid) {
                            ping_args.current_pdp_type = pdp_context_info_tbl.array[i].pdp_type;
                            ping_args.current_sin4 = pdp_context_info_tbl.array[i].sin4;
                            ping_args.current_sin6 = pdp_context_info_tbl.array[i].sin6;
                            strcpy(ping_args.current_apn_str, pdp_context_info_tbl.array[i].apn_str);
                            found = true;
                        }
                    }

                    if (!found) {
                        shell_error(shell, "cannot find CID: %d", ping_args.cid);
                        return -1;
                    }
                }
            }
            else {
                shell_error(shell, "cannot read current connection info");
                return -1;
            }
            if (pdp_context_info_tbl.array != NULL)
                free(pdp_context_info_tbl.array);
        }
		return icmp_ping_start(shell, &ping_args);
    }

show_usage:
	icmp_ping_shell_usage_print(shell);
	return -1;
}
