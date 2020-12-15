/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <stdlib.h>

#include <zephyr.h>
#include <shell/shell.h>

#include "utils/freebsd-getopt/getopt.h"
#include "gnss.h"

typedef enum {
    GNSS_MODE_INVALID = 0,
    GNSS_MODE_CONTINUOUS,
    GNSS_MODE_SINGLE_FIX,
    GNSS_MODE_PERIODIC_FIX
} gnss_tracking_mode;

const struct shell *gnss_shell_global;

/* TODO: Split help by command */
static const char gnss_shell_cmd_usage_str[] =
	"Usage: gnss <command> [options]\n"
	"\n"
    "<command> is one of the following:\n"
    "  help:             Show this message\n"
    "  start:            Start GNSS\n"
    "  stop:             Stop GNSS\n"
    "  mode:             Configure GNSS operation mode\n"
    "  output:           Configure output\n"
    "\n"
    "Parameters for 'start' command:\n"
    "  -d,                   Delete stored data.\n"
    "\n"
    "Parameters for 'mode' command:\n"
    "Operation mode (mandatory):\n"
    "  -c,                   Continuous tracking mode.\n"
    "  -s,                   Single fix mode. See also -t for timeout.\n"
    "  -p <interval>, [int]  Periodic fix mode. See also -t for timeout.\n"
    "Additional parameters:\n"
    "  -t <timeout>,  [int]  Time to try for fix in seconds. Valid for single\n"
    "                        and periodic fix modes.\n"
    "  -d <mode>,     [int]  Duty cycling policy:\n"
    "                        0 = no power saving (default)\n"
    "                        1 = power saving without significant performance degradation\n"
    "                        2 = power saving with acceptable performance degradation\n"
    "                        Valid only for continuous tracking mode.\n"
    "\n"
    "Parameters for 'output' command\n"
    "  -p <level>,    [int]  PVT output level:\n"
    "                        0 = no PVT output\n"
    "                        1 = PVT output\n"
    "                        2 = PVT output with SV information (default)\n"
    "  -n <level>,    [int]  NMEA output level:\n"
    "                        0 = no NMEA output (default)\n"
    "                        1 = NMEA output\n"
    "  -e <level>,    [int]  GPS driver event output level:\n"
    "                        0 = no event output (default)\n"
    "                        1 = event output\n"
    "\n"
	;

static void gnss_shell_usage_print(const struct shell *shell)
{
	shell_print(shell, "%s", gnss_shell_cmd_usage_str);
}

int gnss_shell_cmd_start(size_t argc, char **argv)
{
    int err;
    int flag;
    bool delete_stored_data = false;

    optind = 2;

    while ((flag = getopt(argc, argv, "d")) != -1) {
        switch (flag) {
        case 'd':
            delete_stored_data = true;
            break;
        default:
            /* Unknown option */
            return -EINVAL;
        }
    }

    gnss_set_delete_stored_data(delete_stored_data);

    err = gnss_start();
    if (err) {
        shell_error(gnss_shell_global, "Starting GNSS failed, err %d", err);
    }

    return err;
}

int gnss_shell_cmd_stop(size_t argc, char **argv)
{
    int err;

    err = gnss_stop();
    if (err) {
        shell_error(gnss_shell_global, "Stopping GNSS failed, err %d", err);
    }

    return err;
}

int gnss_shell_cmd_mode(size_t argc, char **argv)
{
    int err = 0;
    int flag;
    int interval = -1;
    int timeout = -1;
    int duty_cycling = -1;
    gnss_tracking_mode mode = GNSS_MODE_INVALID;

    optind = 2;

    while ((flag = getopt(argc, argv, "csp:t:d:")) != -1) {
        switch (flag) {
        case 'c':
            mode = GNSS_MODE_CONTINUOUS;
            break;
        case 's':
            mode = GNSS_MODE_SINGLE_FIX;
            break;
        case 'p':
            mode = GNSS_MODE_PERIODIC_FIX;
            interval = atoi(optarg);
            if (interval < 10 || interval > 1800) {
                shell_error(
                    gnss_shell_global,
                    "Invalid interval value %d. The value must be 10...1800.",
                    interval);
                return -EINVAL;
            }
            break;
        case 't':
            timeout = atoi(optarg);
            if (timeout < 0 || timeout > UINT16_MAX) {
                shell_error(
                    gnss_shell_global,
                    "Invalid timeout value %d.",
                    timeout);
                return -EINVAL;
            }
            break;
        case 'd':
            duty_cycling = atoi(optarg);
            if (duty_cycling < 0 || duty_cycling > 2) {
                shell_error(
                    gnss_shell_global,
                    "Invalid duty cycling policy value %d.",
                    duty_cycling);
                return -EINVAL;
            }
            break;
        default:
            /* Unknown option */
            return -EINVAL;
        }
    }

    /* Duty cycling parameter is only valid for continuous tracking mode */
    if (duty_cycling != -1 && mode != GNSS_MODE_CONTINUOUS) {
        shell_error(gnss_shell_global,
            "Duty cycling is only valid in continuous tracking mode.");
        return -EINVAL;
    }

    switch (mode) {
    case GNSS_MODE_CONTINUOUS:
        err = gnss_set_continuous_mode();
        if (!err) {
            if (duty_cycling != -1) {
                err = gnss_set_duty_cycling_policy(duty_cycling);
            } else {
                err = gnss_set_duty_cycling_policy(GNSS_DUTY_CYCLING_DISABLED);
            }
        }
        break;
    case GNSS_MODE_SINGLE_FIX:
        if (timeout == -1) {
            shell_error(gnss_shell_global, "Timeout missing.");
            return -EINVAL;
        }
        err = gnss_set_single_fix_mode(timeout);
        break;
    case GNSS_MODE_PERIODIC_FIX:
        if (timeout == -1) {
            shell_error(gnss_shell_global, "Timeout missing.");
            return -EINVAL;
        }
        err = gnss_set_periodic_fix_mode(interval, timeout);
        break;
    default:
        gnss_shell_usage_print(gnss_shell_global);
        break;
    }

    return err;
}

int gnss_shell_cmd_output(size_t argc, char **argv)
{
    int err = -1;
    int flag;
    int pvt_level = -1;
    int nmea_level = -1;
    int event_level = -1;

    if (argc <= 2) {
        gnss_shell_usage_print(gnss_shell_global);
        return -EINVAL;
    }

    optind = 2;

    while ((flag = getopt(argc, argv, "p:n:e:")) != -1) {
        switch (flag) {
        case 'p':
            pvt_level = atoi(optarg);
            break;
        case 'n':
            nmea_level = atoi(optarg);
            break;
        case 'e':
            event_level = atoi(optarg);
            break;
        default:
            /* Unknown option */
            return -EINVAL;
        }
    }

    if (pvt_level > -1) {
        err = gnss_set_pvt_output_level(pvt_level);
        if (err) {
            shell_error(gnss_shell_global, "Invalid PVT output level");
        }
    }

    if (nmea_level > -1) {
        err = gnss_set_nmea_output_level(nmea_level);
        if (err) {
            shell_error(gnss_shell_global, "Invalid NMEA output level");
        }
    }

    if (event_level > -1) {
        err = gnss_set_event_output_level(event_level);
        if (err) {
            shell_error(gnss_shell_global, "Invalid event output level");
        }
    }

    return err;
}

/*****************************************************************************/
int gnss_shell(const struct shell *shell, size_t argc, char **argv)
{
    gnss_shell_global = shell;

	if (argc < 2) {
		goto show_usage;
	}

    // sub-command = argv[1]
    if (strcmp(argv[1], "help") == 0) {
        goto show_usage;
    } else if (strcmp(argv[1], "start") == 0) {
        return gnss_shell_cmd_start(argc, argv);
    } else if (strcmp(argv[1], "stop") == 0) {
        return gnss_shell_cmd_stop(argc, argv);
    } else if (strcmp(argv[1], "mode") == 0) {
        return gnss_shell_cmd_mode(argc, argv);
    } else if (strcmp(argv[1], "output") == 0) {
        return gnss_shell_cmd_output(argc, argv);
    } else {
        shell_error(shell, "Unknown command: %s\n", argv[1]);
        goto show_usage;
    }

show_usage:
	gnss_shell_usage_print(shell);
	return -1;
}
