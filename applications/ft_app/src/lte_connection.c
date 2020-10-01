/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <assert.h>

#include <sys/types.h>
#include <nrf9160.h>
#include <hal/nrf_gpio.h>

#include <shell/shell.h>
#include <shell/shell_uart.h>

#include <modem/modem_info.h>
#include <modem/lte_lc.h>

#include "lte_connection.h"
#include "lte_connection_tools.h"

#if defined(CONFIG_MODEM_INFO)
#include <modem/at_cmd.h>
#include <modem/at_cmd_parser.h>
#include <modem/at_params.h>
#endif

static const struct shell *uart_shell;

#if defined(CONFIG_MODEM_INFO)
/* System work queue for getting the modem info that ain't in lte connection ind.
   TODO: things like these might be good to be in lte connection ind, 
   i.e. merge certain stuff from modem info to there? */

static struct k_work modem_info_work;

/* Work queue for signal info: */
static struct k_work modem_info_signal_work;
static int32_t modem_rsrp;

//**************************************************************************

static void lte_conn_modem_info_work(struct k_work *unused)
{
	ARG_UNUSED(unused);

    k_sleep(K_MSEC(1500)); /* Seems that 1st info read fails without this. Thus, let modem have some time */

	lte_conn_modem_info_get_for_shell(uart_shell);
}
//**************************************************************************

static void lte_conn_rsrp_signal_handler(char rsrp_value)
{

	modem_rsrp = (int8_t)rsrp_value - MODEM_INFO_RSRP_OFFSET_VAL;
	//shell_print(uart_shell, "rsrp:%d", modem_rsrp);
	k_work_submit(&modem_info_signal_work);
}

//**************************************************************************

#define FTA_RSRP_UPDATE_INTERVAL_IN_SECS 5
static void lte_conn_rsrp_signal_update(struct k_work *work)
{
	static uint32_t timestamp_prev = 0;

	if ((timestamp_prev != 0) &&
	    (k_uptime_get_32() - timestamp_prev <
	     FTA_RSRP_UPDATE_INTERVAL_IN_SECS * MSEC_PER_SEC)) {
		return;
	}

	shell_print(uart_shell, "RSRP: %d", modem_rsrp);
	timestamp_prev = k_uptime_get_32();
}
#endif
//**************************************************************************
void lte_conn_init(void)
{
#if defined(CONFIG_MODEM_INFO)
	k_work_init(&modem_info_work, lte_conn_modem_info_work);
	k_work_init(&modem_info_signal_work, lte_conn_rsrp_signal_update);
	modem_info_rsrp_register(lte_conn_rsrp_signal_handler);
#endif
}
//**************************************************************************
const char ltelc_usage_str[] =
	"Usage: ltelc <command> [options]\n"
	"\n"
	"<command> is one of the following:\n"
	"  status:  Show status of the current connection\n"
	"\n"
	"General options:\n"
	"  -i, [int]  socket id. Use 'list' command to see open sockets.\n"
	"\n"
	"Options for 'status' command:\n"
	"  -a, [str]  Address as ip address or hostname\n"
	"\n"
	"Options for 'help' command:\n"
	"  -v, [bool] Show examples\n"
	;

static void lte_conn_shell_print_usage(const struct shell *shell)
{
	shell_print(shell, "%s", ltelc_usage_str);

}
typedef enum {
	LTELC_CMD_STATUS = 0,
	LTELC_CMD_HELP
} ltelc_shell_command;

typedef struct {
	ltelc_shell_command command;
} ltelc_shell_cmd_args_t;

static ltelc_shell_cmd_args_t ltelc_cmd_args;

int lte_conn_shell(const struct shell *shell, size_t argc, char **argv)
{
	int err = 0;
	
	if (argc < 2) {
		lte_conn_shell_print_usage(shell);
		return 0;
	}
	
	// Command = argv[1]
	if (!strcmp(argv[1], "status")) {
		ltelc_cmd_args.command = LTELC_CMD_STATUS;
	} else {
		shell_error(uart_shell, "Unsupported command=%s\n", argv[1]);
		lte_conn_shell_print_usage(shell);
		return -EINVAL;
	}

	switch (ltelc_cmd_args.command) {
		case LTELC_CMD_STATUS:
			lte_conn_modem_info_get_for_shell(shell);
			break;
		default:
			shell_error(shell, "Internal error. Unknown ltelc command=%d", ltelc_cmd_args.command);
			err = -EINVAL;
			break;
	}
	return err;
}
//**************************************************************************

void lte_conn_ind_handler(const struct lte_lc_evt *const evt)
{
	uart_shell = shell_backend_uart_get_ptr();
	switch (evt->type) {
	case LTE_LC_EVT_NW_REG_STATUS:
		switch (evt->nw_reg_status) {
		case LTE_LC_NW_REG_NOT_REGISTERED:
			shell_print(
				uart_shell,
				"Network registration status: not registered");
			break;
		case LTE_LC_NW_REG_SEARCHING:
			shell_print(uart_shell,
				   "Network registration status: searching");
			break;
		case LTE_LC_NW_REG_REGISTRATION_DENIED:
			shell_print(uart_shell,
				   "Network registration status: denied");
			break;
		case LTE_LC_NW_REG_UNKNOWN:
			shell_print(uart_shell,
				   "Network registration status: unknown");
			break;
		case LTE_LC_NW_REG_UICC_FAIL:
			shell_print(uart_shell,
				   "Network registration status: UICC fail");
			break;
		case LTE_LC_NW_REG_REGISTERED_HOME:
		case LTE_LC_NW_REG_REGISTERED_ROAMING:
			shell_print(
				uart_shell, "Network registration status: %s",
				evt->nw_reg_status ==
						LTE_LC_NW_REG_REGISTERED_HOME ?
					"Connected - home network" :
					"Connected - roaming");
#if defined(CONFIG_MODEM_INFO)
			k_work_submit(&modem_info_work);
#endif
		default:
			break;
		}
		break;
	case LTE_LC_EVT_CELL_UPDATE:
		shell_print(uart_shell, "LTE cell changed: Cell ID: %d, Tracking area: %d",
		       evt->cell.id, evt->cell.tac);
		break;
	default:
		break;
	}
}
//**************************************************************************
