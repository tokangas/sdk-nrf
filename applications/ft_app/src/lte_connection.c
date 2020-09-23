/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <nrf9160.h>
#include <hal/nrf_gpio.h>

#include <shell/shell.h>
#include <shell/shell_uart.h>

#include <modem/modem_info.h>
#include <modem/lte_lc.h>

#include "lte_connection.h"

static const struct shell *uart_shell;


#if defined(CONFIG_MODEM_INFO)
/* System work queue for getting the modem info that ain't in lte connection ind.
   TODO: things like these mighjt be good to be in lte connection ind, 
   i.e. merge certain stuff from modem info to there */

static struct k_work modem_info_work;

/* Work queue for signal info: */
static struct k_work modem_info_signal_work;
static int32_t modem_rsrp;

static void modem_info_get(struct k_work *unused)
{
	int ret;
	char info_str[MODEM_INFO_MAX_RESPONSE_SIZE];
	
	ARG_UNUSED(unused);

    k_sleep(K_MSEC(1000)); /* Seems that 1st info read fails without this. Thus, let modem have some time */

	ret = modem_info_string_get(MODEM_INFO_OPERATOR, info_str, sizeof(info_str));
	if (ret >= 0) {
		shell_print(uart_shell, "Operator: %s", info_str);
	} else {
		shell_error(uart_shell, "\nUnable to obtain modem operator parameters (%d)", ret);
		}
	ret = modem_info_string_get(MODEM_INFO_IP_ADDRESS, info_str, sizeof(info_str));
	if (ret >= 0) {
		shell_print(uart_shell, "IP address: %s", info_str);
	} else {
		shell_error(uart_shell, "\nUnable to obtain modem ip parameters (%d)", ret);
	}
	ret = modem_info_string_get(MODEM_INFO_FW_VERSION, info_str, sizeof(info_str));
	if (ret >= 0) {
		shell_print(uart_shell, "Modem FW version: %s", info_str);
	} else {
		shell_error(uart_shell, "\nUnable to obtain modem ip parameters (%d)", ret);
	}
}

static void modem_info_signal_handler(char rsrp_value)
{

	modem_rsrp = (int8_t)rsrp_value - MODEM_INFO_RSRP_OFFSET_VAL;
	//shell_print(uart_shell, "rsrp:%d", modem_rsrp);
	k_work_submit(&modem_info_signal_work);
}

#define FTA_RSRP_UPDATE_INTERVAL_IN_SECS 5
static void modem_info_signal_update(struct k_work *work)
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

void lte_connection_init(void)
{
#if defined(CONFIG_MODEM_INFO)
	k_work_init(&modem_info_work, modem_info_get);
	k_work_init(&modem_info_signal_work, modem_info_signal_update);
	modem_info_rsrp_register(modem_info_signal_handler);
#endif
}

void lte_connection_ind_handler(const struct lte_lc_evt *const evt)
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
