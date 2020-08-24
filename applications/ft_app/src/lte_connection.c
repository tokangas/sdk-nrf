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

#include <modem/modem_info.h>
#include <modem/lte_lc.h>

void lte_connection_ind_handler(const struct lte_lc_evt *const evt)
{
	int ret;

	switch (evt->type) {
	case LTE_LC_EVT_NW_REG_STATUS:
		switch (evt->nw_reg_status) {
		case LTE_LC_NW_REG_NOT_REGISTERED:
			printk("\nNetwork registration status: not registered");
			break;
		case LTE_LC_NW_REG_SEARCHING:
			printk("\nNetwork registration status: searching");
			break;
		case LTE_LC_NW_REG_REGISTRATION_DENIED:
			printk("\nNetwork registration status: denied");
			break;
		case LTE_LC_NW_REG_UNKNOWN:
			printk("\nNetwork registration status: unknown");
			break;
		case LTE_LC_NW_REG_UICC_FAIL:
			printk("\nNetwork registration status: UICC fail");
			break;
		case LTE_LC_NW_REG_REGISTERED_HOME:
		case LTE_LC_NW_REG_REGISTERED_ROAMING:
			printk("\nNetwork registration status: %s",
			       evt->nw_reg_status ==
					       LTE_LC_NW_REG_REGISTERED_HOME ?
				       "Connected - home network" :
				       "Connected - roaming\n");
#if defined(CONFIG_MODEM_INFO)
			char info_str[MODEM_INFO_MAX_RESPONSE_SIZE];
			ret = modem_info_string_get(MODEM_INFO_OPERATOR,
						    info_str, sizeof(info_str));
			if (ret >= 0) {
				printk("Operator: %s\n", info_str);
			} else {
				printk("\nUnable to obtain modem parameters (%d)",
				       ret);
			}
			ret = modem_info_string_get(MODEM_INFO_APN, info_str,
						    sizeof(info_str));
			if (ret >= 0) {
				printk("APN: %s\n", info_str);
			} else {
				printk("\nUnable to obtain modem parameters (%d)",
				       ret);
			}
			ret = modem_info_string_get(MODEM_INFO_IP_ADDRESS,
						    info_str, sizeof(info_str));
			if (ret >= 0) {
				printk("IP address: %s\n", info_str);
			} else {
				printk("\nUnable to obtain modem parameters (%d)",
				       ret);
			}
#endif
		default:
			break;
		}
		break;
	case LTE_LC_EVT_CELL_UPDATE:
		printk("\nLTE cell changed: Cell ID: %d, Tracking area: %d\n",
		       evt->cell.id, evt->cell.tac);
		break;
	default:
		break;
	}
}
