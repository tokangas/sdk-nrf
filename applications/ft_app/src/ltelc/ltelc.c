/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/dlist.h>

#include <nrf9160.h>
#include <hal/nrf_gpio.h>

#include <shell/shell.h>
#include <shell/shell_uart.h>

#include <modem/modem_info.h>
#include <modem/lte_lc.h>

#include <nrf_socket.h>

//#include <posix/unistd.h>
//#include <posix/sys/socket.h>

#include "ltelc_api.h"
#include "ltelc.h"

#if defined(CONFIG_MODEM_INFO)
#include <modem/at_cmd.h>
#include <modem/at_cmd_parser.h>
#include <modem/at_params.h>
#endif

static bool ltelc_subscribe_for_rsrp = false;

static const struct shell *uart_shell = NULL;
static sys_dlist_t pdn_socket_list;

typedef struct {
	sys_dnode_t dnode;
	int fd;
	char apn[LTELC_APN_STR_MAX_LENGTH + 1];
} ltelc_pdn_socket_info_t;

#if defined(CONFIG_MODEM_INFO)
/* System work queue for getting the modem info that ain't in lte connection ind.
   TODO: things like these might be good to be in lte connection ind, 
   i.e. merge certain stuff from modem info to there? */

static struct k_work modem_info_work;

/* Work queue for signal info: */
static struct k_work modem_info_signal_work;
static int32_t modem_rsrp;

//**************************************************************************

static void ltelc_modem_info_work(struct k_work *unused)
{
	ARG_UNUSED(unused);

    k_sleep(K_MSEC(1500)); /* Seems that 1st info read fails without this. Thus, let modem have some time */

	ltelc_api_modem_info_get_for_shell(uart_shell);
}
//**************************************************************************

static void ltelc_rsrp_signal_handler(char rsrp_value)
{

	modem_rsrp = (int8_t)rsrp_value - MODEM_INFO_RSRP_OFFSET_VAL;
	//shell_print(uart_shell, "rsrp:%d", modem_rsrp);
	k_work_submit(&modem_info_signal_work);
}

//**************************************************************************

#define FTA_RSRP_UPDATE_INTERVAL_IN_SECS 5
static void ltelc_rsrp_signal_update(struct k_work *work)
{
	static uint32_t timestamp_prev = 0;

	if ((timestamp_prev != 0) &&
	    (k_uptime_get_32() - timestamp_prev <
	     FTA_RSRP_UPDATE_INTERVAL_IN_SECS * MSEC_PER_SEC)) {
		return;
	}

	if (ltelc_subscribe_for_rsrp && uart_shell != NULL)
		shell_print(uart_shell, "RSRP: %d", modem_rsrp);
	timestamp_prev = k_uptime_get_32();
}
#endif
//**************************************************************************
void ltelc_init(void)
{
#if defined(CONFIG_MODEM_INFO)
	k_work_init(&modem_info_work, ltelc_modem_info_work);
	k_work_init(&modem_info_signal_work, ltelc_rsrp_signal_update);
	modem_info_rsrp_register(ltelc_rsrp_signal_handler);
#endif
	sys_dlist_init(&pdn_socket_list);
}


void ltelc_ind_handler(const struct lte_lc_evt *const evt)
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

static int ltelc_pdn_socket_info_clear(ltelc_pdn_socket_info_t* pdn_socket_info)
{
	int ret_val = nrf_close(pdn_socket_info->fd);

	if (sys_dnode_is_linked(&pdn_socket_info->dnode))
		sys_dlist_remove(&pdn_socket_info->dnode);

	free(pdn_socket_info);
	return ret_val;
}

static ltelc_pdn_socket_info_t* ltelc_pdn_socket_info_create(const char* apn_str, int fd)
{
	ltelc_pdn_socket_info_t* new_pdn_socket_info = NULL;
	ltelc_pdn_socket_info_t* iterator = NULL;

	/* TODO: check if already in list, then return existing one? */
	
	new_pdn_socket_info = calloc(1, sizeof(ltelc_pdn_socket_info_t));
	new_pdn_socket_info->fd = fd;
	strcpy(new_pdn_socket_info->apn, apn_str);
	
	SYS_DLIST_FOR_EACH_CONTAINER(&pdn_socket_list, iterator, dnode) {
		if (new_pdn_socket_info->fd < iterator->fd) {
		   sys_dlist_insert(&iterator->dnode, &new_pdn_socket_info->dnode);
		   return new_pdn_socket_info;
		}
	}

	sys_dlist_append(&pdn_socket_list, &new_pdn_socket_info->dnode);
	return new_pdn_socket_info;
}

static ltelc_pdn_socket_info_t* ltelc_pdn_socket_info_get_by_apn(const char* apn)
{
	ltelc_pdn_socket_info_t* iterator = NULL;
	ltelc_pdn_socket_info_t* found_pdn_socket_info = NULL;

	SYS_DLIST_FOR_EACH_CONTAINER(&pdn_socket_list, iterator, dnode) {
		if (strcmp(apn, iterator->apn) == 0) {
			found_pdn_socket_info = iterator;
			break;
		}
	}

	// SYS_DLIST_FOR_EACH_NODE(&pdn_socket_list, node) {
	// 	fd_in_list = CONTAINER_OF(node, struct ltelc_pdn_socket_info_t, node)->fd;
	// 	if (fd == fd_in_list) {
	// 		found = true;
	// 		break;
	// 		}
	// }
	return found_pdn_socket_info;
}

static int ltelc_get_apn_by_pdn_cid(int pdn_cid, char* apn_str)
{
	int ret;
	pdp_context_info_array_t pdp_context_info_tbl;

	ret = ltelc_api_default_pdp_context_read(&pdp_context_info_tbl);
	if (ret) {
		shell_error(uart_shell, "cannot read current connection info: %d", ret);
		return -1;
	}

	/* Find PDP context info for requested CID */
	ret = -1;
	int i;
	for (i = 0; i < pdp_context_info_tbl.size; i++) {
		if (pdp_context_info_tbl.array[i].cid == pdn_cid) {
			memset(apn_str, 0, FTA_APN_STR_MAX_LEN);
			strcpy(apn_str, pdp_context_info_tbl.array[i].apn_str);
			ret = 0;
		}
	}

	if (pdp_context_info_tbl.array != NULL) {
		free(pdp_context_info_tbl.array);
	}
	return ret;
}

void ltelc_rsrp_subscribe(bool subscribe) {
	ltelc_subscribe_for_rsrp = subscribe;
	if (ltelc_subscribe_for_rsrp && uart_shell != NULL) {
		/* print current value right away: */
		shell_print(uart_shell, "RSRP subscribed");
		shell_print(uart_shell, "RSRP: %d", modem_rsrp);
	} else {
		shell_print(uart_shell, "RSRP unsubscribed");
	}
}

int ltelc_func_mode_set(int fun)
{
	int return_value = 0;

	switch (fun) {
	case LTELC_FUNMODE_PWROFF:
		return_value = lte_lc_power_off();
		break;
	case LTELC_FUNMODE_FLIGHTMODE:
		return_value = lte_lc_offline();
		break;
	case LTELC_FUNMODE_NORMAL:
	default:
		return_value = lte_lc_normal();
		break;
	}
	return return_value;
}

int ltelc_func_mode_get(void)
{
    enum lte_lc_func_mode functional_mode;	
	int err = lte_lc_func_mode_get(&functional_mode);
	int lte_lc_shell_fun_mode = 0;
    
	if (err >= 0) {
		switch (functional_mode) {
		case LTE_LC_FUNC_MODE_POWER_OFF:
			lte_lc_shell_fun_mode = LTELC_FUNMODE_PWROFF;
			break;
		case LTE_LC_FUNC_MODE_NORMAL:
			lte_lc_shell_fun_mode = LTELC_FUNMODE_NORMAL;
			break;
		case LTE_LC_FUNC_MODE_OFFLINE:
			lte_lc_shell_fun_mode = LTELC_FUNMODE_FLIGHTMODE;
			break;
		default:
			lte_lc_shell_fun_mode = functional_mode;
			break;
		}
		return lte_lc_shell_fun_mode;
	} else {
		return err;
	}
}

int ltelc_pdn_init_and_connect(const char *apn_name)
{
	if (apn_name != NULL) {
		ltelc_pdn_socket_info_t* pdn_socket_info = ltelc_pdn_socket_info_get_by_apn(apn_name);
		if (pdn_socket_info == NULL) {
			ltelc_pdn_socket_info_t* new_pdn_socket_info = NULL;
			int pdn_fd = nrf_socket(NRF_AF_LTE, NRF_SOCK_MGMT, NRF_PROTO_PDN);

			if (pdn_fd >= 0) {
				/* Connect to the APN. */
				int err = nrf_connect(pdn_fd, apn_name, strlen(apn_name));
				if (err) {
					printk("ltelc_pdn_init_and_connect: could not connect pdn socket: %d", err);
					(void)nrf_close(pdn_fd);
					return -EINVAL;
				}
			}
			/* Add to PDN socket list: */
			new_pdn_socket_info = ltelc_pdn_socket_info_create(apn_name, pdn_fd);
			if (new_pdn_socket_info == NULL) {
				printk("ltelc_pdn_init_and_connect: could not add new PDN socket to list!!!");
			}
			return pdn_fd;
		}
		else {
			/* PDN socket already created to requested AAPN, let's return that: */
			return pdn_socket_info->fd;
		}
	}
	return -EINVAL;
}

int ltelc_pdn_disconnect(const char* apn, int pdn_cid)
{
	ltelc_pdn_socket_info_t* pdn_socket_info = NULL;
	if (apn != NULL) {
		pdn_socket_info = ltelc_pdn_socket_info_get_by_apn(apn);
	} else if (pdn_cid >= 0) {
		// TODO: Check if there is more elegant way of handling apn string
		char apn_str[FTA_APN_STR_MAX_LEN];
		int ret = ltelc_get_apn_by_pdn_cid(pdn_cid, apn_str);
		if (ret != 0) {
			printk("No APN found for PDN CID %d\n", pdn_cid);
		} else {
			pdn_socket_info = ltelc_pdn_socket_info_get_by_apn(apn_str);
		}
	} else {
		shell_error(uart_shell, "Either APN or PDN CID must be given\n");
		return -EINVAL;
	}

	if (pdn_socket_info != NULL) {
		return ltelc_pdn_socket_info_clear(pdn_socket_info);
	} else {
		/* Not existing connection by using ltelc */
		printk("No existing connection created by using ltelc to apn %s\n", FTA_STRING_NULL_CHECK(apn));
		return -EINVAL;
	}
}
