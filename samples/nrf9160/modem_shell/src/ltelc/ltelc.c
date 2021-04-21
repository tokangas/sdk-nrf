/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
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

#include <modem/at_cmd.h>
#include <modem/modem_info.h>
#include <modem/lte_lc.h>

#include <nrf_socket.h>

#include "ltelc_settings.h"
#include "ltelc_shell.h"
#include "ltelc_api.h"
#include "ltelc.h"

#if defined (CONFIG_MOSH_SMS)
#include "sms.h"
#endif

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
#define LTELC_RSRP_VALUE_NOT_KNOWN -999
static int32_t modem_rsrp = LTELC_RSRP_VALUE_NOT_KNOWN;

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

#define MOSH_RSRP_UPDATE_INTERVAL_IN_SECS 5
static void ltelc_rsrp_signal_update(struct k_work *work)
{
	static uint32_t timestamp_prev = 0;

	if ((timestamp_prev != 0) &&
	    (k_uptime_get_32() - timestamp_prev <
	     MOSH_RSRP_UPDATE_INTERVAL_IN_SECS * MSEC_PER_SEC)) {
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
	lte_lc_register_handler(ltelc_ind_handler);

	sys_dlist_init(&pdn_socket_list);

	uart_shell = shell_backend_uart_get_ptr();
	ltelc_sett_init(uart_shell);

/* With CONFIG_LWM2M_CARRIER, MoSH auto connect must be disabled 
   because LwM2M carrier lib handles that. */
#if !defined(CONFIG_LWM2M_CARRIER)
	if (ltelc_sett_is_normal_mode_autoconn_enabled() == true) {
		ltelc_func_mode_set(LTELC_FUNMODE_NORMAL);
	}
#endif
}

void ltelc_ind_handler(const struct lte_lc_evt *const evt)
{
	char snum[64];

	switch (evt->type) {
	case LTE_LC_EVT_LTE_MODE_UPDATE:
		/** The currently active LTE mode is updated. If a system mode that
		 *  enables both LTE-M and NB-IoT is configured, the modem may change
		 *  the currently active LTE mode based on the system mode preference
		 *  and network availability. This event will then indicate which
		 *  LTE mode is currently used by the modem.
		 */
		shell_print(uart_shell, "Currently active system mode: %s", 
			ltelc_shell_sysmode_currently_active_to_string(
				evt->lte_mode, snum));
		break;	
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
	case LTE_LC_EVT_RRC_UPDATE:
		shell_print(uart_shell, "RRC mode: %s",
			evt->rrc_mode == LTE_LC_RRC_MODE_CONNECTED ?
			"Connected" : "Idle");
		break;
	case LTE_LC_EVT_PSM_UPDATE:
		shell_print(uart_shell, "PSM parameter update: TAU: %d, Active time: %d",
			evt->psm_cfg.tau, evt->psm_cfg.active_time);
		break;
	case LTE_LC_EVT_EDRX_UPDATE: {
		char log_buf[60];
		ssize_t len;

		len = snprintf(log_buf, sizeof(log_buf),
			       "eDRX parameter update: eDRX: %f, PTW: %f",
			       evt->edrx_cfg.edrx, evt->edrx_cfg.ptw);
		if (len > 0) {
			shell_print(uart_shell, "%s", log_buf);
		}
		break;
	}			
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
static int ltelc_default_pdp_context_set()
{
	static char cgdcont[128];

	if (ltelc_sett_is_defcont_enabled() == true) {
		snprintf(cgdcont, sizeof(cgdcont),
			"AT+CGDCONT=0,\"%s\",\"%s\"",
				ltelc_sett_defcont_ip_family_get(),
				ltelc_sett_defcont_apn_get());
		if (at_cmd_write(cgdcont, NULL, 0, NULL) != 0) {
			printf("ltelc_default_pdp_context_set: ERROR received for %s", cgdcont);
			return -EIO;
		}
	}
	return 0;
}
static int ltelc_default_pdp_context_auth_set()
{
	static char cgauth[128];

	if (ltelc_sett_is_defcontauth_enabled() == true) {
		snprintf(cgauth, sizeof(cgauth),
			"AT+CGAUTH=0,%d,\"%s\",\"%s\"",
				ltelc_sett_defcontauth_prot_get(),
				ltelc_sett_defcontauth_username_get(),
				ltelc_sett_defcontauth_password_get());
		if (at_cmd_write(cgauth, NULL, 0, NULL) != 0) {
			shell_error(uart_shell, "ltelc_default_pdp_context_auth_set: ERROR received for %s", cgauth);
			return -EIO;
		}
	}
	return 0;
}


static int ltelc_normal_mode_at_cmds_run()
{
	char *normal_mode_at_cmd;
	char response[CONFIG_AT_CMD_RESPONSE_MAX_LEN + 1];
	int mem_slot_index = LTELC_SETT_NMODEAT_MEM_SLOT_INDEX_START;
	int len;

	for (;mem_slot_index <= LTELC_SETT_NMODEAT_MEM_SLOT_INDEX_END; mem_slot_index++) {
		normal_mode_at_cmd = ltelc_sett_normal_mode_at_cmd_str_get(mem_slot_index);
		len = strlen(normal_mode_at_cmd);
		if (len) {
			if (at_cmd_write(
				normal_mode_at_cmd, response, sizeof(response), NULL) != 0) {
				shell_error(
					uart_shell, 
					"Normal mode AT-command from memory slot %d \"%s\" returned: ERROR",
						mem_slot_index,
						normal_mode_at_cmd);
			} 
			else {
				shell_print(
					uart_shell, 
					"Normal mode AT-command from memory slot %d \"%s\" returned:\n\r %s OK",
						mem_slot_index,
						normal_mode_at_cmd,
						response);
			}
		}
	}

	return 0;
}

void ltelc_rsrp_subscribe(bool subscribe) {
	ltelc_subscribe_for_rsrp = subscribe;
	if (uart_shell != NULL) {
		if (ltelc_subscribe_for_rsrp) {
			/* print current value right away: */
			shell_print(uart_shell, "RSRP subscribed");
			if (modem_rsrp != LTELC_RSRP_VALUE_NOT_KNOWN)
				shell_print(uart_shell, "RSRP: %d", modem_rsrp);
		}
		else {
			shell_print(uart_shell, "RSRP unsubscribed");
		}
	}
}

int ltelc_func_mode_set(int fun)
{
	int return_value = 0;
	int sysmode;
	int lte_pref;

	switch (fun) {
	case LTELC_FUNMODE_PWROFF:
#if defined (CONFIG_MOSH_SMS)	
		sms_unregister();
#endif
		return_value = lte_lc_power_off();
		break;
	case LTELC_FUNMODE_FLIGHTMODE:
		return_value = lte_lc_offline();
		break;
	case LTELC_FUNMODE_NORMAL:
	default:
	    /* Run custom at cmds from settings (ltelc nmodeat -mosh command): */
	    ltelc_normal_mode_at_cmds_run();

	    /* Set default context from settings 
		   (ltelc defcont/defcontauth -mosh commands): */
		ltelc_default_pdp_context_set();
		ltelc_default_pdp_context_auth_set();

		/* Set saved system mode (if set) from settings
		   (by ltelc sysmode -mosh command): */
		sysmode = ltelc_sett_sysmode_get();
		lte_pref = ltelc_sett_sysmode_lte_preference_get();
		if (sysmode != LTE_LC_SYSTEM_MODE_NONE) {
			return_value = lte_lc_system_mode_set(sysmode, lte_pref);
			if (uart_shell != NULL && return_value < 0) {
				shell_warn(
					uart_shell, "lte_lc_system_mode_set returned error %d",
						return_value);
			}
		}

		if (IS_ENABLED(CONFIG_LTE_AUTO_INIT_AND_CONNECT)) {
			return_value = lte_lc_normal();
		}
		else {
			return_value = lte_lc_init_and_connect_async(ltelc_ind_handler);
			if (return_value == -EALREADY) {
				return_value = lte_lc_connect_async(ltelc_ind_handler);
			}
		}
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

static int ltelc_family_set(int pdn_fd, const char *family)
{
	nrf_sa_family_t families[2];
	int families_len = sizeof(nrf_sa_family_t);

	if (strcmp(family, "ipv4v6") == 0) {
		families[0] = NRF_AF_INET;
		families[1] = NRF_AF_INET6;
		families_len *= 2;
	} else if (strcmp(family, "ipv4") == 0) {
		families[0] = NRF_AF_INET;
	} else if (strcmp(family, "ipv6") == 0) {
		families[0] = NRF_AF_INET6;
	} else if (strcmp(family, "packet") == 0) {
		families[0] = NRF_AF_PACKET;
	} else {
		printk("ltelc_pdn_init_and_connect: could not decode PDN address family (%s)\n", family);
		return -EINVAL;
	}

	int err = nrf_setsockopt(pdn_fd, NRF_SOL_PDN, NRF_SO_PDN_AF, families, families_len);
	if (err) {
		printk("ltelc_pdn_init_and_connect: could not set address family (%s) for PDN: %d\n", family, err);
	}
	return err;
}

int ltelc_pdn_init_and_connect(const char *apn_name, const char *family)
{
	int pdn_fd = -1;
	if (apn_name != NULL) {
		ltelc_pdn_socket_info_t* pdn_socket_info = ltelc_pdn_socket_info_get_by_apn(apn_name);
		if (pdn_socket_info == NULL) {
			ltelc_pdn_socket_info_t* new_pdn_socket_info = NULL;
			pdn_fd = nrf_socket(NRF_AF_LTE, NRF_SOCK_MGMT, NRF_PROTO_PDN);

			if (pdn_fd >= 0) {
				/* Set address family of the PDN context */
				if (family != NULL) {
					int err = ltelc_family_set(pdn_fd, family);
					if (err) {
						goto error;
					}
				}

				/* Connect to the APN */
				int err = nrf_connect(pdn_fd, apn_name, strlen(apn_name));
				if (err) {
					printk("ltelc_pdn_init_and_connect: could not connect pdn socket: %d\n", err);
					goto error;
				}

				/* Add to PDN socket list: */
				new_pdn_socket_info = ltelc_pdn_socket_info_create(apn_name, pdn_fd);
				if (new_pdn_socket_info == NULL) {
					printk("ltelc_pdn_init_and_connect: could not add new PDN socket to list\n");
					goto error;
				}
				return pdn_fd;
			}
		} else {
			/* PDN socket already created to requested AAPN, let's return that: */
			return pdn_socket_info->fd;
		}
	}
	return -EINVAL;

error:
	(void)nrf_close(pdn_fd);
	return -EINVAL;
}

int ltelc_pdn_disconnect(const char* apn, int pdn_cid)
{
	ltelc_pdn_socket_info_t* pdn_socket_info = NULL;
	if (apn != NULL) {
		pdn_socket_info = ltelc_pdn_socket_info_get_by_apn(apn);
	} else if (pdn_cid >= 0) {
		pdp_context_info_t* pdp_context_info = ltelc_api_get_pdp_context_info_by_pdn_cid(pdn_cid);
		if (pdp_context_info == NULL) {
			printk("No APN found for PDN CID %d\n", pdn_cid);
		} else {
			pdn_socket_info = ltelc_pdn_socket_info_get_by_apn(pdp_context_info->apn_str);
		}
		free(pdp_context_info);
	} else {
		shell_error(uart_shell, "Either APN or PDN CID must be given\n");
		return -EINVAL;
	}

	if (pdn_socket_info != NULL) {
		return ltelc_pdn_socket_info_clear(pdn_socket_info);
	} else {
		/* Not existing connection by using ltelc */
		printk("No existing connection created by using ltelc to apn %s\n", MOSH_STRING_NULL_CHECK(apn));
		return -EINVAL;
	}
}
