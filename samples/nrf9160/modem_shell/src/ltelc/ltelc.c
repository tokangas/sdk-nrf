/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>

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
#include "ltelc_shell_print.h"

#include "ltelc_shell_pdn.h"
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

	ltelc_api_modem_info_get_for_shell(uart_shell, true);
}
//**************************************************************************

static void ltelc_rsrp_signal_handler(char rsrp_value)
{

	modem_rsrp = (int8_t)rsrp_value - MODEM_INFO_RSRP_OFFSET_VAL;
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
	
	uart_shell = shell_backend_uart_get_ptr();

	ltelc_sett_init(uart_shell);

	ltelc_shell_pdn_init(uart_shell);

	lte_lc_register_handler(ltelc_ind_handler);

/* With CONFIG_LWM2M_CARRIER, MoSH auto connect must be disabled 
   because LwM2M carrier lib handles that. */
#if !defined(CONFIG_LWM2M_CARRIER)
	if (ltelc_sett_is_normal_mode_autoconn_enabled() == true) {
		ltelc_func_mode_set(LTE_LC_FUNC_MODE_NORMAL);
	}
#endif
}

void ltelc_ind_handler(const struct lte_lc_evt *const evt)
{
	char snum[64];

	switch (evt->type) {
	case LTE_LC_EVT_TAU_PRE_WARNING:
		/** Tracking Area Update pre-warning.
		 *  This event will be received a configurable amount of time before TAU is scheduled to
		 *  occur. This gives the application the opportunity to send data over the network before
		 *  the TAU happens, thus saving power by avoiding sending data and the TAU separately.
		 */
		shell_print(uart_shell, "TAU pre warning: time %lld", evt->time);
		break;
	case LTE_LC_EVT_NEIGHBOR_CELL_MEAS: {
		int i;
		struct lte_lc_cells_info cells = evt->cells_info;
		struct lte_lc_cell cur_cell = cells.current_cell;

		/* Current cell: */
		shell_print(uart_shell, "Current cell:");
		shell_print(
			uart_shell,
			"    ID %d, phy ID %d, MCC %d MNC %d, RSRP %d, RSRQ %d, TAC %d, earfcn %d, meas time %lld, TA %d",
				cur_cell.id,
				cur_cell.phys_cell_id,
				cur_cell.mcc,
				cur_cell.mnc,
				cur_cell.rsrp,
				cur_cell.rsrq,
				cur_cell.tac,
				cur_cell.earfcn,
				cur_cell.measurement_time,
				cur_cell.timing_advance);

		for (i = 0; i < cells.ncells_count; i++) {
			/* Neighbor cells: */
			shell_print(uart_shell, "Neighbor cell %d", i + 1);
			shell_print(
				uart_shell,
				"    phy ID %d, RSRP %d, RSRQ %d, earfcn %d, timediff %d",
				cells.neighbor_cells[i].phys_cell_id,
				cells.neighbor_cells[i].rsrp,
				cells.neighbor_cells[i].rsrq,
				cells.neighbor_cells[i].earfcn,
				cells.neighbor_cells[i].time_diff);
		}
	}
	break;
	case LTE_LC_EVT_MODEM_SLEEP_EXIT_PRE_WARNING: 
	case LTE_LC_EVT_MODEM_SLEEP_ENTER:
	case LTE_LC_EVT_MODEM_SLEEP_EXIT:
		ltelc_shell_print_modem_sleep_notif(uart_shell, evt);
		break;
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
		ltelc_shell_print_reg_status(uart_shell, evt->nw_reg_status);

#if defined(CONFIG_MODEM_INFO)
		if (evt->nw_reg_status == LTE_LC_NW_REG_REGISTERED_EMERGENCY ||
			evt->nw_reg_status == LTE_LC_NW_REG_REGISTERED_HOME ||
			evt->nw_reg_status == LTE_LC_NW_REG_REGISTERED_ROAMING) {
			k_work_submit(&modem_info_work);
		}
#endif
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
		shell_print(uart_shell, "PSM parameter update: TAU: %d, Active time: %d seconds",
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

void ltelc_ncellmeas_subscribe(bool subscribe) {
	int ret;
	
	if (subscribe) {
		ret = lte_lc_neighbor_cell_measurement();
		if (uart_shell != NULL) {
			if (ret) {
				shell_error(uart_shell, "lte_lc_neighbor_cell_measurement() returned err %d", ret);
			} else {
				shell_print(uart_shell, "Neighbor cell measurements and reporting subscribed");
			}
		}
	} else {
		ret = lte_lc_neighbor_cell_measurement_cancel();
		if (uart_shell != NULL) {
			if (ret) {
				shell_error(uart_shell, "lte_lc_neighbor_cell_measurement_cancel() returned err %d", ret);
			} else {
				shell_print(uart_shell, "Neighbor cell measurements and reporting unsubscribed");
			}
		}
	}
}

#define AT_MDM_SLEEP_NOTIF_START "AT%%XMODEMSLEEP=1,%d,%d"
#define AT_MDM_SLEEP_NOTIF_STOP "AT%XMODEMSLEEP=0"

void ltelc_modem_sleep_notifications_subscribe(uint32_t warn_time_ms, uint32_t threshold_ms)
{
	char buf_sub[48];
	int err;

	snprintk(buf_sub, sizeof(buf_sub), AT_MDM_SLEEP_NOTIF_START,
		 warn_time_ms, threshold_ms);

	err = at_cmd_write(buf_sub, NULL, 0, NULL);
	if (err) {
		shell_error(uart_shell,
			"Cannot subscribe to modem sleep notifications, err %d", err);
	} else {
		shell_print(uart_shell, "Subscribed to modem sleep notifications");
	}
}

void ltelc_modem_sleep_notifications_unsubscribe()
{
	int err;

	err = at_cmd_write(AT_MDM_SLEEP_NOTIF_STOP, NULL, 0, NULL);
	if (err) {
		shell_error(uart_shell,
			"Cannot stop modem sleep notifications, err %d", err);
	} else {
		shell_print(uart_shell, "Unsubscribed from modem sleep notifications");
	}
}

#define AT_TAU_NOTIF_START      "AT%%XT3412=1,%d,%d"
#define AT_TAU_NOTIF_STOP       "AT%%T3412=0"

void ltelc_modem_tau_notifications_subscribe(uint32_t warn_time_ms, uint32_t threshold_ms)
{
	char buf_sub[48];
	int err;

	snprintk(buf_sub, sizeof(buf_sub), AT_TAU_NOTIF_START,
		 warn_time_ms, threshold_ms);

	err = at_cmd_write(buf_sub, NULL, 0, NULL);
	if (err) {
		shell_error(uart_shell,
			"Cannot subscribe to TAU notifications, err %d", err);
	} else {
		shell_print(uart_shell, "Subscribed to TAU notifications");
	}
}

void ltelc_modem_tau_notifications_unsubscribe(void)
{
	int err;

	err = at_cmd_write(AT_MDM_SLEEP_NOTIF_STOP, NULL, 0, NULL);
	if (err) {
		shell_error(uart_shell,
			"Cannot stop modem sleep notifications, err %d", err);
	} else {
		shell_print(uart_shell, "Unsubscribed from modem sleep notifications");
	}
}

int ltelc_func_mode_set(enum lte_lc_func_mode fun)
{
	int return_value = 0;
	int sysmode;
	int lte_pref;

	switch (fun) {
	case LTE_LC_FUNC_MODE_POWER_OFF:
#if defined (CONFIG_MOSH_SMS)	
		sms_unregister();
#endif
		return_value = lte_lc_power_off();
		break;
	case LTE_LC_FUNC_MODE_OFFLINE:
		return_value = lte_lc_offline();
		break;
	case LTE_LC_FUNC_MODE_NORMAL:
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
			/* TODO: why not just do lte_lc_normal() as notifications are subscribed there also nowadays? */ 
			return_value = lte_lc_init_and_connect_async(ltelc_ind_handler);
			if (return_value == -EALREADY) {
				return_value = lte_lc_connect_async(ltelc_ind_handler);
			}
		}
		break;
	case LTE_LC_FUNC_MODE_DEACTIVATE_LTE:
	case LTE_LC_FUNC_MODE_ACTIVATE_LTE:
	case LTE_LC_FUNC_MODE_DEACTIVATE_GNSS:
	case LTE_LC_FUNC_MODE_ACTIVATE_GNSS:
	case LTE_LC_FUNC_MODE_DEACTIVATE_UICC:
	case LTE_LC_FUNC_MODE_ACTIVATE_UICC:
	case LTE_LC_FUNC_MODE_OFFLINE_UICC_ON:
	default:
		return_value = lte_lc_func_mode_set(fun);
		if (return_value) {
			shell_error(
				uart_shell, "lte_lc_func_mode_set returned, error %d",
					return_value);
		}
		break;
	}

	return return_value;
}

