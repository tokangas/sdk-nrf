/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <string.h>
#include <date_time.h>
#include <zephyr.h>
#include <logging/log.h>
#include <sys/timeutil.h>
#include <settings/settings.h>
#include <modem/at_cmd.h>
#include <modem/at_cmd_parser.h>
#include <modem/at_params.h>
#include <modem/at_notif.h>
#include <net/fota_download.h>
#include <modem/modem_fota.h>
#include <nrf_socket.h>
#include "modem_fota_internal.h"

LOG_MODULE_REGISTER(modem_fota, CONFIG_MODEM_FOTA_LOG_LEVEL);

/* Time to sleep between AT+CSCON checks in seconds */
#define WAIT_DATA_INACTIVITY_SLEEP_TIME 10

/* Enums */
enum modem_reg_status {
	MODEM_REG_STATUS_NOT_REGISTERED,
	MODEM_REG_STATUS_HOME,
	MODEM_REG_STATUS_ROAMING
};

enum modem_lte_mode {
	MODEM_LTE_MODE_M = 7,
	MODEM_LTE_MODE_NBIOT = 9
};

/* Forward declarations */
static bool wait_for_data_inactivity();
static void restore_system_mode();
static void schedule_next_update();
static void update_check_timer_handler(struct k_timer *dummy);
static void at_notification_handler(void *context, const char *notif);

/* Work queue */
#define WORK_QUEUE_STACK_SIZE 1024
#define WORK_QUEUE_PRIORITY 5

K_THREAD_STACK_DEFINE(work_q_stack_area, WORK_QUEUE_STACK_SIZE);

static struct k_work_q work_q;
static struct k_work update_work;
static struct finish_update_info {
	struct k_work work;
	enum modem_fota_evt_id event;
} finish_update;

static struct k_sem link;

K_TIMER_DEFINE(update_check_timer, update_check_timer_handler, NULL);

#define AT_CEREG_PARAMS_COUNT_MAX	10
#define AT_CEREG_REG_STATUS_INDEX	1
#define AT_CEREG_TAC_INDEX		2
#define AT_CEREG_TAC_LEN		4
#define AT_CEREG_LTE_MODE_INDEX		4
#define AT_XTIME_PARAMS_COUNT_MAX	4
#define AT_XTIME_UNIVERSAL_TIME_INDEX	2
#define AT_XTIME_UNIVERSAL_TIME_LEN	14
#define AT_CGSN_IMEI_INDEX		1
#define AT_CGMR_VERSION_INDEX		0
#define AT_CSCON_MODE_INDEX		2
#define AT_XSYSTEMMODE_PARAMS_COUNT	5
#define AT_XSYSTEMMODE_RESPONSE_MAX_LEN	30

static const char at_cereg_notif[] = "+CEREG";
static const char at_xtime_notif[] = "\%XTIME";
/* Set the modem to Normal mode */
static const char at_cfun_normal[] = "AT+CFUN=1";
/* Set the modem to Offline mode */
static const char at_cfun_offline[] = "AT+CFUN=4";
static const char at_xsystemmode_read[] = "AT\%XSYSTEMMODE?";
static const char at_xsystemmode_template[] = "AT%%XSYSTEMMODE=%d,%d,%d,%d";
static const char at_xsystemmode_m1_only[] = "AT\%XSYSTEMMODE=1,0,0,0";

static modem_fota_callback_t event_callback;

/* Network time (milliseconds since epoch) and timestamp when it was got */
static s64_t network_time;
static s64_t network_time_timestamp;

/* Current modem registration status and LTE mode */
static enum modem_reg_status reg_status;
static enum modem_lte_mode lte_mode;

/* FOTA is enabled by default */
static bool fota_enabled = true;

/* Settings which are saved to NV memory */
/* Next scheduled update check time (seconds since epoch) */
static s64_t update_check_time_s;
/* DM server host name (if != NULL overrides the configured default) */
static char *dm_server_host;
/* DM server port number (if != 0 overrides the configured default) */
static u16_t dm_server_port;

/* Information needed to fetch the firmware update */
static char *fw_update_host;
static char *fw_update_file;

/* FOTA APN or NULL if default APN is used */
static const char *fota_apn;
/* PDN socket file descriptor for FOTA PDN activation */
static int pdn_fd = -1;

static bool restore_system_mode_needed = false;
static u32_t prev_system_mode_bitmask = 0;

static void parse_network_time(const char *time_str)
{
	struct tm date_time;
	char temp[3] = {0};

	/* Year */
	temp[0] = time_str[1];
	temp[1] = time_str[0];
	date_time.tm_year = atoi(temp) + 2000 - 1900;

	/* Month */
	temp[0] = time_str[3];
	temp[1] = time_str[2];
	date_time.tm_mon = atoi(temp);

	/* Day */
	temp[0] = time_str[5];
	temp[1] = time_str[4];
	date_time.tm_mday = atoi(temp);

	/* Hour */
	temp[0] = time_str[7];
	temp[1] = time_str[6];
	date_time.tm_hour = atoi(temp);

	/* Minute */
	temp[0] = time_str[9];
	temp[1] = time_str[8];
	date_time.tm_min = atoi(temp);

	/* Second */
	temp[0] = time_str[11];
	temp[1] = time_str[10];
	date_time.tm_sec = atoi(temp);

	LOG_DBG("Current time: %d.%d.%d %02d:%02d:%02d UTC",
		date_time.tm_mday, date_time.tm_mon, date_time.tm_year + 1900,
		date_time.tm_hour, date_time.tm_min, date_time.tm_sec);

	network_time = (s64_t)timeutil_timegm64(&date_time) * 1000;
	network_time_timestamp = k_uptime_get();
}

static bool is_network_time_valid()
{
	return network_time != 0 && network_time_timestamp != 0;
}

static char *param_string_get(const char *str, int index)
{
	int err;
	char *param_str = NULL;
	size_t param_str_len;
	struct at_param_list param_list = {0};

	err = at_params_list_init(&param_list, index + 1);
	if (err) {
		LOG_ERR("Could not initialize params list, error: %d", err);
		return NULL;
	}

	err = at_parser_max_params_from_str(str,
					    NULL,
					    &param_list,
					    index + 1);
	if (err && err != -E2BIG) {
		LOG_ERR("Could not parse response, error: %d", err);
		goto clean_exit;
	}

	err = at_params_size_get(&param_list, index, &param_str_len);
	if (err) {
		LOG_ERR("Could not get parameter length, error: %d", err);
		goto clean_exit;
	}

	param_str = k_malloc(param_str_len + 1);

	err = at_params_string_get(&param_list,
				   index,
				   param_str,
				   &param_str_len);
	if (err) {
		LOG_ERR("Could not get parameter, error: %d", err);
		k_free(param_str);
		param_str = NULL;
		goto clean_exit;
	}

	param_str[param_str_len] = '\0';

clean_exit:
	at_params_list_free(&param_list);

	return param_str;
}

static int parse_cereg_notification(const char *notif)
{
	int err;
	u32_t value;
	char tac_str[AT_CEREG_TAC_LEN + 1];
	size_t tac_str_len;
	bool tac_valid;
	struct at_param_list param_list = {0};

	err = at_params_list_init(&param_list, AT_CEREG_PARAMS_COUNT_MAX);
	if (err) {
		LOG_ERR("Could not initialize params list, error: %d", err);
		return err;
	}

	err = at_parser_max_params_from_str(notif,
					    NULL,
					    &param_list,
					    AT_CEREG_PARAMS_COUNT_MAX);
	if (err) {
		LOG_ERR("Could not parse response, error: %d", err);
		goto clean_exit;
	}

	/* Registration status */
	err = at_params_int_get(&param_list,
				AT_CEREG_REG_STATUS_INDEX,
				&value);
	if (err) {
		LOG_ERR("Could not get registration status, error: %d", err);
		goto clean_exit;
	}

	/* Tracking area code */
	tac_str_len = AT_CEREG_TAC_LEN;
	err = at_params_string_get(&param_list,
				   AT_CEREG_TAC_INDEX,
				   tac_str,
				   &tac_str_len);
	if (err) {
		LOG_ERR("Could not get TAC, error: %d", err);
		goto clean_exit;
	}

	if (tac_str_len == AT_CEREG_TAC_LEN &&
			strncmp(tac_str, "FFFE", tac_str_len) != 0) {
		tac_valid = true;
	} else {
		tac_valid = false;
	}

	/* Need to be registered and have a valid TAC */
	if (tac_valid && value == 1) {
		reg_status = MODEM_REG_STATUS_HOME;
		k_sem_give(&link);
	} else if (tac_valid && value == 5) {
		reg_status = MODEM_REG_STATUS_ROAMING;
		k_sem_give(&link);
	} else {
		reg_status = MODEM_REG_STATUS_NOT_REGISTERED;
	}

	/* LTE mode */
	err = at_params_int_get(&param_list,
				AT_CEREG_LTE_MODE_INDEX,
				&value);
	if (err) {
		LOG_ERR("Could not get LTE mode, error: %d", err);
		goto clean_exit;
	}

	if (value == 7)
		lte_mode = MODEM_LTE_MODE_M;
	else if (value == 9)
		lte_mode = MODEM_LTE_MODE_NBIOT;
	else
		LOG_WRN("Unknown LTE mode in +CEREG notification");

clean_exit:
	at_params_list_free(&param_list);

	return err;
}

static int parse_time_from_xtime_notification(const char *notif)
{
	char *time_str;

	time_str = param_string_get(notif, AT_XTIME_UNIVERSAL_TIME_INDEX);
	if (time_str != NULL) {
		parse_network_time(time_str);
		k_free(time_str);
		return 0;
	} else {
		return -1;
	}
}

static void unregister_at_xtime_notification()
{
	int err;

	err = at_cmd_write("AT\%XTIME=0", NULL, 0, NULL);
	if (err) {
		LOG_ERR("Failed to disable XTIME, error: %d", err);
		return;
	}
}

static s64_t get_current_time_in_s()
{
	return (k_uptime_get() - network_time_timestamp + network_time) / 1000;
}

static char *get_modem_imei()
{
	int err;
	char response[32];

	err = at_cmd_write("AT+CGSN=1", response, sizeof(response), NULL);
	if (err) {
		LOG_ERR("Could not execute +CGSN command, error: %d", err);
		return NULL;
	}

	return param_string_get(response, AT_CGSN_IMEI_INDEX);
}

static char *get_modem_fw_version()
{
	int err;
	char response[128];

	err = at_cmd_write("AT+CGMR", response, sizeof(response), NULL);
	if (err) {
		LOG_ERR("Could not execute +CGMR command, error: %d", err);
		return NULL;
	}

	return param_string_get(response, AT_CGMR_VERSION_INDEX);
}

static void free_fw_update_info()
{
	k_free(fw_update_host);
	k_free(fw_update_file);
	fw_update_host = NULL;
	fw_update_file = NULL;
}

static int activate_fota_pdn()
{
	int err;
	nrf_sa_family_t af[2];
	int af_count;

	if (fota_apn == NULL)
		return 0;

	LOG_DBG("Activating FOTA PDN");

	pdn_fd = nrf_socket(NRF_AF_LTE, NRF_SOCK_MGMT, NRF_PROTO_PDN);
	if (pdn_fd < 0) {
		LOG_ERR("Failed to open PDN socket");
		return -1;
	}

	/* Configure PDN type (IPv4/IPv6/IPv4v6) */
	af_count = 0;
	if (IS_ENABLED(CONFIG_MODEM_FOTA_APN_PDN_TYPE_IPV4)) {
		LOG_DBG("FOTA PDN type IPv4");
		af[af_count++] = NRF_AF_INET;
	} else if (IS_ENABLED(CONFIG_MODEM_FOTA_APN_PDN_TYPE_IPV6)) {
		LOG_DBG("FOTA PDN type IPv6");
		af[af_count++] = NRF_AF_INET6;
	} else {
		LOG_DBG("FOTA PDN type IPv4v6");
		af[af_count++] = NRF_AF_INET;
		af[af_count++] = NRF_AF_INET6;
	}
	err = nrf_setsockopt(pdn_fd, NRF_SOL_PDN, NRF_SO_PDN_AF,
			     af, sizeof(nrf_sa_family_t) * af_count);
	if (err) {
		LOG_ERR("Could not set FOTA PDN type, error: %d", err);
		return err;
	}

	err = nrf_connect(pdn_fd, fota_apn, strlen(fota_apn));
	if (err) {
		LOG_ERR("Could not connect FOTA PDN, error: %d", err);
		return err;
	}

	return 0;
}

static void deactivate_fota_pdn()
{
	if (pdn_fd >= 0) {
		nrf_close(pdn_fd);
		pdn_fd = -1;

		LOG_DBG("FOTA PDN deactivated");
	}
}

static const char firmware_host[] =
		"vehoniemi.s3.amazonaws.com";
static const char original_to_fota_firmware_name[] =
		"mfw_nrf9160_update_from_1.2.0_to_1.2.0-FOTA-TEST.bin";
static const char fota_to_original_firmware_name[] =
		"mfw_nrf9160_update_from_1.2.0-FOTA-TEST_to_1.2.0.bin";

/* Temporary stub because we don't yet have the DM implementation */
static int fota_dm_query_fw_update(const char *imei, const char *fw_version,
				   char **fw_update_host, char **fw_update_file)
{
	LOG_DBG("Querying for FW update");
	LOG_DBG("Current FW version: %s", log_strdup(fw_version));

	*fw_update_host = k_malloc(sizeof(firmware_host));
	/* Assuming the filenames have equal length */
	*fw_update_file = k_malloc(sizeof(original_to_fota_firmware_name));

	if (*fw_update_host == NULL || *fw_update_file == NULL) {
		free_fw_update_info();
		return -ENOMEM;
	}

	strcpy(*fw_update_host, firmware_host);
	if (strstr(fw_version, "FOTA") == NULL) {
		/* Original version, update to FOTA test version */
		strcpy(*fw_update_file, original_to_fota_firmware_name);
	} else {
		/* FOTA test version, update to original version */
		strcpy(*fw_update_file, fota_to_original_firmware_name);
	}

	return 0;
}

static void finish_update_check(enum modem_fota_evt_id event_id)
{
	finish_update.event = event_id;
	k_work_submit_to_queue(&work_q, &finish_update.work);
}

/* Performs cleanup after FW update check or FW update and schedules the next
 * update check.
 */
static void finish_update_work(struct k_work *item)
{
	struct finish_update_info *info;

	info = CONTAINER_OF(item, struct finish_update_info, work);

	free_fw_update_info();
	deactivate_fota_pdn();
	schedule_next_update();
	restore_system_mode();

	/* If modem firmware was updated, a restart is needed to apply the
	 * update. Before restarting the device, wait until data activity has
	 * stopped.
	 */
	if (info->event == MODEM_FOTA_EVT_RESTART_PENDING) {
		wait_for_data_inactivity();
		/* Sleep for a while before asking for restart because the
		 * previous function returns immediately when RRC connection is
		 * not active or there's no network connection */
		k_sleep(K_SECONDS(1));
	}

	event_callback(info->event);
}

static void fota_download_callback(const struct fota_download_evt *evt)
{
	switch (evt->id) {
	case FOTA_DOWNLOAD_EVT_PROGRESS:
		break;

	case FOTA_DOWNLOAD_EVT_FINISHED:
		LOG_INF("Update downloaded, reboot needed to apply update");
		finish_update_check(MODEM_FOTA_EVT_RESTART_PENDING);
		break;

	case FOTA_DOWNLOAD_EVT_ERASE_PENDING:
		LOG_DBG("Modem scratch area erase pending...");
		break;

	case FOTA_DOWNLOAD_EVT_ERASE_DONE:
		LOG_DBG("Modem scratch area erase done");
		break;

	case FOTA_DOWNLOAD_EVT_ERROR:
		LOG_ERR("Downloading the update failed");
		finish_update_check(MODEM_FOTA_EVT_ERROR);
		break;

	default:
		LOG_ERR("Unknown event from FOTA download");
		break;
	}
}

static bool is_update_check_allowed()
{
	if (!IS_ENABLED(CONFIG_MODEM_FOTA_ALLOWED_DURING_ROAMING) &&
	    reg_status == MODEM_REG_STATUS_ROAMING) {
		LOG_DBG("Roaming, update check not allowed");
		return false;
	}

	return true;
}

/* Waits until the device is connected to the network. The function blocks
 * until connected or a timeout happens. The timeout is given in seconds.
 * Zero means no timeout, i.e. function can block forever.
 */
static bool wait_until_connected_to_network(u32_t timeout_s)
{
	k_timeout_t timeout;
	bool connected = true;

	if (reg_status != MODEM_REG_STATUS_HOME &&
	    reg_status != MODEM_REG_STATUS_ROAMING) {
		if (timeout_s == 0) {
			LOG_INF("Waiting for network connection "
				"(no timeout)...");
			timeout = K_FOREVER;
		} else {
			LOG_INF("Waiting for network connection "
				"(timeout %d s)...", timeout_s);
			timeout = K_SECONDS(timeout_s);
		}
		k_sem_reset(&link);
		if (k_sem_take(&link, timeout) != 0) {
			connected = false;
		}
	}

	return connected;
}

/* Waits until the RRC connection is idle. This is used to wait until the
 * application is not transferring data before proceeding with the FW update.
 */
static bool wait_for_data_inactivity()
{
	int err;
	int count = 0;
	int wait_count;
	bool idle = false;
	int cscon;
	char response[16 + 2 + 1];
	struct at_param_list param_list = {0};

	err = at_params_list_init(&param_list, AT_CSCON_MODE_INDEX + 1);
	if (err) {
		LOG_ERR("Could not initialize params list, error: %d", err);
		return false;
	}

	wait_count = CONFIG_MODEM_FOTA_DATA_INACTIVITY_TIMEOUT * 60 /
			WAIT_DATA_INACTIVITY_SLEEP_TIME;

	while (1) {
		err = at_cmd_write("AT+CSCON?", response, sizeof(response),
				   NULL);
		if (err) {
			LOG_ERR("Failed to request CSCON, error: %d", err);
			break;
		}

		err = at_parser_max_params_from_str(response,
						    NULL,
						    &param_list,
						    AT_CSCON_MODE_INDEX + 1);
		if (err && err != -E2BIG) {
			LOG_ERR("Could not parse response, error: %d", err);
			break;
		}

		err = at_params_int_get(&param_list,
					AT_CSCON_MODE_INDEX,
					&cscon);
		if (err) {
			LOG_ERR("Could not get CSCON mode, error: %d", err);
			break;
		}

		if (cscon == 0) {
			idle = true;
			break;
		} else {
			at_params_list_clear(&param_list);

			if (count == 0) {
				LOG_INF("Waiting for data connection to become "
					"inactive...");
			}

			if (count++ < wait_count) {
				k_sleep(K_SECONDS(WAIT_DATA_INACTIVITY_SLEEP_TIME));
			} else {
				LOG_INF("Timed out waiting for data connection "
					"inactivity");
				break;
			}
		}
	}

	at_params_list_free(&param_list);

	return idle;
}

static bool switch_system_mode_to_lte_m(void)
{
	int err;
	bool success = true;
	char response[AT_XSYSTEMMODE_RESPONSE_MAX_LEN];
	struct at_param_list param_list = {0};

	/* Get and store system mode */
	err = at_cmd_write(at_xsystemmode_read, response, sizeof(response),
			   NULL);
	if (err) {
		LOG_ERR("Failed to read system mode, error: %d", err);
		return false;
	}

	err = at_params_list_init(&param_list, AT_XSYSTEMMODE_PARAMS_COUNT);
	if (err) {
		LOG_ERR("Could init AT params list, error: %d", err);
		return false;
	}

	err = at_parser_max_params_from_str(response, NULL, &param_list,
					    AT_XSYSTEMMODE_PARAMS_COUNT);
	if (err) {
		LOG_ERR("Could not parse AT response, error: %d", err);
		goto clean_exit;
	}

	/* Current system mode is stored into a bitmap which is used when
	 * restoring the system mode later
	 */
	prev_system_mode_bitmask = 0;
	for (size_t i = 1; i < AT_XSYSTEMMODE_PARAMS_COUNT; i++) {
		int param;

		err = at_params_int_get(&param_list, i, &param);
		if (err) {
			LOG_ERR("Could not parse mode parameter, err: %d", err);
			goto clean_exit;
		}

		prev_system_mode_bitmask = param ?
			prev_system_mode_bitmask | BIT(i) : prev_system_mode_bitmask;
	}

	/* Set modem offline */
	err = at_cmd_write(at_cfun_offline, NULL, 0, NULL);
	if (err) {
		LOG_ERR("Failed to set modem to offline mode, error: %d", err);
		return false;
	}

	LOG_INF("Changing system mode to LTE-M");

	restore_system_mode_needed = true;

	/* Change system mode to LTE-M only */
	err = at_cmd_write(at_xsystemmode_m1_only, NULL, 0, NULL);
	if (err) {
		LOG_ERR("Failed to set system mode, error: %d", err);
		success = false;
	}

	/* Set modem online */
	err = at_cmd_write(at_cfun_normal, NULL, 0, NULL);
	if (err) {
		LOG_ERR("Failed to set modem to normal mode, error: %d", err);
		success = false;
	}

	if (success) {
		/* Wait until connected to network or a timeout occurs */
		if (!wait_until_connected_to_network(300)) {
			LOG_ERR("Could not connect to LTE-M");
			success = false;
		}
	}

clean_exit:
	at_params_list_free(&param_list);

	return success;
}

static void restore_system_mode(void)
{
	int err;
	int len;
	char system_mode_command[32];

	if (!restore_system_mode_needed) {
		return;
	}

	LOG_DBG("Previous system mode bitmask: 0x%x", prev_system_mode_bitmask);
	LOG_INF("Restoring previous system mode");

	/* Set modem offline */
	err = at_cmd_write(at_cfun_offline, NULL, 0, NULL);
	if (err) {
		LOG_ERR("Failed to set modem to offline mode, error: %d", err);
		return;
	}

	/* Restore system mode */
	len = snprintk(system_mode_command, sizeof(system_mode_command),
		       at_xsystemmode_template,
		       prev_system_mode_bitmask & BIT(1) ? 1 : 0,
		       prev_system_mode_bitmask & BIT(2) ? 1 : 0,
		       prev_system_mode_bitmask & BIT(3) ? 1 : 0,
		       prev_system_mode_bitmask & BIT(4) ? 1 : 0);

	err = at_cmd_write(system_mode_command, NULL, 0, NULL);
	if (err)
		LOG_ERR("Failed to set system mode, error: %d", err);

	/* Set modem online */
	err = at_cmd_write(at_cfun_normal, NULL, 0, NULL);
	if (err)
		LOG_ERR("Failed to set modem to normal mode, error: %d", err);

	restore_system_mode_needed = false;
}

static void start_update_check()
{
	k_work_submit_to_queue(&work_q, &update_work);
}

static void start_update_work(struct k_work *item)
{
	int err;
	int retry_count;
	char *imei;
	char *fw_version;

	LOG_INF("Checking for firmware update");

	/* Block fovever until we have a network connection */
	wait_until_connected_to_network(0);

	if (!is_update_check_allowed()) {
		LOG_INF("Update check not allowed");
		schedule_next_update();
		return;
	}

	/* If FOTA is not allowed in NB-IoT and the current mode is NB-IoT,
	 * we need to switch to M1 for the update check
	 */
	if (!IS_ENABLED(CONFIG_MODEM_FOTA_ALLOWED_IN_NBIOT)) {
		if (lte_mode == MODEM_LTE_MODE_NBIOT) {
			LOG_INF("FOTA not allowed in NB-IoT, switching to "
				"LTE-M");
			wait_for_data_inactivity();
			if (!switch_system_mode_to_lte_m()) {
				/* Failed to connect to LTE-M, abort update
				 * check
				 */
				restore_system_mode();
				schedule_next_update();
				return;
			}
		}
	}

	event_callback(MODEM_FOTA_EVT_CHECKING_FOR_UPDATE);

	imei = get_modem_imei();
	fw_version = get_modem_fw_version();

	if (imei == NULL || fw_version == NULL) {
		LOG_ERR("Failed to read IMEI or modem FW version");
		finish_update_check(MODEM_FOTA_EVT_ERROR);
		goto clean_exit;
	}

	err = activate_fota_pdn();
	if (err) {
		LOG_ERR("Activating FOTA PDN failed");
		finish_update_check(MODEM_FOTA_EVT_ERROR);
		goto clean_exit;
	}

	if (fota_dm_query_fw_update(imei, fw_version, &fw_update_host,
				    &fw_update_file) != 0) {
		LOG_DBG("Update check failed");
		finish_update_check(MODEM_FOTA_EVT_ERROR);
		goto clean_exit;
	}

	if (fw_update_host == NULL || fw_update_file == NULL) {
		LOG_DBG("No update available");
		finish_update_check(MODEM_FOTA_EVT_NO_UPDATE_AVAILABLE);
	} else {
		int sec_tag = -1;
		int port = 0;

		LOG_INF("Starting firmware download");

		event_callback(MODEM_FOTA_EVT_DOWNLOADING_UPDATE);

		if (IS_ENABLED(CONFIG_DOWNLOAD_CLIENT_TLS))
			sec_tag = CONFIG_MODEM_FOTA_DOWNLOAD_TLS_SECURITY_TAG;

		retry_count = CONFIG_MODEM_FOTA_SERVER_RETRY_COUNT;
		while (1) {
			err = fota_download_start(fw_update_host,
						  fw_update_file,
						  sec_tag, port, fota_apn);
			if (err == 0 || retry_count <= 0) {
				/* Download started successfully or no retries
				 * left
				 */
				break;
			}

			LOG_WRN("Starting FOTA download failed. %d retries "
				"left...", retry_count);
			retry_count--;
		}

		if (err) {
			LOG_ERR("Couldn't start FOTA download, error: %d", err);
			finish_update_check(MODEM_FOTA_EVT_ERROR);
		}
	}

clean_exit:
	k_free(imei);
	k_free(fw_version);
}

static bool is_update_scheduled()
{
	return update_check_time_s != 0;
}

static bool is_time_for_update_check()
{
	return get_current_time_in_s() >= update_check_time_s;
}

static void start_update_check_timer()
{
	s32_t duration_s;
	u32_t duration_s_without_days;

	if (!is_update_scheduled()) {
		LOG_ERR("Update not scheduled, can't start the timer");
	}

	duration_s = update_check_time_s - get_current_time_in_s();

	duration_s_without_days = duration_s % SECONDS_IN_DAY;
	LOG_INF("Next update check in %d days, %02d:%02d:%02d",
		duration_s / SECONDS_IN_DAY,
		duration_s_without_days / 3600,
		(duration_s_without_days % 3600) / 60,
		(duration_s_without_days % 3600) % 60);

	if (MAX_TIMER_DURATION_S < duration_s)
		duration_s = MAX_TIMER_DURATION_S;

	LOG_DBG("Starting timer for %d seconds", duration_s);

	k_timer_start(&update_check_timer, K_SECONDS(duration_s), K_NO_WAIT);
}

static void update_check_timer_handler(struct k_timer *dummy)
{
	if (is_time_for_update_check())
		start_update_check();
	else
		start_update_check_timer();
}

static void save_update_check_time()
{
	settings_save_one("modem_fota/update_check_time",
			  &update_check_time_s, sizeof(update_check_time_s));
}

static void calculate_next_update_check_time()
{
	u32_t seconds_to_update_check;

	LOG_DBG("Scheduling next update check");

	seconds_to_update_check =
		(CONFIG_MODEM_FOTA_UPDATE_CHECK_INTERVAL * 60);

	if (CONFIG_MODEM_FOTA_UPDATE_CHECK_INTERVAL_RANDOMNESS > 0) {
		/* Add random variation to the update check interval */
		seconds_to_update_check += sys_rand32_get() %
			(CONFIG_MODEM_FOTA_UPDATE_CHECK_INTERVAL_RANDOMNESS * 60);
	}

	update_check_time_s = get_current_time_in_s() + seconds_to_update_check;
	save_update_check_time();
}

static void schedule_next_update()
{
	static bool first_time = true;

	if (!fota_enabled || !is_network_time_valid()) {
		/* FOTA is either disabled or we haven't got network time yet */
		return;
	}

	if (first_time) {
		first_time = false;

		/* Client is starting, check if next update check has already
		 * been scheduled
		 */
		if (is_update_scheduled()) {
			/* Check if the scheduled time has already passed */
			if (is_time_for_update_check()) {
				/* Scheduled update check time has passed while
				 * device was powered off
				 */
				start_update_check();
			} else {
				/* Not yet time for next update check, start
				 * timer
				 */
				start_update_check_timer();
			}
		} else {
			/* Next update not yet scheduled */
			calculate_next_update_check_time();
			start_update_check_timer();
		}
	} else {
		/* Schedule next update */
		calculate_next_update_check_time();
		start_update_check_timer();
	}
}

static bool prefix_matches_imsi(const char *imsi, char *prefix, int prefix_len)
{
	return strncmp(imsi, prefix, prefix_len) == 0 ? true : false;
}

static char *get_next_imsi_prefix(char **pos, int *prefix_len)
{
	char *temp_pos;
	char *prefix_start;

	temp_pos = *pos;
	prefix_start = NULL;
	*prefix_len = 0;
	while (*temp_pos != '\0') {
		if (*temp_pos == ',') {
			/* The char is a comma */
			if (prefix_start != NULL) {
				/* End of a prefix */
				break;
			}
		} else {
			/* The char is not a comma */
			if (prefix_start == NULL) {
				/* Start of a prefix */
				prefix_start = temp_pos;
			}
		}
		temp_pos++;
	}

	if (prefix_start != NULL) {
		/* Found a prefix, calculate its length */
		*prefix_len = temp_pos - prefix_start;
	}

	/* Return the current position */
	*pos = temp_pos;

	return prefix_start;
}

static bool is_fota_disabled_with_usim()
{
	int err;
	char imsi[15 + 2 + 1];
	char *pos;
	char *prefix;
	int prefix_len;

	if (strlen(CONFIG_MODEM_FOTA_DISABLE_IMSI_PREFIXES) == 0)
		return false;

	err = at_cmd_write("AT+CIMI", imsi, sizeof(imsi), NULL);
	if (err) {
		LOG_ERR("Failed to request IMSI, error: %d", err);
		return false;
	}

	pos = CONFIG_MODEM_FOTA_DISABLE_IMSI_PREFIXES;
	while ((prefix = get_next_imsi_prefix(&pos, &prefix_len)) != NULL) {
		if (prefix_matches_imsi(imsi, prefix, prefix_len)) {
			LOG_INF("IMSI matches the disable prefix list");
			return true;
		}
	}

	return false;
}

bool is_fota_enabled()
{
	return fota_enabled;
}

void enable_fota()
{
	fota_enabled = true;

	LOG_INF("FOTA enabled");

	schedule_next_update();
}

void disable_fota()
{
	fota_enabled = false;

	LOG_INF("FOTA disabled");

	/* Stop timer and clear the next update check time */
	k_timer_stop(&update_check_timer);
	update_check_time_s = 0;
	save_update_check_time();
}

u32_t get_time_to_next_update_check()
{
	if (is_update_scheduled() && is_network_time_valid())
		return update_check_time_s - get_current_time_in_s();
	else
		return 0;
}

void set_time_to_next_update_check(u32_t seconds)
{
	update_check_time_s = get_current_time_in_s() + seconds;
	save_update_check_time();

	if (fota_enabled)
		start_update_check_timer();
}

char *get_dm_server_host()
{
	if (dm_server_host == NULL)
		return CONFIG_MODEM_FOTA_DM_SERVER_HOST;
	else
		return dm_server_host;
}

void set_dm_server_host(const char *host)
{
	k_free(dm_server_host);
	dm_server_host = k_malloc(strlen(host) + 1);
	if (dm_server_host != NULL) {
		strcpy(dm_server_host, host);
	}
}

u16_t get_dm_server_port()
{
	if (dm_server_port == 0)
		return CONFIG_MODEM_FOTA_DM_SERVER_PORT;
	else
		return dm_server_port;
}

void set_dm_server_port(u16_t port)
{
	dm_server_port = port;
}

static void at_notification_handler(void *context, const char *notif)
{
	ARG_UNUSED(context);

	static bool first_cereg_notification = true;

	if (notif == NULL) {
		LOG_ERR("Notification buffer is a NULL pointer");
		return;
	}

	if (strncmp(at_cereg_notif, notif, sizeof(at_cereg_notif) - 1) == 0) {
		parse_cereg_notification(notif);
		if (first_cereg_notification) {
			first_cereg_notification = false;
			/* After we've got the first CEREG notification
			 * we can read the IMSI and check if FOTA needs to be
			 * disabled with this USIM
			 */
			if (is_fota_disabled_with_usim())
				disable_fota();
		}
	} else if (strncmp(at_xtime_notif, notif, sizeof(at_xtime_notif) - 1)
			== 0) {
		if (parse_time_from_xtime_notification(notif) == 0) {
			/* Got network time, schedule next update */
			unregister_at_xtime_notification();
			schedule_next_update();
		}
	}
}

static int register_at_notifications()
{
	int err;

	at_notif_register_handler(NULL, at_notification_handler);

	err = at_cmd_write("AT+CEREG=5", NULL, 0, NULL);
	if (err) {
		LOG_ERR("Failed to enable CEREG notification, error: %d", err);
		return err;
	}

	err = at_cmd_write("AT\%XTIME=1", NULL, 0, NULL);
	if (err) {
		LOG_ERR("Failed to enable XTIME notification, error: %d", err);
		return err;
	}

	return err;
}

static int settings_set(const char *name, size_t len,
		settings_read_cb read_cb, void *cb_arg)
{
	if (!strcmp(name, "update_check_time")) {
		if (len != sizeof(update_check_time_s))
			return -EINVAL;

		if (read_cb(cb_arg, &update_check_time_s, len) > 0)
			return 0;
	}

	return -ENOENT;
}

static void init_and_load_settings()
{
    	settings_subsys_init();

	struct settings_handler my_conf = {
	    .name = "modem_fota",
	    .h_set = settings_set
	};

    	settings_register(&my_conf);
    	settings_load();
 }

int modem_fota_init(modem_fota_callback_t callback)
{
	int err = 0;

	if (callback == NULL)
		return -EINVAL;

	event_callback = callback;

	if (strlen(CONFIG_MODEM_FOTA_APN) > 0)
		fota_apn = CONFIG_MODEM_FOTA_APN;

	k_sem_init(&link, 0, 1);

	k_work_q_start(&work_q, work_q_stack_area,
        	K_THREAD_STACK_SIZEOF(work_q_stack_area), WORK_QUEUE_PRIORITY);
	k_work_init(&update_work, start_update_work);
	k_work_init(&finish_update.work, finish_update_work);

	init_and_load_settings();

	err = fota_download_init(&fota_download_callback);
	if (err) {
		LOG_ERR("FOTA download library could not be initialized, "
			"error: %d", err);
		return err;
	}

	register_at_notifications();

	LOG_INF("FOTA Client initialized");

	return err;
}
