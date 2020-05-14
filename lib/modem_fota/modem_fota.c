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

LOG_MODULE_REGISTER(modem_fota, CONFIG_MODEM_FOTA_LOG_LEVEL);

/* Enums */
enum modem_reg_status {
	MODEM_REG_STATUS_NOT_REGISTERED,
	MODEM_REG_STATUS_HOME,
	MODEM_REG_STATUS_ROAMING
};

enum modem_lte_mode {
	MODEM_LTE_MODE_M,
	MODEM_LTE_MODE_NB_IOT
};

/* Forward declarations */
static void schedule_next_update();
static void update_check_timer_handler(struct k_timer *dummy);

/* Work queue */
#define WORK_QUEUE_STACK_SIZE 1024
#define WORK_QUEUE_PRIORITY 5

K_THREAD_STACK_DEFINE(work_q_stack_area, WORK_QUEUE_STACK_SIZE);

struct k_work_q work_q;
struct k_work update_work;

K_TIMER_DEFINE(update_check_timer, update_check_timer_handler, NULL);

#define AT_CEREG_PARAMS_COUNT_MAX	10
#define AT_CEREG_REG_STATUS_INDEX	1
#define AT_CEREG_LTE_MODE_INDEX		4
#define AT_XTIME_PARAMS_COUNT_MAX	4
#define AT_XTIME_UNIVERSAL_TIME_INDEX	2
#define AT_XTIME_UNIVERSAL_TIME_LEN	14
#define AT_CGSN_IMEI_INDEX		1
#define AT_CGMR_VERSION_INDEX		0

static const char * const cereg_notif = "+CEREG";
static const char * const xtime_notif = "\%XTIME";

/* Currently the maximum timer duration is ~18h, so we'll use that */
#define MAX_TIMER_DURATION_S (18 * 60 * 60)

static modem_fota_callback_t event_callback;

/* Network time (milliseconds since epoch) and timestamp when it was updated */
static s64_t network_time;
static s64_t network_time_timestamp;

static enum modem_reg_status reg_status;
static enum modem_lte_mode lte_mode;

/* Next scheduled update check time (seconds since epoch if network time is
 * valid, otherwise seconds since device start (uptime))
 */
static s64_t update_check_time_s;

/* Information needed to fetch the firmware update */
static char *fw_update_host;
static char *fw_update_file;

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

	LOG_DBG("Got network time: %d.%d.%d %02d:%02d:%02d",
			date_time.tm_mday, date_time.tm_mon, date_time.tm_year + 1900,
			date_time.tm_hour, date_time.tm_min, date_time.tm_sec);

	network_time = (s64_t)timeutil_timegm64(&date_time) * 1000;
	network_time_timestamp = k_uptime_get();
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

	if (value == 1) {
		reg_status = MODEM_REG_STATUS_HOME;
	} else if (value == 5) {
		reg_status = MODEM_REG_STATUS_ROAMING;
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

	if (value == 7) {
		lte_mode = MODEM_LTE_MODE_M;
	} else if (value == 9) {
		lte_mode = MODEM_LTE_MODE_NB_IOT;
	} else {
		LOG_WRN("Unknown LTE mode in +CEREG notification");
	}

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
	int err = at_cmd_write("AT\%XTIME=0", NULL, 0, NULL);
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

static void fota_download_callback(const struct fota_download_evt *evt)
{
	switch (evt->id) {
	case FOTA_DOWNLOAD_EVT_PROGRESS:
		break;

	case FOTA_DOWNLOAD_EVT_FINISHED:
		free_fw_update_info();
		schedule_next_update();

		LOG_INF("Update downloaded, reboot needed to apply update");
		event_callback(MODEM_FOTA_EVT_RESTART_PENDING);
		break;

	case FOTA_DOWNLOAD_EVT_ERASE_PENDING:
		LOG_INF("Erasing modem scratch area...");
		break;

	case FOTA_DOWNLOAD_EVT_ERASE_DONE:
		LOG_INF("Modem scratch area erase done");
		break;

	case FOTA_DOWNLOAD_EVT_ERROR:
	default:
		free_fw_update_info();
		event_callback(MODEM_FOTA_EVT_ERROR);
		schedule_next_update();
		break;
	}
}

static void start_update_check(struct k_work *item)
{
	char *imei;
	char *fw_version;

	event_callback(MODEM_FOTA_EVT_CHECKING_FOR_UPDATE);

	/* TODO: LTE may not be connected when the check is started (or may be
	 * connected using NB-IoT)
	 */

	imei = get_modem_imei();
	fw_version = get_modem_fw_version();

	if (imei == NULL || fw_version == NULL) {
		LOG_ERR("Can't start update check");
		event_callback(MODEM_FOTA_EVT_ERROR);
		goto clean_exit;
	}

	if (fota_dm_query_fw_update(imei, fw_version, &fw_update_host, &fw_update_file) != 0) {
		LOG_DBG("Update check failed");
		event_callback(MODEM_FOTA_EVT_ERROR);
		goto clean_exit;
	}

	if (fw_update_host == NULL || fw_update_file == NULL) {
		LOG_DBG("No update available");
		event_callback(MODEM_FOTA_EVT_NO_UPDATE_AVAILABLE);
	} else {
		int err;

		LOG_INF("Starting firmware download");

		event_callback(MODEM_FOTA_EVT_DOWNLOADING_UPDATE);

		err = fota_download_start(
			fw_update_host,
			fw_update_file,
			CONFIG_MODEM_FOTA_DOWNLOAD_TLS_SECURITY_TAG);
		if (err) {
			LOG_ERR("Couldn't start FOTA download, error: %d", err);
			event_callback(MODEM_FOTA_EVT_ERROR);
			schedule_next_update();
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
	return update_check_time_s <= get_current_time_in_s();
}

static void start_update_check_timer()
{
	s32_t duration_s;

	if (is_update_scheduled()) {
		duration_s = update_check_time_s - get_current_time_in_s();
	} else {
		duration_s = CONFIG_MODEM_FOTA_UPDATE_CHECK_INTERVAL * 60;
	}

	if (MAX_TIMER_DURATION_S < duration_s) {
		duration_s = MAX_TIMER_DURATION_S;
	}

	LOG_DBG("Starting timer for %d seconds", duration_s);

	k_timer_start(&update_check_timer, K_SECONDS(duration_s), 0);
}

static void update_check_timer_handler(struct k_timer *dummy)
{
	if (is_time_for_update_check()) {
		k_work_submit(&update_work);
	} else {
		start_update_check_timer();
	}
}

static void calculate_next_update_check_time()
{
	update_check_time_s = get_current_time_in_s() +
			(CONFIG_MODEM_FOTA_UPDATE_CHECK_INTERVAL * 60);
#if CONFIG_MODEM_FOTA_UPDATE_CHECK_INTERVAL_RANDOMNESS > 0
	/* Add random variation to the update check interval */
	update_check_time_s += sys_rand32_get() %
		(CONFIG_MODEM_FOTA_UPDATE_CHECK_INTERVAL_RANDOMNESS * 60);
#endif
	settings_save_one("modem_fota/update_check_time",
			&update_check_time_s, sizeof(update_check_time_s));
}

static void schedule_next_update()
{
	static bool first_time = true;

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
				LOG_DBG("Already past update check time");
				start_update_check(NULL);
			} else {
				/* Not yet time for next update check, start timer */
				LOG_DBG("Not yet update check time, starting update check timer");
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

static void at_notification_handler(void *context, const char *notif)
{
	ARG_UNUSED(context);

	if (notif == NULL) {
		LOG_ERR("Notification buffer is a NULL pointer");
		return;
	}

	if (strncmp(cereg_notif, notif, sizeof(cereg_notif) - 1) == 0) {
		parse_cereg_notification(notif);
	} else if (strncmp(xtime_notif, notif, sizeof(xtime_notif) - 1) == 0) {
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

	/* +CEREG */
	err = at_cmd_write("AT+CEREG=5", NULL, 0, NULL);
	if (err) {
		LOG_ERR("Failed to enable CEREG, error: %d", err);
		return err;
	}

	/* %XTIME */
	err = at_cmd_write("AT\%XTIME=1", NULL, 0, NULL);
	if (err) {
		LOG_ERR("Failed to enable XTIME, error: %d", err);
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

		if (read_cb(cb_arg, &update_check_time_s, sizeof(update_check_time_s)) > 0)
			return 0;
	}

	return -ENOENT;
}

static void settings_init_and_load()
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

	if (callback == NULL) {
		return -EINVAL;
	}

	event_callback = callback;

	k_work_q_start(&work_q, work_q_stack_area,
        	K_THREAD_STACK_SIZEOF(work_q_stack_area), WORK_QUEUE_PRIORITY);
	k_work_init(&update_work, start_update_check);

	settings_init_and_load();

	err = fota_download_init(&fota_download_callback);
	if (err) {
		LOG_ERR("FOTA download library could not be initialized, error: %d", err);
		return err;
	}

	register_at_notifications();

	/* TODO: Read IMSI */

	LOG_DBG("Modem FOTA library initialized");

	return err;
}
