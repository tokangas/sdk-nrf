/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <date_time.h>
#include <zephyr.h>
#include <logging/log.h>
#include <sys/timeutil.h>
#include <settings/settings.h>
#include <modem/at_cmd.h>
#include <modem/at_cmd_parser.h>
#include <modem/at_params.h>
#include <modem/at_notif.h>

LOG_MODULE_REGISTER(modem_fota, LOG_LEVEL_DBG); // TODO: Remove debug

// Forward declarations
static void schedule_next_update();
static void update_check_timer_handler(struct k_timer *dummy);

// Work queue
#define WORK_QUEUE_STACK_SIZE 1024
#define WORK_QUEUE_PRIORITY 5

K_THREAD_STACK_DEFINE(work_q_stack_area, WORK_QUEUE_STACK_SIZE);

struct k_work_q work_q;
struct k_work update_work;

// Timer
K_TIMER_DEFINE(update_check_timer, update_check_timer_handler, NULL);

#define AT_CEREG_PARAMS_COUNT_MAX	10
#define AT_XTIME_PARAMS_COUNT_MAX	4
#define AT_XTIME_UNIVERSAL_TIME_INDEX	2
#define AT_XTIME_UNIVERSAL_TIME_LEN	14

static const char *const cereg_notif = "+CEREG";
static const char *const xtime_notif = "\%XTIME";

// Zephyr timer has maximum duration of 24 days, we use at max. a 7 day timer
#define MAX_TIMER_DURATION_S (7 * 24 * 60 * 60)

// Network time (milliseconds since epoch) and timestamp when it was updated
s64_t network_time;
s64_t network_time_timestamp;

// Next scheduled update check time (seconds since epoch if network time is
// valid, otherwise seconds since device start (uptime))
s64_t update_check_time_s;

static void at_configure()
{
	int err;

	// TODO: Should these be initialized by the library or not?
	err = at_notif_init();
	__ASSERT(err == 0, "AT command notifications could not be initialized.");
	err = at_cmd_init();
	__ASSERT(err == 0, "AT command interface could not be established.");
}

static void parse_network_time(const char *time_str)
{
	struct tm date_time;
	char temp[3] = {0};

	// Year
	temp[0] = time_str[1];
	temp[1] = time_str[0];
	date_time.tm_year = atoi(temp) + 2000 - 1900;

	// Month
	temp[0] = time_str[3];
	temp[1] = time_str[2];
	date_time.tm_mon = atoi(temp);

	// Day
	temp[0] = time_str[5];
	temp[1] = time_str[4];
	date_time.tm_mday = atoi(temp);

	// Hour
	temp[0] = time_str[7];
	temp[1] = time_str[6];
	date_time.tm_hour = atoi(temp);

	// Minute
	temp[0] = time_str[9];
	temp[1] = time_str[8];
	date_time.tm_min = atoi(temp);

	// Second
	temp[0] = time_str[11];
	temp[1] = time_str[10];
	date_time.tm_sec = atoi(temp);

	LOG_DBG("Got network time: %d.%d.%d %02d:%02d:%02d",
			date_time.tm_mday, date_time.tm_mon, date_time.tm_year + 1900,
			date_time.tm_hour, date_time.tm_min, date_time.tm_sec);

	network_time = (s64_t)timeutil_timegm64(&date_time) * 1000;
	network_time_timestamp = k_uptime_get();
}

static int parse_time_from_xtime_notification(const char *notif)
{
	int err;
	struct at_param_list param_list = {0};
	char time_str[AT_XTIME_UNIVERSAL_TIME_LEN + 1];
	size_t time_str_len = AT_XTIME_UNIVERSAL_TIME_LEN;

	err = at_params_list_init(&param_list, AT_XTIME_PARAMS_COUNT_MAX);
	if (err) {
		LOG_ERR("Could not initialize AT params list, error: %d", err);
		return err;
	}

	err = at_parser_max_params_from_str(notif,
					    NULL,
					    &param_list,
					    AT_XTIME_PARAMS_COUNT_MAX);
	if (err) {
		LOG_ERR("Could not parse XTIME response, error: %d", err);
		goto clean_exit;
	}

	err = at_params_string_get(&param_list,
				   AT_XTIME_UNIVERSAL_TIME_INDEX,
				   time_str,
				   &time_str_len);	
	if (err) {
		LOG_ERR("Could not parse time, error: %d", err);
		goto clean_exit;
	}

	time_str[time_str_len] = '\0';

	if (time_str_len != AT_XTIME_UNIVERSAL_TIME_LEN) {
		LOG_ERR("Invalid time string length, received string: %s",
				log_strdup(time_str));
		err = -1;
		goto clean_exit;
	}

	parse_network_time(time_str);

clean_exit:
	at_params_list_free(&param_list);

	return err;
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

static void start_update_check(struct k_work *item)
{
	LOG_INF("Starting update check");

	// TODO: This should be done after the update check (and update)
	schedule_next_update();
}

static bool is_update_scheduled()
{
	return update_check_time_s != 0;
}

static bool is_time_for_update_check()
{
	LOG_DBG("Next update check: %d", (s32_t)update_check_time_s);
	LOG_DBG("Current time:      %d", (s32_t)get_current_time_in_s());

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
	// Add random variation to the update check interval
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

		// Client is starting, check if next update check has already
		// been scheduled
		if (is_update_scheduled()) {
			// Check if the scheduled time has already passed
			if (is_time_for_update_check()) {
				// Scheduled update check time has passed while
				// device was powered off
				LOG_DBG("Already past update check time");
				start_update_check(NULL);
			} else {
				// Not yet time for next update check, start timer
				LOG_DBG("Not yet update check time, starting update check timer");
				start_update_check_timer();
			}
		} else {
			// Next update not yet scheduled
			calculate_next_update_check_time();
			start_update_check_timer();
		}
	} else {
		// Schedule next update
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
		// TODO
	} else if (strncmp(xtime_notif, notif, sizeof(xtime_notif) - 1) == 0) {
		if (parse_time_from_xtime_notification(notif) == 0) {
			// Got network time
			unregister_at_xtime_notification();
			schedule_next_update();
		}
	}
}

static int register_at_notifications()
{
	int err;

	at_notif_register_handler(NULL, at_notification_handler);

	// +CEREG
	err = at_cmd_write("AT+CEREG=5", NULL, 0, NULL);
	if (err) {
		LOG_ERR("Failed to enable CEREG, error: %d", err);
		return err;
	}

	// %XTIME
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

int modem_fota_init()
{
	int err = 0;

	k_work_q_start(&work_q, work_q_stack_area,
        	K_THREAD_STACK_SIZEOF(work_q_stack_area), WORK_QUEUE_PRIORITY);
	k_work_init(&update_work, start_update_check);

	settings_init_and_load();

	//at_configure();
	register_at_notifications();

	// TODO: Read IMSI

	LOG_DBG("Modem FOTA library initialized");

	return err;
}
