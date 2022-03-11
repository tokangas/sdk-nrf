/*
 * Copyright (c) 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr.h>
#include <nrf_modem_at.h>
#include <nrf_modem_gnss.h>
#include <net/nrf_cloud.h>
#include <modem/lte_lc.h>
#include <logging/log.h>
#if defined(CONFIG_NRF_CLOUD_AGPS)
#include <net/nrf_cloud_agps.h>
#endif

LOG_MODULE_REGISTER(gnss_tracker, CONFIG_GNSS_TRACKER_LOG_LEVEL);

/* Workqueue */

#define WORK_QUEUE_STACK_SIZE 4096
#define WORK_QUEUE_PRIORITY 5

K_THREAD_STACK_DEFINE(work_q_stack_area, WORK_QUEUE_STACK_SIZE);

static struct k_work_q work_q;

/* Data */

static struct nrf_modem_gnss_pvt_data_frame pvt_data;
static struct nrf_modem_gnss_nmea_data_frame nmea_data;
#if defined(CONFIG_NRF_CLOUD_AGPS)
static struct nrf_modem_gnss_agps_data_frame agps_request;
#endif

/* Flag indicating if the next fix should be sent to the cloud. The first fix is always sent,
 * after that the fix interval determines how often fixes are sent.
 */
static bool send_next_fix = true;

static bool cloud_ready;

/* Function prototypes */

static void print_pvt_info(void);
static void cloud_connect_work_handler(struct k_work *work);
static void cloud_reconnect_work_handler(struct k_work *work);
static void nrf_cloud_event_handler(const struct nrf_cloud_evt *evt);

/* Timer handler */

void interval_timer_handler(struct k_timer *dummy)
{
	LOG_INF("Time to send position to cloud");

	send_next_fix = true;
}

K_TIMER_DEFINE(interval_timer, interval_timer_handler, NULL);

/* Work handlers */

K_WORK_DELAYABLE_DEFINE(cloud_connect_work, cloud_connect_work_handler);
K_WORK_DELAYABLE_DEFINE(cloud_reconnect_work, cloud_reconnect_work_handler);

static void cloud_connect_work_handler(struct k_work *work)
{
	int err;

	struct nrf_cloud_init_param config = {
		.event_handler = nrf_cloud_event_handler,
	};

	err = nrf_cloud_init(&config);
	if (err) {
		LOG_ERR("nrf_cloud_init(), error: %d", err);
		return;
	}

	err = nrf_cloud_connect(NULL);
	if (err != NRF_CLOUD_CONNECT_RES_SUCCESS) {
		LOG_ERR("Failed to connect to nRF Cloud, error: %d", err);
	}

	/* If the connection attempt times out, trigger retry. */
	k_work_schedule_for_queue(&work_q, &cloud_reconnect_work, K_SECONDS(30));
}

static void cloud_reconnect_work_handler(struct k_work *work)
{
	int err;

	err = nrf_cloud_uninit();
	if (err) {
		LOG_ERR("Could not reset cloud transport, error %d. Continuing anyway.", err);
	}

	/* Try to reconnect to the cloud. */
	k_work_schedule_for_queue(&work_q, &cloud_connect_work, K_SECONDS(5));
}

static void cloud_update_shadow_work_handler(struct k_work *work)
{
	int err;
	struct nrf_cloud_svc_info_ui ui_info = {
		.gps = true
	};
	struct nrf_cloud_svc_info service_info = {
		.ui = &ui_info
	};
	struct nrf_cloud_device_status device_status = {
		.svc = &service_info
	};

	err = nrf_cloud_shadow_device_status_update(&device_status);
	if (err) {
		LOG_ERR("Failed to update device shadow, error: %d", err);
	}
}

K_WORK_DEFINE(cloud_update_shadow_work, cloud_update_shadow_work_handler);

static void gnss_start_work_handler(struct k_work *work)
{
	int err;

	err = nrf_modem_gnss_start();
	if (err) {
		LOG_ERR("Failed to start GNSS, error: %d", err);
	}

	/* Select automotive dynamics mode. */
	err = nrf_modem_gnss_dyn_mode_change(NRF_MODEM_GNSS_DYNAMICS_AUTOMOTIVE);
	if (err) {
		LOG_ERR("Failed to change dynamics mode, error: %d", err);
	}
}

K_WORK_DELAYABLE_DEFINE(gnss_start_work, gnss_start_work_handler);

#if defined(CONFIG_NRF_CLOUD_AGPS)
static void agps_data_get_work_handler(struct k_work *work)
{
	int err;

	err = nrf_cloud_agps_request(&agps_request);
	if (err) {
		LOG_WRN("Failed to request A-GPS data, error: %d", err);
	}
}

K_WORK_DEFINE(agps_data_get_work, agps_data_get_work_handler);
#endif /* CONFIG_NRF_CLOUD_AGPS */

static void cloud_send_work_handler(struct k_work *work)
{
	int err;

	LOG_DBG("%.*s", strlen(nmea_data.nmea_str) - strlen("\r\n"), nmea_data.nmea_str);

	struct nrf_cloud_sensor_data gps_data = {
		.type = NRF_CLOUD_SENSOR_GPS,
		.data.ptr = nmea_data.nmea_str,
		.data.len = strlen(nmea_data.nmea_str),
		.tag = 0
	};

	err = nrf_cloud_sensor_data_stream(&gps_data);
	if (err) {
		LOG_WRN("Failed to send sensor data");
		return;
	}
}

K_WORK_DEFINE(cloud_send_work, cloud_send_work_handler);

/* Event handlers */

static void lte_lc_event_handler(const struct lte_lc_evt *const evt)
{
	switch (evt->type) {
	case LTE_LC_EVT_RRC_UPDATE:
		LOG_INF("LTE_LC_EVT_RRC_UPDATE status: %d", (int)evt->rrc_mode);
		break;

	default:
		break;
	}
}

static void gnss_event_handler(int event)
{
	int err;
	struct nrf_modem_gnss_nmea_data_frame temp_nmea_data;

	switch (event) {
	case NRF_MODEM_GNSS_EVT_PVT:
		err = nrf_modem_gnss_read(&pvt_data, sizeof(pvt_data),
					  NRF_MODEM_GNSS_DATA_PVT);
		if (err) {
			LOG_WRN("Failed to read PVT data, error: %d", err);
			break;
		}

		print_pvt_info();
		break;

	case NRF_MODEM_GNSS_EVT_NMEA:
		if (!send_next_fix || !cloud_ready) {
			/* Not time to send next or cloud connection not ready. */
			break;
		}

		if ((pvt_data.flags & NRF_MODEM_GNSS_PVT_FLAG_FIX_VALID) == 0 ||
		    pvt_data.pdop == 100.0) {
			/* Not a valid fix or DOP is unknown. DOP is unknown in case GNSS wasn't
			 * able to calculate a new solution, but the position is from the EKF.
			 */
			break;
		}

		err = nrf_modem_gnss_read(&temp_nmea_data, sizeof(temp_nmea_data),
					  NRF_MODEM_GNSS_DATA_NMEA);
		if (err) {
			LOG_WRN("Failed to read NMEA data, error: %d", err);
			break;
		}

		/* All NMEAs are enabled to make them visible in the modem log. However, we're
		 * only interested in GPGGA, so skip everything else.
		 */
		if (strstr(temp_nmea_data.nmea_str, "GPGGA") == 0) {
			/* Not GPGGA, skip it. */
			break;
		}

		(void)strcpy(nmea_data.nmea_str, temp_nmea_data.nmea_str);

		LOG_INF("Sending position to cloud");

		k_work_submit_to_queue(&work_q, &cloud_send_work);

		send_next_fix = false;

		/* The timer is half a second shorter than the configured interval, otherwise we
		 * might miss the next PVT.
		 */
		k_timer_start(&interval_timer,
			      K_MSEC((CONFIG_GNSS_TRACKER_FIX_INTERVAL * 1000) - 500),
			      K_NO_WAIT);
		break;

#if defined(CONFIG_NRF_CLOUD_AGPS)
	case NRF_MODEM_GNSS_EVT_AGPS_REQ:
		LOG_INF("NRF_MODEM_GNSS_EVT_AGPS_REQ");
		err = nrf_modem_gnss_read(&agps_request, sizeof(agps_request),
					  NRF_MODEM_GNSS_DATA_AGPS_REQ);
		if (err) {
			LOG_WRN("Failed to read A-GPS request data, error: %d", err);
			break;
		}

		k_work_submit_to_queue(&work_q, &agps_data_get_work);
		break;
#endif /* CONFIG_NRF_CLOUD_AGPS */

	default:
		break;
	}
}

static void nrf_cloud_event_handler(const struct nrf_cloud_evt *evt)
{
	switch (evt->type) {
	case NRF_CLOUD_EVT_TRANSPORT_CONNECTING:
		LOG_INF("NRF_CLOUD_EVT_TRANSPORT_CONNECTING");
		break;

	case NRF_CLOUD_EVT_TRANSPORT_CONNECTED:
		LOG_INF("NRF_CLOUD_EVT_TRANSPORT_CONNECTED");
		/* Connected, cancel retry. */
		k_work_cancel_delayable(&cloud_reconnect_work);
		break;

	case NRF_CLOUD_EVT_READY:
		LOG_INF("NRF_CLOUD_EVT_READY");
		cloud_ready = true;
		k_work_submit_to_queue(&work_q, &cloud_update_shadow_work);
		/* Start GNSS. */
		k_work_schedule_for_queue(&work_q, &gnss_start_work, K_SECONDS(1));
		break;

	case NRF_CLOUD_EVT_TRANSPORT_DISCONNECTED:
		LOG_INF("NRF_CLOUD_EVT_TRANSPORT_DISCONNECTED");
		cloud_ready = false;
		/* Try to reconnect to the cloud. */
		k_work_schedule_for_queue(&work_q, &cloud_reconnect_work, K_SECONDS(20));
		break;

	case NRF_CLOUD_EVT_ERROR:
		LOG_INF("NRF_CLOUD_EVT_ERROR");
		break;

	case NRF_CLOUD_EVT_SENSOR_DATA_ACK:
		LOG_INF("NRF_CLOUD_EVT_SENSOR_DATA_ACK");
		break;

	case NRF_CLOUD_EVT_FOTA_DONE:
		LOG_INF("NRF_CLOUD_EVT_FOTA_DONE");
		break;

	case NRF_CLOUD_EVT_RX_DATA:
		LOG_INF("NRF_CLOUD_EVT_RX_DATA");
#if defined(CONFIG_NRF_CLOUD_AGPS)
		{
			int err;

			if (((char *)evt->data.ptr)[0] == '{') {
				/* Not A-GPS data. */
				break;
			}
			err = nrf_cloud_agps_process((char *)evt->data.ptr, evt->data.len);
			if (!err) {
				LOG_INF("A-GPS data processed");
			} else {
				LOG_WRN("Failed to process A-GPS data, error: %d", err);
			}
		}
#endif /* CONFIG_NRF_CLOUD_AGPS */
		break;

	case NRF_CLOUD_EVT_USER_ASSOCIATION_REQUEST:
		LOG_INF("NRF_CLOUD_EVT_USER_ASSOCIATION_REQUEST");
		LOG_INF("Add the device to nRF Cloud and reconnect");
		break;

	case NRF_CLOUD_EVT_USER_ASSOCIATED:
		LOG_INF("NRF_CLOUD_EVT_USER_ASSOCIATED");
		break;

	default:
		LOG_WRN("Unknown nRF Cloud event type: %d", evt->type);
		break;
	}
}

/* Other functions */

static void print_pvt_info(void)
{
	bool fix;
	bool blocked;
	uint8_t tracked = 0;
	uint8_t in_fix = 0;

	for (int i = 0; i < NRF_MODEM_GNSS_MAX_SATELLITES; i++) {
		if (pvt_data.sv[i].sv == 0) {
			/* SV not valid, skip. */
			continue;
		}

		tracked++;

		if (pvt_data.sv[i].flags & NRF_MODEM_GNSS_SV_FLAG_USED_IN_FIX) {
			in_fix++;
		}
	}

	fix = pvt_data.flags & NRF_MODEM_GNSS_PVT_FLAG_FIX_VALID ? true : false;
	blocked = pvt_data.flags & NRF_MODEM_GNSS_PVT_FLAG_DEADLINE_MISSED ? true : false;

	LOG_INF("NRF_MODEM_GNSS_EVT_PVT fix: %u, blocked: %u, tracked: %u, in fix: %u",
		fix, blocked, tracked, in_fix);
}

static int modem_configure(void)
{
	/* Configure the Low Noise Amplifier (LNA). */

	if (strlen(CONFIG_GNSS_TRACKER_AT_MAGPIO) > 0) {
		if (nrf_modem_at_printf("%s", CONFIG_GNSS_TRACKER_AT_MAGPIO) != 0) {
			LOG_ERR("Failed to set MAGPIO configuration");
			return -1;
		}
	}

	if (strlen(CONFIG_GNSS_TRACKER_AT_COEX0) > 0) {
		if (nrf_modem_at_printf("%s", CONFIG_GNSS_TRACKER_AT_COEX0) != 0) {
			LOG_ERR("Failed to set COEX0 configuration");
			return -1;
		}
	}

	if (IS_ENABLED(CONFIG_GNSS_TRACKER_RELEASE_ASSISTANCE_INDICATION)) {
		if (nrf_modem_at_printf("AT%%REL14FEAT=0,1,0,0,0") == 0) {
			LOG_INF("Enabled RAI in rel14 features");
		} else {
			LOG_ERR("Failed to enable RAI in rel14 features");
		}

		if (nrf_modem_at_printf("AT%%RAI=1") == 0) {
			LOG_INF("Enabled RAI");
		} else {
			LOG_ERR("Failed to enable RAI");
		}
	}

	return 0;
}

static int gnss_configure(void)
{
	int err;

	err = nrf_modem_gnss_event_handler_set(gnss_event_handler);
	if (err) {
		LOG_ERR("Failed to set GNSS event handler, error: %d", err);
		return err;
	}

	err = nrf_modem_gnss_use_case_set(NRF_MODEM_GNSS_USE_CASE_MULTIPLE_HOT_START);
	if (err) {
		LOG_ERR("Failed to set GNSS use case, error: %d", err);
		return err;
	}

	err = nrf_modem_gnss_fix_interval_set(1);
	if (err) {
		LOG_ERR("Failed to set GNSS fix interval, error: %d", err);
		return err;
	}

	err = nrf_modem_gnss_nmea_mask_set(
		NRF_MODEM_GNSS_NMEA_GGA_MASK |
		NRF_MODEM_GNSS_NMEA_GLL_MASK |
		NRF_MODEM_GNSS_NMEA_GSA_MASK |
		NRF_MODEM_GNSS_NMEA_GSV_MASK |
		NRF_MODEM_GNSS_NMEA_RMC_MASK);
	if (err) {
		LOG_ERR("Failed to set GNSS NMEA mask, error: %d", err);
		return err;
	}

	return 0;
}

int main(void)
{
	int err;

	LOG_INF("GNSS tracker started");

	err = modem_configure();
	if (err) {
		return -1;
	}

	lte_lc_register_handler(lte_lc_event_handler);

	err = lte_lc_init_and_connect();
	if (err) {
		LOG_ERR("Failed to initialize LTE Link Controller, error: %d", err);
		return -1;
	}

	err = gnss_configure();
	if (err) {
		return -1;
	}

	k_work_queue_init(&work_q);

	struct k_work_queue_config work_q_config = {
		.name = "gnss_tracker_work_q",
		.no_yield = false
	};

	k_work_queue_start(&work_q, work_q_stack_area,
			   K_THREAD_STACK_SIZEOF(work_q_stack_area), WORK_QUEUE_PRIORITY,
			   &work_q_config);

	/* Trigger connection to cloud. */
	k_work_schedule_for_queue(&work_q, &cloud_connect_work, K_NO_WAIT);

	return 0;
}
