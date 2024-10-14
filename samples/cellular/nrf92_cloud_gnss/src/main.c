/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <modem/nrf_modem_lib.h>
#include <modem/lte_lc.h>
#include <modem/location.h>
#include <date_time.h>
#if defined(CONFIG_NRF_CLOUD_COAP)
#include <net/nrf_cloud_coap.h>
#else
#include <net/nrf_cloud.h>
#include <net/nrf_cloud_codec.h>
#endif

LOG_MODULE_REGISTER(nrf92_cloud_gnss, CONFIG_NRF92_CLOUD_GNSS_LOG_LEVEL);

struct nrf_cloud_gnss_data gnss_data = {
	.type = NRF_CLOUD_GNSS_TYPE_PVT
};

static void location_get_work_fn(struct k_work *work);
K_WORK_DELAYABLE_DEFINE(location_get_work, location_get_work_fn);

static void location_get_work_fn(struct k_work *work)
{
	int err;

	LOG_INF("Requesting location...");

	err = location_request(NULL);
	if (err) {
		LOG_ERR("Failed to request location, error: %d", err);
	}

	k_work_schedule(&location_get_work, K_MINUTES(5));
}

#if defined(CONFIG_NRF_CLOUD_COAP)
static int cloud_location_coap_send(void)
{
	int err = nrf_cloud_coap_location_send(&gnss_data, true);
	if (err) {
		LOG_ERR("Failed to send CoAP message, error: %d", err);
	}

	return err;
}
#endif /* CONFIG_NRF_CLOUD_COAP */

#if defined(CONFIG_NRF_CLOUD_MQTT)
static int cloud_payload_json_encode(char **json_str_out)
{
	int err;

	cJSON *gnss_data_obj = cJSON_CreateObject();
	if (gnss_data_obj == NULL) {
		err = -ENOMEM;
		goto cleanup;
	}

	err = nrf_cloud_gnss_msg_json_encode(&gnss_data, gnss_data_obj);
	if (err) {
		LOG_ERR("Failed to encode GNSS device message, error: %d", err);
		goto cleanup;
	}

	*json_str_out = cJSON_PrintUnformatted(gnss_data_obj);
	if (*json_str_out == NULL) {
		err = -ENOMEM;
	}

cleanup:
	if (gnss_data_obj) {
		cJSON_Delete(gnss_data_obj);
	}

	return err;
}

static int cloud_location_mqtt_send(void)
{
	int err;
	char *json_payload = NULL;

	err = cloud_payload_json_encode(&json_payload);
	if (err) {
		LOG_ERR("Failed to encode cloud payload, error: %d", err);
		return err;
	}

	struct nrf_cloud_tx_data mqtt_msg = {
		.data.ptr = json_payload,
                .data.len = strlen(json_payload),
                .qos = MQTT_QOS_1_AT_LEAST_ONCE,
                .topic_type = NRF_CLOUD_TOPIC_MESSAGE,
        };

        err = nrf_cloud_send(&mqtt_msg);
        if (err) {
                LOG_ERR("Failed to send MQTT message, error: %d", err);
        }

	if (json_payload) {
		cJSON_free(json_payload);
	}

	return err;
}
#endif /* CONFIG_NRF_CLOUD_MQTT */

static void location_send_work_fn(struct k_work *work)
{
	int err;

#if defined(CONFIG_NRF_CLOUD_COAP)
	err = cloud_location_coap_send();
#else
	err = cloud_location_mqtt_send();
#endif
	if (err) {
		LOG_ERR("Failed to send location to cloud");
	} else {
		LOG_INF("Location sent to cloud");
	}
}

K_WORK_DEFINE(location_send_work, location_send_work_fn);

static void lte_lc_event_handler(const struct lte_lc_evt *const evt)
{
	switch (evt->type) {
	case LTE_LC_EVT_NW_REG_STATUS:
		switch (evt->nw_reg_status) {
		case LTE_LC_NW_REG_NOT_REGISTERED:
			LOG_INF("Registration status: not registered");
			break;

		case LTE_LC_NW_REG_REGISTERED_HOME:
			LOG_INF("Registration status: registered, home");
			break;

		case LTE_LC_NW_REG_SEARCHING:
			LOG_INF("Registration status: searching");
			break;

		case LTE_LC_NW_REG_REGISTRATION_DENIED:
			LOG_INF("Registration status: registration denied");
			break;

		case LTE_LC_NW_REG_UNKNOWN:
			LOG_INF("Registration status: unknown");
			break;

		case LTE_LC_NW_REG_REGISTERED_ROAMING:
			LOG_INF("Registration status: registered, roaming");
			break;

		case LTE_LC_NW_REG_UICC_FAIL:
			LOG_INF("Registration status: UICC failure");
			break;
	
		}

	default:
		break;
	}
}

#if defined(CONFIG_NRF_CLOUD_MQTT)
static void nrf_cloud_event_handler(const struct nrf_cloud_evt *evt)
{
	switch (evt->type) {
	case NRF_CLOUD_EVT_TRANSPORT_CONNECTED:
		LOG_INF("nRF Cloud event: transport connected");
		break;

	case NRF_CLOUD_EVT_TRANSPORT_CONNECTING:
		LOG_INF("nRF Cloud event: transport connecting");
		break;

	case NRF_CLOUD_EVT_USER_ASSOCIATION_REQUEST:
		LOG_INF("nRF Cloud event: user association request");
		break;

	case NRF_CLOUD_EVT_USER_ASSOCIATED:
		LOG_INF("nRF Cloud event: user associated");
		break;

	case NRF_CLOUD_EVT_READY:
		LOG_INF("nRF Cloud event: ready");
		k_work_schedule(&location_get_work, K_NO_WAIT);
		break;

	case NRF_CLOUD_EVT_RX_DATA_GENERAL:
		LOG_INF("nRF Cloud event: non-specific data received");
		break;

	case NRF_CLOUD_EVT_RX_DATA_DISCON:
		LOG_INF("nRF Cloud event: device removed from cloud");
		break;

	case NRF_CLOUD_EVT_RX_DATA_LOCATION:
		LOG_INF("nRF Cloud event: location data received");
		break;

	case NRF_CLOUD_EVT_RX_DATA_SHADOW:
		LOG_INF("nRF Cloud event: shadow data received");
		break;

	case NRF_CLOUD_EVT_PINGRESP:
		LOG_INF("nRF Cloud event: ping response received");
		break;

	case NRF_CLOUD_EVT_SENSOR_DATA_ACK:
		LOG_INF("nRF Cloud event: sensor data acknowledged");
		break;

	case NRF_CLOUD_EVT_TRANSPORT_DISCONNECTED:
		LOG_INF("nRF Cloud event: transport disconnected");
		break;

	case NRF_CLOUD_EVT_FOTA_START:
		LOG_INF("nRF Cloud event: FOTA started");
		break;

	case NRF_CLOUD_EVT_FOTA_DONE:
		LOG_INF("nRF Cloud event: FOTA finished");
		break;

	case NRF_CLOUD_EVT_FOTA_ERROR:
		LOG_INF("nRF Cloud event: error during FOTA update");
		break;

	case NRF_CLOUD_EVT_TRANSPORT_CONNECT_ERROR:
		LOG_INF("nRF Cloud event: error while connecting transport");
		break;

	case NRF_CLOUD_EVT_FOTA_JOB_AVAILABLE:
		LOG_INF("nRF Cloud event: FOTA job available");
		break;

	case NRF_CLOUD_EVT_ERROR:
		LOG_INF("nRF Cloud event: error");
		break;
	}
}
#endif

static void location_event_handler(const struct location_event_data *event_data)
{
	switch (event_data->id) {
	case LOCATION_EVT_LOCATION:
		LOG_INF("Location event: location update");
		date_time_now(&gnss_data.ts_ms);
		gnss_data.pvt.lon = event_data->location.longitude;
		gnss_data.pvt.lat = event_data->location.latitude;
		gnss_data.pvt.accuracy = event_data->location.accuracy;
		k_work_submit(&location_send_work);
		break;
	
	case LOCATION_EVT_TIMEOUT:
		LOG_INF("Location event: timeout");
		break;
	
	case LOCATION_EVT_ERROR:
		LOG_INF("Location event: error");
		break;
	
	case LOCATION_EVT_RESULT_UNKNOWN:
		LOG_INF("Location event: result unknown");
		break;
	
	case LOCATION_EVT_GNSS_ASSISTANCE_REQUEST:
		LOG_INF("Location event: GNSS assistance request");
		break;
	
	case LOCATION_EVT_GNSS_PREDICTION_REQUEST:
		LOG_INF("Location event: GNSS prediction request");
		break;
	
	case LOCATION_EVT_CLOUD_LOCATION_EXT_REQUEST:
		LOG_INF("Location event: external cloud request");
		break;
	
	case LOCATION_EVT_STARTED:
		LOG_INF("Location event: location request started");
		break;
	
	case LOCATION_EVT_FALLBACK:
		LOG_INF("Location event: fallback");
		break;
	}
}

int main(void)
{
	int err;

	LOG_INF("nRF92 Cloud GNSS sample started");

	err = nrf_modem_lib_init();
	if (err) {
		LOG_ERR("Modem library initialization failed, error: %d", err);
		return err;
	}

	lte_lc_register_handler(lte_lc_event_handler);

#if defined(CONFIG_NRF_CLOUD_COAP)
	err = nrf_cloud_coap_init();
#else
	const struct nrf_cloud_init_param cloud_params = {
		.event_handler = nrf_cloud_event_handler,
		.client_id = NULL
	};

	err = nrf_cloud_init(&cloud_params);
#endif
	if (err) {
		LOG_ERR("Failed to initialize nRF Cloud library, error: %d", err);
		return err;
	}

	err = location_init(location_event_handler);
	if (err) {
		LOG_ERR("Failed to initialize Location library, error: %d", err);
		return err;
	}

	LOG_INF("Connecting to LTE...");

	err = lte_lc_connect();
	if (err) {
		LOG_ERR("Failed to connect to LTE, error: %d", err);
		return err;
	}

	LOG_INF("Connecting to nRF Cloud...");

#if defined(CONFIG_NRF_CLOUD_COAP)
	err = nrf_cloud_coap_connect(NULL);
#else
	err = nrf_cloud_connect();
#endif
	if (err) {
		LOG_ERR("Failed to connect to nRF Cloud, error: %d", err);
		return err;
	}

	return 0;
}
