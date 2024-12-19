/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <net/nrf_cloud_rest.h>
#include <modem/location.h>

#include "cloud_location.h"

LOG_MODULE_REGISTER(cloud_location, CONFIG_LOCATION_MODULE_LOG_LEVEL);

static char recv_buf[512];

int cloud_location_get(
	const struct location_data_cloud *location_data,
	struct location_data *location)
{
	int err;
	struct nrf_cloud_rest_context rest_ctx = {
		.connect_socket = -1,
		.keep_alive = false,
		.timeout_ms = 30000,
		.rx_buf = recv_buf,
		.rx_buf_len = sizeof(recv_buf),
		.fragment_size = 0
	};
	struct nrf_cloud_rest_location_request request = {
		.cell_info = (struct lte_lc_cells_info *)location_data->cell_data,
		.wifi_info = NULL
	};
	struct nrf_cloud_location_result result;

	LOG_INF("Sending location request to nRF Cloud over REST");

	err = nrf_cloud_rest_location_get(&rest_ctx, &request, &result);
	if (err) {
		LOG_ERR("Getting location failed, error: %d", err);
	} else {
		LOG_INF("Got location, latitude: %.6f, longitude: %.6f, accuracy: %d",
			result.lat, result.lon, result.unc);

		location->latitude = result.lat;
		location->longitude = result.lon;
		location->accuracy = result.unc;
		location->datetime.valid = false;
	}

	return err;
}
