/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef CLOUD_LOCATION_H_
#define CLOUD_LOCATION_H_

#ifdef __cplusplus
extern "C" {
#endif

int cloud_location_get(
	const struct location_data_cloud *location_data,
	struct location_data *location);

#ifdef __cplusplus
}
#endif

#endif /* CLOUD_LOCATION_H_ */
