/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

/**
 * @file modem_fota.h
 *
 * @brief Public APIs for the modem FOTA client.
 * @defgroup modem_fota Modem FOTA client
 * @{
 */

#ifndef MODEM_FOTA_H_
#define MODEM_FOTA_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Modem FOTA event IDs.
 */
enum modem_fota_evt_id {
	/** Checking for update started */
	MODEM_FOTA_EVT_CHECKING_FOR_UPDATE,
	/** No update available */
	MODEM_FOTA_EVT_NO_UPDATE_AVAILABLE,
	/** Update available, download started */
	MODEM_FOTA_EVT_DOWNLOADING_UPDATE,
	/** Update downloaded, restart needed to apply the update */
	MODEM_FOTA_EVT_RESTART_PENDING,
	/** Error during update check or download */
	MODEM_FOTA_EVT_ERROR,
};

/**
 * @brief Modem FOTA asynchronous callback function.
 *
 * @param event_id Event ID.
 *
 */
typedef void (*modem_fota_callback_t)(enum modem_fota_evt_id event_id);

/**
 * @brief Initializes the modem FOTA client.
 *
 * TOOD: Add detailed description.
 *
 * @param callback Callback for the generated events.
 *
 * @retval 0 If the operation was successful.
 *           Otherwise, a (negative) error code is returned.
 */
int modem_fota_init(modem_fota_callback_t callback);

#ifdef __cplusplus
}
#endif

#endif /* MODEM_FOTA_H_ */

/** @} */
