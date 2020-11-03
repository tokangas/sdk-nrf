/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#ifndef GNSS_H
#define GNSS_H

#include <zephyr/types.h>

enum gnss_duty_cycling_policy {
	GNSS_DUTY_CYCLING_DISABLED,
	GNSS_DUTY_CYCLING_PERFORMANCE,
	GNSS_DUTY_CYCLING_POWER
};

/**
 * @brief Starts GNSS.
 *
 * @retval 0 if the operation was successful.
 *         Otherwise, a (negative) error code is returned.
 */
int gnss_start(void);

/**
 * @brief Stops GNSS.
 *
 * @retval 0 if the operation was successful.
 *         Otherwise, a (negative) error code is returned.
 */
int gnss_stop(void);

/**
 * @brief Sets continuous tracking mode.
 *
 * @retval 0 if the operation was successful.
 *         Otherwise, a (negative) error code is returned.
 */
int gnss_set_continuous_mode();

/**
 * @brief Sets single fix mode.
 *
 * @param fix_retry Fix retry period (in seconds). Indicates how long
 *                  GNSS tries to get a fix before giving up. Value 0
 *                  denotes unlimited retry period.
 *
 * @retval 0 if the operation was successful.
 *         Otherwise, a (negative) error code is returned.
 */
int gnss_set_single_fix_mode(uint16_t fix_retry);

/**
 * @brief Sets periodic fix mode.
 *
 * @param fix_interval Delay between fixes (in seconds). Allowed values are
 *                     10...1800.
 * @param fix_retry    Fix retry period (in seconds). Indicates how long
 *                     GNSS tries to get a fix before giving up. Value 0
 *                     denotes unlimited retry period.
 *
 * @retval 0 if the operation was successful.
 *         Otherwise, a (negative) error code is returned.
 */
int gnss_set_periodic_fix_mode(uint16_t fix_interval, uint16_t fix_retry);

/**
 * @brief Sets duty cycling policy for continuous tracking mode.
 *
 * Duty cycled tracking saves power by operating the GNSS receiver in on/off
 * cycles. Two different duty cycling modes are supported, one which saves
 * power without significant performance degradation and one which saves even
 * more power with an acceptable performance degradation.
 *
 * @param policy Duty cycling policy value.
 *
 * @retval 0 if the operation was successful.
 *         Otherwise, a (negative) error code is returned.
 */
int gnss_set_duty_cycling_policy(enum gnss_duty_cycling_policy policy);

/**
 * @brief Sets whether stored data is cleared whenever the GNSS is started.
 *
 * @param value True if stored data should be cleared, false if not.
 */
void gnss_set_delete_stored_data(bool value);

/**
 * @brief Configures how much PVT information is printed out.
 *
 * @param level 0 = PVT output disabled
 *              1 = fix information enabled
 *              2 = fix and SV information enabled
 *
 * @retval 0 if the operation was successful.
 *         Otherwise, a (negative) error code is returned.
 */
int gnss_set_pvt_output_level(uint8_t level);

/**
 * @brief Configures whether NMEA strings are printed out.
 *
 * @param level 0 = NMEA output disabled
 *              1 = NMEA output enabled
 *
 * @retval 0 if the operation was successful.
 *         Otherwise, a (negative) error code is returned.
 */
int gnss_set_nmea_output_level(uint8_t level);

/**
 * @brief Configures whether GPS driver event information is printed out.
 *
 * @param level 0 = event output disabled
 *              1 = event output enabled
 *
 * @retval 0 if the operation was successful.
 *         Otherwise, a (negative) error code is returned.
 */
int gnss_set_event_output_level(uint8_t level);

#endif /* GNSS_H */
