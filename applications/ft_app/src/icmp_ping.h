#ifndef ICMP_PING_H
#define ICMP_PING_H

/*
 * Copyright (c) 2018 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

/**@file ping.h
 *
 * @brief ICMP ping.
 * @{
 */

#include <zephyr/types.h>

/**
 * @brief ICMP AT command parser.
 *
 * @param shell Requesting shell.
 * @param target_name Target domain name.
 *
 * @retval 0 If the operation was successful.
 *           Otherwise, a (negative) error code is returned.
 */
int icmp_ping_start(const struct shell *shell, const char *target_name);

#endif /* ICMP_PING_H */
