#ifndef ICMP_PING_H
#define ICMP_PING_H

/*
 * Copyright (c) 2018 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

/**@file icmp_ping.h
 *
 * @brief ICMP ping.
 * @{
 */

#include <zephyr/types.h>

#define ICMP_MAX_URL		128
#define ICMP_MAX_LEN		512
#define ICMP_PARAM_COUNT_DEFAULT 4
/**
 * @brief ICMP AT command parser.
 *
 * @param shell Requesting shell.
 * @param target_name Target domain name.
 *
 * @retval 0 If the operation was successful.
 *           Otherwise, a (negative) error code is returned.
 */
int icmp_ping_start(const struct shell *shell, const char *target_name, int count);

#endif /* ICMP_PING_H */
