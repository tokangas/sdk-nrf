#ifndef ICMP_PING_H
#define ICMP_PING_H

/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
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
#define ICMP_PARAM_LENGTH_DEFAULT 0
#define ICMP_PARAM_COUNT_DEFAULT 4
#define ICMP_PARAM_TIMEOUT_DEFAULT 3000
#define ICMP_PARAM_INTERVAL_DEFAULT 1000

/**@ ICMP Ping command arguments */
typedef struct {
	char target_name[ICMP_MAX_URL];
	struct addrinfo *src;
	struct addrinfo *dest;
	struct sockaddr_in current_sin4;
	struct sockaddr_in6 current_sin6;
    char current_pdp_type;
	int len;
	int timeout;
	int count;
	int interval;
    bool force_ipv6;
} icmp_ping_shell_cmd_argv_t;

/**
 * @brief ICMP initiator.
 *
 * @param shell Requesting shell.
 * @param target_name Target domain name.
 *
 * @retval 0 If the operation was successful.
 *           Otherwise, a (negative) error code is returned.
 */
int icmp_ping_start(const struct shell *shell, icmp_ping_shell_cmd_argv_t *ping_args);

#endif /* ICMP_PING_H */
