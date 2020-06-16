/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#ifndef MODEM_FOTA_INTERNAL_H_
#define MODEM_FOTA_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#define SECONDS_IN_DAY (24 * 60 * 60)

/* Currently the maximum timer duration is ~18h, so we'll use that */
#define MAX_TIMER_DURATION_S (18 * 60 * 60)

bool is_fota_enabled();

void enable_fota();

void disable_fota();

u32_t get_time_to_next_update_check();

void set_time_to_next_update_check(u32_t seconds);

char *get_dm_server_host();

void set_dm_server_host(const char *host);

u16_t get_dm_server_port();

void set_dm_server_port(u16_t port);

#ifdef __cplusplus
}
#endif

#endif /* MODEM_FOTA_INTERNAL_H_ */
