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

bool is_fota_enabled();

void enable_fota();

void disable_fota();

u32_t get_time_to_next_update_check();

u32_t get_update_check_interval();

void set_update_check_interval(u32_t interval);

void reset_update_check_interval();

char *get_dm_server_host();

void set_dm_server_host(const char *host);

void reset_dm_server_host();

u16_t get_dm_server_port();

void set_dm_server_port(u16_t port);

void reset_dm_server_port();

#ifdef __cplusplus
}
#endif

#endif /* MODEM_FOTA_INTERNAL_H_ */
