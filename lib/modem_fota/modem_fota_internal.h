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

bool is_fota_enabled(void);

void enable_fota(void);

void disable_fota(void);

u32_t get_time_to_next_update_check(void);

void set_time_to_next_update_check(u32_t seconds);

char *get_api_hostname(void);

void set_api_hostname(const char *hostname);

u16_t get_api_port(void);

void set_api_port(u16_t port);

char *get_fw_api_hostname(void);

void set_fw_api_hostname(const char *hostname);

#ifdef __cplusplus
}
#endif

#endif /* MODEM_FOTA_INTERNAL_H_ */
