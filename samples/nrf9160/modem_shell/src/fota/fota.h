/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef FOTA_H
#define FOTA_H

#include <zephyr/types.h>

int fota_init(void);

int fota_start(const char *host, const char *file);

#endif /* FOTA_H */
