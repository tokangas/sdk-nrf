/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#ifndef MOSH_DEFINES_H
#define MOSH_DEFINES_H

#define FTA_EMPTY_STRING "\0"

#define FTA_APN_STR_MAX_LEN (64)
#define FTA_ARG_NOT_SET -6

#define FTA_STRING_NULL_CHECK(string) ((string != NULL) ? string : FTA_EMPTY_STRING)

#endif /* MOSH_DEFINES_H */
