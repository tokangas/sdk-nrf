/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#ifndef _SMS_DELIVER_INCLUDE_H_
#define _SMS_DELIVER_INCLUDE_H_

/* Forward declaration */
struct sms_data;

int sms_deliver_pdu_parse(char *pdu, struct sms_data *out);

#endif

