/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#ifndef SMS_H
#define SMS_H

#define SMS_NUMBER_NONE -1

int sms_send(char* number, char* data);
int sms_register();
int sms_unregister();

#endif
