/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#ifndef _SMS_DELIVER_INCLUDE_H_
#define _SMS_DELIVER_INCLUDE_H_

#include <stdint.h>

enum sms_deliver_alphabet {
	GSM_ENCODING_8BIT,
	GSM_ENCODING_UCS2,
};

enum sms_deliver_class {
	GSM_CLASS0,
	GSM_CLASS1,
	GSM_CLASS2,
	GSM_CLASS3,
};

struct sms_deliver_time {
	uint8_t year;
	uint8_t month;
	uint8_t day;
	uint8_t hour;
	uint8_t minute;
	uint8_t second;
	int8_t timezone;
};

struct sms_deliver_address {
	uint8_t address[12];
	uint8_t length;
	uint8_t type;
};

struct sms_deliver_header {
	struct sms_deliver_time    time;
	uint8_t                    protocol_id;
	enum sms_deliver_alphabet  alphabet;
	bool                       compressed;
	bool                       presence_of_class;
	enum sms_deliver_class     class;
	struct sms_deliver_address service_center_address;
	struct sms_deliver_address orginator_address;
};

void *sms_deliver_get_api(void);

#endif

