/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <logging/log.h>
#include <stdio.h>
#include <errno.h>
#include <modem/at_cmd.h>
#include <modem/sms.h>

#include "string_conversion.h"


LOG_MODULE_DECLARE(sms, CONFIG_SMS_LOG_LEVEL);

#define SMS_MAX_DATA_LEN_CHARS 160


/**
 * @brief Encode phone number into format specified within SMS header.
 * 
 * Phone number means address specified in 3GPP TS 23.040 chapter 9.1.2.5.
 *
 * @param number Number as a string.
 * @param number_size In: Length of the number string.
 *                    Out: Amount of characters in number. Special characters
 *                         ignored from original number_size. This is also
 *                         number of semi-octets in encoded_number.
 * @param encoded_number Number encoded into 3GPP format.
 * @param encoded_number_size_octets Number of octets/bytes in encoded_number
 * 
 * @retval -EINVAL Invalid parameter.
 * @return Zero on success, otherwise error code.
 */
static int sms_submit_encode_number(
	char *number,
	uint8_t *number_size,
	char *encoded_number,
	uint8_t *encoded_number_size_octets)
{
	*encoded_number_size_octets = 0;

	if (number == NULL) {
		LOG_ERR("SMS number not given but NULL");
		return -EINVAL;
	}

	if (*number_size == 0) {
		LOG_ERR("SMS number not given but zero length");
		return -EINVAL;
	}

	if (number[0] == '+') {
		/* If first character of the number is plus, just ignore it.
		   We are using international number format always anyway */
		number += 1;
		*number_size = strlen(number);
		LOG_DBG("Ignoring leading '+' in the number");
	}

	memset(encoded_number, 0, SMS_MAX_ADDRESS_LEN_CHARS + 1);
	memcpy(encoded_number, number, *number_size);

	for (int i = 0; i < *number_size; i++) {
		if (!(i%2)) {
			if (i+1 < *number_size) {
				char first = encoded_number[i];
				char second = encoded_number[i+1];
				encoded_number[i] = second;
				encoded_number[i+1] = first;
			} else {
				encoded_number[i+1] = encoded_number[i];
				encoded_number[i] = 'F';
			}
			(*encoded_number_size_octets)++;
		}
	}
	return 0;
}

int sms_submit_send(char* number, char* text)
{
	char at_response_str[CONFIG_AT_CMD_RESPONSE_MAX_LEN + 1];
	int ret;

	LOG_DBG("Sending SMS to number=%s, text='%s'",
		log_strdup(number), log_strdup(text));

	/* Encode text into GSM 7bit encoding */
	uint8_t size = 0;
	uint8_t encoded[SMS_MAX_DATA_LEN_CHARS];
	uint8_t encoded_data_hex_str[SMS_MAX_DATA_LEN_CHARS * 2 + 1];
	uint8_t encoded_size = 0;
	uint8_t encoded_data_size = 0;
	memset(encoded, 0, SMS_MAX_DATA_LEN_CHARS);
	memset(encoded_data_hex_str, 0, SMS_MAX_DATA_LEN_CHARS * 2 + 1);

	size = string_conversion_ascii_to_gsm7bit(
		text, strlen(text), encoded, &encoded_size, &encoded_data_size, true);

	/* Create hexadecimal string representation of GSM 7bit encoded text */
	uint8_t hex_str_number = 0;
	for (int i = 0; i < encoded_size; i++) {
		sprintf(encoded_data_hex_str + hex_str_number,
			"%02X", encoded[i]);
		hex_str_number += 2;
	}

	/* Encode number into format required in SMS header */
	uint8_t encoded_number[SMS_MAX_ADDRESS_LEN_CHARS + 1];
	uint8_t encoded_number_size = strlen(number);
	uint8_t encoded_number_size_octets = SMS_MAX_ADDRESS_LEN_CHARS + 1;
	ret = sms_submit_encode_number(number, &encoded_number_size, encoded_number, &encoded_number_size_octets);
	if (ret) {
		return ret;
	}

	/* Create and send CMGS AT command */
	char send_data[500];
	memset(send_data, 0, 500);

	int msg_size = 2 + 1 + 1 + encoded_number_size_octets + 3 + 1 + encoded_size;
	sprintf(send_data, "AT+CMGS=%d\r003100%02X91%s0000FF%02X%s\x1a",
		msg_size, encoded_number_size, encoded_number,
		encoded_data_size, encoded_data_hex_str);
	LOG_DBG("Sending encoded SMS data (length=%d):", msg_size);
	LOG_DBG("%s", log_strdup(send_data));
	LOG_DBG("SMS data encoded: %s", log_strdup(encoded_data_hex_str));

	enum at_cmd_state state = 0;
	ret = at_cmd_write(send_data, at_response_str,
		sizeof(at_response_str), &state);
	if (ret) {
		LOG_ERR("at_cmd_write returned state=%d, err=%d", state, ret);
		return ret;
	}
	LOG_DBG("AT Response:%s", log_strdup(at_response_str));
	return 0;
}
