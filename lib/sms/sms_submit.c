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
#define SMS_UDH_CONCAT_SIZE_OCTETS 6
#define SMS_UDH_CONCAT_SIZE_SEPTETS 7


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

static int sms_submit_send_concat(char* text, uint8_t *encoded_number, uint8_t encoded_number_size, uint8_t encoded_number_size_octets)
{
	char at_response_str[CONFIG_AT_CMD_RESPONSE_MAX_LEN + 1];
	int ret;
	static uint8_t concat_msg_id = 1;
	static uint8_t message_ref = 1;
	char send_data[500];
	memset(send_data, 0, 500);

	uint8_t size = 0;
	uint16_t text_size = strlen(text);
	uint8_t encoded[SMS_MAX_DATA_LEN_CHARS];
	uint8_t encoded_size = 0;
	uint8_t encoded_data_size = 0;
	memset(encoded, 0, SMS_MAX_DATA_LEN_CHARS);

	const uint8_t udh[] = {0x05, 0x00, 0x03, 0x01, 0x01, 0x01, 0x00};
	char ud[SMS_MAX_DATA_LEN_CHARS];
	memcpy(ud, udh, sizeof(udh));

	uint16_t text_encoded_size = 0;
	uint8_t concat_seq_number = 1;
	char *text_index = text;
	while (text_encoded_size < text_size) {
		uint8_t text_part_size = strlen(text_index);
		if (text_part_size > 153) {
			text_part_size = 153;
		}
		memcpy(ud + SMS_UDH_CONCAT_SIZE_SEPTETS, text_index, text_part_size);
		
		size = string_conversion_ascii_to_gsm7bit(
			ud, sizeof(udh) + text_part_size, encoded, &encoded_size, &encoded_data_size, true);

		text_encoded_size += size - sizeof(udh);
		text_index += size - sizeof(udh);

		/* Create hexadecimal string representation of GSM 7bit encoded text 
			which starts after user data header bytes in the encoded data */
		uint8_t encoded_data_hex_str[SMS_MAX_DATA_LEN_CHARS * 2 + 1];
		memset(encoded_data_hex_str, 0, SMS_MAX_DATA_LEN_CHARS * 2 + 1);
		for (int i = SMS_UDH_CONCAT_SIZE_OCTETS; i < encoded_size; i++) {
			sprintf(encoded_data_hex_str + (2 * (i - SMS_UDH_CONCAT_SIZE_OCTETS)), "%02X", encoded[i]);
		}

		char udh_str[13];
		/* TODO: We can only have concatenated message in two parts.
		         Need to run a loop to count how many messages are
			 needed first. */
		uint8_t concat_number_of_parts = 2;
		sprintf(udh_str, "050003%02X%02X%02X",
			concat_msg_id, concat_number_of_parts, concat_seq_number);
		int msg_size = 2 + 1 + 1 + encoded_number_size_octets + 2 + 1 + encoded_size;
		/* TODO: For non-concatenated SMS, we have TP-Validity-Period
		   set to 0xFF. Hsving this byte in the concatenated SMS causes
		   failure in sending CMGS AT command:
		       CMS ERROR: 304	Invalid PDU mode parameter
		   This is how it is in non-concatenated SMS:
		       "AT+CMGS=%d\r0061%02X%02X91%s0000FF%02X%s%s\x1a",
		   */
		sprintf(send_data, "AT+CMGS=%d\r0061%02X%02X91%s0000%02X%s%s\x1a",
			msg_size, message_ref++, encoded_number_size, encoded_number,
			encoded_data_size, udh_str, encoded_data_hex_str);
		LOG_DBG("Sending encoded SMS data (length=%d):", msg_size);
		LOG_DBG("%s", log_strdup(send_data));
		LOG_DBG("SMS data encoded: %s", log_strdup(encoded_data_hex_str));
		LOG_DBG("encoded_number_size_octets=%d, encoded_number_size=%d, "
			"size=%d, encoded_size=%d, encoded_data_size=%d, text_encoded_size=%d, text_size=%d, msg_size=%d",
			encoded_number_size_octets,
			encoded_number_size,
			size,
			encoded_size,
			encoded_data_size,
			text_encoded_size,
			text_size,
			msg_size);

		concat_seq_number++;

		enum at_cmd_state state = 0;
		ret = at_cmd_write(send_data, at_response_str,
			sizeof(at_response_str), &state);
		if (ret) {
			LOG_ERR("at_cmd_write returned state=%d, err=%d", state, ret);
			return ret;
		}
		LOG_DBG("AT Response:%s", log_strdup(at_response_str));

		/* TODO: Just looping without threading may not work out and
		        we need to wait for CDS response, which would mean
			we need to send 2nd message from work queue and store
			a lot of state information */
	}
	concat_msg_id++;
	return 0;
}

int sms_submit_send(char* number, char* text)
{
	char at_response_str[CONFIG_AT_CMD_RESPONSE_MAX_LEN + 1];
	int ret;

	LOG_DBG("Sending SMS to number=%s, text='%s'",
		log_strdup(number), log_strdup(text));

	/* Encode number into format required in SMS header */
	uint8_t encoded_number[SMS_MAX_ADDRESS_LEN_CHARS + 1];
	uint8_t encoded_number_size = strlen(number);
	uint8_t encoded_number_size_octets = SMS_MAX_ADDRESS_LEN_CHARS + 1;
	ret = sms_submit_encode_number(number, &encoded_number_size, encoded_number, &encoded_number_size_octets);
	if (ret) {
		return ret;
	}

	/* Encode text into GSM 7bit encoding */
	uint8_t size = 0;
	uint16_t text_size = strlen(text);
	uint8_t encoded[SMS_MAX_DATA_LEN_CHARS];
	uint8_t encoded_size = 0;
	uint8_t encoded_data_size = 0;
	memset(encoded, 0, SMS_MAX_DATA_LEN_CHARS);

	size = string_conversion_ascii_to_gsm7bit(
		text, text_size, encoded, &encoded_size, &encoded_data_size, true);

	/* Check if this should be sent as concatenated SMS */
	if (size < text_size) {
		LOG_DBG("Entire message doesn't fit into single SMS message. Using concatenated SMS.");
		sms_submit_send_concat(text, encoded_number, encoded_number_size, encoded_number_size_octets);
		return 0;
	}

	/* Create hexadecimal string representation of GSM 7bit encoded text */
	uint8_t encoded_data_hex_str[SMS_MAX_DATA_LEN_CHARS * 2 + 1];
	memset(encoded_data_hex_str, 0, SMS_MAX_DATA_LEN_CHARS * 2 + 1);
	for (int i = 0; i < encoded_size; i++) {
		sprintf(encoded_data_hex_str + (2 * i), "%02X", encoded[i]);
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
	LOG_DBG("encoded_number_size_octets=%d, encoded_number_size=%d, "
		"size=%d, encoded_size=%d, encoded_data_size=%d, msg_size=%d",
		encoded_number_size_octets,
		encoded_number_size,
		size,
		encoded_size,
		encoded_data_size,
		msg_size);

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
