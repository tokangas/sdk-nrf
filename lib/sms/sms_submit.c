/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <logging/log.h>
#include <stdio.h>
#include <zephyr.h>
#include <errno.h>
#include <modem/at_cmd.h>
#include <modem/sms.h>

#include "string_conversion.h"


LOG_MODULE_DECLARE(sms, CONFIG_SMS_LOG_LEVEL);

/** @brief User Data Header size in octets/bytes. */
#define SMS_UDH_CONCAT_SIZE_OCTETS 6
/** @brief User Data Header size in septets. */
#define SMS_UDH_CONCAT_SIZE_SEPTETS 7

/* TODO: This is somewhere else too */
#define SMS_AT_RESPONSE_MAX_LEN 256

/**
 * @brief Encode phone number into format specified within SMS header.
 * 
 * @details Phone number means address specified in 3GPP TS 23.040 chapter 9.1.2.5.
 *
 * @param[in] number Number as a string.
 * @param[in,out] number_size In: Length of the number string.
 *                    Out: Amount of characters in number. Special characters
 *                         ignored from original number_size. This is also
 *                         number of semi-octets in encoded_number.
 * @param[in] encoded_number Number encoded into 3GPP format.
 * @param[out] encoded_number_size_octets Number of octets/bytes in encoded_number.
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
		if (!(i % 2)) {
			if (i + 1 < *number_size) {
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

/**
 * @brief Encode and send concatenated SMS.
 * 
 * @details Compose and send multiple SMS-SUBMIT messages with CMGS AT command.
 * Includes User-Data-Header for concatenated message to indicate information
 * about multiple messages that should be reconstructed in the receiving end.
 * 
 * This function should not be used for short texts that don't need concatenation
 * because this will add concatenation User-Data-Header.
 * 
 * @param[in] text Text to be sent.
 * @param[in] encoded_number Number in semi-octet representation for SMS-SUBMIT message.
 * @param[in] encoded_number_size Number of characters in number (encoded_number).
 * @param[in] encoded_number_size_octets Number of octets in number (encoded_number).
 */
static int sms_submit_send_concat(char* text, uint8_t *encoded_number,
	uint8_t encoded_number_size, uint8_t encoded_number_size_octets)
{
	char at_response_str[SMS_AT_RESPONSE_MAX_LEN];
	int ret;
	static uint8_t concat_msg_id = 1;
	static uint8_t message_ref = 1;

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
	uint8_t concat_seq_number = 0;
	char *text_index = text;
	char *send_bufs[CONFIG_SMS_SEND_CONCATENATED_MSG_MAX_CNT] = {0};
	uint16_t send_bufs_udh_pos[CONFIG_SMS_SEND_CONCATENATED_MSG_MAX_CNT] = {0};

	while (text_encoded_size < text_size) {
		if (concat_seq_number >= CONFIG_SMS_SEND_CONCATENATED_MSG_MAX_CNT) {
			LOG_WRN("Sent data cannot fit into maximum number of concatenated messages (%d)",
				CONFIG_SMS_SEND_CONCATENATED_MSG_MAX_CNT);
			for (int i = 0; i < concat_seq_number; i++) {
				k_free(send_bufs[i]);
			}
			return -E2BIG;
		}

		uint16_t text_part_size = strlen(text_index);
		if (text_part_size > 153) {
			text_part_size = 153;
		}
		send_bufs[concat_seq_number] = k_malloc(500);
		if (send_bufs[concat_seq_number] == NULL) {
			LOG_ERR("Unable to send concatenated message due to no memory");
			/* Free memory reserved earlier */
			for (int i = 0; i < concat_seq_number; i++) {
				k_free(send_bufs[i]);
			}
			return -ENOMEM;
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

		int msg_size = 2 + 1 + 1 + encoded_number_size_octets + 2 + 1 + encoded_size;
		/* First, compose SMS header so that we get an index for
		   User-Data-Header to add that when number of messages is known */
		sprintf(send_bufs[concat_seq_number], "AT+CMGS=%d\r0061%02X%02X91%s0000%02X",
			msg_size, message_ref, encoded_number_size, encoded_number, encoded_data_size);
		send_bufs_udh_pos[concat_seq_number] = strlen(send_bufs[concat_seq_number]);

		/* Then, add empty User-Data-Header to be filled later,
		   and the actual user data */
		sprintf(send_bufs[concat_seq_number] + send_bufs_udh_pos[concat_seq_number], "000000000000%s\x1a",
			encoded_data_hex_str);
		LOG_DBG("Sending encoded SMS data (length=%d):", msg_size);
		LOG_DBG("%s", log_strdup(send_bufs[concat_seq_number]));
		LOG_DBG("SMS data encoded: %s", log_strdup(encoded_data_hex_str));

		message_ref++;
		concat_seq_number++;
	}

	for (int i = 0; i < concat_seq_number; i++) {
		char udh_str[13] = {};
		sprintf(udh_str, "050003%02X%02X%02X",
			concat_msg_id, concat_seq_number, i + 1);

		memcpy(send_bufs[i] + send_bufs_udh_pos[i], udh_str, strlen(udh_str));

		enum at_cmd_state state = 0;
		ret = at_cmd_write(send_bufs[i], at_response_str,
			sizeof(at_response_str), &state);
		if (ret) {
			LOG_ERR("at_cmd_write returned state=%d, err=%d", state, ret);
			return ret;
		}
		LOG_DBG("AT Response:%s", log_strdup(at_response_str));

		k_free(send_bufs[i]);
		/* Just looping without threading seems to work fine and we don't need to wait
		 * for CDS response. Otherwise we would need to send 2nd message from work queue
		 * and store a lot of state information. */
	}
	concat_msg_id++;
	return 0;
}

/**
 * @brief Send SMS message, which is called SMS-SUBMIT message in SMS protocol.
 * 
 * SMS-SUBMIT message format is specified in 3GPP TS 23.040 chapter 9.2.2.2.
 *
 * @param[in] number Recipient number.
 * @param[in] text Text to be sent.
 * 
 * @retval -EINVAL Invalid parameter.
 * @return Zero on success, otherwise error code.
 */
int sms_submit_send(char* number, char* text)
{
	char at_response_str[SMS_AT_RESPONSE_MAX_LEN];
	char empty_string[] = "";
	int ret;

	if (number == NULL) {
		number = empty_string;
	}
	if (text == NULL) {
		text = empty_string;
	}

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
		/* TODO: Still need to see if we could do both single and concatenated SMS from same function. */
		LOG_DBG("Entire message doesn't fit into single SMS message. Using concatenated SMS.");
		return sms_submit_send_concat(text, encoded_number, encoded_number_size, encoded_number_size_octets);
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

	int msg_size = 2 + 1 + 1 + encoded_number_size_octets + 2 + 1 + encoded_size;
	sprintf(send_data, "AT+CMGS=%d\r002100%02X91%s0000%02X%s\x1a",
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
