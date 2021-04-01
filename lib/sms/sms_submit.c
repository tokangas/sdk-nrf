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
/** @brief Maximum length of the response for AT commands. */
#define SMS_AT_RESPONSE_MAX_LEN 256
/** @brief Buffer size reserved for CMGS AT command. */
#define SMS_AT_CMGS_BUF_SIZE 500

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
 * @brief Create SMS-SUBMIT message as specified in specified in 3GPP TS 23.040 chapter 9.2.2.2.
 * 
 * @details Optionally allows adding space for User-Data-Header.
 * 
 * @param[out] send_buf Output buffer where SMS-SUBMIT message is created. Caller should allocate
 * 		enough space. Minimum of 400 bytes is required with maximum message size and if
 * 		encoded User-Data is smaller, buffer can also be smaller.
 * @param[in] encoded_number Number in semi-octet representation for SMS-SUBMIT message.
 * @param[in] encoded_number_size Number of characters in number (encoded_number).
 * @param[in] encoded_number_size_octets Number of octets in number (encoded_number).
 * @param[in] encoded_data Encoded User-Data in bytes.
 * @param[in] encoded_data_size_octets Encoded User-Data size in octets.
 * @param[in] encoded_data_size_septets Encoded User-Data size in septets.
 * @param[in] message_ref TP-Message-Reference field in SMS-SUBMIT message.
 * @param[in] udh_size Size of the User-Data-Header in bytes.
 * @param[out] udh_start_index Index to send_buf, where User-Data-Header starts.
 */
void sms_submit_encode(
	char *send_buf,
	uint8_t *encoded_number,
	uint8_t encoded_number_size,
	uint8_t encoded_number_size_octets,
	uint8_t *encoded,
	uint8_t encoded_data_size_octets,
	uint8_t encoded_data_size_septets,
	uint8_t message_ref,
	uint8_t udh_size,
	uint16_t *udh_start_index)
{
	/* Create hexadecimal string representation of GSM 7bit encoded text */
	uint8_t encoded_data_hex_str[SMS_MAX_DATA_LEN_CHARS * 2 + 1];
	memset(encoded_data_hex_str, 0, SMS_MAX_DATA_LEN_CHARS * 2 + 1);
	for (int i = 0; i < encoded_data_size_octets; i++) {
		sprintf(encoded_data_hex_str + (2 * i), "%02X", encoded[i]);
	}

	/* Create and send CMGS AT command */
	int msg_size =
		2 + /* First header byte and TP-MR fields */
		1 + /* Length of phone number */
		1 + /* Phone number Type-of-Address byte */
		encoded_number_size_octets +
		2 + /* TP-PID and TP-DCS fields */
		1 + /* TP-UDL field */
		udh_size +
		encoded_data_size_octets;

	uint8_t sms_submit_header_byte = 0x21;
	if (udh_start_index != NULL) {
		sms_submit_header_byte = 0x61;
	}
	/* First, compose SMS header without User-Data so that we get an index for
	 * User-Data-Header to be added later */
	sprintf(send_buf,
		"AT+CMGS=%d\r00%02X%02X%02X91%s0000%02X",
		msg_size,
		sms_submit_header_byte,
		message_ref,
		encoded_number_size,
		encoded_number,
		encoded_data_size_septets);
	/* Store the position for User-Data */
	uint8_t ud_start_index = strlen(send_buf);

	/* Then, add empty User-Data-Header to be filled later if requested */
	if (udh_start_index != NULL) {
		*udh_start_index = ud_start_index;
		/* Add "00" for each UDH byte for two character long hexadecimal representation */
		for (int i = 0; i < udh_size; i++) {
			send_buf[ud_start_index + i * 2] = '0';
			send_buf[ud_start_index + i * 2 + 1] = '0';
		}
		send_buf[ud_start_index + udh_size * 2] = '\0';
		/* Update position where USer-Data is added. */
		ud_start_index = strlen(send_buf);
	}
	/* Then, add the actual user data */
	sprintf(send_buf + ud_start_index, "%s\x1a", encoded_data_hex_str);

	LOG_DBG("Sending encoded SMS data (length=%d):", msg_size);
	LOG_DBG("%s", log_strdup(send_buf));
	LOG_DBG("SMS data encoded: %s", log_strdup(encoded_data_hex_str));
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
	int err = 0;
	static uint8_t concat_msg_id = 1;
	static uint8_t message_ref = 1;

	uint8_t size = 0;
	uint16_t text_size = strlen(text);
	uint8_t encoded[SMS_MAX_DATA_LEN_CHARS];
	uint8_t encoded_data_size_octets = 0;
	uint8_t encoded_data_size_septets = 0;
	memset(encoded, 0, SMS_MAX_DATA_LEN_CHARS);

	const uint8_t udh[] = {0x05, 0x00, 0x03, 0x01, 0x01, 0x01, 0x00};
	char ud[SMS_MAX_DATA_LEN_CHARS];
	memcpy(ud, udh, sizeof(udh));

	uint16_t text_encoded_size = 0;
	uint8_t concat_seq_number = 0;
	char *text_index = text;
	char *send_bufs[CONFIG_SMS_SEND_CONCATENATED_MSG_MAX_CNT] = {0};
	uint16_t send_bufs_ud_pos[CONFIG_SMS_SEND_CONCATENATED_MSG_MAX_CNT] = {0};

	while (text_encoded_size < text_size) {
		if (concat_seq_number >= CONFIG_SMS_SEND_CONCATENATED_MSG_MAX_CNT) {
			LOG_WRN("Sent data cannot fit into maximum number of concatenated messages (%d)",
				CONFIG_SMS_SEND_CONCATENATED_MSG_MAX_CNT);
			err = -E2BIG;
			goto error;
		}

		send_bufs[concat_seq_number] = k_malloc(SMS_AT_CMGS_BUF_SIZE);
		if (send_bufs[concat_seq_number] == NULL) {
			LOG_ERR("Unable to send concatenated message due to no memory");
			err = -ENOMEM;
			goto error;
		}

		uint16_t text_part_size = MIN(strlen(text_index), 153);
		memcpy(ud + SMS_UDH_CONCAT_SIZE_SEPTETS, text_index, text_part_size);
		
		size = string_conversion_ascii_to_gsm7bit(ud, sizeof(udh) + text_part_size,
			encoded, &encoded_data_size_octets, &encoded_data_size_septets, true);

		text_encoded_size += size - sizeof(udh);
		text_index += size - sizeof(udh);

		sms_submit_encode(
			send_bufs[concat_seq_number],
			encoded_number,
			encoded_number_size,
			encoded_number_size_octets,
			encoded + SMS_UDH_CONCAT_SIZE_OCTETS,
			encoded_data_size_octets - SMS_UDH_CONCAT_SIZE_OCTETS,
			encoded_data_size_septets,
			message_ref,
			SMS_UDH_CONCAT_SIZE_OCTETS,
			&send_bufs_ud_pos[concat_seq_number]);

		message_ref++;
		concat_seq_number++;
	}

	for (int i = 0; i < concat_seq_number; i++) {
		char udh_str[13] = {0};
		sprintf(udh_str, "050003%02X%02X%02X", concat_msg_id, concat_seq_number, i + 1);

		memcpy(send_bufs[i] + send_bufs_ud_pos[i], udh_str, strlen(udh_str));

		enum at_cmd_state state = 0;
		err = at_cmd_write(send_bufs[i], at_response_str, sizeof(at_response_str), &state);
		if (err) {
			LOG_ERR("at_cmd_write returned state=%d, err=%d", state, err);
			goto error;
		}
		LOG_DBG("AT Response:%s", log_strdup(at_response_str));

		/* Just looping without threading seems to work fine and we don't need to wait
		 * for CDS response. Otherwise we would need to send 2nd message from work queue
		 * and store a lot of state information. */
	}

error:
	for (int i = 0; i < concat_seq_number; i++) {
		k_free(send_bufs[i]);
	}
	concat_msg_id++;
	return err;
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

	LOG_DBG("Sending SMS to number=%s, text='%s'", log_strdup(number), log_strdup(text));

	/* Encode number into format required in SMS header */
	uint8_t encoded_number[SMS_MAX_ADDRESS_LEN_CHARS + 1];
	uint8_t encoded_number_size = strlen(number);
	uint8_t encoded_number_size_octets = SMS_MAX_ADDRESS_LEN_CHARS + 1;
	ret = sms_submit_encode_number(number, &encoded_number_size,
		encoded_number, &encoded_number_size_octets);
	if (ret) {
		return ret;
	}

	/* Encode text into GSM 7bit encoding */
	uint8_t size = 0;
	uint16_t text_size = strlen(text);
	uint8_t encoded[SMS_MAX_DATA_LEN_CHARS];
	uint8_t encoded_data_size_octets = 0;
	uint8_t encoded_data_size_septets = 0;
	memset(encoded, 0, SMS_MAX_DATA_LEN_CHARS);

	size = string_conversion_ascii_to_gsm7bit(
		text, text_size, encoded, &encoded_data_size_octets, &encoded_data_size_septets, true);

	/* Check if this should be sent as concatenated SMS */
	if (size < text_size) {
		LOG_DBG("Entire message doesn't fit into single SMS message. Using concatenated SMS.");
		return sms_submit_send_concat(text, encoded_number,
				encoded_number_size, encoded_number_size_octets);
	}

	char send_buf[SMS_AT_CMGS_BUF_SIZE];
	sms_submit_encode(
		send_buf,
		encoded_number,
		encoded_number_size,
		encoded_number_size_octets,
		encoded,
		encoded_data_size_octets,
		encoded_data_size_septets,
		0,
		0,
		NULL);

	enum at_cmd_state state = 0;
	ret = at_cmd_write(send_buf, at_response_str,
		sizeof(at_response_str), &state);
	if (ret) {
		LOG_ERR("at_cmd_write returned state=%d, err=%d", state, ret);
		return ret;
	}
	LOG_DBG("AT Response:%s", log_strdup(at_response_str));
	return 0;
}
