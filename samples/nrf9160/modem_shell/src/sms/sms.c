/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <shell/shell.h>
#include <assert.h>
#include <strings.h>
#include <stdio.h>

#include <modem/at_cmd.h>
#include <modem/at_cmd_parser.h>
#include <modem/at_params.h>
#include <modem/sms.h>

#include "sms.h"
#include "string_conversion.h"
#include "parser.h"
#include "sms_deliver.h"
#include "fta_defines.h"

#define PAYLOAD_BUF_SIZE 160
#define SMS_HANDLE_NONE -1

extern const struct shell* shell_global;
static int sms_handle = SMS_HANDLE_NONE;

void sms_callback(struct sms_data *const data, void *context)
{
	if (data == NULL) {
		printk("sms_callback with NULL data\n");
	}

	if (data->type == SMS_TYPE_SUBMIT_REPORT) {
		/* TODO: Check whether we should parse SMS-SUBMIT-REPORT more carefully */
		shell_print(shell_global, "SMS submit report received");
		return;
	}

	// Alpha is phone number
	shell_print(shell_global, "SMS received from number=%s with data (length=%d):", data->alpha, data->length);
	shell_print(shell_global, "%s", data->pdu);

	struct  parser sms_deliver;

	int     err=0;
	char    deliver_data[PAYLOAD_BUF_SIZE];
	uint8_t payload_size = 0;

	struct sms_deliver_header sms_header;

	parser_create(&sms_deliver, sms_deliver_get_api());

	err = parser_process_str(&sms_deliver, data->pdu);

	if(err) {
		printk("Parsing return code: %d\n", err);
		// TODO: Check this when SMS SUBMIT REPORT is handled properly
		//return err;
	}

	payload_size = parser_get_payload(&sms_deliver,
					  deliver_data,
					  PAYLOAD_BUF_SIZE);
	deliver_data[payload_size] = '\0';
	parser_get_header(&sms_deliver, &sms_header);

	if(payload_size < 0) {
		printk("Getting sms deliver payload failed: %d\n",
			payload_size);
		// TODO: Check this when SMS SUBMIT REPORT is handled properly
		//return payload_size;
	}

	shell_print(shell_global, "Number: %s", data->alpha);
	shell_print(shell_global, "Time:   %02x-%02x-%02x %02x:%02x:%02x",
		sms_header.time.year,
		sms_header.time.month,
		sms_header.time.day,
		sms_header.time.hour,
		sms_header.time.minute,
		sms_header.time.second);

	shell_print(shell_global, "Text:   '%s'", deliver_data);

	parser_delete(&sms_deliver);
}

int sms_register()
{
	int ret;

	if (sms_handle != SMS_HANDLE_NONE) {
		return 0;
	}

	ret = sms_init();
	if (ret) {
		printf("sms_init returned err: %d\n", ret);
		return ret;
	}
	int handle = sms_register_listener(sms_callback, NULL);
	if (handle) {
		printf("sms_register_listener returned err: %d\n", handle);
		return handle;
	}

	sms_handle = handle;
	return 0;
}

int sms_unregister()
{
	sms_handle = SMS_HANDLE_NONE;

	sms_unregister_listener(sms_handle);
	sms_uninit();

	return 0;
}

int sms_send(char* number, char* text)
{
	char at_response_str[CONFIG_AT_CMD_RESPONSE_MAX_LEN + 1];
	int ret;

	if (number == NULL) {
		shell_error(shell_global, "SMS number not given\n");
		return -EINVAL;
	}

	shell_print(shell_global, "Sending SMS to number=%s, text='%s'", number, text);

	ret = sms_register();
	if (ret != 0) {
		return ret;
	}

	// SEND MESSAGE
	uint8_t size = 0;
	uint8_t encoded[160];
	uint8_t encoded_data_hex_str[400];
	uint8_t encoded_size = 0;
	memset(encoded, 0, 160);
	memset(encoded_data_hex_str, 0, 400);

	size = string_conversion_ascii_to_gsm7bit(text, strlen(text), encoded, &encoded_size, NULL, true);

	uint8_t hex_str_number = 0;
	for (int i = 0; i < encoded_size; i++) {
		//printf("%02X, %02d\n", encoded[i], encoded[i]);
		sprintf(encoded_data_hex_str + hex_str_number, "%02X", encoded[i]);
		hex_str_number += 2;
	}

	uint8_t encoded_number[30];
	uint8_t encoded_number_size = strlen(number);

	if (encoded_number_size == 0) {
		shell_error(shell_global, "SMS number not given\n");
		return -EINVAL;
	}

	if (number[0] == '+') {
		/* If first character of the number is plus, just ignore it.
		   We are using international number format always anyway */
		number += 1;
		encoded_number_size = strlen(number);
		printf("Ignoring leading '+' in the number. Remaining number=%s\n", number);
	}

	memset(encoded_number, 0, 30);
	memcpy(encoded_number, number, encoded_number_size);

	for (int i = 0; i < encoded_number_size; i++) {
		if (!(i%2)) {
			if (i+1 < encoded_number_size) {
				char first = encoded_number[i];
				char second = encoded_number[i+1];
				encoded_number[i] = second;
				encoded_number[i+1] = first;
			} else {
				encoded_number[i+1] = encoded_number[i];
				encoded_number[i] = 'F';
			}
		}
	}

	char send_data[500];
	memset(send_data, 0, 500);

	int msg_size = 2 + 1 + 1 + (encoded_number_size / 2) + 3 + 1 + encoded_size;
	sprintf(send_data, "AT+CMGS=%d\r003100%02X91%s0000FF%02X%s\x1a", msg_size, encoded_number_size, encoded_number, size, encoded_data_hex_str);
	shell_print(shell_global, "Sending encoded SMS data (length=%d):", msg_size);
	shell_print(shell_global, "%s", send_data);

	ret = at_cmd_write(send_data, at_response_str, sizeof(at_response_str), NULL);
	if (ret) {
		printf("at_cmd_write returned err: %2d\n", ret);
		return ret;
	}
	//printf("\nAT Response:%s\n", at_response_str);

	return 0;
}
