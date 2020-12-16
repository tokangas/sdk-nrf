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
#include "utils/freebsd-getopt/getopt.h"

#define PAYLOAD_BUF_SIZE 160

void sms_callback(struct sms_data *const data, void *context)
{
	// Alpha is phone number

	// TODO: Decode length and PDU
	printf("SMS Received: %s\nlength=%d: %s\n", data->alpha, data->length, data->pdu);

	struct  parser sms_deliver;

	int     err=0;
	char    deliver_data[PAYLOAD_BUF_SIZE];
	uint8_t payload_size = 0;

	struct sms_deliver_header sms_header;

	parser_create(&sms_deliver, sms_deliver_get_api());

	err = parser_process_str(&sms_deliver, data->pdu);

	if(err) {
		printk("Parsing return code: %d\n", err);
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
		//return payload_size;
	}

	printk("SMS time, day:%02x month:%02x year:%02x  %02x:%02x:%02x \n",
		sms_header.time.day,
		sms_header.time.month,
		sms_header.time.year,
		sms_header.time.hour,
		sms_header.time.minute,
		sms_header.time.second);
	/*
	printk("SMS deliver message data length: %d\n", payload_size);
	printk("SMS deliver message data payload: ");

	for(int i=0;i<payload_size;++i) {
		printk("%02x", deliver_data[i]);
	}

	printk("\n");*/
	printk("Received length=%d, data='%s'\n", payload_size, deliver_data);

	parser_delete(&sms_deliver);
}

static int initialize()
{
	int ret;
	static bool initialized = false;

	if (initialized) {
		return 0;
	}

	ret = sms_init();
	if (ret) {
		printf("sms_init returned err: %d\n", ret);
		return ret;
	}
	ret = sms_register_listener(sms_callback, NULL);
	if (ret) {
		printf("sms_register_listener returned err: %d\n", ret);
		return ret;
	}

	initialized = true;
	return 0;
}

int sms_send(char* number, char* data)
{
	char at_response_str[CONFIG_AT_CMD_RESPONSE_MAX_LEN + 1];
	int ret;

	printf("Sending SMS to number=%s, data(%d)=%s\n", number, strlen(data), data);

	ret = initialize();
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

	size = string_conversion_ascii_to_gsm7bit(data, strlen(data), encoded, &encoded_size, NULL, true);

	uint8_t hex_str_number = 0;
	for (int i = 0; i < encoded_size; i++) {
		//printf("%02X, %02d\n", encoded[i], encoded[i]);
		sprintf(encoded_data_hex_str + hex_str_number, "%02X", encoded[i]);
		hex_str_number += 2;
	}

	//printf("string_conversion_ascii_to_gsm7bit: %d, encoded_size=%d, encoded_data_hex_str=%s\n", size, encoded_size, encoded_data_hex_str);

	// TODO: Remove leading +, -, etc. sign
	uint8_t encoded_number[30];
	uint8_t encoded_number_size = strlen(number);
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

	//printf("Number encoded: encoded_number_size=%d number=%s, encoded_number=%s\n", encoded_number_size, number, encoded_number);

	char send_data[500];
	memset(send_data, 0, 500);

	int msg_size = 2 + 1 + 1 + (encoded_number_size / 2) + 3 + 1 + encoded_size;
	sprintf(send_data, "AT+CMGS=%d\r003100%02X91%s0000FF%02X%s\x1a", msg_size, encoded_number_size, encoded_number, size, encoded_data_hex_str);
	printf("%s:send_data (msg_size=%d)\n", send_data, msg_size);

	ret = at_cmd_write(send_data, at_response_str, sizeof(at_response_str), NULL);
	if (ret) {
		printf("at_cmd_write returned err: %2d\n", ret);
		return ret;
	}
	printf("\nAT Response:%s\n", at_response_str);

	return 0;
}
