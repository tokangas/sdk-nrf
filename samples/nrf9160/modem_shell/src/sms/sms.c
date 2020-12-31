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
	/*
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
	*/
	shell_print(shell_global, "Number: %s", data->alpha);
	/*shell_print(shell_global, "Time:   %02x-%02x-%02x %02x:%02x:%02x",
		sms_header.time.year,
		sms_header.time.month,
		sms_header.time.day,
		sms_header.time.hour,
		sms_header.time.minute,
		sms_header.time.second);*/

	shell_print(shell_global, "Text:   '%s'", data->pdu);

	//parser_delete(&sms_deliver);
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

	ret = sms_send_message(number, text);

	return ret;
}
