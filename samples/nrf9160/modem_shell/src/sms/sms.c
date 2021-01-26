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
static int sms_recv_counter = 0;


static void sms_callback(struct sms_data *const data, void *context)
{
	struct sms_deliver_header sms_header;

	if (data == NULL) {
		printk("sms_callback with NULL data\n");
	}

	if (data->type == SMS_TYPE_SUBMIT_REPORT) {
		/* TODO: Check whether we should parse SMS-SUBMIT-REPORT more carefully */
		shell_print(shell_global, "SMS submit report received");
		return;
	}

	int err = sms_get_header(data, &sms_header);
	if (err) {
		printf("sms_get_header returned err: %d\n", err);
		return;
	}

	shell_print(shell_global, "Number: %s", data->alpha);
	shell_print(shell_global, "Time:   %02x-%02x-%02x %02x:%02x:%02x",
		sms_header.time.year,
		sms_header.time.month,
		sms_header.time.day,
		sms_header.time.hour,
		sms_header.time.minute,
		sms_header.time.second);

	shell_print(shell_global, "Text:   '%s'", sms_header.ud);
	shell_print(shell_global, "Length: %d", sms_header.ud_len);
	shell_print(shell_global, "PDU:    %s", data->pdu);

	if (sms_header.app_port.present) {
		shell_print(shell_global,
			"Application port addressing scheme: dest_port=%d, src_port=%d",
			sms_header.app_port.dest_port,
			sms_header.app_port.src_port);
	}
	if (sms_header.concatenated.present) {
		shell_print(shell_global,
			"Concatenated short messages: ref_number=%d, msg %d/%d",
			sms_header.concatenated.ref_number,
			sms_header.concatenated.seq_number,
			sms_header.concatenated.total_msgs);
	}

	/* TODO: Handle memory in a better way */
	k_free(sms_header.ud);

	sms_recv_counter++;
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

/* Function name is not sms_send() because it's reserved by SMS library. */
int sms_send_msg(char* number, char* text)
{
	int ret;

	if (number == NULL || strlen(number) == 0) {
		shell_error(shell_global, "Number not given");
		return -EINVAL;
	}
	if (text == NULL || strlen(text) == 0) {
		shell_error(shell_global, "Text not given");
		return -EINVAL;
	}

	shell_print(shell_global, "Sending SMS to number=%s, text='%s'", number, text);

	ret = sms_register();
	if (ret != 0) {
		return ret;
	}

	ret = sms_send(number, text);

	return ret;
}

int sms_recv(bool arg_receive_start)
{
	if (arg_receive_start) {
		sms_recv_counter = 0;
		shell_print(shell_global, "SMS receive counter set to zero");
	} else {
		shell_print(shell_global, "SMS receive counter = %d",
			sms_recv_counter);
	}

	return 0;
}
