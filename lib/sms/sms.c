/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <logging/log.h>
#include <zephyr.h>
#include <stdio.h>
#include <modem/sms.h>
#include <errno.h>
#include <modem/at_cmd.h>
#include <modem/at_cmd_parser.h>
#include <modem/at_params.h>
#include <modem/at_notif.h>

#include "string_conversion.h"
#include "parser.h"
#include "sms_deliver.h"

LOG_MODULE_REGISTER(sms, CONFIG_SMS_LOG_LEVEL);

#define AT_SMS_PARAMS_COUNT_MAX 6
#define AT_SMS_RESPONSE_MAX_LEN 256

#define AT_CNMI_PARAMS_COUNT 6
#define AT_CMT_PARAMS_COUNT 4
#define AT_CDS_PARAMS_COUNT 3

/** @brief AT command to check if a client already exist. */
#define AT_SMS_SUBSCRIBER_READ "AT+CNMI?"

/** @brief AT command to register an SMS client. */
#define AT_SMS_SUBSCRIBER_REGISTER "AT+CNMI=3,2,0,1"

/** @brief AT command to unregister an SMS client. */
#define AT_SMS_SUBSCRIBER_UNREGISTER "AT+CNMI=0,0,0,0"

/** @brief AT command to an ACK in PDU mode. */
#define AT_SMS_PDU_ACK "AT+CNMA=1"

/** @brief Start of AT notification for incoming SMS. */
#define AT_SMS_NOTIFICATION "+CMT:"
#define AT_SMS_NOTIFICATION_LEN (sizeof(AT_SMS_NOTIFICATION) - 1)

#define AT_SMS_NOTIFICATION_DS "+CDS:"
#define AT_SMS_NOTIFICATION_DS_LEN (sizeof(AT_SMS_NOTIFICATION_DS) - 1)

static struct k_work sms_ack_work;
static struct at_param_list resp_list;
static char resp[AT_SMS_RESPONSE_MAX_LEN];

/**
 * @brief Indicates that the module has been successfully initialized
 * and registered as an SMS client.
 */
static bool sms_client_registered;

/** @brief SMS event. */
static struct sms_data cmt_rsp;

struct sms_subscriber {
	/* Listener user context. */
	void *ctx;
	/* Listener callback. */
	sms_callback_t listener;
};

/** @brief List of subscribers. */
static struct sms_subscriber subscribers[CONFIG_SMS_MAX_SUBSCRIBERS_CNT];

/** @brief Save the SMS notification parameters. */
static int sms_cmt_at_parse(const char *const buf, struct sms_data *cmt_rsp)
{
	int err = at_parser_max_params_from_str(buf, NULL, &resp_list,
						AT_CMT_PARAMS_COUNT);
	if (err != 0) {
		LOG_ERR("Unable to parse CMT notification, err=%d", err);
		return err;
	}

	if (cmt_rsp->alpha != NULL) {
		k_free(cmt_rsp->alpha);
	}

	if (cmt_rsp->pdu != NULL) {
		k_free(cmt_rsp->pdu);
	}

	/* Save alpha as a null-terminated String. */
	size_t alpha_len;
	(void)at_params_size_get(&resp_list, 1, &alpha_len);

	cmt_rsp->alpha = k_malloc(alpha_len + 1);
	if (cmt_rsp->alpha == NULL) {
		LOG_ERR("Unable to parse CMT notification due to no memory");
		return -ENOMEM;
	}
	(void)at_params_string_get(&resp_list, 1, cmt_rsp->alpha, &alpha_len);
	cmt_rsp->alpha[alpha_len] = '\0';

	/* Length field saved as number. */
	(void)at_params_short_get(&resp_list, 2, &cmt_rsp->length);

	/* Save PDU as a null-terminated String. */
	size_t pdu_len;
	(void)at_params_size_get(&resp_list, 3, &pdu_len);
	cmt_rsp->pdu = k_malloc(pdu_len + 1);
	if (cmt_rsp->pdu == NULL) {
		LOG_ERR("Unable to parse CMT notification due to no memory");
		return -ENOMEM;
	}

	(void)at_params_string_get(&resp_list, 3, cmt_rsp->pdu, &pdu_len);
	cmt_rsp->pdu[pdu_len] = '\0';

	return 0;
}

static void sms_ack(struct k_work *work)
{
	int ret = at_cmd_write(AT_SMS_PDU_ACK, NULL, 0, NULL);

	if (ret != 0) {
		LOG_ERR("Unable to ACK the SMS PDU");
	}
}

static int sms_cmt_pdu_parse(char *pdu)
{
	/* TODO: This decodes the pdu to the same 'pdu' variable. Need to think if this is OK. */
	struct  parser sms_deliver;
	int     err=0;
	uint8_t payload_size = 0;

	struct sms_deliver_header sms_header;

	if (pdu == NULL) {
		printk("sms_callback with NULL data\n");
	}

	parser_create(&sms_deliver, sms_deliver_get_api());

	err = parser_process_str(&sms_deliver, pdu);

	if(err) {
		printk("Parsing return code: %d\n", err);
		// TODO: Check this when SMS SUBMIT REPORT is handled properly
		//return err;
	}

	payload_size = parser_get_payload(&sms_deliver,
					  pdu,
					  strlen(pdu));
	pdu[payload_size] = '\0';
	parser_get_header(&sms_deliver, &sms_header);

	if(payload_size < 0) {
		printk("Getting sms deliver payload failed: %d\n",
			payload_size);
		// TODO: Check this when SMS SUBMIT REPORT is handled properly
		//return payload_size;
	}

	LOG_INF("Time:   %02x-%02x-%02x %02x:%02x:%02x",
		sms_header.time.year,
		sms_header.time.month,
		sms_header.time.day,
		sms_header.time.hour,
		sms_header.time.minute,
		sms_header.time.second);
	LOG_INF("Text:   '%s'", log_strdup(pdu));

	parser_delete(&sms_deliver);
	return 0;
}


/** @brief Handler for AT responses and unsolicited events. */
void sms_at_handler(void *context, const char *at_notif)
{
	ARG_UNUSED(context);

	if (at_notif == NULL) {
		return;
	}

	if (strncmp(at_notif, AT_SMS_NOTIFICATION,
		AT_SMS_NOTIFICATION_LEN) == 0) {

		cmt_rsp.type = SMS_TYPE_DELIVER;

		/* Extract and save the SMS notification parameters. */
		int valid_notif = sms_cmt_at_parse(at_notif, &cmt_rsp);
		if (valid_notif != 0) {
			return;
		}
		LOG_INF("Number: %s", log_strdup(cmt_rsp.alpha));

		int valid_pdu = sms_cmt_pdu_parse(cmt_rsp.pdu);
		if (valid_pdu != 0) {
			return;
		}

	} else if (strncmp(at_notif, AT_SMS_NOTIFICATION_DS,
		AT_SMS_NOTIFICATION_DS_LEN) == 0) {

		LOG_INF("SMS submit report received");
		cmt_rsp.type = SMS_TYPE_SUBMIT_REPORT;
	} else {
		/* Ignore all other notifications */
		return;
	}

	/* Notify all subscribers. */
	LOG_DBG("Valid SMS notification decoded");
	for (size_t i = 0; i < ARRAY_SIZE(subscribers); i++) {
		if (subscribers[i].listener != NULL) {
			subscribers[i].listener(&cmt_rsp, subscribers[i].ctx);
		}
	}

	/* Use system work queue to ACK SMS PDU because we cannot
	 * call at_cmd_write from a notification callback.
	 */
	k_work_submit(&sms_ack_work);
}

int sms_init(void)
{
	int ret = at_params_list_init(&resp_list, AT_SMS_PARAMS_COUNT_MAX);

	k_work_init(&sms_ack_work, &sms_ack);

	if (ret) {
		LOG_ERR("AT params error, err: %d", ret);
		return ret;
	}

	/* Check if one SMS client has already been registered. */
	ret = at_cmd_write(AT_SMS_SUBSCRIBER_READ, resp, sizeof(resp), NULL);
	if (ret) {
		LOG_ERR("Unable to check if an SMS client exists, err: %d",
			ret);
		return ret;
	}

	ret = at_parser_max_params_from_str(resp, NULL, &resp_list,
					    AT_CNMI_PARAMS_COUNT);
	if (ret) {
		LOG_INF("%s", log_strdup(resp));
		LOG_ERR("Invalid AT response, err: %d", ret);
		return ret;
	}

	/* Check the response format and parameters. */
	for (int i = 1; i < (AT_CNMI_PARAMS_COUNT - 1); i++) {
		int value;

		ret = at_params_int_get(&resp_list, i, &value);
		if (ret) {
			LOG_ERR("Invalid AT response parameters, err: %d", ret);
			return ret;
		}

		/* Parameters 1 to 4 should be 0 if no client is registered. */
		if (value != 0) {
			LOG_ERR("Only one SMS client can be registered");
			return -EBUSY;
		}
	}

	/* Register for AT commands notifications before creating the client. */
	ret = at_notif_register_handler(NULL, sms_at_handler);
	if (ret) {
		LOG_ERR("Cannot register AT notification handler, err: %d",
			ret);
		return ret;
	}

	/* Register this module as an SMS client. */
	ret = at_cmd_write(AT_SMS_SUBSCRIBER_REGISTER, NULL, 0, NULL);
	if (ret) {
		(void)at_notif_deregister_handler(NULL, sms_at_handler);
		LOG_ERR("Unable to register a new SMS client, err: %d", ret);
		return ret;
	}

	/* Clear all observers. */
	for (size_t i = 0; i < ARRAY_SIZE(subscribers); i++) {
		subscribers[i].ctx = NULL;
		subscribers[i].listener = NULL;
	}

	sms_client_registered = true;
	LOG_INF("SMS client successfully registered");
	return 0;
}

int sms_register_listener(sms_callback_t listener, void *context)
{
	if (listener == NULL) {
		return -EINVAL; /* Invalid parameter. */
	}

	/* Search for a free slot to register a new listener. */
	for (size_t i = 0; i < ARRAY_SIZE(subscribers); i++) {
		if (subscribers[i].ctx == NULL &&
		    subscribers[i].listener == NULL) {
			subscribers[i].ctx = context;
			subscribers[i].listener = listener;
			return i;
		}
	}

	/* Too many subscribers. */
	return -ENOMEM;
}

void sms_unregister_listener(int handle)
{
	/* Unregister the listener. */
	if (handle < 0 || handle >= ARRAY_SIZE(subscribers)) {
		/* Invalid handle. Unknown listener. */
		return;
	}

	subscribers[handle].ctx = NULL;
	subscribers[handle].listener = NULL;
}

void sms_uninit(void)
{
	/* Unregister the SMS client if this module was registered as client. */
	if (sms_client_registered) {
		int ret = at_cmd_write(AT_SMS_SUBSCRIBER_UNREGISTER, resp,
				       sizeof(resp), NULL);
		if (ret) {
			LOG_ERR("Unable to unregister the SMS client, err: %d",
				ret);
			return;
		}
		LOG_INF("SMS client unregistered");
	}

	/* Cleanup resources. */
	at_params_list_free(&resp_list);

	if (cmt_rsp.alpha != NULL) {
		k_free(cmt_rsp.alpha);
	}

	if (cmt_rsp.pdu != NULL) {
		k_free(cmt_rsp.pdu);
	}

	/* Unregister from AT commands notifications. */
	(void)at_notif_deregister_handler(NULL, sms_at_handler);

	sms_client_registered = false;
}

int sms_send_message(char* number, char* text)
{
	char at_response_str[CONFIG_AT_CMD_RESPONSE_MAX_LEN + 1];
	int ret;

	if (number == NULL) {
		LOG_ERR("SMS number not given");
		return -EINVAL;
	}

	LOG_INF("Sending SMS to number=%s, text='%s'",
		log_strdup(number), log_strdup(text));

	uint8_t size = 0;
	uint8_t encoded[160];
	uint8_t encoded_data_hex_str[400];
	uint8_t encoded_size = 0;
	memset(encoded, 0, 160);
	memset(encoded_data_hex_str, 0, 400);

	size = string_conversion_ascii_to_gsm7bit(
		text, strlen(text), encoded, &encoded_size, NULL, true);

	uint8_t hex_str_number = 0;
	for (int i = 0; i < encoded_size; i++) {
		//printf("%02X, %02d\n", encoded[i], encoded[i]);
		sprintf(encoded_data_hex_str + hex_str_number,
			"%02X", encoded[i]);
		hex_str_number += 2;
	}

	uint8_t encoded_number[30];
	uint8_t encoded_number_size = strlen(number);

	if (encoded_number_size == 0) {
		LOG_ERR("SMS number not given");
		return -EINVAL;
	}

	if (number[0] == '+') {
		/* If first character of the number is plus, just ignore it.
		   We are using international number format always anyway */
		number += 1;
		encoded_number_size = strlen(number);
		LOG_INF("Ignoring leading '+' in the number");
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
	sprintf(send_data, "AT+CMGS=%d\r003100%02X91%s0000FF%02X%s\x1a",
		msg_size, encoded_number_size, encoded_number,
		size, encoded_data_hex_str);
	LOG_INF("Sending encoded SMS data (length=%d):", msg_size);
	LOG_INF("%s", log_strdup(send_data));

	ret = at_cmd_write(send_data, at_response_str,
		sizeof(at_response_str), NULL);
	if (ret) {
		LOG_ERR("at_cmd_write returned err: %2d", ret);
		return ret;
	}
	LOG_DBG("AT Response:%s", log_strdup(at_response_str));
	return 0;
}