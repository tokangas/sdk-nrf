/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
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

#include "sms_submit.h"
#include "sms_deliver.h"
#include "sms_at.h"

LOG_MODULE_REGISTER(sms, CONFIG_SMS_LOG_LEVEL);

#define AT_SMS_PARAMS_COUNT_MAX 6
#define AT_SMS_RESPONSE_MAX_LEN 256

#define AT_CNMI_PARAMS_COUNT 6

/** @brief AT command to check if a client already exist. */
#define AT_SMS_SUBSCRIBER_READ "AT+CNMI?"

/** @brief AT command to register an SMS client. */
#define AT_SMS_SUBSCRIBER_REGISTER "AT+CNMI=3,2,0,1"

/** @brief AT command to unregister an SMS client. */
#define AT_SMS_SUBSCRIBER_UNREGISTER "AT+CNMI=0,0,0,0"

/** @brief AT command to an ACK in PDU mode. */
#define AT_SMS_PDU_ACK "AT+CNMA=1"

static struct k_work sms_ack_work;
static struct at_param_list resp_list;
static char resp[AT_SMS_RESPONSE_MAX_LEN];

/**
 * @brief Indicates that the module has been successfully initialized
 * and registered as an SMS client.
 */
static bool sms_client_registered;

/** @brief SMS event. */
static struct sms_data cmt_rsp = {0};

struct sms_subscriber {
	/* Listener user context. */
	void *ctx;
	/* Listener callback. */
	sms_callback_t listener;
};

/** @brief List of subscribers. */
static struct sms_subscriber subscribers[CONFIG_SMS_SUBSCRIBERS_MAX_CNT];

static void sms_ack(struct k_work *work)
{
	int ret = at_cmd_write(AT_SMS_PDU_ACK, NULL, 0, NULL);

	if (ret != 0) {
		LOG_ERR("Unable to ACK the SMS PDU");
	}
}

/** @brief Handler for AT responses and unsolicited events. */
void sms_at_handler(void *context, const char *at_notif)
{
	ARG_UNUSED(context);

	if (at_notif == NULL) {
		return;
	}

	int err = sms_at_parse(at_notif, &cmt_rsp, &resp_list);
	if (err) {
		return;
	}

	/* Notify all subscribers. */
	LOG_DBG("Valid SMS notification decoded");
	for (size_t i = 0; i < ARRAY_SIZE(subscribers); i++) {
		if (subscribers[i].listener != NULL) {
			subscribers[i].listener(&cmt_rsp, subscribers[i].ctx);
		}
	}

	/* TODO: Free cmp_rsp memory including header, ud, udh*/

	/* Use system work queue to ACK SMS PDU because we cannot
	 * call at_cmd_write from a notification callback.
	 */
	k_work_submit(&sms_ack_work);
}

int sms_init(void)
{
	k_work_init(&sms_ack_work, &sms_ack);

	int ret = at_params_list_init(&resp_list, AT_SMS_PARAMS_COUNT_MAX);
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

static int sms_subscriber_count()
{
	int count = 0;
	for (size_t i = 0; i < ARRAY_SIZE(subscribers); i++) {
		if (subscribers[i].ctx != NULL ||
		    subscribers[i].listener != NULL) {
			count++;
		}
	}
	return count;
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
	/* Don't do anything if there are subscribers */
	int subscribers = sms_subscriber_count();
	if (subscribers > 0) {
		LOG_WRN("Unregistering skipped as there are %d subscriber(s)",
			subscribers);
		return;
	}

	if (sms_client_registered) {
		int ret = at_cmd_write(AT_SMS_SUBSCRIBER_UNREGISTER, resp,
				       sizeof(resp), NULL);
		if (ret) {
			LOG_ERR("Unable to unregister the SMS client, err: %d",
				ret);
			return;
		}
		LOG_INF("SMS client unregistered");

		/* Unregister from AT commands notifications. */
		(void)at_notif_deregister_handler(NULL, sms_at_handler);
	}

	/* Cleanup resources. */
	at_params_list_free(&resp_list);

	if (cmt_rsp.alpha != NULL) {
		k_free(cmt_rsp.alpha);
		cmt_rsp.alpha = NULL;
	}

	if (cmt_rsp.pdu != NULL) {
		k_free(cmt_rsp.pdu);
		cmt_rsp.pdu = NULL;
	}

	if (cmt_rsp.header != NULL) {
		if (cmt_rsp.header->ud != NULL) {
			k_free(cmt_rsp.header->ud);
			cmt_rsp.header->ud = NULL;
		}
		k_free(cmt_rsp.header);
		cmt_rsp.header = NULL;
	}

	sms_client_registered = false;
}

int sms_send(char* number, char* text)
{
	return sms_submit_send(number, text);
}
