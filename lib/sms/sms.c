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

#include "string_conversion.h"
#include "parser.h"
#include "sms_submit.h"
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
static struct sms_data cmt_rsp = {0};

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
		cmt_rsp->alpha = NULL;
	}

	if (cmt_rsp->pdu != NULL) {
		k_free(cmt_rsp->pdu);
		cmt_rsp->pdu = NULL;
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

	LOG_DBG("Number: %s", log_strdup(cmt_rsp->alpha));

	/* Length field saved as number. */
	(void)at_params_short_get(&resp_list, 2, &cmt_rsp->length);

	LOG_DBG("PDU length: %d", cmt_rsp->length);

	/* Save PDU as a null-terminated String. */
	size_t pdu_len;
	(void)at_params_size_get(&resp_list, 3, &pdu_len);
	LOG_DBG("PDU string length: %d", pdu_len);
	cmt_rsp->pdu = k_malloc(pdu_len + 1);
	if (cmt_rsp->pdu == NULL) {
		LOG_ERR("Unable to parse CMT notification due to no memory");
		return -ENOMEM;
	}

	(void)at_params_string_get(&resp_list, 3, cmt_rsp->pdu, &pdu_len);
	cmt_rsp->pdu[pdu_len] = '\0';

	LOG_DBG("PDU: %s", log_strdup(cmt_rsp->pdu));

	return 0;
}

/** @brief Save the SMS status report parameters. */
static int sms_cds_at_parse(const char *const buf, struct sms_data *cmt_rsp)
{
	int err = at_parser_max_params_from_str(buf, NULL, &resp_list,
						AT_CDS_PARAMS_COUNT);
	if (err != 0) {
		LOG_ERR("Unable to parse CDS notification, err=%d", err);
		return err;
	}

	if (cmt_rsp->alpha != NULL) {
		k_free(cmt_rsp->alpha);
		cmt_rsp->alpha = NULL;
	}

	if (cmt_rsp->pdu != NULL) {
		k_free(cmt_rsp->pdu);
		cmt_rsp->pdu = NULL;
	}

	/* Length field saved as number. */
	(void)at_params_short_get(&resp_list, 1, &cmt_rsp->length);

	/* Save PDU as a null-terminated string. */
	size_t pdu_len;
	(void)at_params_size_get(&resp_list, 2, &pdu_len);
	cmt_rsp->pdu = k_malloc(pdu_len + 1);
	if (cmt_rsp->pdu == NULL) {
		LOG_ERR("Unable to parse CDS notification due to no memory");
		return -ENOMEM;
	}

	(void)at_params_string_get(&resp_list, 2, cmt_rsp->pdu, &pdu_len);
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

/** 
 * @brief Decode received SMS message, i.e., SMS-DELIVER message as specified
 * in 3GPP TS 23.040 Section 9.2.2.1.
 * 
 * @param pdu SMS-DELIVER PDU.
 * @param out SMS message decoded into a structure.
 * 
 * @retval -EINVAL Invalid parameter.
 * @retval -ENOMEM No memory to register new observers.
 * @return Zero on success, otherwise error code.
 */
int sms_deliver_pdu_parse(char *pdu, struct sms_deliver_header *out)
{
	struct  parser sms_deliver;
	int     err=0;

	__ASSERT(pdu != NULL, "Parameter 'pdu' cannot be NULL.");
	__ASSERT(out != NULL, "Parameter 'out' cannot be NULL.");

	memset(out, 0, sizeof(struct sms_deliver_header));

	parser_create(&sms_deliver, sms_deliver_get_api());

	err = parser_process_str(&sms_deliver, pdu);

	if (err) {
		LOG_ERR("Parsing error (%d) in decoding SMS-DELIVER message due to no memory", err);
		return err;
	}

	parser_get_header(&sms_deliver, out);

	out->ud = k_calloc(1, out->ud_len + 1);
	if (out->ud == NULL) {
		LOG_ERR("Unable to parse SMS-DELIVER message due to no memory");
		return -ENOMEM;
	}

	out->data_len = parser_get_payload(&sms_deliver,
					  out->ud,
					  out->ud_len);

	if (out->data_len < 0) {
		LOG_ERR("Getting sms deliver payload failed: %d\n",
			out->data_len);
		return out->data_len;
	}

	LOG_DBG("Time:   %02x-%02x-%02x %02x:%02x:%02x",
		out->time.year,
		out->time.month,
		out->time.day,
		out->time.hour,
		out->time.minute,
		out->time.second);
	LOG_DBG("Text:   '%s'", log_strdup(out->ud));

	LOG_DBG("Length: %d", out->data_len);

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

		/* Parse SMS-DELIVER PDU */
		if (cmt_rsp.header != NULL) {
			if (cmt_rsp.header->ud != NULL) {
				k_free(cmt_rsp.header->ud);
				cmt_rsp.header->ud = NULL;
			}
			k_free(cmt_rsp.header);
			cmt_rsp.header = NULL;
		}
		cmt_rsp.header = k_malloc(sizeof(struct sms_deliver_header));
		if (cmt_rsp.header == NULL) {
			LOG_ERR("Unable to parse SMS-DELIVER message due to no memory");
			return;
		}
		int err = sms_deliver_pdu_parse(cmt_rsp.pdu, cmt_rsp.header);
		if (err) {
			LOG_ERR("sms_deliver_pdu_parse error: %d\n", err);
			return;
		}
	} else if (strncmp(at_notif, AT_SMS_NOTIFICATION_DS,
		AT_SMS_NOTIFICATION_DS_LEN) == 0) {

		LOG_DBG("SMS submit report received");
		cmt_rsp.type = SMS_TYPE_SUBMIT_REPORT;

		/* Parse SMS-DELIVER PDU */
		if (cmt_rsp.header != NULL) {
			if (cmt_rsp.header->ud != NULL) {
				k_free(cmt_rsp.header->ud);
				cmt_rsp.header->ud = NULL;
			}
			k_free(cmt_rsp.header);
			cmt_rsp.header = NULL;
		}

		int valid_notif = sms_cds_at_parse(at_notif, &cmt_rsp);
		if (valid_notif != 0) {
			LOG_ERR("sms_cds_at_parse");
			return;
		}
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
