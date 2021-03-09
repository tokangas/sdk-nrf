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

LOG_MODULE_DECLARE(sms, CONFIG_SMS_LOG_LEVEL);

#define AT_CMT_PARAMS_COUNT 4
#define AT_CDS_PARAMS_COUNT 3

/** @brief Start of AT notification for incoming SMS. */
#define AT_SMS_NOTIFICATION "+CMT:"
#define AT_SMS_NOTIFICATION_LEN (sizeof(AT_SMS_NOTIFICATION) - 1)

#define AT_SMS_NOTIFICATION_DS "+CDS:"
#define AT_SMS_NOTIFICATION_DS_LEN (sizeof(AT_SMS_NOTIFICATION_DS) - 1)


/** @brief Save the SMS notification parameters. */
static int sms_cmt_at_parse(const char *const buf, struct sms_data *cmt_rsp, struct at_param_list *resp_list)
{
	int err = at_parser_max_params_from_str(buf, NULL, resp_list,
						AT_CMT_PARAMS_COUNT);
	if (err != 0) {
		LOG_ERR("Unable to parse CMT notification, err=%d", err);
		return err;
	}

	/* Save alpha as a null-terminated String. */
	size_t alpha_len;
	(void)at_params_size_get(resp_list, 1, &alpha_len);

	cmt_rsp->alpha = k_malloc(alpha_len + 1);
	if (cmt_rsp->alpha == NULL) {
		LOG_ERR("Unable to parse CMT notification due to no memory");
		return -ENOMEM;
	}
	(void)at_params_string_get(resp_list, 1, cmt_rsp->alpha, &alpha_len);
	cmt_rsp->alpha[alpha_len] = '\0';

	LOG_DBG("Number: %s", log_strdup(cmt_rsp->alpha));

	/* Length field saved as number. */
	(void)at_params_short_get(resp_list, 2, &cmt_rsp->length);

	LOG_DBG("PDU length: %d", cmt_rsp->length);

	/* Save PDU as a null-terminated String. */
	size_t pdu_len;
	(void)at_params_size_get(resp_list, 3, &pdu_len);
	LOG_DBG("PDU string length: %d", pdu_len);
	cmt_rsp->pdu = k_malloc(pdu_len + 1);
	if (cmt_rsp->pdu == NULL) {
		LOG_ERR("Unable to parse CMT notification due to no memory");
		return -ENOMEM;
	}

	(void)at_params_string_get(resp_list, 3, cmt_rsp->pdu, &pdu_len);
	cmt_rsp->pdu[pdu_len] = '\0';

	LOG_DBG("PDU: %s", log_strdup(cmt_rsp->pdu));

	return 0;
}

/** @brief Save the SMS status report parameters. */
static int sms_cds_at_parse(const char *const buf, struct sms_data *cmt_rsp, struct at_param_list *resp_list)
{
	int err = at_parser_max_params_from_str(buf, NULL, resp_list,
						AT_CDS_PARAMS_COUNT);
	if (err != 0) {
		LOG_ERR("Unable to parse CDS notification, err=%d", err);
		return err;
	}

	/* Length field saved as number. */
	(void)at_params_short_get(resp_list, 1, &cmt_rsp->length);

	/* Save PDU as a null-terminated string. */
	size_t pdu_len;
	(void)at_params_size_get(resp_list, 2, &pdu_len);
	cmt_rsp->pdu = k_malloc(pdu_len + 1);
	if (cmt_rsp->pdu == NULL) {
		LOG_ERR("Unable to parse CDS notification due to no memory");
		return -ENOMEM;
	}

	(void)at_params_string_get(resp_list, 2, cmt_rsp->pdu, &pdu_len);
	cmt_rsp->pdu[pdu_len] = '\0';

	return 0;
}

/** @brief Handler for AT responses and unsolicited events. */
int sms_at_parse(const char *at_notif, struct sms_data *cmt_rsp, struct at_param_list *resp_list)
{
	int err;

	__ASSERT(at_notif != NULL, "at_notif is NULL");
	__ASSERT(cmt_rsp != NULL, "cmt_rsp is NULL");
	__ASSERT(cmt_rsp->alpha == NULL, "cmt_rsp->alpha is not NULL");
	__ASSERT(cmt_rsp->pdu == NULL, "cmt_rsp->pdu is not NULL");
	__ASSERT(cmt_rsp->header == NULL, "cmt_rsp->header is not NULL");
	__ASSERT(resp_list != NULL, "resp_list is NULL");

	if (strncmp(at_notif, AT_SMS_NOTIFICATION,
		AT_SMS_NOTIFICATION_LEN) == 0) {

		cmt_rsp->type = SMS_TYPE_DELIVER;

		/* Extract and save the SMS notification parameters */
		int err = sms_cmt_at_parse(at_notif, cmt_rsp, resp_list);
		if (err) {
			return err;
		}

		cmt_rsp->header = k_malloc(sizeof(struct sms_deliver_header));
		if (cmt_rsp->header == NULL) {
			LOG_ERR("Unable to parse SMS-DELIVER message due to no memory");
			return -ENOMEM;
		}
		err = sms_deliver_pdu_parse(cmt_rsp->pdu, cmt_rsp->header);
		if (err) {
			LOG_ERR("sms_deliver_pdu_parse error: %d\n", err);
			return err;
		}
	} else if (strncmp(at_notif, AT_SMS_NOTIFICATION_DS,
		AT_SMS_NOTIFICATION_DS_LEN) == 0) {

		LOG_DBG("SMS submit report received");
		cmt_rsp->type = SMS_TYPE_SUBMIT_REPORT;

		err = sms_cds_at_parse(at_notif, cmt_rsp, resp_list);
		if (err != 0) {
			LOG_ERR("sms_cds_at_parse error: %d", err);
			return err;
		}
	} else {
		/* Ignore all other notifications */
		return -EINVAL;
	}

	return 0;
}
