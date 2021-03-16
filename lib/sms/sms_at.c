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
static int sms_cmt_at_parse(const char *const buf, char *pdu, struct at_param_list *resp_list)
{
	int err = at_parser_max_params_from_str(buf, NULL, resp_list,
						AT_CMT_PARAMS_COUNT);
	if (err != 0) {
		LOG_ERR("Unable to parse CMT notification, err=%d", err);
		return err;
	}

	/* TODO: Handle response length better. This function could be inlined to caller. */
	size_t pdu_len = CONFIG_AT_CMD_RESPONSE_MAX_LEN;
	(void)at_params_string_get(resp_list, 3, pdu, &pdu_len);
	pdu[pdu_len] = '\0';

	LOG_DBG("PDU: %s", log_strdup(pdu));

	return 0;
}

/** @brief Save the SMS status report parameters. */
static int sms_cds_at_parse(const char *const buf, char *pdu, struct at_param_list *resp_list)
{
	int err = at_parser_max_params_from_str(buf, NULL, resp_list,
						AT_CDS_PARAMS_COUNT);
	if (err != 0) {
		LOG_ERR("Unable to parse CDS notification, err=%d", err);
		return err;
	}

	size_t pdu_len = CONFIG_AT_CMD_RESPONSE_MAX_LEN;
	(void)at_params_string_get(resp_list, 2, pdu, &pdu_len);
	pdu[pdu_len] = '\0';

	return 0;
}

/** @brief Handler for AT responses and unsolicited events. */
int sms_at_parse(const char *at_notif, struct sms_data *cmt_rsp, struct at_param_list *resp_list)
{
	char pdu[1024 + 1];
	int err;

	__ASSERT(at_notif != NULL, "at_notif is NULL");
	__ASSERT(cmt_rsp != NULL, "cmt_rsp is NULL");
	__ASSERT(resp_list != NULL, "resp_list is NULL");

	if (strncmp(at_notif, AT_SMS_NOTIFICATION,
		AT_SMS_NOTIFICATION_LEN) == 0) {

		cmt_rsp->type = SMS_TYPE_DELIVER;

		/* Extract and save the SMS notification parameters */
		int err = sms_cmt_at_parse(at_notif, pdu, resp_list);
		if (err) {
			return err;
		}

		err = sms_deliver_pdu_parse(pdu, cmt_rsp);
		if (err) {
			LOG_ERR("sms_deliver_pdu_parse error: %d\n", err);
			return err;
		}
	} else if (strncmp(at_notif, AT_SMS_NOTIFICATION_DS,
		AT_SMS_NOTIFICATION_DS_LEN) == 0) {

		LOG_DBG("SMS submit report received");
		cmt_rsp->type = SMS_TYPE_SUBMIT_REPORT;

		err = sms_cds_at_parse(at_notif, pdu, resp_list);
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
