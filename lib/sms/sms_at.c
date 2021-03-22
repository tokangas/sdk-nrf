/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
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
/* SMS PDU is a bit below 180 bytes which means 360 two character long
 * hexadecimal numbers. In addition CMT response has alpha and length so
 * reserving safely a bit over maximum. */
#define AT_CMT_PDU_MAX_LEN 512
#define AT_CDS_PARAMS_COUNT 3

/** @brief Start of AT notification for incoming SMS. */
#define AT_SMS_NOTIFICATION "+CMT:"
#define AT_SMS_NOTIFICATION_LEN (sizeof(AT_SMS_NOTIFICATION) - 1)

/** @brief Start of AT notification for incoming SMS status report. */
#define AT_SMS_NOTIFICATION_DS "+CDS:"
#define AT_SMS_NOTIFICATION_DS_LEN (sizeof(AT_SMS_NOTIFICATION_DS) - 1)


/* Parse 'CMT' notification with the following format:
 *   +CMT: <alpha>,<length><CR><LF><pdu>
 * For example:
 *   +CMT:""555272744"",4<CR><LF>DEADBEEF"
 * 
 * @param[in] buf 'CDS' notification buffer.
 * @param[out] pdu Output buffer where PDU is copied.
 * @param[in] pdu_len Length of the output buffer.
 * @param[in] temp_resp_list Response list used by AT parser library. This is
 *                 readily initialized by caller and is passed here to
 *                 avoid using another instance of the list.
 * @return Zero on success and negative value in error cases.
 */
static int sms_cmt_at_parse(const char *const buf, char *pdu, size_t pdu_len,
	struct at_param_list *temp_resp_list)
{
	int err = at_parser_max_params_from_str(buf, NULL, temp_resp_list,
						AT_CMT_PARAMS_COUNT);
	if (err != 0) {
		LOG_ERR("Unable to parse CMT notification, err=%d", err);
		return err;
	}

	(void)at_params_string_get(temp_resp_list, 3, pdu, &pdu_len);
	pdu[pdu_len] = '\0';

	LOG_DBG("PDU: %s", log_strdup(pdu));

	return 0;
}

/* Parse 'CDS' notification with the following format:
 *   +CDS: <length><CR><LF><pdu>
 * For example:
 *   +CDS:4<CR><LF>DEADBEEF"
 * 
 * @param[in] buf 'CDS' notification buffer.
 * @param[out] pdu Output buffer where PDU is copied.
 * @param[in] pdu_len Length of the output buffer.
 * @param[in] temp_resp_list Response list used by AT parser library. This is
 *                 readily initialized by caller and is passed here to
 *                 avoid using another instance of the list.
 * @return Zero on success and negative value in error cases.
 */
static int sms_cds_at_parse(const char *const buf, char *pdu, size_t pdu_len,
	struct at_param_list *temp_resp_list)
{
	int err = at_parser_max_params_from_str(buf, NULL, temp_resp_list,
						AT_CDS_PARAMS_COUNT);
	if (err != 0) {
		LOG_ERR("Unable to parse CDS notification, err=%d", err);
		return err;
	}

	(void)at_params_string_get(temp_resp_list, 2, pdu, &pdu_len);
	pdu[pdu_len] = '\0';

	return 0;
}

/* Parse AT notifications finding relevant notifications for SMS and
 * dropping the rest.
 * 
 * @param at_notif[in] AT notication string.
 * @param sms_data_info[out] Parsed output data.
 * @param temp_resp_list[in] Response list used by AT parser library. This is
 *                 readily initialized by caller and is passed here to
 *                 avoid using another instance of the list.
 * @return Zero on success and negative value in error cases.
 */
int sms_at_parse(const char *at_notif, struct sms_data *sms_data_info,
	struct at_param_list *temp_resp_list)
{
	char pdu[AT_CMT_PDU_MAX_LEN];
	size_t pdu_len = sizeof(pdu) - 1; /* -1 so there is space for NUL */
	int err;

	__ASSERT(at_notif != NULL, "at_notif is NULL");
	__ASSERT(sms_data_info != NULL, "sms_data_info is NULL");
	__ASSERT(temp_resp_list != NULL, "temp_resp_list is NULL");

	if (strncmp(at_notif, AT_SMS_NOTIFICATION,
		AT_SMS_NOTIFICATION_LEN) == 0) {

		sms_data_info->type = SMS_TYPE_DELIVER;

		/* Extract and save the SMS notification parameters */
		int err = sms_cmt_at_parse(at_notif, pdu, pdu_len,
			temp_resp_list);
		if (err) {
			return err;
		}

		err = sms_deliver_pdu_parse(pdu, sms_data_info);
		if (err) {
			LOG_ERR("sms_deliver_pdu_parse error: %d\n", err);
			return err;
		}
	} else if (strncmp(at_notif, AT_SMS_NOTIFICATION_DS,
		AT_SMS_NOTIFICATION_DS_LEN) == 0) {

		LOG_DBG("SMS submit report received");
		sms_data_info->type = SMS_TYPE_SUBMIT_REPORT;

		err = sms_cds_at_parse(at_notif, pdu, pdu_len, temp_resp_list);
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
