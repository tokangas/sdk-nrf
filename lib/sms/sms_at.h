/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef _SMS_AT_INCLUDE_H_
#define _SMS_AT_INCLUDE_H_

int sms_at_parse(const char *at_notif, struct sms_data *sms_data_info,
        struct at_param_list *temp_resp_list);

#endif

