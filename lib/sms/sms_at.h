/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#ifndef _SMS_AT_INCLUDE_H_
#define _SMS_AT_INCLUDE_H_

int sms_at_parse(const char *at_notif, struct sms_data *cmt_rsp,
        struct at_param_list *resp_list);

#endif

