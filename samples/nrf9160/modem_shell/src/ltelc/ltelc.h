/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef LTE_CONNECTION_H
#define LTE_CONNECTION_H
#include <modem/lte_lc.h>

#define LTELC_APN_STR_MAX_LENGTH 100
#define LTELC_MAX_PDN_SOCKETS 5 //TODO: what is the actual max in modem?

#define LTELC_FUNMODE_NONE 99

void ltelc_init(void);
void ltelc_ind_handler(const struct lte_lc_evt *const evt);
void ltelc_rsrp_subscribe(bool subscribe) ;
int ltelc_func_mode_set(enum lte_lc_func_mode fun);
int ltelc_func_mode_get(void);

#endif
