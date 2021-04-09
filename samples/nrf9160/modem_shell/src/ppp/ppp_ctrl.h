/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef PPP_CTRL_H
#define PPP_CTRL_H

#if defined (CONFIG_MOSH_PPP)
#define PPP_MODEM_DATA_RAW_SCKT_FD_NONE -666

void ppp_ctrl_init();
int ppp_ctrl_start(const struct shell *shell);
void ppp_ctrl_stop();

#endif

#endif /* PPP_CTRL_H */
