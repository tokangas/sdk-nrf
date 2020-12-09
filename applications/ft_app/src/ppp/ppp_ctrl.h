/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#ifndef PPP_CTRL_H
#define PPP_CTRL_H

#if defined (CONFIG_FTA_PPP)
void ppp_ctrl_init();

int ppp_ctrl_start(const struct shell *shell);
void ppp_shell_set_ppp_carrier_off();

#endif

#endif /* PPP_CTRL_H */
