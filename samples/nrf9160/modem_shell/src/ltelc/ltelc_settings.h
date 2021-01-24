/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#ifndef LTELC_SETTINGS_H
#define LTELC_SETTINGS_H

int ltelc_settings_init(void);

void ltelc_settings_defcont_conf_shell_print(const struct shell *shell);

int ltelc_settings_save_defcont_apn(const char *default_apn_str);
char *ltelc_settings_defcont_apn_get();

int ltelc_settings_save_defcont_ip_family(const char *ip_family_str);
char *ltelc_settings_defcont_ip_family_get();

void ltelc_settings_save_defcont_enabled(bool enabled);
bool ltelc_settings_is_defcont_enabled();

#endif /* LTELC_SETTINGS_H */
