/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#ifndef LTELC_SETTINGS_H
#define LTELC_SETTINGS_H

int ltelc_sett_init(const struct shell *shell);

int ltelc_sett_save_defcont_enabled(bool enabled);
bool ltelc_sett_is_defcont_enabled();
void ltelc_sett_defcont_conf_shell_print(const struct shell *shell);
int ltelc_sett_save_defcont_apn(const char *default_apn_str);
char *ltelc_sett_defcont_apn_get();
int ltelc_sett_save_defcont_ip_family(const char *ip_family_str);
char *ltelc_sett_defcont_ip_family_get();

int ltelc_sett_save_defcontauth_enabled(bool enabled);
bool ltelc_sett_is_defcontauth_enabled();
void ltelc_sett_defcontauth_conf_shell_print(const struct shell *shell);
int ltelc_sett_save_defcontauth_prot(int auth_prot);
int ltelc_sett_defcontauth_prot_get();
int ltelc_sett_save_defcontauth_username(const char *username_str);
char *ltelc_sett_defcontauth_username_get();
int ltelc_sett_save_defcontauth_password(const char *password_str);
char *ltelc_sett_defcontauth_password_get();

#endif /* LTELC_SETTINGS_H */
