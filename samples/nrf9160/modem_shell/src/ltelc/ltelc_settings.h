/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#ifndef LTELC_SETTINGS_H
#define LTELC_SETTINGS_H

int ltelc_sett_init(const struct shell *shell);

void ltelc_sett_defaults_set(const struct shell *shell);
void ltelc_sett_all_print(const struct shell *shell);

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

int ltelc_sett_sysmode_save(enum lte_lc_system_mode mode);
int ltelc_sett_sysmode_get();


#define LTELC_SETT_NMODEAT_MEM_SLOT_INDEX_START 1
#define LTELC_SETT_NMODEAT_MEM_SLOT_INDEX_END 3

char *ltelc_sett_normal_mode_at_cmd_str_get(uint8_t mem_slot);
int ltelc_sett_save_normal_mode_at_cmd_str(const char *at_str, uint8_t mem_slot);
int ltelc_sett_clear_normal_mode_at_cmd_str(uint8_t mem_slot);
void ltelc_sett_normal_mode_at_cmds_shell_print(const struct shell *shell);

int ltelc_sett_save_normal_mode_autoconn_enabled(bool enabled);
bool ltelc_sett_is_normal_mode_autoconn_enabled();
void ltelc_sett_normal_mode_autoconn_shell_print(const struct shell *shell);

#endif /* LTELC_SETTINGS_H */
