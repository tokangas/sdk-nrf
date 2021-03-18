/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <stdio.h>
#include <strings.h>

#include <assert.h>

#include <shell/shell.h>

#include <settings/settings.h>

#include <modem/lte_lc.h>

#include "fta_defines.h"

#include "ltelc_shell.h"
#include "ltelc_settings.h"

#define LTELC_SETT_KEY			                  "mosh_ltelc_settings"

/* ****************************************************************************/

#define LTELC_SETT_DEFCONT_ENABLED		          "defcont_enabled"
#define LTELC_SETT_DEFCONT_APN_KEY		          "defcont_apn"
#define LTELC_SETT_DEFCONT_IP_FAMILY_KEY	      "defcont_ip_family"

#define LTELC_SETT_DEFCONT_MAX_IP_FAMILY_STR_LEN 6
#define LTELC_SETT_DEFCONT_DEFAULT_APN       "internet"
#define LTELC_SETT_DEFCONT_DEFAULT_IP_FAMILY "IPV4V6"

/* ****************************************************************************/

#define LTELC_SETT_DEFCONTAUTH_ENABLED		      "defcontauth_enabled"
#define LTELC_SETT_DEFCONTAUTH_USERNAME_KEY       "defcontauth_username"
#define LTELC_SETT_DEFCONTAUTH_PASSWORD_KEY       "defcontauth_password"
#define LTELC_SETT_DEFCONTAUTH_PROTOCOL_KEY       "defcontauth_prot"

#define LTELC_SETT_DEFCONTAUTH_MAX_UNAME_STR_LEN 32
#define LTELC_SETT_DEFCONTAUTH_MAX_PWORD_STR_LEN 32

#define LTELC_SETT_DEFCONTAUTH_DEFAULT_USERNAME   "username"
#define LTELC_SETT_DEFCONTAUTH_DEFAULT_PASSWORD   "password"

/* ****************************************************************************/

#define LTELC_SETT_SYSMODE_KEY		              "sysmode"

/* ****************************************************************************/

#define LTELC_SETT_NORMAL_MODE_AT_CMD_1_KEY       "funmmode_normal_at_cmd_1"
#define LTELC_SETT_NORMAL_MODE_AT_CMD_2_KEY       "funmmode_normal_at_cmd_2"
#define LTELC_SETT_NORMAL_MODE_AT_CMD_3_KEY       "funmmode_normal_at_cmd_3"

/* ****************************************************************************/

#define LTELC_SETT_NORMAL_MODE_AUTOCONN_ENABLED	  "normal_mode_autoconn_enabled"

/* ****************************************************************************/

enum ltelc_sett_defcontauth_prot {
	LTELC_SETT_DEFCONTAUTH_PROT_NONE = 0,
	LTELC_SETT_DEFCONTAUTH_PROT_PAP  = 1,
	LTELC_SETT_DEFCONTAUTH_PROT_CHAP = 2
};

/* ****************************************************************************/
static const struct shell *uart_shell = NULL;

struct ltelc_sett_t {
	char defcont_apn_str[FTA_APN_STR_MAX_LEN + 1];
	char defcont_ip_family_str[LTELC_SETT_DEFCONT_MAX_IP_FAMILY_STR_LEN + 1]; //TODO: store as enum
	bool defcont_enabled;

	char defcontauth_uname_str[LTELC_SETT_DEFCONTAUTH_MAX_UNAME_STR_LEN + 1];
	char defcontauth_pword_str[LTELC_SETT_DEFCONTAUTH_MAX_PWORD_STR_LEN + 1];
	enum ltelc_sett_defcontauth_prot defcontauth_prot;
	bool defcontauth_enabled;

	enum lte_lc_system_mode sysmode;

	/* note: if adding more memory slots, remember also update 
	   LTELC_SETT_NMODEAT_MEM_SLOT_INDEX_START/END accordingly. */
	char normal_mode_at_cmd_str_1[CONFIG_FTA_LTELC_SETT_NORMAL_MODE_AT_CMD_STR_LEN + 1];
	char normal_mode_at_cmd_str_2[CONFIG_FTA_LTELC_SETT_NORMAL_MODE_AT_CMD_STR_LEN + 1];
	char normal_mode_at_cmd_str_3[CONFIG_FTA_LTELC_SETT_NORMAL_MODE_AT_CMD_STR_LEN + 1];

	bool normal_mode_autoconn_enabled;
};
static struct ltelc_sett_t ltelc_settings;
/* ****************************************************************************/

/**@brief Callback when settings_load() is called. */
static int ltelc_sett_handler(const char *key, size_t len,
				settings_read_cb read_cb, void *cb_arg)
{
	int err;

	if (strcmp(key, LTELC_SETT_DEFCONT_ENABLED) == 0) {
		err = read_cb(cb_arg, &ltelc_settings.defcont_enabled,
			      sizeof(ltelc_settings.defcont_enabled));
		if (err < 0) {
			shell_error(uart_shell, "Failed to read defcont enabled, error: %d",
				err);
			return err;
		}
		return 0;
	}
	else if (strcmp(key, LTELC_SETT_DEFCONT_APN_KEY) == 0) {
		err = read_cb(cb_arg, &ltelc_settings.defcont_apn_str,
			      sizeof(ltelc_settings.defcont_apn_str));
		if (err < 0) {
			shell_error(uart_shell, "Failed to read defcont APN, error: %d",
				err);
			return err;
		}
		return 0;
	}
	else if (strcmp(key, LTELC_SETT_DEFCONT_IP_FAMILY_KEY) == 0) {
		err = read_cb(cb_arg, &ltelc_settings.defcont_ip_family_str,
			      sizeof(ltelc_settings.defcont_ip_family_str));
		if (err < 0) {
			shell_error(uart_shell, "Failed to read defcont IP family, error: %d",
				err);
			return err;
		}
		return 0;
	}
	if (strcmp(key, LTELC_SETT_DEFCONTAUTH_ENABLED) == 0) {
		err = read_cb(cb_arg, &ltelc_settings.defcontauth_enabled,
			      sizeof(ltelc_settings.defcontauth_enabled));
		if (err < 0) {
			shell_error(uart_shell, "Failed to read defcontauth enabled, error: %d",
				err);
			return err;
		}
		return 0;
	}
	else if (strcmp(key, LTELC_SETT_DEFCONTAUTH_USERNAME_KEY) == 0) {
		err = read_cb(cb_arg, &ltelc_settings.defcontauth_uname_str,
			      sizeof(ltelc_settings.defcontauth_uname_str));
		if (err < 0) {
			shell_error(uart_shell, "Failed to read defcontauth username, error: %d",
				err);
			return err;
		}
		return 0;
	}
	else if (strcmp(key, LTELC_SETT_DEFCONTAUTH_PASSWORD_KEY) == 0) {
		err = read_cb(cb_arg, &ltelc_settings.defcontauth_pword_str,
			      sizeof(ltelc_settings.defcontauth_pword_str));
		if (err < 0) {
			printf("Failed to read defcontauth password, error: %d",
				err);
			return err;
		}
		return 0;
	}
	else if (strcmp(key, LTELC_SETT_DEFCONTAUTH_PROTOCOL_KEY) == 0) {
		err = read_cb(cb_arg, &ltelc_settings.defcontauth_prot,
			      sizeof(ltelc_settings.defcontauth_prot));
		if (err < 0) {
			shell_error(uart_shell, "Failed to read defcontauth password, error: %d",
				err);
			return err;
		}
		return 0;
	}
	else if (strcmp(key, LTELC_SETT_SYSMODE_KEY) == 0) {
		err = read_cb(cb_arg, &ltelc_settings.sysmode,
			      sizeof(ltelc_settings.sysmode));
		if (err < 0) {
			shell_error(uart_shell, "Failed to read syhsmode, error: %d", err);
			return err;
		}
		return 0;
	}
	else if (strcmp(key, LTELC_SETT_NORMAL_MODE_AT_CMD_1_KEY) == 0) {
		err = read_cb(cb_arg, &ltelc_settings.normal_mode_at_cmd_str_1,
			      sizeof(ltelc_settings.normal_mode_at_cmd_str_1));
		if (err < 0) {
			shell_error(uart_shell, "Failed to read normal mode at cmd 1, error: %d",
				err);
			return err;
		}
		return 0;
	}
	else if (strcmp(key, LTELC_SETT_NORMAL_MODE_AT_CMD_2_KEY) == 0) {
		err = read_cb(cb_arg, &ltelc_settings.normal_mode_at_cmd_str_2,
			      sizeof(ltelc_settings.normal_mode_at_cmd_str_2));
		if (err < 0) {
			shell_error(uart_shell, "Failed to read normal mode at cmd 2, error: %d",
				err);
			return err;
		}
		return 0;
	}
	else if (strcmp(key, LTELC_SETT_NORMAL_MODE_AT_CMD_3_KEY) == 0) {
		err = read_cb(cb_arg, &ltelc_settings.normal_mode_at_cmd_str_3,
			      sizeof(ltelc_settings.normal_mode_at_cmd_str_3));
		if (err < 0) {
			shell_error(uart_shell, "Failed to read normal mode at cmd 3, error: %d",
				err);
			return err;
		}
		return 0;
	}
	else if (strcmp(key, LTELC_SETT_NORMAL_MODE_AUTOCONN_ENABLED) == 0) {
		err = read_cb(cb_arg, &ltelc_settings.normal_mode_autoconn_enabled,
			      sizeof(ltelc_settings.normal_mode_autoconn_enabled));
		if (err < 0) {
			shell_error(uart_shell, "Failed to read normal mode autoconnect, error: %d",
				err);
			return err;
		}
		return 0;
	}

	return 0;
}
/* ****************************************************************************/

int ltelc_sett_save_defcont_enabled(bool enabled)
{
	const char *key = LTELC_SETT_KEY "/" LTELC_SETT_DEFCONT_ENABLED;
	int err;
	
	ltelc_settings.defcont_enabled = enabled;
	shell_print(uart_shell, "ltelc defcont %s", ((enabled == true)? "enabled": "disabled"));

	err = settings_save_one(key, &ltelc_settings.defcont_enabled, sizeof(ltelc_settings.defcont_enabled));
	if (err) {
		shell_error(uart_shell, "ltelc_sett_save_defcont_enabled: err %d from settings_save_one()", err);
		return err;
	}
	return 0;
}

bool ltelc_sett_is_defcont_enabled()
{
	return ltelc_settings.defcont_enabled;
}

char *ltelc_sett_defcont_ip_family_get()
{
	return ltelc_settings.defcont_ip_family_str;
}

int ltelc_sett_save_defcont_ip_family(const char *ip_family_str)
{
	int err;
	const char *key = LTELC_SETT_KEY "/" LTELC_SETT_DEFCONT_IP_FAMILY_KEY;
	int len = strlen(ip_family_str);
	char tmp_family_str[LTELC_SETT_DEFCONT_MAX_IP_FAMILY_STR_LEN + 1];

	if (len <= LTELC_SETT_DEFCONT_MAX_IP_FAMILY_STR_LEN) {
		/* Mapping to AT command PDP types: */
		if (strcasecmp(ip_family_str, "ipv4v6") == 0) {
			strcpy(tmp_family_str, "IPV4V6");
		}
		else if ((strcasecmp(ip_family_str, "ipv4") == 0) ||
		        (strcasecmp(ip_family_str, "ip") == 0)) {
			strcpy(tmp_family_str, "IP");
		}
		else if (strcasecmp(ip_family_str, "ipv6") == 0) {
			strcpy(tmp_family_str, "IPV6");
		}
		else if (strcasecmp(ip_family_str, "packet") == 0) {
			strcpy(tmp_family_str, "Non-IP");
		}
		else {
			shell_error(uart_shell, "ltelc_sett_save_defcont_ip_family: could not decode PDN address family (%s)", 
				ip_family_str);			
			return -EINVAL;			
		}
		err = settings_save_one(
			key,
			tmp_family_str, len + 1);
		if (err) {
			shell_error(uart_shell, "ltelc_sett_save_defcont_ip_family: err %d from settings_save_one()", err);
			return err;
		}
		strcpy(ltelc_settings.defcont_ip_family_str, tmp_family_str);
	}
	else {
		shell_error(uart_shell, "ltelc_sett_save_defcont_ip_family: family len exceed the max (%d)", 
			LTELC_SETT_DEFCONT_MAX_IP_FAMILY_STR_LEN);
		return -EINVAL;
	}

	return 0;
}

char *ltelc_sett_defcont_apn_get()
{
	return ltelc_settings.defcont_apn_str;
}

int ltelc_sett_save_defcont_apn(const char *defcont_apn_str)
{
	int err;
	const char *key = LTELC_SETT_KEY "/" LTELC_SETT_DEFCONT_APN_KEY;
	int len = strlen(defcont_apn_str);

	assert(len <= FTA_APN_STR_MAX_LEN);

	err = settings_save_one(
		key,
		defcont_apn_str, len + 1);
	if (err) {
		shell_error(uart_shell, "ltelc_sett_save_defcont_apn: err %d from settings_save_one()", err);
		return err;
	}
	shell_print(uart_shell, "ltelc_settings: key %s with value %s saved", key, defcont_apn_str);

	strcpy(ltelc_settings.defcont_apn_str, defcont_apn_str);

	return 0;
}

void ltelc_sett_defcont_conf_shell_print(const struct shell *shell)
{
	shell_print(shell, "ltelc defcont config:");
	shell_print(shell, "  Enabled: %s", ltelc_settings.defcont_enabled ? "true" : "false" );
	shell_print(shell, "  APN: %s", ltelc_settings.defcont_apn_str);
	shell_print(shell, "  IP family / PDP type: %s", ltelc_settings.defcont_ip_family_str);
}
/* ****************************************************************************/

int ltelc_sett_save_defcontauth_enabled(bool enabled)
{
	const char *key = LTELC_SETT_KEY "/" LTELC_SETT_DEFCONTAUTH_ENABLED;
	int err;

	ltelc_settings.defcontauth_enabled = enabled;
	shell_print(uart_shell, "ltelc defcontauth  %s", ((enabled == true) ? "enabled" : "disabled"));
	
	err = settings_save_one(key, &ltelc_settings.defcontauth_enabled, sizeof(ltelc_settings.defcontauth_enabled));
	if (err) {
		shell_error(uart_shell, "ltelc_sett_save_defcontauth_enabled: erro %d from settings_save_one()", err);
		return err;
	}
	
	return 0;
}

bool ltelc_sett_is_defcontauth_enabled()
{
	return ltelc_settings.defcontauth_enabled;
}

int ltelc_sett_save_defcontauth_username(const char *username_str)
{
	int err;
	const char *key = LTELC_SETT_KEY "/" LTELC_SETT_DEFCONTAUTH_USERNAME_KEY;
	int len = strlen(username_str);

	if (len > LTELC_SETT_DEFCONTAUTH_MAX_UNAME_STR_LEN) {
		shell_error(uart_shell, "ltelc_sett_save_defcontauth_username: username length over the limit %d", 
			LTELC_SETT_DEFCONTAUTH_MAX_UNAME_STR_LEN);
		return -EINVAL;
	}

	err = settings_save_one(
		key,
		username_str, len + 1);
	if (err) {
		shell_error(uart_shell, "Saving of authentication username failed with err %d", err);
		return err;
	}
	shell_print(uart_shell, "Key \"%s\" with value \"%s\" saved", key, username_str);

	strcpy(ltelc_settings.defcontauth_uname_str, username_str);

	return 0;
}

int ltelc_sett_save_defcontauth_password(const char *password_str)
{
	int err;
	const char *key = LTELC_SETT_KEY "/" LTELC_SETT_DEFCONTAUTH_PASSWORD_KEY;
	int len = strlen(password_str);

	if (len > LTELC_SETT_DEFCONTAUTH_MAX_PWORD_STR_LEN) {
		shell_error(uart_shell, "ltelc_sett_save_defcontauth_password: username length over the limit %d", 
			LTELC_SETT_DEFCONTAUTH_MAX_PWORD_STR_LEN);
		return -EINVAL;
	}

	err = settings_save_one(key, password_str, len + 1);
	if (err) {
		shell_error(uart_shell, "Saving of authentication password failed with err %d", err);
		return err;
	}
	shell_print(uart_shell, "Key \"%s\" with value \"%s\" saved", key, password_str);

	strcpy(ltelc_settings.defcontauth_pword_str, password_str);

	return 0;
}

int ltelc_sett_save_defcontauth_prot(int auth_prot)
{
	int err;
	const char *key = LTELC_SETT_KEY "/" LTELC_SETT_DEFCONTAUTH_PROTOCOL_KEY;
	enum ltelc_sett_defcontauth_prot prot;

	if (auth_prot == 0) {
		prot = LTELC_SETT_DEFCONTAUTH_PROT_NONE;
	}
	else if (auth_prot == 1) {
		prot = LTELC_SETT_DEFCONTAUTH_PROT_PAP;
	}
	else if (auth_prot == 2) {
		prot = LTELC_SETT_DEFCONTAUTH_PROT_CHAP;
	}
	else {
		shell_error(uart_shell, "Uknown auth protocol %d", auth_prot);
		return -EINVAL;
	}

	err = settings_save_one(
		key,
		&prot, 
		sizeof(enum ltelc_sett_defcontauth_prot));
	if (err) {
		shell_error(uart_shell, "Saving of authentication protocol failed with err %d", err);
		return err;
	}
	ltelc_settings.defcontauth_prot = prot;

	shell_print(uart_shell, "Key \"%s\" with value \"%d\" saved", key, prot);

	return 0;
}
int ltelc_sett_defcontauth_prot_get()
{
	int prot = ltelc_settings.defcontauth_prot;
	return prot;
}
char *ltelc_sett_defcontauth_username_get()
{
	return ltelc_settings.defcontauth_uname_str;
}
char *ltelc_sett_defcontauth_password_get()
{
	return ltelc_settings.defcontauth_pword_str;
}
void ltelc_sett_defcontauth_conf_shell_print(const struct shell *shell)
{
	static const char * const prot_type_str[] = {
		"None", "PAP", "CHAP"
	};

	shell_print(shell, "ltelc defcontauth config:");
	shell_print(shell, "  Enabled: %s", ltelc_settings.defcontauth_enabled ? "true" : "false" );
	shell_print(shell, "  Username: %s", ltelc_settings.defcontauth_uname_str);
	shell_print(shell, "  Password: %s", ltelc_settings.defcontauth_pword_str);
	shell_print(shell, "  Authentication protocol: %s", prot_type_str[ltelc_settings.defcontauth_prot]);
}

/* ****************************************************************************/
int ltelc_sett_sysmode_save(enum lte_lc_system_mode mode)
{
	const char *key = LTELC_SETT_KEY "/" LTELC_SETT_SYSMODE_KEY;
	int err;

	err = settings_save_one(key, &mode, sizeof(mode));
	if (err) {
		shell_error(uart_shell, "ltelc_sett_save_sysmode: erro %d from settings_save_one()", err);
		return err;
	}
	ltelc_settings.sysmode = mode;
	shell_print(uart_shell, "sysmode %d saved succesfully to settings", mode);

	return 0;
}
void ltelc_sett_sysmode_print(const struct shell *shell)
{
	char snum[64];

	shell_print(shell, "ltelc sysmode config:");
		shell_print(shell, "  mode: %s", 
			ltelc_shell_sysmode_to_string(ltelc_sett_sysmode_get(), snum));
}

int ltelc_sett_sysmode_get()
{
	return ltelc_settings.sysmode;
}
/* ****************************************************************************/

char *ltelc_sett_normal_mode_at_cmd_str_get(uint8_t mem_slot)
{
	if (mem_slot == 1) {
		return ltelc_settings.normal_mode_at_cmd_str_1;
	}
	else if (mem_slot == 2) {
		return ltelc_settings.normal_mode_at_cmd_str_2;
	}
	else if (mem_slot == 3) {
		return ltelc_settings.normal_mode_at_cmd_str_3;
	}
	else {
		shell_error(uart_shell, 
			"ltelc_sett_normal_mode_at_cmd_str_get:unsupported memory slot %d", mem_slot);
		return NULL;
	}
}
int ltelc_sett_save_normal_mode_at_cmd_str(const char *at_str, uint8_t mem_slot)
{
	int err;
	const char *key;
	int len = strlen(at_str);
	char *at_cmd_ram_storage_ptr;

	if (len > CONFIG_FTA_LTELC_SETT_NORMAL_MODE_AT_CMD_STR_LEN) {
		shell_error(uart_shell, "ltelc_sett_save_normal_mode_at_cmd_str: at command string length (%d) over the limit %d",
			len,
			CONFIG_FTA_LTELC_SETT_NORMAL_MODE_AT_CMD_STR_LEN);
		return -EINVAL;
	}

	if (mem_slot == 1) {
		at_cmd_ram_storage_ptr = ltelc_settings.normal_mode_at_cmd_str_1;
		key = LTELC_SETT_KEY "/" LTELC_SETT_NORMAL_MODE_AT_CMD_1_KEY;
	} 
	else if (mem_slot == 2) {
		at_cmd_ram_storage_ptr = ltelc_settings.normal_mode_at_cmd_str_2;
		key = LTELC_SETT_KEY "/" LTELC_SETT_NORMAL_MODE_AT_CMD_2_KEY;
	}
	else if (mem_slot == 3) {
		at_cmd_ram_storage_ptr = ltelc_settings.normal_mode_at_cmd_str_3;
		key = LTELC_SETT_KEY "/" LTELC_SETT_NORMAL_MODE_AT_CMD_3_KEY;
	}
	else {
		shell_error(uart_shell, 
			"ltelc_sett_save_normal_mode_at_cmd_str: unsupported memory slot %d", mem_slot);
		return -EINVAL;
	}

	err = settings_save_one(
		key,
		at_str, len + 1);
	if (err) {
		shell_error(
			uart_shell, 
			"Saving of normal mode at cmd %d to settings failed with err %d", 
			mem_slot, 
			err);
		return err;
	}

	shell_print(uart_shell, "Key \"%s\" with value \"%s\" saved", key, at_str);

	strcpy(at_cmd_ram_storage_ptr, at_str);
	return 0;
}

int ltelc_sett_clear_normal_mode_at_cmd_str(uint8_t mem_slot)
{
	int err;
	const char *key;
	char *at_cmd_ram_storage_ptr;

	if (mem_slot == 1) {
		at_cmd_ram_storage_ptr = ltelc_settings.normal_mode_at_cmd_str_1;
		key = LTELC_SETT_KEY "/" LTELC_SETT_NORMAL_MODE_AT_CMD_1_KEY;
	} 
	else if (mem_slot == 2) {
		at_cmd_ram_storage_ptr = ltelc_settings.normal_mode_at_cmd_str_2;
		key = LTELC_SETT_KEY "/" LTELC_SETT_NORMAL_MODE_AT_CMD_2_KEY;
	}
	else if (mem_slot == 3) {
		at_cmd_ram_storage_ptr = ltelc_settings.normal_mode_at_cmd_str_3;
		key = LTELC_SETT_KEY "/" LTELC_SETT_NORMAL_MODE_AT_CMD_3_KEY;
	}
	else {
		shell_error(uart_shell, 
			"ltelc_sett_delete_normal_mode_at_cmd_str: unsupported memory slot %d", mem_slot);
		return -EINVAL;
	}

	err = settings_save_one(key, '\0', 1);
	if (err) {
		shell_error(
			uart_shell, 
			"Clearing of normal mode at cmd %d to settings failed with err %d", 
			mem_slot, 
			err);
		return err;
	}

	shell_print(uart_shell, "Key \"%s\" cleared", key);

	at_cmd_ram_storage_ptr[0] = '\0';

	return 0;
}
void ltelc_sett_normal_mode_at_cmds_shell_print(const struct shell *shell)
{
	shell_print(shell, "ltelc normal mode at commands:");
	shell_print(shell, "  Memory slot 1: \"%s\"", ltelc_settings.normal_mode_at_cmd_str_1);
	shell_print(shell, "  Memory slot 2: \"%s\"", ltelc_settings.normal_mode_at_cmd_str_2);
	shell_print(shell, "  Memory slot 3: \"%s\"", ltelc_settings.normal_mode_at_cmd_str_3);
}
/* ****************************************************************************/

int ltelc_sett_save_normal_mode_autoconn_enabled(bool enabled)
{
	const char *key = LTELC_SETT_KEY "/" LTELC_SETT_NORMAL_MODE_AUTOCONN_ENABLED;
	int err;
	
	ltelc_settings.normal_mode_autoconn_enabled = enabled;
	shell_print(uart_shell, "ltelc nmodeauto %s", ((enabled == true)? "enabled": "disabled"));

	err = settings_save_one(
		key, 
		&ltelc_settings.normal_mode_autoconn_enabled, 
		sizeof(ltelc_settings.normal_mode_autoconn_enabled));
	
	if (err) {
		shell_error(uart_shell, "ltelc_sett_save_defcont_enabled: err %d from settings_save_one()", err);
		return err;
	}
	return 0;
}

bool ltelc_sett_is_normal_mode_autoconn_enabled()
{
	return ltelc_settings.normal_mode_autoconn_enabled;
}

void ltelc_sett_normal_mode_autoconn_shell_print(const struct shell *shell)
{
	shell_print(shell, "ltelc nmodeauto settings:");
	shell_print(
		shell, 
		"  Autoconnect enabled: %s", 
			ltelc_settings.normal_mode_autoconn_enabled ? "true" : "false" );
}
/* ****************************************************************************/

static void ltelc_sett_ram_data_init()
{
	memset(&ltelc_settings, 0 , sizeof(ltelc_settings));
	
	ltelc_settings.normal_mode_autoconn_enabled = true;
	ltelc_settings.sysmode = LTE_LC_SYSTEM_MODE_NONE;

	strcpy(ltelc_settings.defcont_apn_str, LTELC_SETT_DEFCONT_DEFAULT_APN);
	strcpy(ltelc_settings.defcont_ip_family_str, LTELC_SETT_DEFCONT_DEFAULT_IP_FAMILY);
	strcpy(ltelc_settings.defcontauth_uname_str, LTELC_SETT_DEFCONTAUTH_DEFAULT_USERNAME);
	strcpy(ltelc_settings.defcontauth_pword_str, LTELC_SETT_DEFCONTAUTH_DEFAULT_PASSWORD);
}

/* ****************************************************************************/
void ltelc_sett_all_print(const struct shell *shell)
{
	ltelc_sett_sysmode_print(shell);
	ltelc_sett_defcont_conf_shell_print(shell);
	ltelc_sett_defcontauth_conf_shell_print(shell);
	ltelc_sett_normal_mode_at_cmds_shell_print(shell);
	ltelc_sett_normal_mode_autoconn_shell_print(shell);
}

void ltelc_sett_defaults_set(const struct shell *shell)
{
	ltelc_sett_ram_data_init();

	ltelc_sett_save_defcont_enabled(false);
	ltelc_sett_save_defcont_ip_family(LTELC_SETT_DEFCONT_DEFAULT_IP_FAMILY);
	ltelc_sett_save_defcont_apn(LTELC_SETT_DEFCONT_DEFAULT_APN);
	
	ltelc_sett_save_defcontauth_enabled(false);
	ltelc_sett_save_defcontauth_username(
		LTELC_SETT_DEFCONTAUTH_DEFAULT_USERNAME);
	ltelc_sett_save_defcontauth_password(
		LTELC_SETT_DEFCONTAUTH_DEFAULT_PASSWORD);
	ltelc_sett_save_defcontauth_prot(LTELC_SETT_DEFCONTAUTH_PROT_NONE);

	ltelc_sett_sysmode_save(LTE_LC_SYSTEM_MODE_NONE);

	ltelc_sett_clear_normal_mode_at_cmd_str(1);
	ltelc_sett_clear_normal_mode_at_cmd_str(2);
	ltelc_sett_clear_normal_mode_at_cmd_str(3);


	ltelc_sett_save_normal_mode_autoconn_enabled(true);

	shell_print(shell, "ltelc settings reseted");
}

int ltelc_sett_init(const struct shell *shell) 
{
	int err;
	struct settings_handler cfg = {
		.name = LTELC_SETT_KEY,
		.h_set = ltelc_sett_handler
	};
	
	uart_shell = shell;

	/* Set the defaults: */
	ltelc_sett_ram_data_init();

	err = settings_subsys_init();
	if (err) {
		shell_error(uart_shell, "Failed to initialize settings subsystem, error: %d",
			err);
		return err;
	}
	err = settings_register(&cfg);
	if (err) {
		shell_error(uart_shell, "Cannot register settings handler %d", err);
		return err;
	}
	err = settings_load();
	if (err) {
		shell_error(uart_shell, "Cannot load settings %d", err);
		return err;
	}
	return 0;	
}