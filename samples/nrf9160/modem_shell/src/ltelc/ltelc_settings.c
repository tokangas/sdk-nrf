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

#include "fta_defines.h"
#include "ltelc_settings.h"

#define LTELC_SETTINGS_KEY			                  "mosh_ltelc_settings"
#define LTELC_SETTINGS_DEFAULT_CONT_ENABLED		      "defcont_enabled"
#define LTELC_SETTINGS_DEFAULT_CONT_APN_KEY		      "defcont_apn"
#define LTELC_SETTINGS_DEFAULT_CONT_IP_FAMILY_KEY	  "defcont_ip_family"

#define LTELC_SETTINGS_DEFAULT_CONT_USERNAME_KEY      "defcont_username"
#define LTELC_SETTINGS_DEFAULT_CONT_PASSWORD_KEY      "defcont_password"

#define LTELC_SETTINGS_DEFAULT_CONT_DEFAULT_APN       "internet"
#define LTELC_SETTINGS_DEFAULT_CONT_DEFAULT_IP_FAMILY "IPV4V6"

#define LTELC_SETTINGS_DEFCONT_MAX_IP_FAMILY_STR_LEN 6

struct ltelc_settings_t {
	char defcont_apn_str[FTA_APN_STR_MAX_LEN + 1];
	char defcont_ip_family_str[LTELC_SETTINGS_DEFCONT_MAX_IP_FAMILY_STR_LEN + 1];
	bool defcont_enabled;
};
static struct ltelc_settings_t ltelc_settings;

/**@brief Callback when settings_load() is called. */
static int ltelc_settings_handler(const char *key, size_t len,
				settings_read_cb read_cb, void *cb_arg)
{
	int err;

	if (strcmp(key, LTELC_SETTINGS_DEFAULT_CONT_ENABLED) == 0) {
		err = read_cb(cb_arg, &ltelc_settings.defcont_enabled,
			      sizeof(ltelc_settings.defcont_enabled));
		if (err < 0) {
			printf("Failed to read defcont enabled, error: %d",
				err);
			return err;
		}
		return 0;
	}
	else if (strcmp(key, LTELC_SETTINGS_DEFAULT_CONT_APN_KEY) == 0) {
		err = read_cb(cb_arg, &ltelc_settings.defcont_apn_str,
			      sizeof(ltelc_settings.defcont_apn_str));
		if (err < 0) {
			printf("Failed to read default APN, error: %d",
				err);
			return err;
		}
		return 0;
	}
	else if (strcmp(key, LTELC_SETTINGS_DEFAULT_CONT_IP_FAMILY_KEY) == 0) {
		err = read_cb(cb_arg, &ltelc_settings.defcont_ip_family_str,
			      sizeof(ltelc_settings.defcont_ip_family_str));
		if (err < 0) {
			printf("Failed to read default IP family, error: %d",
				err);
			return err;
		}
		return 0;
	}

	return 0;
}

void ltelc_settings_save_defcont_enabled(bool enabled)
{
	const char *key = LTELC_SETTINGS_KEY "/" LTELC_SETTINGS_DEFAULT_CONT_ENABLED;
	ltelc_settings.defcont_enabled = enabled;

	settings_save_one(key, &ltelc_settings.defcont_enabled, sizeof(ltelc_settings.defcont_enabled));
}

bool ltelc_settings_is_defcont_enabled()
{
	return ltelc_settings.defcont_enabled;
}

char *ltelc_settings_defcont_ip_family_get()
{
	return ltelc_settings.defcont_ip_family_str;
}

int ltelc_settings_save_defcont_ip_family(const char *ip_family_str)
{
	int err;
	const char *key = LTELC_SETTINGS_KEY "/" LTELC_SETTINGS_DEFAULT_CONT_IP_FAMILY_KEY;
	int len = strlen(ip_family_str);
	char tmp_family_str[LTELC_SETTINGS_DEFCONT_MAX_IP_FAMILY_STR_LEN + 1];

	if (len <= LTELC_SETTINGS_DEFCONT_MAX_IP_FAMILY_STR_LEN) {
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
		else {
			printk("ltelc_settings_save_defcont_ip_family: could not decode PDN address family (%s)\n", 
				ip_family_str);			
			return -EINVAL;			
		}
		err = settings_save_one(
			key,
			tmp_family_str, len + 1);
		if (err) {
			printf("ltelc_settings_save_defcont_ip_family: err %d\n", err);
			return err;
		}
		strcpy(ltelc_settings.defcont_ip_family_str, tmp_family_str);
	}
	else {
		printk("ltelc_settings_save_defcont_ip_family: family len exceed the max (%d)\n", 
			LTELC_SETTINGS_DEFCONT_MAX_IP_FAMILY_STR_LEN);
		return -EINVAL;
	}

	return 0;
}

char *ltelc_settings_defcont_apn_get()
{
	return ltelc_settings.defcont_apn_str;
}

int ltelc_settings_save_defcont_apn(const char *defcont_apn_str)
{
	int err;
	const char *key = LTELC_SETTINGS_KEY "/" LTELC_SETTINGS_DEFAULT_CONT_APN_KEY;
	int len = strlen(defcont_apn_str);

	assert(len <= FTA_APN_STR_MAX_LEN);

	err = settings_save_one(
		key,
		defcont_apn_str, len + 1);
	if (err) {
		printf("ltelc_settings_save_defcont_apn: err %d\n", err);
		return err;
	}
	printf("ltelc_settings: key %s with value %s saved\n", key, defcont_apn_str);

	strcpy(ltelc_settings.defcont_apn_str, defcont_apn_str);

	return 0;
}

void ltelc_settings_defcont_conf_shell_print(const struct shell *shell)
{
	shell_print(shell, "ltelc defcont config:");
	shell_print(shell, "  Enabled: %s", ltelc_settings.defcont_enabled ? "true" : "false" );
	shell_print(shell, "  APN: %s", ltelc_settings.defcont_apn_str);
	shell_print(shell, "  IP family / PDP type: %s", ltelc_settings.defcont_ip_family_str);
}

int ltelc_settings_init(void) 
{
	int err;
	struct settings_handler cfg = {
		.name = LTELC_SETTINGS_KEY,
		.h_set = ltelc_settings_handler
	};

	memset(&ltelc_settings, 0 , sizeof(ltelc_settings));
	strcpy(ltelc_settings.defcont_apn_str, LTELC_SETTINGS_DEFAULT_CONT_DEFAULT_APN);
	strcpy(ltelc_settings.defcont_ip_family_str, LTELC_SETTINGS_DEFAULT_CONT_DEFAULT_IP_FAMILY);

	err = settings_subsys_init();
	if (err) {
		printf("Failed to initialize settings subsystem, error: %d",
			err);
		return err;
	}
	err = settings_register(&cfg);
	if (err) {
		printf("Cannot register settings handler %d", err);
		return err;
	}
	err = settings_load();
	if (err) {
		printf("Cannot load settings %d", err);
		return err;
	}
	return 0;	
}