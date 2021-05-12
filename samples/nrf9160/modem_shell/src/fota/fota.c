/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <stdio.h>
#include <string.h>

#include <zephyr.h>
#include <power/reboot.h>
#include <shell/shell.h>
#include <modem/at_cmd.h>
#include <net/fota_download.h>

#include "fota.h"

#define MOSH_FOTA_TLS_SECURITY_TAG 4242424

#define AT_CMNG_TYPE_ROOT_CA_CERT 0
#define AT_CMNG_TYPE_CLIENT_CERT 1

static const char root_ca_cert[] = {
#include "cert/Baltimore-CyberTrust-Root"
};

static const char at_cmng_list_template[] = "AT%%CMNG=1,%d,%d";
static const char at_cmng_write_template[] = "AT%%CMNG=0,%d,%d,\"%s\"";

extern const struct shell *fota_shell_global;

static void reboot_timer_handler(struct k_timer *dummy)
{
	sys_reboot(SYS_REBOOT_WARM);
}

K_TIMER_DEFINE(reboot_timer, reboot_timer_handler, NULL);

static const char *get_error_cause(enum fota_download_error_cause cause)
{
	switch (cause) {
	case FOTA_DOWNLOAD_ERROR_CAUSE_DOWNLOAD_FAILED:
		return "download failed";
	case FOTA_DOWNLOAD_ERROR_CAUSE_INVALID_UPDATE:
		return "invalid update";
	default:
		return "unknown cause value";
	}
}

static void fota_download_callback(const struct fota_download_evt *evt)
{
	switch (evt->id) {
	case FOTA_DOWNLOAD_EVT_PROGRESS:
		shell_print(fota_shell_global, "FOTA: Progress %d%%",
			    evt->progress);
		break;
	case FOTA_DOWNLOAD_EVT_FINISHED:
		shell_print(
			fota_shell_global,
			"FOTA: Download finished, rebooting in 5 seconds...");
		k_timer_start(&reboot_timer, K_SECONDS(5), K_NO_WAIT);
		break;
	case FOTA_DOWNLOAD_EVT_ERASE_PENDING:
		shell_print(fota_shell_global, "FOTA: Still erasing...");
		break;
	case FOTA_DOWNLOAD_EVT_ERASE_DONE:
		shell_print(fota_shell_global, "FOTA: Erasing finished");
		break;
	case FOTA_DOWNLOAD_EVT_ERROR:
		shell_error(fota_shell_global, "FOTA: Error, %s",
			    get_error_cause(evt->cause));
		break;
	default:
		shell_error(fota_shell_global, "FOTA: Unknown event %d",
			    evt->id);
		break;
	}
}

static bool fota_ca_cert_exists(void)
{
	int err;
	char buf[128];

	sprintf(buf, at_cmng_list_template, MOSH_FOTA_TLS_SECURITY_TAG,
		AT_CMNG_TYPE_ROOT_CA_CERT);
	err = at_cmd_write(buf, buf, sizeof(buf), NULL);
	if (err) {
		return false;
	}

	return strlen(buf) == 0 ? false : true;
}

static int fota_write_ca_cert(void)
{
	int err;
	char *buf;

	err = 0;

	buf = k_malloc(sizeof(root_ca_cert) + 32);
	if (buf == NULL) {
		return -ENOMEM;
	}

	sprintf(buf, at_cmng_write_template, MOSH_FOTA_TLS_SECURITY_TAG,
		AT_CMNG_TYPE_ROOT_CA_CERT, root_ca_cert);
	err = at_cmd_write(buf, NULL, 0, NULL);

	k_free(buf);

	return err;
}

int fota_init(void)
{
	int err;

	if (!fota_ca_cert_exists()) {
		err = fota_write_ca_cert();
		if (err) {
			printk("Failed to write root CA to modem, error %d\n",
			       err);
		}
	}

	return fota_download_init(&fota_download_callback);
}

int fota_start(const char *host, const char *file)
{
	return fota_download_start(host, file, MOSH_FOTA_TLS_SECURITY_TAG, NULL, 0);
}
