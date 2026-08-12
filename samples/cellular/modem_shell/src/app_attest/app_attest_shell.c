/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <string.h>

#include <app_attest_token.h>
#include <zephyr/shell/shell.h>

#include "mosh_print.h"
#include "str_utils.h"

static int cmd_app_attest_get(const struct shell *shell, size_t argc, char **argv)
{
	char token[APP_ATTEST_TOKEN_BUF_SZ];
	uint8_t challenge[APP_ATTEST_TOKEN_CHALLENGE_SZ];
	const uint8_t *challenge_ptr = NULL;
	int err;

	if (argc == 2) {
		if (str_hex_to_bytes(argv[1], strlen(argv[1]), challenge,
				     sizeof(challenge)) != APP_ATTEST_TOKEN_CHALLENGE_SZ) {
			mosh_error("Challenge must be %d bytes (%d hex chars)",
				   APP_ATTEST_TOKEN_CHALLENGE_SZ,
				   APP_ATTEST_TOKEN_CHALLENGE_SZ * 2);
			return -EINVAL;
		}
		challenge_ptr = challenge;
	}

	err = app_attest_token_get(token, sizeof(token), challenge_ptr);
	if (err) {
		mosh_error("app_attest_token_get failed: %d", err);
		return err;
	}

	mosh_print("%s", token);
	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(
	sub_app_attest,
	SHELL_CMD_ARG(
		get, NULL,
		"[<32 hex char challenge>]\nGenerate and print an application attestation token.",
		cmd_app_attest_get, 1, 1),
	SHELL_SUBCMD_SET_END);

SHELL_CMD_REGISTER(app_attest, &sub_app_attest,
		   "Temporary test command for application attestation tokens.",
		   mosh_print_help_shell);
