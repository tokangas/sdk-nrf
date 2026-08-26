/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#if defined(CONFIG_MODEM_JWT)
#include <modem/modem_jwt.h>
#else
#include <psa/crypto.h>
#include <ncs_commit.h>
#include <app_jwt.h>
#endif

#include "nrf_provisioning_jwt.h"
#include "nrf_provisioning_at.h"

LOG_MODULE_REGISTER(nrf_provisioning_jwt, CONFIG_NRF_PROVISIONING_LOG_LEVEL);

#define TIME_MAX_LEN 64

int nrf_provisioning_jwt_generate(uint32_t time_valid_s, char *const jwt_buf, size_t jwt_buf_sz)
{
	if (!jwt_buf || !jwt_buf_sz) {
		return -EINVAL;
	}

	int err;
	uint32_t validity_s;

	if (time_valid_s > CONFIG_NRF_PROVISIONING_JWT_MAX_VALID_TIME_S) {
		validity_s = CONFIG_NRF_PROVISIONING_JWT_MAX_VALID_TIME_S;
	} else if (time_valid_s == 0) {
		validity_s = CONFIG_NRF_PROVISIONING_JWT_MAX_VALID_TIME_S;
	} else {
		validity_s = time_valid_s;
	}

#if defined(CONFIG_MODEM_JWT)
	char buf[TIME_MAX_LEN + 1];
	struct jwt_data jwt = { .audience = NULL,
				.sec_tag = CONFIG_NRF_PROVISIONING_JWT_SEC_TAG,
				.key = JWT_KEY_TYPE_CLIENT_PRIV,
				.alg = JWT_ALG_TYPE_ES256,
				.exp_delta_s = validity_s,
				.jwt_buf = jwt_buf,
				.jwt_sz = jwt_buf_sz,
				/* The UUID is present in the iss claim */
				.subject = NULL };

	/* Check if modem time is valid */
	err = nrf_provisioning_at_time_get(buf, sizeof(buf));
	if (err != 0) {
		LOG_ERR("Modem does not have valid date/time, JWT not generated");
		return -ETIME;
	}

	if (time_valid_s > CONFIG_NRF_PROVISIONING_JWT_MAX_VALID_TIME_S) {
		jwt.exp_delta_s = CONFIG_NRF_PROVISIONING_JWT_MAX_VALID_TIME_S;
	} else if (time_valid_s == 0) {
		jwt.exp_delta_s = CONFIG_NRF_PROVISIONING_JWT_MAX_VALID_TIME_S;
	} else {
		jwt.exp_delta_s = time_valid_s;
	}

	LOG_DBG("Generating JWT");
	err = modem_jwt_generate(&jwt);
	if (err) {
		LOG_ERR("Failed to generate JWT, error: %d", err);
	}
#else
	char issuer[8 + APP_JWT_UUID_V4_STR_LEN] = { 0 };
	char json_token_id[8 + sizeof(NCS_COMMIT_STRING) + 32 + 1] = { 0 };
	uint8_t random_data[16];
	char random_data_hex[32 + 1];

	if (!date_time_is_valid()) {
		LOG_ERR("Date/time is not valid, JWT not generated");
		return -ENODATA;
	}

	(void)snprintf(issuer, sizeof(issuer), "nRF9251.");
	err = app_jwt_get_uuid(issuer + strlen(issuer), sizeof(issuer) - strlen(issuer));
	if (err) {
		LOG_ERR("Failed to get UUID, error: %d", err);
		return err;
	}

	psa_status_t status = psa_crypto_init();
	if (status != PSA_SUCCESS) {
		LOG_ERR("Failed to initialize crypto, error: %d", status);
		return err;
	}
	status = psa_generate_random(random_data, sizeof(random_data));
	if (status != PSA_SUCCESS) {
		LOG_ERR("Failed to generate random data, error: %d", status);
		return err;
	}

	(void)bin2hex(random_data, sizeof(random_data), random_data_hex, sizeof(random_data_hex));
	random_data_hex[sizeof(random_data_hex) - 1] = '\0';

	(void)snprintf(json_token_id, sizeof(json_token_id), "nRF9251.");
	(void)snprintf(json_token_id + strlen(json_token_id),
		       sizeof(json_token_id) - strlen(json_token_id), "%s.", NCS_COMMIT_STRING);
	(void)snprintf(json_token_id + strlen(json_token_id),
		       sizeof(json_token_id) - strlen(json_token_id), "%s", random_data_hex);

	struct app_jwt_data jwt = {
		.sec_tag = 0, /* Use IAK key for signing */
		.key_type = 0,
		.alg = JWT_ALG_TYPE_ES256,
		.add_keyid_to_header = true,
		.json_token_id = json_token_id,
		.subject = NULL,
		.audience = NULL,
		.issuer = issuer,
		.add_timestamp = true,
		.validity_s = validity_s,
		.jwt_buf = jwt_buf,
		.jwt_sz = jwt_buf_sz,
	};

	err = app_jwt_generate(&jwt);
	if (err) {
		LOG_ERR("Failed to generate JWT, error: %d", err);
		return err;
	}

	// debug
	LOG_INF("JWT: %s", jwt_buf);
#endif
	return err;
}
