/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

/* TODO: this enum will be in nrf_cloud_fota.h when PR#3160 is merged */
/**@brief FOTA status reported to nRF Cloud. */
enum nrf_cloud_fota_status {
	NRF_CLOUD_FOTA_QUEUED = 0,
	NRF_CLOUD_FOTA_IN_PROGRESS = 1,
	NRF_CLOUD_FOTA_FAILED = 2,
	NRF_CLOUD_FOTA_SUCCEEDED = 3,
	NRF_CLOUD_FOTA_TIMED_OUT = 4,
	NRF_CLOUD_FOTA_CANCELED = 5,
	NRF_CLOUD_FOTA_REJECTED = 6,
	NRF_CLOUD_FOTA_DOWNLOADING = 7,
};

struct fota_client_mgmt_job {

	/** Hostname for download */
	char * host;
	/** Path for download */
	char * path;

	/* TODO */
	/** Job ID */
	char * id;
	/** Job status */
	enum nrf_cloud_fota_status status;
	/** Job status details */
	char * status_details;
};

void fota_client_set_fota_apn(const char *apn);

int fota_client_provision_device(void);
int fota_client_set_device_state(void);

int fota_client_get_pending_job(struct fota_client_mgmt_job * const job);
void fota_client_job_free(struct fota_client_mgmt_job * const job);

int fota_client_update_job(const struct fota_client_mgmt_job * job);
