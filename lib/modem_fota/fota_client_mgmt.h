/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */
#include <net/aws_jobs.h>

struct fota_client_mgmt_job {

	/** Hostname for download */
	char * host;
	/** Path for download */
	char * path;

	/* TODO */
	/** Job ID */
	char * id;
	/** Job status */
	enum execution_status status;
	/** Job status details */
	char * status_details;
};

int fota_client_provision_device(void);

int fota_client_get_pending_job(struct fota_client_mgmt_job * const job);
void fota_client_job_free(struct fota_client_mgmt_job * const job);

int fota_client_update_job(const struct fota_client_mgmt_job * job);
