/*
 * Copyright (c) 2018 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <stdio.h>
#include <string.h>
#include <zephyr.h>
#include <modem/lte_lc.h>
#include <modem/modem_fota.h>

/**@brief Recoverable BSD library error. */
void bsd_recoverable_error_handler(uint32_t err)
{
	printk("bsdlib recoverable error: %u\n", err);
}

void main(void)
{
	printk("Modem FOTA sample started\n");

	modem_fota_init();

	printk("LTE link connecting...\n");
	int err = lte_lc_init_and_connect();
	__ASSERT(err == 0, "LTE link could not be established.");
	printk("LTE link connected!\n");

	k_sleep(K_FOREVER);
}
