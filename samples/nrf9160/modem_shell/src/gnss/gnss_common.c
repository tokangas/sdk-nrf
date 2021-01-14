/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <stdio.h>
#include <string.h>

#include <zephyr.h>
#include <modem/at_cmd.h>

#include "gnss.h"

#define GNSS_LNA_ENABLE_XMAGPIO		"AT\%XMAGPIO=1,0,0,1,1,1574,1577"
#define GNSS_LNA_DISABLE_XMAGPIO	"AT\%XMAGPIO"
#define GNSS_LNA_ENABLE_XCOEX0		"AT\%XCOEX0=1,1,1565,1586"
#define GNSS_LNA_DISABLE_XCOEX0		"AT\%XCOEX0"

int gnss_set_lna_enabled(bool enabled)
{
	int err;
	const char *xmagpio_command;
	const char *xcoex0_command;

	if (enabled) {
		xmagpio_command = GNSS_LNA_ENABLE_XMAGPIO;
		xcoex0_command = GNSS_LNA_ENABLE_XCOEX0;
	} else {
		xmagpio_command = GNSS_LNA_DISABLE_XMAGPIO;
		xcoex0_command = GNSS_LNA_DISABLE_XCOEX0;
	}

	err = at_cmd_write(xmagpio_command, NULL, 0, NULL);
	if (err) {
		printk("Failed to send XMAGPIO command\n");
		return err;
	}

	err = at_cmd_write(xcoex0_command, NULL, 0, NULL);
	if (err) {
		printk("Failed to send XCOEX0 command\n");
		return err;
	}

	return 0;
}
