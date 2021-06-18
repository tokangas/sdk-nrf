/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <stdio.h>
#include <string.h>

#include <zephyr.h>
#include <init.h>
#include <nrf_modem.h>

#include <sys/types.h>
#include <nrf9160.h>
#include <hal/nrf_gpio.h>
#include <logging/log_ctrl.h>
#include <power/reboot.h>
#include <dfu/mcuboot.h>

#include <modem/nrf_modem_lib.h>
#include <modem/at_cmd.h>
#include <modem/at_notif.h>
#include <modem/modem_info.h>
#include <modem/lte_lc.h>

#include "private.h"

#if defined(CONFIG_MOSH_PPP)
#include <shell/shell.h>
#include "ppp_ctrl.h"
#endif

#if defined(CONFIG_MOSH_LTELC)
#include "ltelc.h"
#endif

#if defined(CONFIG_MOSH_GNSS)
#include "gnss.h"
#endif

#if defined(CONFIG_MOSH_FOTA)
#include "fota.h"
#endif

/* global variables */
struct modem_param_info modem_param;

K_SEM_DEFINE(nrf_modem_lib_initialized, 0, 1);

#if !defined (CONFIG_RESET_ON_FATAL_ERROR)
#if 0
void k_sys_fatal_error_handler(unsigned int reason,
			       const z_arch_esf_t *esf)
{
//	ARG_UNUSED(esf);

	LOG_PROCESS();
	LOG_PANIC();
	printk("OHO! Running main.c error handler, reason: %d", reason);
	z_fatal_error(reason, esf);
//	k_fatal_halt(reason);
//	CODE_UNREACHABLE;
}
#endif
#endif

static void mosh_print_version_info(void)
{
#if defined(APP_VERSION)
	printk("\nMOSH version:       %s", STRINGIFY(APP_VERSION));
#else
	printk("\nMOSH version:       unknown");
#endif

#if defined(BUILD_ID)
	printk("\nMOSH build id:      v%s", STRINGIFY(BUILD_ID));
#else
	printk("\nMOSH build id:      custom");
#endif

#if defined(BUILD_VARIANT)
#if defined(BRANCH_NAME)
	printk("\nMOSH build variant: %s/%s\n\n", STRINGIFY(BRANCH_NAME), STRINGIFY(BUILD_VARIANT));
#else
	printk("\nMOSH build variant: %s\n\n", STRINGIFY(BUILD_VARIANT));
#endif
#else
	printk("\nMOSH build variant: dev\n\n");
#endif
}

void main(void)
{
	int err;

	mosh_print_version_info();

	/* Initialize private parts of the application */
	private_initialization();

#if !defined(CONFIG_LWM2M_CARRIER)
	printk("Initializing modemlib...\n");
	err = nrf_modem_lib_init(NORMAL_MODE);
	switch (err) {
	case MODEM_DFU_RESULT_OK:
		printk("Modem firmware update successful!\n");
		printk("Modem will run the new firmware after reboot\n");
		sys_reboot(SYS_REBOOT_WARM);
		break;
	case MODEM_DFU_RESULT_UUID_ERROR:
	case MODEM_DFU_RESULT_AUTH_ERROR:
		printk("Modem firmware update failed!\n");
		printk("Modem will run non-updated firmware on reboot.\n");
		sys_reboot(SYS_REBOOT_WARM);
		break;
	case MODEM_DFU_RESULT_HARDWARE_ERROR:
	case MODEM_DFU_RESULT_INTERNAL_ERROR:
		printk("Modem firmware update failed!\n");
		printk("Fatal error.\n");
		sys_reboot(SYS_REBOOT_WARM);
		break;
	case -1:
		printk("Could not initialize bsdlib.\n");
		printk("Fatal error.\n");
		return;
	default:
		break;
	}
	printk("Initialized modemlib\n");

	at_cmd_init();
#if !defined (CONFIG_AT_NOTIF_SYS_INIT)
	at_notif_init();
#endif
	lte_lc_init();
#else
	/* Wait until bsdlib has been initialized. */
	k_sem_take(&nrf_modem_lib_initialized, K_FOREVER);

#endif

#if defined(CONFIG_MOSH_GNSS_ENABLE_LNA)
	gnss_set_lna_enabled(true);
#endif

#if defined(CONFIG_MOSH_FOTA)
	err = fota_init();
	if (err) {
		printk("Could not initialize FOTA: %d\n", err);
	}
#endif

#if defined(CONFIG_LTE_LINK_CONTROL) && defined(CONFIG_MOSH_LTELC)
	ltelc_init();
#endif

#if defined(CONFIG_MODEM_INFO)
	err = modem_info_init();
	if (err) {
		printk("\nModem info could not be established: %d", err);
		return;
	}
	modem_info_params_init(&modem_param);
#endif


	/* Application started successfully, mark image as OK to prevent
	 * revert at next reboot.
	 */
#if defined (CONFIG_BOOTLOADER_MCUBOOT )	
	boot_write_img_confirmed();
#endif
}

#if defined (CONFIG_MOSH_PPP)
static int mosh_shell_init(const struct device *unused)
{
	ppp_ctrl_init();
	return 0;
}
SYS_INIT(mosh_shell_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);
#endif
