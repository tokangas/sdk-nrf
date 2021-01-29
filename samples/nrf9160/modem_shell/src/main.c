/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <stdio.h>
#include <string.h>

#include <zephyr.h>
#include <init.h>
#include <bsd.h>

#include <sys/types.h>
#include <nrf9160.h>
#include <hal/nrf_gpio.h>
#include <logging/log_ctrl.h>
#include <power/reboot.h>
#include <dfu/mcuboot.h>

#include <modem/bsdlib.h>
#include <modem/at_cmd.h>
#include <modem/at_notif.h>
#include <modem/modem_info.h>
#include <modem/lte_lc.h>

#if defined(CONFIG_FTA_PPP)
#include <shell/shell.h>
#include "ppp_ctrl.h"
#endif

#if defined(CONFIG_FTA_LTELC)
#include "ltelc.h"
#endif

#if defined(CONFIG_FTA_GNSS)
#include "gnss.h"
#endif

#if defined(CONFIG_FTA_FOTA)
#include "fota.h"
#endif

/* global variables */
struct modem_param_info modem_param;

K_SEM_DEFINE(bsdlib_initialized, 0, 1);

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

static void modem_trace_enable(void)
{
/* GPIO configurations for trace and debug */
#define CS_PIN_CFG_TRACE_CLK 21 //GPIO_OUT_PIN21_Pos
#define CS_PIN_CFG_TRACE_DATA0 22 //GPIO_OUT_PIN22_Pos
#define CS_PIN_CFG_TRACE_DATA1 23 //GPIO_OUT_PIN23_Pos
#define CS_PIN_CFG_TRACE_DATA2 24 //GPIO_OUT_PIN24_Pos
#define CS_PIN_CFG_TRACE_DATA3 25 //GPIO_OUT_PIN25_Pos

	// Configure outputs.
	// CS_PIN_CFG_TRACE_CLK
	NRF_P0_NS->PIN_CNF[CS_PIN_CFG_TRACE_CLK] =
		(GPIO_PIN_CNF_DRIVE_H0H1 << GPIO_PIN_CNF_DRIVE_Pos) |
		(GPIO_PIN_CNF_INPUT_Disconnect << GPIO_PIN_CNF_INPUT_Pos);

	// CS_PIN_CFG_TRACE_DATA0
	NRF_P0_NS->PIN_CNF[CS_PIN_CFG_TRACE_DATA0] =
		(GPIO_PIN_CNF_DRIVE_H0H1 << GPIO_PIN_CNF_DRIVE_Pos) |
		(GPIO_PIN_CNF_INPUT_Disconnect << GPIO_PIN_CNF_INPUT_Pos);

	// CS_PIN_CFG_TRACE_DATA1
	NRF_P0_NS->PIN_CNF[CS_PIN_CFG_TRACE_DATA1] =
		(GPIO_PIN_CNF_DRIVE_H0H1 << GPIO_PIN_CNF_DRIVE_Pos) |
		(GPIO_PIN_CNF_INPUT_Disconnect << GPIO_PIN_CNF_INPUT_Pos);

	// CS_PIN_CFG_TRACE_DATA2
	NRF_P0_NS->PIN_CNF[CS_PIN_CFG_TRACE_DATA2] =
		(GPIO_PIN_CNF_DRIVE_H0H1 << GPIO_PIN_CNF_DRIVE_Pos) |
		(GPIO_PIN_CNF_INPUT_Disconnect << GPIO_PIN_CNF_INPUT_Pos);

	// CS_PIN_CFG_TRACE_DATA3
	NRF_P0_NS->PIN_CNF[CS_PIN_CFG_TRACE_DATA3] =
		(GPIO_PIN_CNF_DRIVE_H0H1 << GPIO_PIN_CNF_DRIVE_Pos) |
		(GPIO_PIN_CNF_INPUT_Disconnect << GPIO_PIN_CNF_INPUT_Pos);

	NRF_P0_NS->DIR = 0xFFFFFFFF;
}

void main(void)
{
	int err;

	printk("\nMoSH build %s\n\n", STRINGIFY(APP_VERSION));

	modem_trace_enable();

#if !defined(CONFIG_LWM2M_CARRIER)
	printk("Initializing bsdlib...\n");
	err = bsdlib_init();
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
	printk("Initialized bsdlib\n");

	at_cmd_init();
	at_notif_init();
	lte_lc_init();
#else
	/* Wait until bsdlib has been initialized. */
	k_sem_take(&bsdlib_initialized, K_FOREVER);

#endif

#if defined(CONFIG_FTA_GNSS_ENABLE_LNA)
	gnss_set_lna_enabled(true);
#endif

#if defined(CONFIG_FTA_FOTA)
	err = fota_init();
	if (err) {
		printk("Could not initialize FOTA: %d\n", err);
	}
#endif

#if defined(CONFIG_LTE_LINK_CONTROL) && defined(CONFIG_FTA_LTELC)
	ltelc_init();
#if defined(CONFIG_FTA_LTELC_AUTO_CONNECT)
	ltelc_func_mode_set(LTELC_FUNMODE_NORMAL);
#endif
#endif

#if defined(CONFIG_MODEM_INFO)
	err = modem_info_init();
	if (err) {
		printk("\nModem info could not be established: %d", err);
		return;
	}
	modem_info_params_init(&modem_param);
#endif

#if defined (CONFIG_FTA_PPP)
	ppp_ctrl_init();
#endif

	/* Application started successfully, mark image as OK to prevent
	 * revert at next reboot.
	 */
#if defined (CONFIG_BOOTLOADER_MCUBOOT )	
	boot_write_img_confirmed();
#endif
}
