/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <stdio.h>
#include <string.h>

#include <zephyr.h>
#include <init.h>

#include <sys/types.h>
#include <nrf9160.h>
#include <hal/nrf_gpio.h>
#include <logging/log_ctrl.h>

#include <modem/modem_info.h>
#include <modem/lte_lc.h>
#include "ltelc.h"

/* global variables */
struct modem_param_info modem_param;
char rsp_buf[CONFIG_AT_CMD_RESPONSE_MAX_LEN];

#if !defined (CONFIG_RESET_ON_FATAL_ERROR)
void k_sys_fatal_error_handler(unsigned int reason,
			       const z_arch_esf_t *esf)
{
//	ARG_UNUSED(esf);

	LOG_PROCESS();
	LOG_PANIC();
	printk("OHO! Running main.c error handler, reason: %d", reason);
//	z_fatal_error(reason, esf);
//	k_fatal_halt(reason);
//	error_handler(ERROR_SYSTEM_FAULT, reason);
//	CODE_UNREACHABLE;
}
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
static int fta_shell_init(const struct device *unused)
{
	ARG_UNUSED(unused);

	printk("\nThe FT app sample started\n\n");

#if defined(CONFIG_BSD_LIBRARY)
	ltelc_init();

	lte_lc_register_handler(ltelc_ind_handler); //for autoconnect
#endif
	return 0;
}

void main(void)
{
	int err;

#if defined(CONFIG_BSD_LIBRARY)
	if (IS_ENABLED(CONFIG_LTE_AUTO_INIT_AND_CONNECT)) {
		/* Do nothing, modem is already configured and LTE connected. */
	} else {
		err = lte_lc_init_and_connect_async(ltelc_ind_handler);
		if (err) {
			printk("\nModem could not be configured, error: %d",
			       err);
			return;
		}

		/* Check LTE events of type LTE_LC_EVT_NW_REG_STATUS in
		 * lte_async_connect_handler() to determine when the LTE link is up.
		 */
	}
#endif

	modem_trace_enable();

#if defined(CONFIG_MODEM_INFO)
	err = modem_info_init();
	if (err) {
		printk("\nModem info could not be established: %d", err);
		return;
	}
	modem_info_params_init(&modem_param);
#endif
}

SYS_INIT(fta_shell_init, APPLICATION, CONFIG_KERNEL_INIT_PRIORITY_DEFAULT);
