/*
 * Copyright (c) 2018 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <zephyr.h>
#include <stdio.h>
#include <string.h>

#include <nrf9160.h>
#include <hal/nrf_gpio.h>

#include <modem/modem_info.h>

/* global variable defined in different files */
struct modem_param_info modem_param;
char rsp_buf[CONFIG_AT_CMD_RESPONSE_MAX_LEN];

static void modem_trace_enable(void)
{
	/* GPIO configurations for trace and debug */
	#define CS_PIN_CFG_TRACE_CLK	21 //GPIO_OUT_PIN21_Pos
	#define CS_PIN_CFG_TRACE_DATA0	22 //GPIO_OUT_PIN22_Pos
	#define CS_PIN_CFG_TRACE_DATA1	23 //GPIO_OUT_PIN23_Pos
	#define CS_PIN_CFG_TRACE_DATA2	24 //GPIO_OUT_PIN24_Pos
	#define CS_PIN_CFG_TRACE_DATA3	25 //GPIO_OUT_PIN25_Pos

	// Configure outputs.
	// CS_PIN_CFG_TRACE_CLK
	NRF_P0_NS->PIN_CNF[CS_PIN_CFG_TRACE_CLK] = (GPIO_PIN_CNF_DRIVE_H0H1 << GPIO_PIN_CNF_DRIVE_Pos) |
		(GPIO_PIN_CNF_INPUT_Disconnect << GPIO_PIN_CNF_INPUT_Pos);

	// CS_PIN_CFG_TRACE_DATA0
	NRF_P0_NS->PIN_CNF[CS_PIN_CFG_TRACE_DATA0] = (GPIO_PIN_CNF_DRIVE_H0H1 << GPIO_PIN_CNF_DRIVE_Pos) |
		(GPIO_PIN_CNF_INPUT_Disconnect << GPIO_PIN_CNF_INPUT_Pos);

	// CS_PIN_CFG_TRACE_DATA1
	NRF_P0_NS->PIN_CNF[CS_PIN_CFG_TRACE_DATA1] = (GPIO_PIN_CNF_DRIVE_H0H1 << GPIO_PIN_CNF_DRIVE_Pos) |
		(GPIO_PIN_CNF_INPUT_Disconnect << GPIO_PIN_CNF_INPUT_Pos);

	// CS_PIN_CFG_TRACE_DATA2
	NRF_P0_NS->PIN_CNF[CS_PIN_CFG_TRACE_DATA2] = (GPIO_PIN_CNF_DRIVE_H0H1 << GPIO_PIN_CNF_DRIVE_Pos) |
		(GPIO_PIN_CNF_INPUT_Disconnect << GPIO_PIN_CNF_INPUT_Pos);

	// CS_PIN_CFG_TRACE_DATA3
	NRF_P0_NS->PIN_CNF[CS_PIN_CFG_TRACE_DATA3] = (GPIO_PIN_CNF_DRIVE_H0H1 << GPIO_PIN_CNF_DRIVE_Pos) |
		(GPIO_PIN_CNF_INPUT_Disconnect << GPIO_PIN_CNF_INPUT_Pos);

	NRF_P0_NS->DIR = 0xFFFFFFFF;
}

void main(void)
{
	int err;

	printk("The FT host sample started\n");
	modem_trace_enable();

	err = modem_info_init();
	if (err) {
		printk("Modem info could not be established: %d", err);
		return;
	}
	modem_info_params_init(&modem_param);
}
