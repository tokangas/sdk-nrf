/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <stdlib.h>

#include <zephyr.h>
#include <shell/shell.h>
#include <shell/shell_uart.h>
#include <modem/lte_lc.h>
#if defined (CONFIG_LWM2M_CARRIER)
#include <lwm2m_carrier.h>
#endif
#include "at/at_shell.h"
#if defined (CONFIG_FTA_PING)
#include "ping/icmp_ping_shell.h"
#endif
#if defined (CONFIG_FTA_SOCK)
#include "sock/sock_shell.h"
#endif
#if defined (CONFIG_POSIX_API)
#include <sys/select.h>
#else
#if !defined (CONFIG_NET_SOCKETS_POSIX_NAMES)
#include <posix/sys/select.h>
#endif
#endif
#if defined (CONFIG_FTA_IPERF3)
#include <iperf_api.h>
#endif
#if defined (CONFIG_FTA_LTELC)
#include "ltelc_shell.h"
#endif
#if defined (CONFIG_FTA_CURL)	
#include "fta_curl.h"
#endif
#if defined (CONFIG_FTA_GNSS)
#include "gnss/gnss_shell.h"
#endif
#if defined (CONFIG_FTA_SMS)
#include "sms/sms_shell.h"
#endif
#if defined(CONFIG_FTA_PPP)
#include "ppp/ppp_shell.h"
#endif

const struct shell* shell_global;

extern struct k_sem bsdlib_ready;

#if defined (CONFIG_LWM2M_CARRIER)
void lwm2m_print_err(const lwm2m_carrier_event_t *evt)
{
	const lwm2m_carrier_event_error_t *err =
		(lwm2m_carrier_event_error_t *)evt->data;

	static const char *strerr[] = {
		[LWM2M_CARRIER_ERROR_NO_ERROR] =
			"No error",
		[LWM2M_CARRIER_ERROR_BOOTSTRAP] =
			"Bootstrap error",
		[LWM2M_CARRIER_ERROR_CONNECT_FAIL] =
			"Failed to connect to the LTE network",
		[LWM2M_CARRIER_ERROR_DISCONNECT_FAIL] =
			"Failed to disconnect from the LTE network",
		[LWM2M_CARRIER_ERROR_FOTA_PKG] =
			"Package refused from modem",
		[LWM2M_CARRIER_ERROR_FOTA_PROTO] =
			"Protocol error",
		[LWM2M_CARRIER_ERROR_FOTA_CONN] =
			"Connection to remote server failed",
		[LWM2M_CARRIER_ERROR_FOTA_CONN_LOST] =
			"Connection to remote server lost",
		[LWM2M_CARRIER_ERROR_FOTA_FAIL] =
			"Modem firmware update failed",
	};

	shell_error(shell_global, "%s, reason %d\n", strerr[err->code], err->value);
}

void lwm2m_print_deferred(const lwm2m_carrier_event_t *evt)
{
	const lwm2m_carrier_event_deferred_t *def =
		(lwm2m_carrier_event_deferred_t *)evt->data;

	static const char *strdef[] = {
		[LWM2M_CARRIER_DEFERRED_NO_REASON] =
			"No reason given",
		[LWM2M_CARRIER_DEFERRED_PDN_ACTIVATE] =
			"Failed to activate PDN",
		[LWM2M_CARRIER_DEFERRED_BOOTSTRAP_NO_ROUTE] =
			"No route to bootstrap server",
		[LWM2M_CARRIER_DEFERRED_BOOTSTRAP_CONNECT] =
			"Failed to connect to bootstrap server",
		[LWM2M_CARRIER_DEFERRED_BOOTSTRAP_SEQUENCE] =
			"Bootstrap sequence not completed",
		[LWM2M_CARRIER_DEFERRED_SERVER_NO_ROUTE] =
			"No route to server",
		[LWM2M_CARRIER_DEFERRED_SERVER_CONNECT] =
			"Failed to connect to server",
		[LWM2M_CARRIER_DEFERRED_SERVER_REGISTRATION] =
			"Server registration sequence not completed",
	};

	shell_error(shell_global, "Reason: %s, timeout: %d seconds\n",
		    strdef[def->reason], def->timeout);
}

int lwm2m_carrier_event_handler(const lwm2m_carrier_event_t *event)
{
	shell_global = shell_backend_uart_get_ptr();

	switch (event->type) {
	case LWM2M_CARRIER_EVENT_BSDLIB_INIT:
		shell_print(shell_global, "LwM2M carrier event: bsdlib initialized");
		break;
	case LWM2M_CARRIER_EVENT_CONNECTING:
		shell_print(shell_global, "LwM2M carrier event: connecting");
		/* Semaphore is given after CONNECTING event so that also
		 * AT command interface has been initialized.
		 */
		k_sem_give(&bsdlib_ready);
		break;
	case LWM2M_CARRIER_EVENT_CONNECTED:
		shell_print(shell_global, "LwM2M carrier event: connected");
		break;
	case LWM2M_CARRIER_EVENT_DISCONNECTING:
		shell_print(shell_global, "LwM2M carrier event: disconnecting");
		break;
	case LWM2M_CARRIER_EVENT_DISCONNECTED:
		shell_print(shell_global, "LwM2M carrier event: disconnected");
		break;
	case LWM2M_CARRIER_EVENT_BOOTSTRAPPED:
		shell_print(shell_global, "LwM2M carrier event: bootstrapped");
		break;
	case LWM2M_CARRIER_EVENT_LTE_READY:
		shell_print(shell_global, "LwM2M carrier event: LTE ready");
		break;
	case LWM2M_CARRIER_EVENT_REGISTERED:
		shell_print(shell_global, "LwM2M carrier event: registered");
		break;
	case LWM2M_CARRIER_EVENT_DEFERRED:
		shell_print(shell_global, "LwM2M carrier event: deferred");
		lwm2m_print_deferred(event);
		break;
	case LWM2M_CARRIER_EVENT_FOTA_START:
		shell_print(shell_global, "LwM2M carrier event: fota start");
		break;
	case LWM2M_CARRIER_EVENT_REBOOT:
		shell_print(shell_global, "LwM2M carrier event: reboot");
		break;
	case LWM2M_CARRIER_EVENT_ERROR:
		shell_print(shell_global, "LwM2M carrier event: error");
		lwm2m_print_err(event);
		break;
	}

	return 0;
}
#endif

#if defined (CONFIG_FTA_IPERF3)	
static int cmd_iperf3(const struct shell *shell, size_t argc, char **argv)
{
	(void)iperf_main(argc, argv);
	return 0;
}
#endif

#if defined (CONFIG_FTA_CURL)	
static int cmd_curl(const struct shell *shell, size_t argc, char **argv)
{
	(void)curl_tool_main(argc, argv);
	shell_print(shell, "\nDONE");
	return 0;
}
SHELL_CMD_REGISTER(curl, NULL, "For curl usage, just type \"curl --manual\"", cmd_curl);
#endif

SHELL_CMD_REGISTER(at, NULL, "Execute an AT command.", at_shell);

#if defined (CONFIG_FTA_SOCK)
SHELL_CMD_REGISTER(sock, NULL,
	"Commands for socket operations such as connect and send.",
	sock_shell);
#endif

#if defined (CONFIG_FTA_PING)
SHELL_CMD_REGISTER(ping, NULL, "For ping usage, just type \"ping\"", icmp_ping_shell);
#endif

#if defined (CONFIG_FTA_LTELC)
SHELL_CMD_REGISTER(ltelc, NULL,
	"Commands for LTE link controlling and status information.",
	ltelc_shell);
#endif

#if defined (CONFIG_FTA_IPERF3)
SHELL_CMD_REGISTER(iperf3, NULL, "For iperf3 usage, just type \"iperf3 --manual\"", cmd_iperf3);
#endif

#if defined (CONFIG_FTA_SMS)
SHELL_CMD_REGISTER(sms, NULL, "Commands for sending and receiving SMS.", sms_shell);
#endif

#if defined (CONFIG_FTA_PPP)
SHELL_CMD_REGISTER(ppp, NULL,
	"Commands for controlling FTA PPP.",
	ppp_shell_cmd);
#endif