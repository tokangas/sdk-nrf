/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */
#include <stdlib.h>

#include <shell/shell.h>
#include <modem/at_cmd.h>
#include <modem/lte_lc.h>
#if defined (CONFIG_FTA_PING)
#include "ping/icmp_ping_shell.h"
#endif
#if defined (CONFIG_FTA_SOCK)
#include "sock.h"
#endif
#if defined (CONFIG_POSIX_API)
#include <sys/select.h>
#else
#if !defined (CONFIG_NET_SOCKETS_POSIX_NAMES)
#include <posix/sys/select.h>
#endif
#endif
#if defined (CONFIG_FTA_IPERF3)
#include "iperf/iperf_api.h"
#endif
#if defined (CONFIG_FTA_LTELC)
#include "ltelc_shell.h"
#endif

static int app_cmd_at(const struct shell *shell, size_t argc, char **argv)
{
	int err;
	char response[CONFIG_AT_CMD_RESPONSE_MAX_LEN + 1];

	err = at_cmd_write(argv[1], response, sizeof(response), NULL);
	if (err) {
		shell_error(shell, "ERROR");
		return -EINVAL;
	}

	shell_print(shell, "%sOK", response);

	return 0;
}


#if defined (CONFIG_FTA_IPERF3)	
static int cmd_iperf3(const struct shell *shell, size_t argc, char **argv)
{
	(void)iperf_main(argc, argv);
	return 0;
}
#endif

SHELL_CMD_ARG_REGISTER(at, NULL, "Execute an AT command.", app_cmd_at, 2, 0);

#if defined (CONFIG_FTA_SOCK)
SHELL_CMD_REGISTER(sock, NULL,
	"Commands for socket operations such as connect and send.",
	socket_shell);
#endif

#if defined (CONFIG_FTA_PING)
SHELL_CMD_REGISTER(ping, NULL, NULL, icmp_ping_shell);
#endif

#if defined (CONFIG_FTA_LTELC)
SHELL_CMD_REGISTER(ltelc, NULL,
	"Commands for LTE link controlling and status information.",
	ltelc_shell);
#endif

#if defined (CONFIG_FTA_IPERF3)
SHELL_CMD_REGISTER(iperf3, NULL, NULL, cmd_iperf3);
#endif
