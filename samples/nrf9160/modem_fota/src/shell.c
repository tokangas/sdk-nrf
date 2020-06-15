/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <shell/shell.h>
#include <modem/at_cmd.h>
#include <net/socket.h>

#define DEFAULT_DATA_SEND_INTERVAL 10

static int fd = -1;
static struct addrinfo *addrinfo_res;
static char dummy_data[] = "01234567890123456789012345678901"
			   "01234567890123456789012345678901"
			   "01234567890123456789012345678901"
			   "01234567890123456789012345678901"
			   "01234567890123456789012345678901"
			   "01234567890123456789012345678901"
			   "01234567890123456789012345678901"
			   "01234567890123456789012345678901";

static void udp_socket_open()
{
	int err;
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_DGRAM,
	};

	/* Use dummy destination address and port */
	err = getaddrinfo("192.168.123.45", NULL, &hints, &addrinfo_res);
	if (err) {
		printk("getaddrinfo() failed, err %d\n", errno);
	}

	((struct sockaddr_in *)addrinfo_res->ai_addr)->sin_port = htons(61234);

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
}

void data_send_work_handler(struct k_work *work)
{
	sendto(fd, dummy_data, sizeof(dummy_data) - 1, 0,
	       addrinfo_res->ai_addr, sizeof(struct sockaddr_in));
}

K_WORK_DEFINE(data_send_work, data_send_work_handler);

void data_send_timer_handler(struct k_timer *dummy)
{
	k_work_submit(&data_send_work);
}

K_TIMER_DEFINE(data_send_timer, data_send_timer_handler, NULL);

static int app_cmd_at(const struct shell *shell, size_t argc, char **argv)
{
	int err;
	char response[256];

	err = at_cmd_write(argv[1], response, sizeof(response), NULL);
	if (err) {
		shell_error(shell, "ERROR");
		return -EINVAL;
	}

	shell_print(shell, "%sOK", response);

	return 0;
}

static int app_cmd_data_start(const struct shell *shell, size_t argc, char **argv)
{
	int period = 0;

	if (fd < 0) {
		udp_socket_open();
	}

	if (fd >= 0) {
		if (argc > 1) {
			period = atoi(argv[1]);
		}
		if (period < 1) {
			period = DEFAULT_DATA_SEND_INTERVAL;
		}
		shell_print(shell, "start: sending periodic data every %d seconds",
			    period);
		k_timer_start(&data_send_timer,
			      K_NO_WAIT, K_SECONDS(period));
	} else {
		shell_error(shell, "start: socket not open");
		return -EINVAL;
	}

	return 0;
}

static int app_cmd_data_stop(const struct shell *shell, size_t argc, char **argv)
{
	if (k_timer_remaining_get(&data_send_timer) > 0) {
		k_timer_stop(&data_send_timer);
		shell_print(shell, "stop: periodic data stopped");
	} else {
		shell_error(shell, "stop: periodic data not started");
		return -ENOEXEC;
	}

	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(app_data_cmds,
	SHELL_CMD(start, NULL, "'app data start [interval in seconds]' starts "
		               "periodic UDP data sending. The default "
		               "interval is 10 seconds.", app_cmd_data_start),
	SHELL_CMD(stop, NULL, "Stop periodic UDP data sending.",
		  app_cmd_data_stop),
	SHELL_SUBCMD_SET_END
);

SHELL_STATIC_SUBCMD_SET_CREATE(app_cmds,
	SHELL_CMD_ARG(at, NULL, "Execute an AT command.", app_cmd_at, 2, 0),
	SHELL_CMD(data, &app_data_cmds, "Send periodic UDP data over default "
					"APN.", NULL),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(app, &app_cmds,
		   "Commands for controlling the FOTA sample application",
		   NULL);
