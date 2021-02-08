/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#ifndef SOCK_H
#define SOCK_H

#define SOCK_ID_NONE -1
#define SOCK_BUFFER_SIZE_NONE -1
#define SOCK_SEND_DATA_INTERVAL_NONE -1

enum sock_recv_print_format {
	SOCK_RECV_PRINT_FORMAT_NONE = 0,
	SOCK_RECV_PRINT_FORMAT_STR,
	SOCK_RECV_PRINT_FORMAT_HEX,
};

int sock_open_and_connect(int family, int type, char* address, int port,
	int bind_port, int pdn_cid);
int sock_send_data(int socket_id, char* data, int data_length, int interval,
	bool blocking, int buffer_size);
int sock_recv(int socket_id, bool receive_start, bool blocking,
	enum sock_recv_print_format print_format);
int sock_close(int socket_id);
int sock_list();

#endif
