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
/* Maximum length of the data that can be specified with -d option */
#define SOCK_MAX_SEND_DATA_LEN 200

enum sock_recv_print_format {
	SOCK_RECV_PRINT_FORMAT_NONE = 0,
	SOCK_RECV_PRINT_FORMAT_STR,
	SOCK_RECV_PRINT_FORMAT_HEX,
};

int sock_open_and_connect(int family, int type, char* address, int port,
	int bind_port, int pdn_cid, bool secure, int sec_tag, bool session_cache,
	int peer_verify, char* peer_hostname);
int sock_send_data(int socket_id, char* data, int data_length, int interval,
	bool blocking, int buffer_size, bool data_format_hex);
int sock_recv(int socket_id, bool receive_start, bool blocking,
	enum sock_recv_print_format print_format);
int sock_close(int socket_id);
int sock_list();

#endif
