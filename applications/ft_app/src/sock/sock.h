#ifndef SOCK_H
#define SOCK_H

#include <unistd.h>

struct data_transfer_info {
	struct k_work work;
	struct k_timer timer;
	int socket_id;
};

typedef struct {
	int id;
	int fd;
	int family;
	int type;
	int port;
	int bind_port;
	int pdn_cid;
	bool in_use;
	bool log_receive_data;
	int64_t recv_start_time_ms;
	int64_t recv_end_time_ms;
	uint32_t recv_data_len;
	bool recv_start_throughput;
	struct addrinfo *addrinfo;
	struct data_transfer_info send_info;
} socket_info_t;

int socket_open_and_connect(int family, int type, char* ip_address, int port, int bind_port, int pdn_cid);
int socket_send_data(socket_info_t* socket_info, char* data, int data_length, int interval);
void socket_recv(socket_info_t* socket_info, bool receive_start);
void socket_close(socket_info_t* socket_info);
void socket_list();

#endif
