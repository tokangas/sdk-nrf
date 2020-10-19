#ifndef SOCK_H
#define SOCK_H

#define SOCK_ID_NONE -1
#define SOCK_SEND_DATA_INTERVAL_NONE -1

int sock_open_and_connect(int family, int type, char* address, int port, int bind_port, int pdn_cid);
int sock_send_data(int socket_id, char* data, int data_length, int interval);
int sock_recv(int socket_id, bool receive_start);
int sock_close(int socket_id);
int sock_list();

#endif
