#ifndef SOCK_H
#define SOCK_H

#define SOCKET_ID_NONE -1
#define SOCKET_SEND_DATA_INTERVAL_NONE -1

int socket_open_and_connect(int family, int type, char* ip_address, int port, int bind_port, int pdn_cid);
int socket_send_data(int socket_id, char* data, int data_length, int interval);
int socket_recv(int socket_id, bool receive_start);
int socket_close(int socket_id);
void socket_list();

#endif
