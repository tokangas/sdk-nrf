#ifndef SOCK_H
#define SOCK_H

int socket_open_and_connect(int family, int type, char* ip_address, int port, int bind_port, int pdn_cid);
int socket_send_data(int socket_id, char* data, int data_length, int interval);
int socket_recv(int socket_id, bool receive_start);
int socket_close(int socket_id);
void socket_list();

#endif
