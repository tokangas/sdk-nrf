#ifndef SOCKET_H
#define SOCKET_H

int app_cmd_data_start(const struct shell *shell, size_t argc, char **argv);
int app_cmd_data_stop(const struct shell *shell, size_t argc, char **argv);

int tcp_cmd_send_data(const struct shell *shell, size_t argc, char **argv);
int sc_cmd_data_stop(const struct shell *shell, size_t argc, char **argv);

#endif
