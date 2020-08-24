#ifndef SOCKET_H
#define SOCKET_H

int app_cmd_data_start(const struct shell *shell, size_t argc, char **argv);
int app_cmd_data_stop(const struct shell *shell, size_t argc, char **argv);

int socket_connect_shell(const struct shell *shell, size_t argc, char **argv);
int socket_send_shell(const struct shell *shell, size_t argc, char **argv);
int socket_close_shell(const struct shell *shell, size_t argc, char **argv);
int socket_list_shell(const struct shell *shell, size_t argc, char **argv);

#endif
