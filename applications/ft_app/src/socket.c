#include <shell/shell.h>
#include <strings.h>
#include <net/socket.h>
#include <fcntl.h>

#include "utils/getopt_port/getopt.h"

// Maximum number of sockets set to CONFIG_POSIX_MAX_FDS-1 as AT commands reserve one
#define MAX_SOCKETS (CONFIG_POSIX_MAX_FDS-1)
#define SEND_BUFFER_SIZE 4096+1
#define RECEIVE_BUFFER_SIZE 1536
#define RECEIVE_STACK_SIZE 2048
#define RECEIVE_PRIORITY 5
// Timeout for polling socket receive data. This limits how quickly data can be received after socket creation.
#define RECEIVE_POLL_TIMEOUT_MS 1000 // Milliseconds


struct data_transfer_info {
	struct k_work work;
	struct k_timer timer;
	int socket_id;
};

typedef struct
{
	int fd;
	int family;
	int type;
	int port;
	int bind_port;
	bool in_use;
	bool log_receive_data;
	struct addrinfo *addrinfo;
	struct data_transfer_info send_info;
} socket_info_t;

static socket_info_t sockets[MAX_SOCKETS] = {0};
char send_buffer[SEND_BUFFER_SIZE];
char receive_buffer[RECEIVE_BUFFER_SIZE];


void socket_info_clear(socket_info_t* socket_info) {
	close(socket_info->fd);
	socket_info->fd = -1;
	socket_info->in_use = false;
	socket_info->log_receive_data = true;
	freeaddrinfo(socket_info->addrinfo);
	socket_info->addrinfo = NULL;
}

int get_socket_id_by_fd(int fd)
{
	for (int i = 0; i < MAX_SOCKETS; i++) {
		if (sockets[i].fd == fd) {
			return i;
		}
		}
	return -1;
}

static void socket_receive_handler()
{
	struct pollfd fds[MAX_SOCKETS];

	while (true) {
		int count = 0;

		for (int i = 0; i < MAX_SOCKETS; i++) {
			if (sockets[i].in_use) {
				fds[count].fd = sockets[i].fd;
				fds[count].events = POLLIN;
				fds[count].revents = 0;
				count++;
			}
		}

		int ret = poll(fds, count, RECEIVE_POLL_TIMEOUT_MS);

		if (ret > 0) {
			for (int i = 0; i < count; i++) {
				if (fds[i].revents & POLLIN) {
					int buffer_size;
					int socket_id = get_socket_id_by_fd(fds[i].fd);
					socket_info_t* socket_info = &(sockets[i]);
					while ((buffer_size = recv(
							fds[i].fd,
							receive_buffer,
							RECEIVE_BUFFER_SIZE,
							0)) > 0) {
						if (socket_info->log_receive_data) {
							printk("\nreceived data for socket socket_id=%d,buffer_size=%d:\n%s\n",
								socket_id,
							buffer_size,
							receive_buffer);
						}
						memset(receive_buffer, '\0',
							RECEIVE_BUFFER_SIZE);
					}
				}
			}
		}
	}
	printk("socket_receive_handler exit\n");
}

K_THREAD_DEFINE(socket_receive_thread, RECEIVE_STACK_SIZE,
                socket_receive_handler, NULL, NULL, NULL,
                RECEIVE_PRIORITY, 0, 0);

static void socket_send(socket_info_t *socket_info, char* data, bool log_data)
{
	if (log_data) {
	printk("socket data send: %s\n", data);
	}
	int bytes;
	if (socket_info->type == SOCK_STREAM) {
		// TCP
		bytes = send(socket_info->fd, data, strlen(data), 0);
		if (bytes < 0) {
			printk("socket send failed, err %d\n", errno);
			return;
		}
	} else {
		// UDP
		int dest_addr_len = 0;
		if (socket_info->family == AF_INET) {
			dest_addr_len = sizeof(struct sockaddr_in);
		} else if (socket_info->family == AF_INET6) {
			dest_addr_len = sizeof(struct sockaddr_in6);
		}
		sendto(socket_info->fd, data, strlen(data), 0,
			socket_info->addrinfo->ai_addr, dest_addr_len);
	}
}

static void data_send_work_handler(struct k_work *item)
{
	struct data_transfer_info* data_send_info_ptr =
		CONTAINER_OF(item, struct data_transfer_info, work);
	int socket_id = data_send_info_ptr->socket_id;
	socket_info_t* socket_info = &sockets[socket_id];

	if (!sockets[socket_id].in_use) {
		printk("Socket id=%d not in use. Fatal error and sending won't work.\n",
			socket_id);
			// TODO: stop timer
		return;
	}

	socket_send(socket_info, send_buffer, true);
}

static void data_send_timer_handler(struct k_timer *dummy)
{
	struct data_transfer_info* data_send_info_ptr =
		CONTAINER_OF(dummy, struct data_transfer_info, timer);
	int socket_id = data_send_info_ptr->socket_id;
	socket_info_t* socket_info = &sockets[socket_id];

	k_work_submit(&socket_info->send_info.work);
}

static void socket_open_and_connect(int family, int type, int proto, char* ip_address, int port, int bind_port)
{
	// TODO: TLS support

	int err;
	struct addrinfo hints = {
		.ai_family = family,
		.ai_socktype = type,
	};

	// Create socket
	socket_info_t *socket_info = NULL;
	int socket_id = 0;
	while (socket_id < MAX_SOCKETS) {
		if (!sockets[socket_id].in_use) {
			socket_info = &(sockets[socket_id]);
			socket_info_clear(socket_info);
			break;
		}
		socket_id++;
	}
	if (socket_info == NULL) {
		printk("Socket creation failed. MAX_SOCKETS=%d exceeded\n", MAX_SOCKETS);
		return;
	}

	// If proto is set to zero to let lower stack select it,
	// socket creation fails with errno=43 (PROTONOSUPPORT)
	int fd = socket(family, type, proto);
	if (fd < 0) {
		printk("socket create failed, err %d\n", errno);
		return;
	}
	socket_info->in_use = true;
	socket_info->fd = fd;
	socket_info->family = family;
	socket_info->type = type;
	socket_info->port = port;
	socket_info->bind_port = bind_port;

	// Get address to connect to
	err = getaddrinfo(ip_address, NULL, &hints, &socket_info->addrinfo);
	if (err) {
		printk("getaddrinfo() failed, err %d errno %d\n", err, errno);
		socket_info_clear(socket_info);
		return;
	}
	if (family == AF_INET) {
		((struct sockaddr_in *)socket_info->addrinfo->ai_addr)->sin_port = htons(port);
	} else if (family == AF_INET6) {
		((struct sockaddr_in6 *)socket_info->addrinfo->ai_addr)->sin6_port = htons(port);
	} else {
		printk("Unsupport family=%d\n", family);
	}

	printk("socket created socket_id=%d, fd=%d\n", socket_id, fd);

	// Bind socket
	if (bind_port > 0) {
		struct sockaddr_in sa_local;
		struct sockaddr_in6 sa_local6;
		memset(&sa_local, 0, sizeof(struct sockaddr_in));
		memset(&sa_local6, 0, sizeof(struct sockaddr_in6));

		sa_local.sin_family = family;
		sa_local.sin_port = htons(bind_port);
		sa_local.sin_addr.s_addr = INADDR_ANY;

		sa_local6.sin6_family = family;
		sa_local6.sin6_port = htons(bind_port);
		sa_local6.sin6_addr = in6addr_any;

		struct sockaddr *sa_local_ptr = NULL;
		int sa_local_len = 0;

		if (family == AF_INET) {
			sa_local_ptr = (struct sockaddr *)&sa_local;
			sa_local_len = sizeof(struct sockaddr_in);
		} else if (family == AF_INET6) {
			sa_local_ptr = (struct sockaddr *)&sa_local6;
			sa_local_len = sizeof(struct sockaddr_in6);
		}

		err = bind(fd, sa_local_ptr, sa_local_len);
		if (err) {
			printk("Unable to bind, errno %d\n", errno);
			socket_info_clear(socket_info);
			return;
		}
		}

	if (type == SOCK_STREAM) {
		// Connect TCP socket
		err = connect(fd, socket_info->addrinfo->ai_addr, socket_info->addrinfo->ai_addrlen);
		if (err) {
			printk("Unable to connect, errno %d\n", errno);
			socket_info_clear(socket_info);
			return;
		}
	}

	// Set socket to non-blocking mode to make sure receiving is not blocking polling of all sockets.
	int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | (int) O_NONBLOCK);
}

int socket_connect_shell(const struct shell *shell, size_t argc, char **argv)
{
	int domain = -1;
	int type = -1;
	int proto = -1;
	int port = 0;
	int bind_port = 0;

	// TODO: Check that LTE link is connected because errors are not very descriptive if it's not.

	if (argc <= 4) {
		shell_error(shell, "At least 4 arguments required.");
		return -EINVAL;
	}

	// Address family = argv[1]
	if (!strcmp(argv[1], "inet")) {
		domain = AF_INET;
	} else if (!strcmp(argv[1], "inet6")) {
		domain = AF_INET6;
	} else if (!strcmp(argv[1], "packet")) {
		domain = AF_PACKET;
	} else {
		shell_error(shell, "Unsupported domain=%d", argv[1]);
		return -EINVAL;
	}

	// Socket type = argv[2]
	if (!strcmp(argv[2], "stream")) {
		type = SOCK_STREAM;
		proto = IPPROTO_TCP;
	} else if (!strcmp(argv[2], "dgram")) {
		type = SOCK_DGRAM;
		proto = IPPROTO_UDP;
	} else if (!strcmp(argv[2], "raw")) {
		type = SOCK_RAW;
		proto = 0;
	} else {
		shell_error(shell, "Unsupported type=%d", argv[2]);
		return -EINVAL;
	}

	// IP address = argv[3]

	// Port = argv[4]
	port = atoi(argv[4]);

	// Bind port = argv[5]
	if (argc > 5) {
		bind_port = atoi(argv[5]);
	}

	socket_open_and_connect(domain, type, proto, argv[3], port, bind_port);

	return 0;
}

int socket_send_shell(const struct shell *shell, size_t argc, char **argv)
{
	// Socket ID = argv[1]
	int socket_id = atoi(argv[1]);
	socket_info_t *socket_info = &(sockets[socket_id]);
	if (!socket_info->in_use) {
		shell_print(shell, "Socket id=%d not available", socket_id);
		return -EINVAL;
	}

	// Data to be sent = argv[2]
	// TODO: what if it's not given
	char* data = argv[2];

	// Data sending interval = argv[3]
	int interval = -1;
	if (argc > 3) {
		interval = atoi(argv[3]);
	}

	// Data length = argv[4]
	int data_len = 0;
	if (argc > 4) {
		data_len = atoi(argv[4]);
	}

	// Downlink data length = argv[5]
	int dl_data_len = 0;
	if (argc > 5) {
		dl_data_len = atoi(argv[5]);
	}

	if (socket_info->fd < 0) {
		// TODO: Should we be able to send without having socket connected, i.e.,
		// open, connect, send and close with one simple command?
		//socket_open_and_connect(20180);
	}

	socket_info->log_receive_data = true;
	if (dl_data_len > 0) {
		// Create Contabo request
		// TODO: This is not a solution for public version as Contabo is our internal stuff
		// We could avoid this if there is a way to pass double quotes through zephyr shell command line
		char dl_data[300];
		memset(dl_data, 0, 300);
		sprintf(dl_data,
			"trigger_dl_data: {\"wait_time\":\"1\",\"dl_data_len\":\"%d\",\"random_data\":\"True\",\"insert_packet_number\":\"True\"}",
			dl_data_len);
		socket_info->log_receive_data = false;
		socket_send(socket_info, dl_data, true);
	} else if (data_len > 0) {
		socket_info->log_receive_data = false;
		int data_left = data_len;
		memset(send_buffer, 0, SEND_BUFFER_SIZE);
		memset(send_buffer, 'd', SEND_BUFFER_SIZE-1);
		while (data_left > 0) {
			if (data_left < SEND_BUFFER_SIZE-1) {
				memset(send_buffer, 0, SEND_BUFFER_SIZE-1);
				memset(send_buffer, 'l', data_left);
			}
			socket_send(socket_info, send_buffer, false);
			data_left -= strlen(send_buffer);
		}
		memset(send_buffer, 0, SEND_BUFFER_SIZE);
	} else if (interval == 0 ) {
		if (k_timer_remaining_get(&socket_info->send_info.timer) > 0) {
			k_timer_stop(&socket_info->send_info.timer);
			shell_print(shell, "socket data send periodic stop");
		} else {
			shell_error(shell, "socket data send stop: periodic data not started");
			return -ENOEXEC;
		}
	} else if (interval > 0 ) {
		// TODO: This only work with data less than SEND_BUFFER_SIZE which is now 64 bytes.
		memcpy(send_buffer, data, strlen(data));
		shell_print(shell, "socket data send periodic with interval=%d", interval);
		k_timer_init(&socket_info->send_info.timer, data_send_timer_handler, NULL);
		k_work_init(&socket_info->send_info.work, data_send_work_handler);
		k_timer_start(&socket_info->send_info.timer, K_NO_WAIT, K_SECONDS(interval));
	} else {
		shell_print(shell, "socket data send");
		socket_send(socket_info, data, true);
		shell_print(shell, "socket data sent");
	}
	return 0;
}

int socket_close_shell(const struct shell *shell, size_t argc, char **argv)
{
	// Socket ID = argv[1]
	int socket_id = atoi(argv[1]);
	socket_info_t *socket_info = &(sockets[socket_id]);
	if (!socket_info->in_use) {
		shell_print(shell, "Socket id=%d not available", socket_id);
		return -EINVAL;
	}

	shell_print(shell, "close socket socket_id=%d, fd=%d", socket_id, socket_info->fd);
	socket_info_clear(socket_info);
	return 0;
}

int socket_list_shell(const struct shell *shell, size_t argc, char **argv)
{
	bool opened_sockets = false;
	for (int i = 0; i < MAX_SOCKETS; i++) {
		socket_info_t* socket_info = &(sockets[i]);
		if (socket_info->in_use) {
			opened_sockets = true;
			shell_print(shell, "Socket id=%d, fd=%d, family=%d, type=%d, port=%d, bind_port=%d", 
				i,
				socket_info->fd,
				socket_info->family,
				socket_info->type,
				socket_info->port,
				socket_info->bind_port);
		}
	}

	if (!opened_sockets) {
		shell_print(shell, "there are no open sockets");
	}
	return 0;
}