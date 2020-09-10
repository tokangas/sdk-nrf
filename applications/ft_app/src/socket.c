#include <shell/shell.h>
#include <assert.h>
#include <strings.h>
#if defined (CONFIG_POSIX_API)
#include <unistd.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#else
#include <net/socket.h>
#endif
#include <fcntl.h>

#include "utils/freebsd-getopt/getopt.h"

// Maximum number of sockets set to CONFIG_POSIX_MAX_FDS-1 as AT commands reserve one
#define MAX_SOCKETS (CONFIG_POSIX_MAX_FDS-1)
#define SEND_BUFFER_SIZE 4096+1
#define RECEIVE_BUFFER_SIZE 1536
#define RECEIVE_STACK_SIZE 2048
#define RECEIVE_PRIORITY 5
// Timeout for polling socket receive data. This limits how quickly data can be received after socket creation.
#define RECEIVE_POLL_TIMEOUT_MS 1000 // Milliseconds

enum socket_mode {
	SOCKET_MODE_BLOCKING = 0,
	SOCKET_MODE_NONBLOCKING
};

typedef enum {
	SOCKET_CMD_CONNECT = 0,
	SOCKET_CMD_SEND,
	SOCKET_CMD_RECV,
	SOCKET_CMD_CLOSE,
	SOCKET_CMD_LIST,
	SOCKET_CMD_HELP
} socket_command;

#define SOCKET_ID_NONE -1
#define SOCKET_FD_NONE -1
#define SOCKET_SEND_DATA_INTERVAL_NONE -1

typedef struct {
	socket_command command;
	int id;
	int family;
	int type;
	char ip_address[100+1];
	int port;
	int bind_port;
	bool data_to_be_sent;
	int data_length;
	int data_interval;
	bool receive_start;
} socket_cmd_args_t;

static socket_cmd_args_t socket_cmd_args;

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
	bool in_use;
	bool log_receive_data;
	int64_t recv_start_time_ms;
	int64_t recv_end_time_ms;
	uint32_t recv_data_len;
	bool recv_start_throughput;
	struct addrinfo *addrinfo;
	struct data_transfer_info send_info;
} socket_info_t;

static socket_info_t sockets[MAX_SOCKETS] = {0};
char send_buffer[SEND_BUFFER_SIZE];
char receive_buffer[RECEIVE_BUFFER_SIZE];
const struct shell* shell_global;


static void socket_cmd_args_clear(socket_cmd_args_t* args) {
	memset(args, 0, sizeof(socket_cmd_args_t));
	socket_cmd_args.id = SOCKET_ID_NONE;
	socket_cmd_args.family = AF_INET;
	socket_cmd_args.type = SOCK_STREAM;
	socket_cmd_args.data_interval = SOCKET_SEND_DATA_INTERVAL_NONE;
}

static void socket_info_clear(socket_info_t* socket_info) {
	if (socket_info->in_use) {
		close(socket_info->fd);
		freeaddrinfo(socket_info->addrinfo);
	}

	memset(socket_info, 0, sizeof(socket_info_t));

	socket_info->id = SOCKET_ID_NONE;
	socket_info->fd = SOCKET_FD_NONE;
	socket_info->log_receive_data = true;
}

static int get_socket_id_by_fd(int fd)
{
	for (int i = 0; i < MAX_SOCKETS; i++) {
		if (sockets[i].fd == fd) {
			return i;
		}
	}
	return -1;
}

static socket_info_t* reserve_socket_id()
{
	socket_info_t* socket_info = NULL;
	int socket_id = 0;
	while (socket_id < MAX_SOCKETS) {
		if (!sockets[socket_id].in_use) {
			socket_info = &(sockets[socket_id]);
			socket_info_clear(socket_info);
			socket_info->id = socket_id;
			break;
		}
		socket_id++;
	}
	return socket_info;
}

const char usage_str[] =
	"Usage: sock <command> [options]\n"
	"\n"
	"<command> is one of the following:\n"
	"  connect: Open socket and connect to given host. Mandatory options: -a, -p\n"
	"  close:   Close socket connection. Mandatory options: -i\n"
	"  send:    Send data. Mandatory options: -i\n"
	"  recv:    Initialize and query receive throughput metrics. Without -r option,\n"
	"           returns current metrics so that can be used as status request for receiving.\n"
	"           Mandatory options: -i\n"
	"  list:    List open sockets. No options available.\n"
	"  help:    Show this usage. No options available.\n"
	"\n"
	"General options:\n"
	"  -i, [int]  socket id. Use 'list' command to see open sockets.\n"
	"\n"
	"Options for 'connect' command:\n"
	"  -a, [str]  Address as ip address or hostname\n"
	"  -p, [int]  Port\n"
	"  -f, [str]  Address family: 'inet' (ipv4) or 'inet6' (ipv6)\n"
	"  -t, [str]  Address type: 'stream' (tcp) or 'dgram' (udp)\n"
	"  -b, [int]  Local port to bind the socket to\n"
	"\n"
	"Options for 'send' command:\n"
	"  -d, [str]  Data to be sent. Cannot be used with -l option.\n"
	"  -l, [int]  Length of undefined data in bytes. This can be used for testing with\n"
	"             bigger data amounts. Cannot be used with -d or -e option.\n"
	"  -e, [int]  Data sending interval in milliseconds. You must also specify -d.\n"
	"\n"
	"Options for 'recv' command:\n"
	"  -r, [bool] Initialize variables for receive throughput calculation\n"
	"\n"
	"Examples:\n"
	"\n"
	"connect\n"
	"send\n"
	"send -l\n"
	"send -e\n"
	"recv\n"
	;

static void print_usage()
{
	shell_print(shell_global, "%s", usage_str);
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

					if (socket_info->recv_start_throughput) {
						socket_info->recv_start_time_ms = k_uptime_get();
						socket_info->recv_start_throughput = false;
					}

					while ((buffer_size = recv(
							fds[i].fd,
							receive_buffer,
							RECEIVE_BUFFER_SIZE,
							0)) > 0) {
								
						if (socket_info->log_receive_data) {
							shell_print(shell_global,
								"Received data for socket socket_id=%d, buffer_size=%d:\n\t%s",
								socket_id,
								buffer_size,
								receive_buffer);
						}
						socket_info->recv_data_len += buffer_size;
						memset(receive_buffer, '\0',
							RECEIVE_BUFFER_SIZE);
					}
					socket_info->recv_end_time_ms = k_uptime_get();
				}
			}
		}
	}
	shell_print(shell_global, "socket_receive_handler exit");
}

K_THREAD_DEFINE(socket_receive_thread, RECEIVE_STACK_SIZE,
                socket_receive_handler, NULL, NULL, NULL,
                RECEIVE_PRIORITY, 0, 0);

static int socket_send(socket_info_t *socket_info, char* data, bool log_data)
{
	int bytes;

	if (log_data) {
		shell_print(shell_global, "Socket data send:\n\t%s", data);
	}

	if (socket_info->type == SOCK_STREAM) {
		// TCP
		bytes = send(socket_info->fd, data, strlen(data), 0);
	} else {
		// UDP
		int dest_addr_len = 0;
		if (socket_info->family == AF_INET) {
			dest_addr_len = sizeof(struct sockaddr_in);
		} else if (socket_info->family == AF_INET6) {
			dest_addr_len = sizeof(struct sockaddr_in6);
		}
		bytes = sendto(socket_info->fd, data, strlen(data), 0,
			socket_info->addrinfo->ai_addr, dest_addr_len);
	}
	if (bytes < 0) {
		shell_print(shell_global, "socket send failed, err %d", errno);
		return -1;
	}
	return bytes;
}

static void data_send_work_handler(struct k_work *item)
{
	struct data_transfer_info* data_send_info_ptr =
		CONTAINER_OF(item, struct data_transfer_info, work);
	int socket_id = data_send_info_ptr->socket_id;
	socket_info_t* socket_info = &sockets[socket_id];

	if (!sockets[socket_id].in_use) {
		shell_print(shell_global,
			"Socket id=%d not in use. Fatal error and sending won't work.",
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

static void set_socket_mode(int fd, enum socket_mode mode)
{
    int flags = fcntl(fd, F_GETFL, 0);

    if (mode == SOCKET_MODE_NONBLOCKING) {
        fcntl(fd, F_SETFL, flags | (int) O_NONBLOCK);
    } else if (mode == SOCKET_MODE_BLOCKING) {
        fcntl(fd, F_SETFL, flags & ~(int) O_NONBLOCK);
    }
}

static int socket_open_and_connect(int family, int type, char* ip_address, int port, int bind_port)
{
	int err;

	shell_print(shell_global, "Socket open and connect family=%d, type=%d, port=%d, bind_port=%d, ip_address=%s",
		family, type, port, bind_port, ip_address);

	// TODO: TLS support
	// TODO: Check that LTE link is connected because errors are not very descriptive if it's not.

	// Reserve socket ID and structure for a new connection
	socket_info_t* socket_info = reserve_socket_id();
	if (socket_info == NULL) {
		shell_error(shell_global, "Socket creation failed. MAX_SOCKETS=%d exceeded", MAX_SOCKETS);
		return -EINVAL;
	}

	// VALIDATE PARAMETERS

	// Validate family parameter
	if (family != AF_INET && family != AF_INET6) {
		shell_error(shell_global, "Unsupported address family=%d", family);
		return -EINVAL;
	}

	// Validate type parameter and map it to protocol
	int proto = 0;
	if (type == SOCK_STREAM) {
		proto = IPPROTO_TCP;
	} else if (type == SOCK_DGRAM) {
		proto = IPPROTO_UDP;
	} else {
		shell_error(shell_global, "Unsupported address type=%d", type);
		return -EINVAL;
	}

	// Validate port
	if (port < 1 || port > 65535) {
		shell_error(shell_global, "Port (%d) must be bigger than 0 and smaller than 65536", port);
		return -EINVAL;
	}

	// Validate bind port. Zero means that binding is not done.
	if (bind_port > 65535) {
		shell_error(shell_global, "Bind port (%d) must be smaller than 65536", port);
		return -EINVAL;
	}

	// CREATE SOCKET
	// If proto is set to zero to let lower stack select it,
	// socket creation fails with errno=43 (PROTONOSUPPORT)
	int fd = socket(family, type, proto);
	if (fd < 0) {
		shell_error(shell_global, "Socket create failed, err %d", errno);
		return errno;
	}
	// Socket has been created so populate its structure with information
	socket_info->in_use = true;
	socket_info->fd = fd;
	socket_info->family = family;
	socket_info->type = type;
	socket_info->port = port;
	socket_info->bind_port = bind_port;

	// GET ADDRESS
	struct addrinfo hints = {
		.ai_family = family,
		.ai_socktype = type,
	};
	err = getaddrinfo(ip_address, NULL, &hints, &socket_info->addrinfo);
	if (err) {
		shell_error(shell_global, "getaddrinfo() failed, err %d errno %d", err, errno);
		socket_info_clear(socket_info);
		return errno;
	}

	// Set port to address info
	if (family == AF_INET) {
		((struct sockaddr_in *)socket_info->addrinfo->ai_addr)->sin_port = htons(port);
	} else if (family == AF_INET6) {
		((struct sockaddr_in6 *)socket_info->addrinfo->ai_addr)->sin6_port = htons(port);
	} else {
		assert(0);
	}

	shell_print(shell_global, "Socket created socket_id=%d, fd=%d", socket_info->id, fd);

	// BIND SOCKET
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
			shell_error(shell_global, "Unable to bind, errno %d", errno);
			socket_info_clear(socket_info);
			return errno;
			}
		}

	if (type == SOCK_STREAM) {
		// Connect TCP socket
		err = connect(fd, socket_info->addrinfo->ai_addr, socket_info->addrinfo->ai_addrlen);
		if (err) {
			shell_error(shell_global, "Unable to connect, errno %d", errno);
			socket_info_clear(socket_info);
			return errno;
		}
	}

	// Set socket to non-blocking mode to make sure receiving is not blocking polling of all sockets.
	set_socket_mode(socket_info->fd, SOCKET_MODE_NONBLOCKING);
	return 0;
}

static void calculate_throughput(const struct shell *shell, uint32_t data_len, int64_t time_ms)
{
	// 8 for bits in one byte, and 1000 for ms->s conversion.
	// Parenthesis used to change order of multiplying so that intermediate values do not overflow from 32bit integer.
	double throughput = 8 * 1000 * ((double)data_len / time_ms);

	shell_print(shell_global,
			"Summary:\n"
			"Data length: %7u bytes\n"
			"Time:        %7.2f s\n"
			"Throughput:  %7.0f bit/s\n",
			data_len,
			(float)time_ms / 1000,
			throughput);
}

static int socket_send_data(socket_info_t* socket_info, char* data, int data_length, int interval) {

	// Enable receive data logging as previous commands might have left it disabled
	socket_info->log_receive_data = true;
	if (data_length > 0) {
		// Send given amount of data

		// Interval is not supported with data length
		if (interval != SOCKET_SEND_DATA_INTERVAL_NONE) {
			shell_error(shell_global, "Data lenght and interval cannot be specified at the same time");
			return -EINVAL;
		}

		uint32_t bytes_sent = 0;
		int data_left = data_length;
		socket_info->log_receive_data = false;
		set_socket_mode(socket_info->fd, SOCKET_MODE_BLOCKING);

		memset(send_buffer, 0, SEND_BUFFER_SIZE);
		memset(send_buffer, 'd', SEND_BUFFER_SIZE-1);

		int64_t time_stamp = k_uptime_get();
		while (data_left > 0) {
			if (data_left < SEND_BUFFER_SIZE-1) {
				memset(send_buffer, 0, SEND_BUFFER_SIZE-1);
				memset(send_buffer, 'l', data_left);
			}
			bytes_sent += socket_send(socket_info, send_buffer, false);
			data_left -= strlen(send_buffer);
		}
		int64_t ul_time_ms = k_uptime_delta(&time_stamp);
		memset(send_buffer, 0, SEND_BUFFER_SIZE);
		set_socket_mode(socket_info->fd, SOCKET_MODE_NONBLOCKING);
		calculate_throughput(shell_global, bytes_sent, ul_time_ms);

	} else if (interval != SOCKET_SEND_DATA_INTERVAL_NONE) {

		if (interval == 0 ) {
			// Stop periodic data sending
			if (k_timer_remaining_get(&socket_info->send_info.timer) > 0) {
				k_timer_stop(&socket_info->send_info.timer);
				shell_print(shell_global, "Socket data send periodic stop");
			} else {
				shell_error(shell_global, "Socket data send stop: periodic data not started");
				return -EINVAL;
			}
		} else if (interval > 0 ) {
			// Send data with given interval

			// Data to be sent must also be specified
			if (strlen(data) < 1) {
				shell_error(shell_global, "Data sending interval is specified without data to be send.");
				return -EINVAL;
			}

			memcpy(send_buffer, data, strlen(data));
			shell_print(shell_global, "Socket data send periodic with interval=%d", interval);
			k_timer_init(&socket_info->send_info.timer, data_send_timer_handler, NULL);
			k_work_init(&socket_info->send_info.work, data_send_work_handler);
			k_timer_start(&socket_info->send_info.timer, K_NO_WAIT, K_SECONDS(interval));
		}

	} else if (data != NULL && strlen(data) > 0) {
		// Send data if it's given and is not zero length
		socket_send(socket_info, data, true);
	} else {
		shell_print(shell_global, "No send parameters given");
		return -EINVAL;
	}
	return 0;
}

static void socket_recv(socket_info_t* socket_info, bool receive_start) {

	if (receive_start) {
		shell_print(shell_global, "Receive data calculation start socket id=%d", socket_info->id);
		socket_info->recv_start_throughput = true;
		socket_info->recv_data_len = 0;
		socket_info->log_receive_data = false;
		socket_info->recv_start_time_ms = 0;
		socket_info->recv_end_time_ms = 0;
	} else {
		calculate_throughput(shell_global, socket_info->recv_data_len, socket_info->recv_end_time_ms - socket_info->recv_start_time_ms);
	}
}

static void socket_close(socket_info_t* socket_info)
{
	shell_print(shell_global, "Close socket id=%d, fd=%d", socket_info->id, socket_info->fd);
	socket_info_clear(socket_info);
}

static void socket_list() {
	bool opened_sockets = false;
	for (int i = 0; i < MAX_SOCKETS; i++) {
		socket_info_t* socket_info = &(sockets[i]);
		if (socket_info->in_use) {
			opened_sockets = true;
			shell_print(shell_global, "Socket id=%d, fd=%d, family=%d, type=%d, port=%d, bind_port=%d", 
				i,
				socket_info->fd,
				socket_info->family,
				socket_info->type,
				socket_info->port,
				socket_info->bind_port);
		}
	}

	if (!opened_sockets) {
		shell_print(shell_global, "There are no open sockets");
	}
}

int socket_shell(const struct shell *shell, size_t argc, char **argv)
{
	int err = 0;
	shell_global = shell;
	socket_cmd_args_clear(&socket_cmd_args);
	// Before parsing the command line, reset getopt index to the start of the arguments
	optind = 1;

	if (argc < 2) {
		print_usage();
		return 0;
	}

	// Command = argv[1]
	bool require_socket_id = false;
	if (!strcmp(argv[1], "connect")) {
		socket_cmd_args.command = SOCKET_CMD_CONNECT;
	} else if (!strcmp(argv[1], "send")) {
		socket_cmd_args.command = SOCKET_CMD_SEND;
		require_socket_id = true;
		memset(send_buffer, 0, SEND_BUFFER_SIZE);
	} else if (!strcmp(argv[1], "recv")) {
		socket_cmd_args.command = SOCKET_CMD_RECV;
		require_socket_id = true;
	} else if (!strcmp(argv[1], "close")) {
		socket_cmd_args.command = SOCKET_CMD_CLOSE;
		require_socket_id = true;
	} else if (!strcmp(argv[1], "list")) {
		socket_cmd_args.command = SOCKET_CMD_LIST;
	} else if (!strcmp(argv[1], "help")) {
		socket_cmd_args.command = SOCKET_CMD_HELP;
	} else {
		shell_error(shell, "Unsupported command=%s\n", argv[1]);
		print_usage();
		return -EINVAL;
	}
	// Increase getopt command line parsing index not to handle command
	optind++;

	int flag;
	// TODO: Handle arguments in similar manner, i.e., move everything here or move 'data' to socket_cmd_args
	while ((flag = getopt(argc, argv, "i:a:p:f:t:b:d:l:e:r")) != -1) {
		int ip_address_len = 0;
		switch (flag) {
		case 'i': // Socket ID
			socket_cmd_args.id = atoi(optarg);
			break;
		case 'a': // IP address, or hostname
			ip_address_len = strlen(optarg);
			if (ip_address_len > 100) {
				shell_error(shell, "Address length %d exceeded. Maximum is 100.", ip_address_len);
			}
			memcpy(socket_cmd_args.ip_address, optarg, ip_address_len);
			break;
		case 'p': // Port
			socket_cmd_args.port = atoi(optarg);
			break;
		case 'f': // Address family
			if (!strcmp(optarg, "inet")) {
				socket_cmd_args.family = AF_INET;
			} else if (!strcmp(optarg, "inet6")) {
				socket_cmd_args.family = AF_INET6;
			} else if (!strcmp(optarg, "packet")) {
				socket_cmd_args.family = AF_PACKET;
			} else {
				shell_error(shell, "Unsupported family=%s", optarg);
				return -EINVAL;
			}
			break;
		case 't': // Socket type
			if (!strcmp(optarg, "stream")) {
				socket_cmd_args.type = SOCK_STREAM;
			} else if (!strcmp(optarg, "dgram")) {
				socket_cmd_args.type = SOCK_DGRAM;
			} else if (!strcmp(optarg, "raw")) {
				socket_cmd_args.type = SOCK_RAW;
			} else {
				shell_error(shell, "Unsupported type=%s", optarg);
				return -EINVAL;
			}
			break;
		case 'b': // Bind port
			socket_cmd_args.bind_port = atoi(optarg);
			break;
		case 'd': // Data to be sent is available in send buffer
			strcpy(send_buffer, optarg);
			break;
		case 'l': // Length of undefined data to be sent
			socket_cmd_args.data_length = atoi(optarg);
			break;
		case 'e': // Interval in which data will be sent
			socket_cmd_args.data_interval = atoi(optarg);
			break;
		case 'r': // Start monitoring received data
			socket_cmd_args.receive_start = true;
			break;
		}
	}

	socket_info_t *socket_info = NULL;
	if (require_socket_id) {
		if (socket_cmd_args.id == SOCKET_ID_NONE) {
			shell_error(shell, "Socket id not given. -i option is mandatory for command=%s",
				argv[1]); // TODO: Change argv to command
			return -EINVAL;
		}
		if (socket_cmd_args.id < 0 || socket_cmd_args.id > MAX_SOCKETS) {
			shell_error(shell, "Socket id=%d must a postive number smaller than %d",
				socket_cmd_args.id, MAX_SOCKETS);
			return -EINVAL;
		}
		socket_info = &(sockets[socket_cmd_args.id]);
		if (!socket_info->in_use) {
			shell_error(shell, "Socket id=%d not available", socket_cmd_args.id);
			return -EINVAL;
		}
	}

	switch (socket_cmd_args.command) {
		case SOCKET_CMD_CONNECT:
			err = socket_open_and_connect(socket_cmd_args.family, socket_cmd_args.type, socket_cmd_args.ip_address, socket_cmd_args.port, socket_cmd_args.bind_port);
			break;
		case SOCKET_CMD_SEND:
			err = socket_send_data(socket_info, send_buffer, socket_cmd_args.data_length, socket_cmd_args.data_interval);
			break;
		case SOCKET_CMD_RECV:
			socket_recv(socket_info, socket_cmd_args.receive_start);
			break;
		case SOCKET_CMD_CLOSE:
			socket_close(socket_info);
			break;
		case SOCKET_CMD_LIST:
			socket_list();
			break;
		case SOCKET_CMD_HELP:
			print_usage();
			break;
		default:
			shell_error(shell, "Internal error. Unknown socket command=%d", socket_cmd_args.command);
			err = -EINVAL;
			break;
	}

	return err;
}
