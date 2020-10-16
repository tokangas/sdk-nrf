#include <shell/shell.h>
#include <assert.h>
#include <strings.h>
#include <stdio.h>
#if defined (CONFIG_POSIX_API)
#include <unistd.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#else
#include <net/socket.h>
#endif
#include <fcntl.h>

#include "fta_defines.h"
#include "ltelc_api.h"
#include "utils/freebsd-getopt/getopt.h"
#include "utils/fta_net_utils.h"

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

static socket_info_t sockets[MAX_SOCKETS] = {0};
char send_buffer[SEND_BUFFER_SIZE];
char receive_buffer[RECEIVE_BUFFER_SIZE];
const struct shell* shell_global;


static void socket_info_clear(socket_info_t* socket_info) {
	if (socket_info->in_use) {
		close(socket_info->fd);
	}
	freeaddrinfo(socket_info->addrinfo);

	memset(socket_info, 0, sizeof(socket_info_t));

	socket_info->id = SOCKET_ID_NONE;
	socket_info->fd = SOCKET_FD_NONE;
	socket_info->log_receive_data = true;
}

static int get_socket_id_by_fd(int fd)
{
	for (int i = 0; i < MAX_SOCKETS; i++) {
		if (sockets[i].fd == fd) {
			assert(i == sockets[i].id);
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
	"           returns current metrics so that can be used both as status request\n"
	"           and final summary for receiving.\n"
	"           Mandatory options: -i\n"
	"  list:    List open sockets. No options available.\n"
	"  help:    Show this usage. No mandatory options.\n"
	"\n"
	"General options:\n"
	"  -i, [int]  Socket id. Use 'list' command to see open sockets.\n"
	"\n"
	"Options for 'connect' command:\n"
	"  -a, [str]  Address as ip address or hostname\n"
	"  -p, [int]  Port\n"
	"  -f, [str]  Address family: 'inet' (ipv4, default) or 'inet6' (ipv6)\n"
	"  -t, [str]  Address type: 'stream' (tcp, default) or 'dgram' (udp)\n"
	"  -b, [int]  Local port to bind the socket to\n"
	"  -I, [int]  Use this option to bind socket to specific PDN CID.\n"
	"             See ltelc command for available interfaces.\n"
	"\n"
	"Options for 'send' command:\n"
	"  -d, [str]  Data to be sent. Cannot be used with -l option.\n"
	"  -l, [int]  Length of undefined data in bytes. This can be used when testing\n"
	"             with bigger data amounts. Cannot be used with -d or -e option.\n"
	"  -e, [int]  Data sending interval in milliseconds. You must also specify -d.\n"
	"\n"
	"Options for 'recv' command:\n"
	"  -r, [bool] Initialize variables for receive throughput calculation\n"
	"\n"
	"Options for 'help' command:\n"
	"  -v, [bool] Show examples\n"
	;

const char usage_example_str[] =
	"Examples:\n"
	"\n"
	"Open and connect to an ip address and port (IPv4 TCP socket):\n"
	"  sock connect -a 111.222.111.222 -p 20000\n"
	"\n"
	"Open and connect to hostname and port (IPv4 TCP socket):\n"
	"  sock connect -a google.com -p 20000\n"
	"\n"
	"Open and connect IPv6 TCP socket and bind to a port:\n"
	"  sock connect -a 1a2b:1a2b:1a2b:1a2b::1 -p 20000 -f inet6 -t stream -b 40000\n"
	"\n"
	"Open IPv6 UDP socket:\n"
	"  sock connect -a 1a2b:1a2b:1a2b:1a2b::1 -p 20000 -f inet6 -t dgram\n"
	"\n"
	"Send string through socket:\n"
	"  sock send -i 0 -d testing\n"
	"\n"
	"Send 100kB of data and show throughput statistics:\n"
	"  sock send -i 0 -l 100000\n"
	"\n"
	"Send data periodically with 10s interval:\n"
	"  sock send -i 0 -e 10 -d test_periodic\n"
	"\n"
	"Calculate receive throughput:\n"
	"  <do whatever is needed to make device receive data after some time>\n"
	"  sock recv -i 0 -r\n"
	"  sock recv -i 0\n"
	"  sock recv -i 0\n"
	"\n"
	"Close socket:\n"
	"  sock close -i 0\n"
	"\n"
	"List open sockets:\n"
	"  sock list\n"
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
				int socket_id = get_socket_id_by_fd(fds[i].fd);
				if (socket_id == SOCKET_ID_NONE) {
					// Socket has been already deleted from internal structures.
					// This occurs at least when we close socket after which
					// there will be notification for it.
					continue;
				}
				socket_info_t* socket_info = &(sockets[socket_id]);

				if (fds[i].revents & POLLIN) {
					int buffer_size;

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
				if (fds[i].revents & POLLHUP) {
					shell_print(shell_global, "Socket id=%d (fd=%d) disconnected so closing.", socket_id, fds[i].fd);
					socket_info_clear(socket_info);
				}
				if (fds[i].revents & POLLNVAL) {
					shell_print(shell_global, "Socket id=%d invalid", socket_id);
					socket_info_clear(socket_info);
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

static int socket_open_and_connect(int family, int type, char* ip_address, int port, int bind_port, int pdn_cid)
{
	int err;

	shell_print(shell_global, "Socket open and connect family=%d, type=%d, port=%d, bind_port=%d, pdn_cid=%d, ip_address=%s",
		family, type, port, bind_port, pdn_cid, ip_address);

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
	socket_info->pdn_cid = pdn_cid;

	if (pdn_cid > 0) {
		int ret;
		char apn_str[FTA_APN_STR_MAX_LEN];
		memset(apn_str, 0, FTA_APN_STR_MAX_LEN);
		pdp_context_info_array_t pdp_context_info_tbl;

		ret = ltelc_api_default_pdp_context_read(&pdp_context_info_tbl);
		if (ret) {
			shell_error(shell_global, "cannot read current connection info: %d", ret);
			return -1;
		} else {
			/* Find PDP context info for requested CID */
			int i;
			bool found = false;

			for (i = 0; i < pdp_context_info_tbl.size; i++) {
				if (pdp_context_info_tbl.array[i].cid == pdn_cid) {
					strcpy(apn_str, pdp_context_info_tbl.array[i].apn_str);
					found = true;
				}
			}
			if (!found) {
				shell_error(shell_global, "cannot find CID: %d", pdn_cid);
				return -1;
			}
		}

		/* Binding a data socket to an APN: */
		ret = fta_net_utils_socket_apn_set(fd, apn_str);
		if (ret != 0) {
			shell_error(shell_global, "Cannot bind socket to apn %s", apn_str);
			shell_error(shell_global, "probably due to https://projecttools.nordicsemi.no/jira/browse/NCSDK-6645");

			if (pdp_context_info_tbl.array != NULL)
				free(pdp_context_info_tbl.array);
			return -1;
		}

		if (pdp_context_info_tbl.array != NULL)
			free(pdp_context_info_tbl.array);
	}

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

static double calculate_throughput(uint32_t data_len, int64_t time_ms)
{
	// 8 for bits in one byte, and 1000 for ms->s conversion.
	// Parenthesis used to change order of multiplying so that intermediate values do not overflow from 32bit integer.
	double throughput = 8 * 1000 * ((double)data_len / time_ms);

	return throughput;
}

static void print_throughput_summary(uint32_t data_len, int64_t time_ms)
{
	char output_buffer[100];

	// 8 for bits in one byte, and 1000 for ms->s conversion.
	// Parenthesis used to change order of multiplying so that intermediate values do not overflow from 32bit integer.
	double throughput = calculate_throughput(data_len, time_ms);

	sprintf(output_buffer,
		"\nSummary:\n"
		"Data length: %7u bytes\n"
		"Time:        %7.2f s\n"
		"Throughput:  %7.0f bit/s\n",
		data_len,
		(float)time_ms / 1000,
		throughput);

	shell_print(shell_global, "%s", output_buffer);
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
		int print_interval = 10;
		char output_buffer[50];
		while (data_left > 0) {
			if (data_left < SEND_BUFFER_SIZE-1) {
				memset(send_buffer, 0, SEND_BUFFER_SIZE-1);
				memset(send_buffer, 'l', data_left);
			}
			bytes_sent += socket_send(socket_info, send_buffer, false);
			data_left -= strlen(send_buffer);

			// Print throughput stats every 10 seconds
			int64_t time_intermediate = k_uptime_get();
			int64_t ul_time_intermediate_ms = time_intermediate - time_stamp;

			if ((ul_time_intermediate_ms / (double)1000) > print_interval) {
				double throughput = calculate_throughput(bytes_sent, ul_time_intermediate_ms);
				sprintf(output_buffer, "%7u bytes, %6.2fs, %6.0f bit/s",
					bytes_sent, (float)ul_time_intermediate_ms / 1000, throughput);
				shell_print(shell_global, "%s", output_buffer);
				print_interval += 10;
			}
		}
		int64_t ul_time_ms = k_uptime_delta(&time_stamp);
		memset(send_buffer, 0, SEND_BUFFER_SIZE);
		set_socket_mode(socket_info->fd, SOCKET_MODE_NONBLOCKING);
		print_throughput_summary(bytes_sent, ul_time_ms);

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
		print_throughput_summary(
			socket_info->recv_data_len,
			socket_info->recv_end_time_ms - socket_info->recv_start_time_ms);
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
			shell_print(shell_global, "Socket id=%d, fd=%d, family=%d, type=%d, port=%d, bind_port=%d, pdn=%d", 
				i,
				socket_info->fd,
				socket_info->family,
				socket_info->type,
				socket_info->port,
				socket_info->bind_port,
				socket_info->pdn_cid);
		}
	}

	if (!opened_sockets) {
		shell_print(shell_global, "There are no open sockets");
	}
}

static void socket_help(bool verbose) {
	print_usage();
	if (verbose) {
		shell_print(shell_global, "%s", usage_example_str);
	}
}

int socket_shell(const struct shell *shell, size_t argc, char **argv)
{
	int err = 0;
	shell_global = shell;
	// Before parsing the command line, reset getopt index to the start of the arguments
	optind = 1;

	if (argc < 2) {
		print_usage();
		return 0;
	}

	// Command = argv[1]
	socket_command command;
	bool require_socket_id = false;
	if (!strcmp(argv[1], "connect")) {
		command = SOCKET_CMD_CONNECT;
	} else if (!strcmp(argv[1], "send")) {
		command = SOCKET_CMD_SEND;
		require_socket_id = true;
		memset(send_buffer, 0, SEND_BUFFER_SIZE);
	} else if (!strcmp(argv[1], "recv")) {
		command = SOCKET_CMD_RECV;
		require_socket_id = true;
	} else if (!strcmp(argv[1], "close")) {
		command = SOCKET_CMD_CLOSE;
		require_socket_id = true;
	} else if (!strcmp(argv[1], "list")) {
		command = SOCKET_CMD_LIST;
	} else if (!strcmp(argv[1], "help")) {
		command = SOCKET_CMD_HELP;
	} else {
		shell_error(shell, "Unsupported command=%s\n", argv[1]);
		print_usage();
		return -EINVAL;
	}
	// Increase getopt command line parsing index not to handle command
	optind++;

	int flag = 0;
	int arg_socket_id = SOCKET_ID_NONE;
	int arg_family = AF_INET;
	int arg_type = SOCK_STREAM;
	char arg_ip_address[100+1];
	int arg_port = 0;
	int arg_bind_port = 0;
	int arg_pdn_cid = 0;
	int arg_data_length = 0;
	int arg_data_interval = SOCKET_SEND_DATA_INTERVAL_NONE;
	bool arg_receive_start = false;
	bool arg_verbose = false;
	while ((flag = getopt(argc, argv, "i:I:a:p:f:t:b:d:l:e:rv")) != -1) {
		int ip_address_len = 0;
		switch (flag) {
		case 'i': // Socket ID
			arg_socket_id = atoi(optarg);
			break;
		case 'I': // PDN CID
			arg_pdn_cid = atoi(optarg);
			if (arg_pdn_cid == 0) {
				shell_error(shell, "PDN CID (%d) must be positive integer.", arg_pdn_cid);
				return -EINVAL;
			}
			break;
		case 'a': // IP address, or hostname
			ip_address_len = strlen(optarg);
			if (ip_address_len > 100) {
				shell_error(shell, "Address length %d exceeded. Maximum is 100.", ip_address_len);
			}
			memcpy(arg_ip_address, optarg, ip_address_len);
			break;
		case 'p': // Port
			arg_port = atoi(optarg);
			break;
		case 'f': // Address family
			if (!strcmp(optarg, "inet")) {
				arg_family = AF_INET;
			} else if (!strcmp(optarg, "inet6")) {
				arg_family = AF_INET6;
			} else if (!strcmp(optarg, "packet")) {
				arg_family = AF_PACKET;
			} else {
				shell_error(shell, "Unsupported family=%s", optarg);
				return -EINVAL;
			}
			break;
		case 't': // Socket type
			if (!strcmp(optarg, "stream")) {
				arg_type = SOCK_STREAM;
			} else if (!strcmp(optarg, "dgram")) {
				arg_type = SOCK_DGRAM;
			} else {
				shell_error(shell, "Unsupported type=%s", optarg);
				return -EINVAL;
			}
			break;
		case 'b': // Bind port
			arg_bind_port = atoi(optarg);
			break;
		case 'd': // Data to be sent is available in send buffer
			strcpy(send_buffer, optarg);
			break;
		case 'l': // Length of undefined data to be sent
			arg_data_length = atoi(optarg);
			break;
		case 'e': // Interval in which data will be sent
			arg_data_interval = atoi(optarg);
			break;
		case 'r': // Start monitoring received data
			arg_receive_start = true;
			break;
		case 'v': // Start monitoring received data
			arg_verbose = true;
			break;
		}
	}

	socket_info_t *socket_info = NULL;
	if (require_socket_id) {
		if (arg_socket_id == SOCKET_ID_NONE) {
			shell_error(shell, "Socket id not given. -i option is mandatory for command=%s",
				argv[1]); // TODO: Change argv to command
			return -EINVAL;
		}
		if (arg_socket_id < 0 || arg_socket_id > MAX_SOCKETS) {
			shell_error(shell, "Socket id=%d must a postive number smaller than %d",
				arg_socket_id, MAX_SOCKETS);
			return -EINVAL;
		}
		socket_info = &(sockets[arg_socket_id]);
		if (!socket_info->in_use) {
			shell_error(shell, "Socket id=%d not available", arg_socket_id);
			return -EINVAL;
		}
	}

	switch (command) {
		case SOCKET_CMD_CONNECT:
			err = socket_open_and_connect(arg_family, arg_type, arg_ip_address, arg_port, arg_bind_port, arg_pdn_cid);
			break;
		case SOCKET_CMD_SEND:
			err = socket_send_data(socket_info, send_buffer, arg_data_length, arg_data_interval);
			break;
		case SOCKET_CMD_RECV:
			socket_recv(socket_info, arg_receive_start);
			break;
		case SOCKET_CMD_CLOSE:
			socket_close(socket_info);
			break;
		case SOCKET_CMD_LIST:
			socket_list();
			break;
		case SOCKET_CMD_HELP:
			socket_help(arg_verbose);
			break;
		default:
			shell_error(shell, "Internal error. Unknown socket command=%d", command);
			err = -EINVAL;
			break;
	}

	return err;
}
