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

#include "sock.h"
#include "fta_defines.h"
#include "ltelc_api.h"
#include "utils/freebsd-getopt/getopt.h"
#include "utils/fta_net_utils.h"

// Maximum number of sockets set to CONFIG_POSIX_MAX_FDS-1 as AT commands reserve one
#define MAX_SOCKETS (CONFIG_POSIX_MAX_FDS-1)
#define SOCK_SEND_BUFFER_SIZE 4096+1
#define SOCK_RECEIVE_BUFFER_SIZE 1536
#define SOCK_RECEIVE_STACK_SIZE 2048
#define SOCK_RECEIVE_PRIORITY 5
// Timeout for polling socket receive data. This limits how quickly data can be received after socket creation.
#define SOCK_RECEIVE_POLL_TIMEOUT_MS 1000 // Milliseconds
#define SOCK_FD_NONE -1

enum sock_mode {
	SOCK_MODE_BLOCKING = 0,
	SOCK_MODE_NONBLOCKING
};

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
} sock_info_t;

sock_info_t sockets[MAX_SOCKETS] = {0};
char send_buffer[SOCK_SEND_BUFFER_SIZE];
char receive_buffer[SOCK_RECEIVE_BUFFER_SIZE];
extern const struct shell* shell_global; // TODO: Get rid of this variable here


static void sock_info_clear(sock_info_t* socket_info) {
	if (socket_info->in_use) {
		close(socket_info->fd);
	}
	freeaddrinfo(socket_info->addrinfo);

	memset(socket_info, 0, sizeof(sock_info_t));

	socket_info->id = SOCK_ID_NONE;
	socket_info->fd = SOCK_FD_NONE;
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

static sock_info_t* get_socket_info_by_id(int socket_id)
{
	sock_info_t *socket_info = NULL;
	if (socket_id == SOCK_ID_NONE) {
		shell_error(shell_global, "Socket id not given. -i option is mandatory"); //for command=%s", argv[1]); // TODO: Can we print command somehow
		return NULL;
	}
	if (socket_id < 0 || socket_id > MAX_SOCKETS) {
		shell_error(shell_global, "Socket id=%d must a postive number smaller than %d",
			socket_id, MAX_SOCKETS);
		return NULL;
	}
	socket_info = &(sockets[socket_id]);
	if (!socket_info->in_use) {
		shell_error(shell_global, "Socket id=%d not available", socket_id);
		return NULL;
	}
	return socket_info;
}

static sock_info_t* reserve_socket_id()
{
	sock_info_t* socket_info = NULL;
	int socket_id = 0;
	while (socket_id < MAX_SOCKETS) {
		if (!sockets[socket_id].in_use) {
			socket_info = &(sockets[socket_id]);
			sock_info_clear(socket_info);
			socket_info->id = socket_id;
			break;
		}
		socket_id++;
	}
	return socket_info;
}

static void set_sock_mode(int fd, enum sock_mode mode)
{
    int flags = fcntl(fd, F_GETFL, 0);

    if (mode == SOCK_MODE_NONBLOCKING) {
        fcntl(fd, F_SETFL, flags | (int) O_NONBLOCK);
    } else if (mode == SOCK_MODE_BLOCKING) {
        fcntl(fd, F_SETFL, flags & ~(int) O_NONBLOCK);
    }
}

int sock_open_and_connect(int family, int type, char* address, int port, int bind_port, int pdn_cid)
{
	int err;

	shell_print(shell_global, "Socket open and connect family=%d, type=%d, port=%d, bind_port=%d, pdn_cid=%d, address=%s",
		family, type, port, bind_port, pdn_cid, address);

	// TODO: TLS support
	// TODO: Check that LTE link is connected because errors are not very descriptive if it's not.

	// Reserve socket ID and structure for a new connection
	sock_info_t* socket_info = reserve_socket_id();
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
		shell_error(shell_global, "Bind port (%d) must be smaller than 65536", bind_port);
		return -EINVAL;
	}

	// GET ADDRESS
	if ((address == NULL) || (strlen(address) == 0)) {
		shell_error(shell_global, "Address not given");
		sock_info_clear(socket_info);
		return -EINVAL;
	}

	struct addrinfo hints = {
		.ai_family = family,
		.ai_socktype = type,
	};
	err = getaddrinfo(address, NULL, &hints, &socket_info->addrinfo);
	if (err) {
		shell_error(shell_global, "getaddrinfo() failed, err %d errno %d", err, errno);
		sock_info_clear(socket_info);
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

	// CREATE SOCKET
	// If proto is set to zero to let lower stack select it,
	// socket creation fails with errno=43 (PROTONOSUPPORT)
	int fd = socket(family, type, proto);
	if (fd < 0) {
		if (errno == ENFILE || errno == EMFILE) {
			shell_error(shell_global,
				"Socket creation failed due to maximum number of sockets in the system exceeded (%d). "
				"Notice that all file descriptors in the system are taken into account and "
				"not just sockets created through this application.", CONFIG_POSIX_MAX_FDS);
		} else {
			shell_error(shell_global, "Socket create failed, err %d", errno);
		}
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
			sock_info_clear(socket_info);
			return errno;
			}
		}

	if (type == SOCK_STREAM) {
		// Connect TCP socket
		err = connect(fd, socket_info->addrinfo->ai_addr, socket_info->addrinfo->ai_addrlen);
		if (err) {
			shell_error(shell_global, "Unable to connect, errno %d", errno);
			sock_info_clear(socket_info);
			return errno;
		}
	}

	// Set socket to non-blocking mode to make sure receiving is not blocking polling of all sockets.
	set_sock_mode(socket_info->fd, SOCK_MODE_NONBLOCKING);

	shell_print(shell_global, "Socket created socket_id=%d, fd=%d", socket_info->id, fd);

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

static int sock_send(sock_info_t *socket_info, char* data, bool log_data)
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
	sock_info_t* socket_info = &sockets[socket_id];

	if (!sockets[socket_id].in_use) {
		shell_print(shell_global,
			"Socket id=%d not in use. Fatal error and sending won't work.",
			socket_id);
			// TODO: stop timer
		return;
	}

	sock_send(socket_info, send_buffer, true);
}

static void data_send_timer_handler(struct k_timer *dummy)
{
	struct data_transfer_info* data_send_info_ptr =
		CONTAINER_OF(dummy, struct data_transfer_info, timer);
	int socket_id = data_send_info_ptr->socket_id;
	sock_info_t* socket_info = &sockets[socket_id];

	k_work_submit(&socket_info->send_info.work);
}

int sock_send_data(int socket_id, char* data, int data_length, int interval)
{
	sock_info_t* socket_info = get_socket_info_by_id(socket_id);
	if (socket_info == NULL) {
		return -EINVAL;
	}

	// Enable receive data logging as previous commands might have left it disabled
	socket_info->log_receive_data = true;
	if (data_length > 0) {
		// Send given amount of data

		// Interval is not supported with data length
		if (interval != SOCK_SEND_DATA_INTERVAL_NONE) {
			shell_error(shell_global, "Data lenght and interval cannot be specified at the same time");
			return -EINVAL;
		}

		uint32_t bytes_sent = 0;
		int data_left = data_length;
		socket_info->log_receive_data = false;
		set_sock_mode(socket_info->fd, SOCK_MODE_BLOCKING);

		memset(send_buffer, 0, SOCK_SEND_BUFFER_SIZE);
		memset(send_buffer, 'd', SOCK_SEND_BUFFER_SIZE-1);

		int64_t time_stamp = k_uptime_get();
		int print_interval = 10;
		char output_buffer[50];
		while (data_left > 0) {
			if (data_left < SOCK_SEND_BUFFER_SIZE-1) {
				memset(send_buffer, 0, SOCK_SEND_BUFFER_SIZE-1);
				memset(send_buffer, 'l', data_left);
			}
			bytes_sent += sock_send(socket_info, send_buffer, false);
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
		memset(send_buffer, 0, SOCK_SEND_BUFFER_SIZE);
		set_sock_mode(socket_info->fd, SOCK_MODE_NONBLOCKING);
		print_throughput_summary(bytes_sent, ul_time_ms);

	} else if (interval != SOCK_SEND_DATA_INTERVAL_NONE) {

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
				shell_error(shell_global, "Data sending interval is specified without data to be send");
				return -EINVAL;
			}

			memset(send_buffer, 0, SOCK_SEND_BUFFER_SIZE);
			memcpy(send_buffer, data, strlen(data));
			shell_print(shell_global, "Socket data send periodic with interval=%d", interval);
			k_timer_init(&socket_info->send_info.timer, data_send_timer_handler, NULL);
			k_work_init(&socket_info->send_info.work, data_send_work_handler);
			k_timer_start(&socket_info->send_info.timer, K_NO_WAIT, K_SECONDS(interval));
		}

	} else if (data != NULL && strlen(data) > 0) {
		// Send data if it's given and is not zero length
		sock_send(socket_info, data, true);
	} else {
		shell_print(shell_global, "No send parameters given");
		return -EINVAL;
	}
	return 0;
}

static void sock_receive_handler()
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

		int ret = poll(fds, count, SOCK_RECEIVE_POLL_TIMEOUT_MS);

		if (ret > 0) {
			for (int i = 0; i < count; i++) {
				int socket_id = get_socket_id_by_fd(fds[i].fd);
				if (socket_id == SOCK_ID_NONE) {
					// Socket has been already deleted from internal structures.
					// This occurs at least when we close socket after which
					// there will be notification for it.
					continue;
				}
				sock_info_t* socket_info = &(sockets[socket_id]);

				if (fds[i].revents & POLLIN) {
					int buffer_size;

					if (socket_info->recv_start_throughput) {
						socket_info->recv_start_time_ms = k_uptime_get();
						socket_info->recv_start_throughput = false;
					}

					while ((buffer_size = recv(
							fds[i].fd,
							receive_buffer,
							SOCK_RECEIVE_BUFFER_SIZE,
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
							SOCK_RECEIVE_BUFFER_SIZE);
					}
					socket_info->recv_end_time_ms = k_uptime_get();
				}
				if (fds[i].revents & POLLHUP) {
					shell_print(shell_global, "Socket id=%d (fd=%d) disconnected so closing.", socket_id, fds[i].fd);
					sock_info_clear(socket_info);
				}
				if (fds[i].revents & POLLNVAL) {
					shell_print(shell_global, "Socket id=%d invalid", socket_id);
					sock_info_clear(socket_info);
				}
			}
		}
	}
	shell_print(shell_global, "sock_receive_handler exit");
}

K_THREAD_DEFINE(sock_receive_thread, SOCK_RECEIVE_STACK_SIZE,
                sock_receive_handler, NULL, NULL, NULL,
                SOCK_RECEIVE_PRIORITY, 0, 0);

int sock_recv(int socket_id, bool receive_start)
{
	sock_info_t* socket_info = get_socket_info_by_id(socket_id);
	if (socket_info == NULL) {
		return -EINVAL;
	}

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
	return 0;
}

int sock_close(int socket_id)
{
	sock_info_t* socket_info = get_socket_info_by_id(socket_id);
	if (socket_info == NULL) {
		return -EINVAL;
	}
	shell_print(shell_global, "Close socket id=%d, fd=%d", socket_info->id, socket_info->fd);
	sock_info_clear(socket_info);
	return 0;
}

int sock_list() {
	bool opened_sockets = false;
	for (int i = 0; i < MAX_SOCKETS; i++) {
		sock_info_t* socket_info = &(sockets[i]);
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
	return 0;
}
