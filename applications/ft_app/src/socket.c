#include <shell/shell.h>
#include <strings.h>
#include <net/socket.h>
//#include <nrf_socket.h>

#define MAX_SOCKETS 4
#define RECEIVE_BUFFER_SIZE 1536
#define RECEIVE_STACK_SIZE 2048
#define RECEIVE_PRIORITY 5
#define DEFAULT_DATA_SEND_INTERVAL 10 // Seconds


typedef struct
{
    int fd;
    int family;
    int type;
    int port;
    bool in_use;
    struct addrinfo *addrinfo;
} socket_info_t;

struct data_receive_info {
	struct k_work work;
	int socket_id;
};

static socket_info_t sockets[MAX_SOCKETS] = {0};
char receive_buffer[RECEIVE_BUFFER_SIZE];
static struct data_receive_info data_receive_struct;
static struct k_work_q my_work_q;

K_THREAD_STACK_DEFINE(receive_stack_area, RECEIVE_STACK_SIZE);

// TODO: DELETE THESE when sending with interval has been implemented
static int fd = -1;
static struct addrinfo *addrinfo_res;
static const char dummy_data[] = "01234567890123456789012345678901"
				 "01234567890123456789012345678901"
				 "01234567890123456789012345678901"
				 "01234567890123456789012345678901"
				 "01234567890123456789012345678901"
				 "01234567890123456789012345678901"
				 "01234567890123456789012345678901"
				 "01234567890123456789012345678901";


void socket_info_clear(socket_info_t* socket_info) {
	close(socket_info->fd);
	socket_info->fd = -1;
	socket_info->in_use = false;
	freeaddrinfo(socket_info->addrinfo);
	socket_info->addrinfo = NULL;
}

static void data_recv_handler(struct k_work *item)
{
	struct data_receive_info* data_receive_info =
		CONTAINER_OF(item, struct data_receive_info, work);
	int socket_id = data_receive_info->socket_id;
	socket_info_t* socket_info = &sockets[socket_id];

	if (!sockets[socket_id].in_use) {
		printk("Socket id=%d not in use. Fatal error and receiving won't work.\n",
			socket_id);
		return;
	}

	printk("data receive handler started for socket_id=%d, fd=%d\n", socket_id, socket_info->fd);
	int buffer_size;
	while ((buffer_size = recv(socket_info->fd, receive_buffer, RECEIVE_BUFFER_SIZE, 0)) > 0) {
		printk("\nreceived data for socket id=%d,buffer_size=%d:\n%s",
			socket_id,
			buffer_size,
			receive_buffer);
		memset(receive_buffer, '\0', RECEIVE_BUFFER_SIZE);
	}
	printk("data receive handler exit\n");
}

static void socket_receive(int socket_id)
{
	data_receive_struct.socket_id = socket_id;

	k_work_q_start(&my_work_q, receive_stack_area,
			K_THREAD_STACK_SIZEOF(receive_stack_area), RECEIVE_PRIORITY);
	k_work_init(&data_receive_struct.work, data_recv_handler);
	k_work_submit_to_queue(&my_work_q, &data_receive_struct.work);
}

static void socket_open_and_connect(int family, int type, int proto, char* ip_address, int port, int bind_port)
{
	// TODO: TLS support
	// TODO: Bind hasn't been done

	int err;
	struct addrinfo hints = {
		.ai_family = family,
		.ai_socktype = type,
	};

	/*struct sockaddr bind_addr = {
		0,
	};*/

	//printk("socket created ip_address=%s\n", ip_address);

	// Create socket
	socket_info_t *socket_info = NULL;
	int socket_id = 0;
	while (socket_id < MAX_SOCKETS) {
		if (!sockets[socket_id].in_use) {
			socket_info = &(sockets[socket_id]);
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
	fd = socket(family, type, proto);
	if (fd < 0) {
		printk("socket create failed, err %d\n", errno);
		return;
	}
	socket_info->in_use = true;
	socket_info->fd = fd;
	socket_info->family = family;
	socket_info->type = type;
	socket_info->port = port;

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
	/*
	if (bind_port > 0) {
		err = bind(fd, addrinfo_res->ai_addr, sizeof(addrinfo_res->ai_addr));
		if (err) {
			printk("Unable to bind, errno %d\n", errno);
			return;
		}
	}*/

	if (type == SOCK_STREAM) {
		// Connect TCP socket
		err = connect(fd, socket_info->addrinfo->ai_addr, socket_info->addrinfo->ai_addrlen);
		if (err) {
			printk("Unable to connect, errno %d\n", errno);
			socket_info_clear(socket_info);
			return;
		}
		socket_receive(socket_id);
	}
}

static void udp_socket_open()
{
	int err;
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_DGRAM,
	};

	/* Use dummy destination address and port */
	err = getaddrinfo("5.189.130.26", NULL, &hints, &addrinfo_res);
	if (err) {
		printk("getaddrinfo() failed, err %d\n", errno);
		return;
	}

	((struct sockaddr_in *)addrinfo_res->ai_addr)->sin_port = htons(61234);

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
}

static void data_send_work_handler(struct k_work *work)
{
	sendto(fd, dummy_data, sizeof(dummy_data) - 1, 0,
	       addrinfo_res->ai_addr, sizeof(struct sockaddr_in));
}

K_WORK_DEFINE(data_send_work, data_send_work_handler);

static void data_send_timer_handler(struct k_timer *dummy)
{
	k_work_submit(&data_send_work);
}

K_TIMER_DEFINE(data_send_timer, data_send_timer_handler, NULL);

int app_cmd_data_start(const struct shell *shell, size_t argc, char **argv)
{
	int period = 0;

	if (fd < 0) {
		udp_socket_open();
	}

	if (fd >= 0) {
		if (argc > 1) {
			period = atoi(argv[1]);
		}
		if (period < 1) {
			period = DEFAULT_DATA_SEND_INTERVAL;
		}
		shell_print(shell, "start: sending periodic data every %d seconds",
			    period);
		k_timer_start(&data_send_timer,
			      K_NO_WAIT, K_SECONDS(period));
	} else {
		shell_error(shell, "start: socket not open");
		return -EINVAL;
	}

	return 0;
}

int app_cmd_data_stop(const struct shell *shell, size_t argc, char **argv)
{
	if (k_timer_remaining_get(&data_send_timer) > 0) {
		k_timer_stop(&data_send_timer);
		shell_print(shell, "stop: periodic data stopped");
	} else {
		shell_error(shell, "stop: periodic data not started");
		return -ENOEXEC;
	}

	return 0;
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
	
	if (socket_info->fd < 0) {
		// TODO: Should we be able to send without having socket connected, i.e.,
		// open, connect, send and close with one simple command?
		//socket_open_and_connect(20180);
	}

	// TODO: Implement periodic sending here, i.e., copy paste from app_cmd_data_start()

	shell_print(shell, "socket data send");
	if (socket_info->type == SOCK_STREAM) {
		// TCP
		send(socket_info->fd, data, strlen(data), 0);
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
	shell_print(shell, "socket data sent");

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
			shell_print(shell, "Socket id=%d, fd=%d, family=%d, type=%d, port=%d", 
				i,
				socket_info->fd,
				socket_info->family,
				socket_info->type,
				socket_info->port);
		}
	}

	if (!opened_sockets) {
		shell_print(shell, "there are no open sockets");
	}
	return 0;
}