#include <shell/shell.h>
#include <strings.h>
#include <net/socket.h>
//#include <nrf_socket.h>

#define MAX_SOCKETS     8
#define DEFAULT_DATA_SEND_INTERVAL 10

static int s_fd[MAX_SOCKETS] = { -1 };
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


static void socket_open_and_connect(int family, int type, int proto, char* ip_address, int port, int bind_port)
{
	// TODO: TLS support
	// TODO: IPv6 support
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

	err = getaddrinfo(ip_address, NULL, &hints, &addrinfo_res);
	if (err) {
		printk("getaddrinfo() failed, err %d errno %d\n", err, errno);
		return;
	}

	// TODO: IPv6 support needed to this:
	((struct sockaddr_in *)addrinfo_res->ai_addr)->sin_port = htons(port);

	// Create socket
	// If proto is set to zero to let lower stack select it,
	// socket creation fails with errno=43 (PROTONOSUPPORT)
	fd = socket(family, type, proto);
	if (fd < 0) {
		printk("socket create failed, err %d\n", errno);
		return;
	}
	printk("socket created fd=%d\n", fd);

	// Bind socket
	/*
	if (bind_port > 0) {
		err = bind(fd, addrinfo_res->ai_addr, sizeof(addrinfo_res->ai_addr));
		if (err) {
			printk("Unable to bind, errno %d\n", errno);
			return;
		}
	}*/

	// Connect socket
	// TODO: Handle this for UDP as no need for connect
	err = connect(fd, addrinfo_res->ai_addr, addrinfo_res->ai_addrlen);
	if (err) {
		printk("Unable to connect, errno %d\n", errno);
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
	}

	// IP address = argv[3]

	// Port = argv[4]
	port = atoi(argv[4]);

	// Bind port = argv[5]
	if (argc > 5) {
		bind_port = atoi(argv[5]);
	}

	socket_open_and_connect(domain, type, proto, argv[3], port, bind_port);

	if (fd < -1) {
		shell_error(shell, "start: socket not open");
		return -EINVAL;
	} else {
		shell_print(shell, "socket connect fd=%d", fd);
	}

	return 0;
}

int socket_send_shell(const struct shell *shell, size_t argc, char **argv)
{
	char data[] = "moi";

	if (fd < 0) {
		// TODO: Should we be able to send without having socket connected, i.e.,
		// open, connect, send and close with one simple command?
		//socket_open_and_connect(20180);
	}

	// TODO: Implement priodic sending here, i.e., copy paste from app_cmd_data_start()

	if (fd >= 0) {
		shell_print(shell, "socket send data");
		// TODO: Handle this for UDP (sendto)
		send(fd, data, 3, 0);
		shell_print(shell, "socket sent data");
	} else {
		shell_error(shell, "socket_send: socket not open");
		return -EINVAL;
	}

	return 0;
}

int socket_close_shell(const struct shell *shell, size_t argc, char **argv)
{
	close(fd);
	shell_print(shell, "close socket fd=%d", fd);
	fd = -1;
	return 0;
}
