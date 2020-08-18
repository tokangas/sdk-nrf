#include <shell/shell.h>

#include <net/socket.h>
//#include <nrf_socket.h>

#define DEFAULT_DATA_SEND_INTERVAL 10

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

static void tcp_socket_open_and_connect(int port)
{
	int err;
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
	};

	/* Use dummy destination address and port */
	err = getaddrinfo("5.189.130.26", NULL, &hints, &addrinfo_res);
	if (err) {
		printk("getaddrinfo() failed, err %d\n", errno);
	}

	((struct sockaddr_in *)addrinfo_res->ai_addr)->sin_port = htons(port);

	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (fd >= 0) {

		err = connect(fd, addrinfo_res->ai_addr, addrinfo_res->ai_addrlen);
		if (err) {
			/* Try next address */
			printk("Unable to connect, errno %d\n", errno);
		}
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

int tcp_cmd_send_data(const struct shell *shell, size_t argc, char **argv)
{
	char data[] = "moi";

	if (fd < 0) {
		tcp_socket_open_and_connect(20180);
	}

	if (fd >= 0) {
		shell_print(shell, "start: send data");
		send(fd, data, 3, 0);
		shell_print(shell, "start: data sent");
		close(fd);
	} else {
		shell_error(shell, "start: socket not open");
		return -EINVAL;
	}

	return 0;
}

int sc_cmd_data_stop(const struct shell *shell, size_t argc, char **argv)
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
