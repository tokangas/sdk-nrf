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

extern socket_info_t sockets[MAX_SOCKETS];
extern char send_buffer[SEND_BUFFER_SIZE];
//char receive_buffer[RECEIVE_BUFFER_SIZE];
const struct shell* shell_global;


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

static void socket_help(bool verbose) {
	print_usage();
	if (verbose) {
		shell_print(shell_global, "%s", usage_example_str);
	}
}

int sock_shell(const struct shell *shell, size_t argc, char **argv)
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

// TODO: Handle socket id in corresponding functions and pass just arg_socket_id in there
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
