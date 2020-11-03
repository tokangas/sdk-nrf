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

// Maximum length of the address
#define SOCK_MAX_ADDR_LEN 100
// Maximum length of the data that can be specified with -d option
#define SOCK_MAX_SEND_DATA_LEN 200

typedef enum {
	SOCK_CMD_CONNECT = 0,
	SOCK_CMD_SEND,
	SOCK_CMD_RECV,
	SOCK_CMD_CLOSE,
	SOCK_CMD_LIST,
	SOCK_CMD_HELP
} sock_command;

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

static void sock_print_usage()
{
	shell_print(shell_global, "%s", usage_str);
}

static int sock_help(bool verbose) {
	sock_print_usage();
	if (verbose) {
		shell_print(shell_global, "%s", usage_example_str);
	}
	return 0;
}

int sock_shell(const struct shell *shell, size_t argc, char **argv)
{
	int err = 0;
	shell_global = shell;
	// Before parsing the command line, reset getopt index to the start of the arguments
	optind = 1;

	if (argc < 2) {
		sock_print_usage();
		return 0;
	}

	// Command = argv[1]
	sock_command command;
	if (!strcmp(argv[1], "connect")) {
		command = SOCK_CMD_CONNECT;
	} else if (!strcmp(argv[1], "send")) {
		command = SOCK_CMD_SEND;
	} else if (!strcmp(argv[1], "recv")) {
		command = SOCK_CMD_RECV;
	} else if (!strcmp(argv[1], "close")) {
		command = SOCK_CMD_CLOSE;
	} else if (!strcmp(argv[1], "list")) {
		command = SOCK_CMD_LIST;
	} else if (!strcmp(argv[1], "help")) {
		command = SOCK_CMD_HELP;
	} else {
		shell_error(shell, "Unsupported command=%s\n", argv[1]);
		sock_print_usage();
		return -EINVAL;
	}
	// Increase getopt command line parsing index not to handle command
	optind++;

	int flag = 0;
	int arg_socket_id = SOCK_ID_NONE;
	int arg_family = AF_INET;
	int arg_type = SOCK_STREAM;
	char arg_address[SOCK_MAX_ADDR_LEN+1];
	int arg_port = 0;
	int arg_bind_port = 0;
	int arg_pdn_cid = 0;
	char arg_send_data[SOCK_MAX_SEND_DATA_LEN+1];
	int arg_data_length = 0;
	int arg_data_interval = SOCK_SEND_DATA_INTERVAL_NONE;
	bool arg_receive_start = false;
	bool arg_verbose = false;

	memset(arg_address, 0, SOCK_MAX_ADDR_LEN+1);
	memset(arg_send_data, 0, SOCK_MAX_SEND_DATA_LEN+1);

	// Parse command line
	while ((flag = getopt(argc, argv, "i:I:a:p:f:t:b:d:l:e:rv")) != -1) {
		int addr_len = 0;
		int send_data_len = 0;

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
			addr_len = strlen(optarg);
			if (addr_len > SOCK_MAX_ADDR_LEN) {
				shell_error(shell, "Address length %d exceeded. Maximum is %d.",
					addr_len, SOCK_MAX_ADDR_LEN);
				return -EINVAL;
			}
			memcpy(arg_address, optarg, addr_len);
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
				shell_error(shell, "Unsupported address family=%s", optarg);
				return -EINVAL;
			}
			break;
		case 't': // Socket type
			if (!strcmp(optarg, "stream")) {
				arg_type = SOCK_STREAM;
			} else if (!strcmp(optarg, "dgram")) {
				arg_type = SOCK_DGRAM;
			} else {
				shell_error(shell, "Unsupported address type=%s", optarg);
				return -EINVAL;
			}
			break;
		case 'b': // Bind port
			arg_bind_port = atoi(optarg);
			break;
		case 'd': // Data to be sent is available in send buffer
			send_data_len = strlen(optarg);
			if (send_data_len > SOCK_MAX_SEND_DATA_LEN) {
				shell_error(shell, "Data length %d exceeded. Maximum is %d. Given data: %s",
					send_data_len, SOCK_MAX_SEND_DATA_LEN, optarg);
				return -EINVAL;
			}
			strcpy(arg_send_data, optarg);
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

	// Run given command with it's arguments
	switch (command) {
		case SOCK_CMD_CONNECT:
			err = sock_open_and_connect(arg_family, arg_type, arg_address, arg_port, arg_bind_port, arg_pdn_cid);
			break;
		case SOCK_CMD_SEND:
			err = sock_send_data(arg_socket_id, arg_send_data, arg_data_length, arg_data_interval);
			break;
		case SOCK_CMD_RECV:
			err = sock_recv(arg_socket_id, arg_receive_start);
			break;
		case SOCK_CMD_CLOSE:
			err = sock_close(arg_socket_id);
			break;
		case SOCK_CMD_LIST:
			err = sock_list();
			break;
		case SOCK_CMD_HELP:
			err = sock_help(arg_verbose);
			break;
		default:
			shell_error(shell, "Internal error. Unknown socket command=%d", command);
			err = -EINVAL;
			break;
	}

	return err;
}
