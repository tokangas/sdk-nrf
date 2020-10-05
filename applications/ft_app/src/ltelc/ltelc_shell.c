#include <shell/shell.h>
#include <shell/shell_uart.h>

#include "utils/freebsd-getopt/getopt.h"

#include "ltelc_api.h"
#include "ltelc_shell.h"

typedef enum {
	LTELC_CMD_STATUS = 0,
	LTELC_CMD_CONNECT,
	LTELC_CMD_HELP
} ltelc_shell_command;

typedef struct {
	ltelc_shell_command command;
} ltelc_shell_cmd_args_t;

static ltelc_shell_cmd_args_t ltelc_cmd_args;

//**************************************************************************
const char ltelc_usage_str[] =
	"Usage: ltelc <command> [options]\n"
	"\n"
	"<command> is one of the following:\n"
	"  status:  Show status of the current connection\n"
	"\n"
	"General options:\n"
	"  -i, [int]  socket id. Use 'list' command to see open sockets.\n"
	"\n"
	"Options for 'status' command:\n"
	"  -a, [str]  Address as ip address or hostname\n"
	"\n"
	"Options for 'help' command:\n"
	"  TODO\n"
	;

static void ltelc_shell_print_usage(const struct shell *shell)
{
	shell_print(shell, "%s", ltelc_usage_str);

}
//**************************************************************************

int ltelc_shell(const struct shell *shell, size_t argc, char **argv)
{
	int err = 0;
	
	if (argc < 2) {
		ltelc_shell_print_usage(shell);
		return 0;
	}
	
	// command = argv[0] = "ltelc"
	// sub-command = argv[1]
	if (strcmp(argv[1], "status") == 0) {
		ltelc_cmd_args.command = LTELC_CMD_STATUS;
    }
	if (strcmp(argv[1], "connect") == 0) {
		ltelc_cmd_args.command = LTELC_CMD_CONNECT;
	} else {
		shell_error(shell, "Unsupported command=%s\n", argv[1]);
		ltelc_shell_print_usage(shell);
		return -EINVAL;
	}
	
    //We start from subcmd arguments
	optind = 2;

	int flag;
	while ((flag = getopt(argc, argv, "i:a:p:f:t:b:d:l:e:a:rv")) != -1) {
		int apn_len = 0;
		switch (flag) {
		case 'a': // APN
			apn_len = strlen(optarg);
			if (apn_len > 100) {
				shell_error(shell, "Address length %d exceeded. Maximum is 100.", apn_len);
			}
//			memcpy(socket_cmd_args.ip_address, optarg, ip_address_len);
			break;
		}
	}

	switch (ltelc_cmd_args.command) {
		case LTELC_CMD_STATUS:
			ltelc_api_modem_info_get_for_shell(shell);
			break;
		default:
			shell_error(shell, "Internal error. Unknown ltelc command=%d", ltelc_cmd_args.command);
			err = -EINVAL;
			break;
	}
	return err;
}
