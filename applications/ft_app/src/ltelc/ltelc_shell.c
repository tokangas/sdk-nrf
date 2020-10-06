#include <shell/shell.h>
#include <shell/shell_uart.h>

#include "utils/freebsd-getopt/getopt.h"

#include "ltelc.h"
#include "ltelc_api.h"
#include "ltelc_shell.h"


typedef enum {
	LTELC_CMD_STATUS = 0,
    LTELC_CMD_RSRP,
	LTELC_CMD_CONNECT,
    LTELC_CMD_DISCONNECT,
	LTELC_CMD_HELP
} ltelc_shell_command;

typedef enum {
	LTELC_RSRP_NONE = 0,
    LTELC_RSRP_SUBSCRIBE,
    LTELC_RSRP_UNSUBSCRIBE
} ltelc_shell_rsrp_options;

typedef struct {
	ltelc_shell_command command;
	ltelc_shell_rsrp_options rsrp_option;
} ltelc_shell_cmd_args_t;

static ltelc_shell_cmd_args_t ltelc_cmd_args;

//**************************************************************************
const char ltelc_usage_str[] =
	"Usage: ltelc <command> [options]\n"
	"\n"
	"<command> is one of the following:\n"
	"  help:             Show this message\n"
	"  status:           Show status of the current connection\n"
	"  signal -u | -s:   Subscribe/unsubscribe for RSRP signal info\n"
	"  connect <apn>:    Connect to given apn\n"
	"  disconnect <apn>: Disconnect from given apn\n"
	"\n"
	"General options:\n"
	"  -a, [str]  Access Point Name.\n"
	"Options for signal:\n"
	"  -s, [bool]  Subscribe for RSRP info.\n"
	"  -u, [bool]  Unsubscribe for RSRP info.\n"
	"\n"
	;

static void ltelc_shell_print_usage(const struct shell *shell)
{
	shell_print(shell, "%s", ltelc_usage_str);

}

static void ltelc_shell_cmd_defaults_set(ltelc_shell_cmd_args_t *ltelc_cmd_args)
{
    memset(ltelc_cmd_args, 0, sizeof(ltelc_shell_cmd_args_t));
}
//**************************************************************************

int ltelc_shell(const struct shell *shell, size_t argc, char **argv)
{
	int err = 0;
	bool require_apn = false;
	bool require_rsrp_subscribe = false;
    char *apn = NULL;

    ltelc_shell_cmd_defaults_set(&ltelc_cmd_args);
	
	if (argc < 2) {
		goto show_usage;
	}
	
	// command = argv[0] = "ltelc"
	// sub-command = argv[1]
	if (strcmp(argv[1], "status") == 0) {
		ltelc_cmd_args.command = LTELC_CMD_STATUS;
    }
	else if (strcmp(argv[1], "rsrp") == 0) {
        require_rsrp_subscribe = true;
		ltelc_cmd_args.command = LTELC_CMD_RSRP;
    }
	else if (strcmp(argv[1], "connect") == 0) {
        require_apn = true;
		ltelc_cmd_args.command = LTELC_CMD_CONNECT;
    }
	else if (strcmp(argv[1], "disconnect") == 0) {
        require_apn = true;
		ltelc_cmd_args.command = LTELC_CMD_DISCONNECT;
	} else if (strcmp(argv[1], "help") == 0) {
		ltelc_cmd_args.command = LTELC_CMD_HELP;
        goto show_usage;
	} else {
		shell_error(shell, "Unsupported command=%s\n", argv[1]);
		err = -EINVAL;
        goto show_usage;
	}
	
    //We start from subcmd arguments
	optind = 2;

	int flag;
	while ((flag = getopt(argc, argv, "a:su")) != -1) {
		int apn_len = 0;
		switch (flag) {
            //TODO: setting family for connect and print connections after connect and disconnect
            //TODO: cmd signal -u / -s (rsrp indication subscribe/unsubscribe)
		case 's': // subscribe for RSRP
			ltelc_cmd_args.rsrp_option = LTELC_RSRP_SUBSCRIBE;
			break;
		case 'u': // unsubscribe for RSRP
			ltelc_cmd_args.rsrp_option = LTELC_RSRP_UNSUBSCRIBE;
			break;
		case 'a': // APN
			apn_len = strlen(optarg);
			if (apn_len > LTELC_APN_STR_MAX_LENGTH) {
				shell_error(shell, "APN string length %d exceeded. Maximum is %d.", apn_len, LTELC_APN_STR_MAX_LENGTH);
                err = -EINVAL;
                goto show_usage;
			}
            apn = optarg;
			//memcpy(ltelc_cmd_args.apn, optarg, apn_len);
			break;
		}
	}

    /* Check that all mandatory args were given: */
    if (require_apn && apn == NULL) {
        shell_error(shell, "-a apn MUST be given. See usage:");
        goto show_usage;
    } else if (require_rsrp_subscribe && ltelc_cmd_args.rsrp_option == LTELC_RSRP_NONE) {
        shell_error(shell, "either -s or -u MUST be given. See usage:");
        goto show_usage;
    }

    int pdn_fd;
    int ret_val;
	switch (ltelc_cmd_args.command) {
		case LTELC_CMD_STATUS:
			ltelc_api_modem_info_get_for_shell(shell);
			break;
		case LTELC_CMD_RSRP:
            (ltelc_cmd_args.rsrp_option == LTELC_RSRP_SUBSCRIBE) ? ltelc_rsrp_subscribe(true) : ltelc_rsrp_subscribe(false); 
			break;
		case LTELC_CMD_CONNECT:
			pdn_fd = ltelc_pdn_init_and_connect(apn);
            if (pdn_fd < 0) {
                shell_error(shell, "cannot connect pdn socket: %d", pdn_fd);
            }
            else {
                shell_print(shell, "pdn socket = %d created and connected", pdn_fd);
            }
			break;
		case LTELC_CMD_DISCONNECT:
            ret_val = ltelc_pdn_disconnect(apn);
            if (ret_val < 0) {
                shell_error(shell, "cannot disconnect with apn = %s", apn);
            }
            else {
                shell_print(shell, "%s disconnected", apn);
            }
			break;
		default:
			shell_error(shell, "Internal error. Unknown ltelc command=%d", ltelc_cmd_args.command);
			err = -EINVAL;
			break;
	}
	return err;

show_usage:
	ltelc_shell_print_usage(shell);
	return err;
}
