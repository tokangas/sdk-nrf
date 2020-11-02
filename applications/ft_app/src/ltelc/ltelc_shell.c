#include <shell/shell.h>
#include <shell/shell_uart.h>
#include <unistd.h>

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
	"  help:                  Show this message\n"
	"  status:                Show status of the current connection\n"
	"  rsrp [rsrp options]:   Subscribe/unsubscribe for RSRP signal info\n"
	"  connect -a <apn> | --apn <apn>: Connect to given apn\n"
	"  disconnect [<apn> | <cid>]:     Disconnect from given apn\n"
//	"  funmode -0 (power off)| -1 | -4: Set functional mode\n"
	"\n"
	"General options:\n"
	"  -a <apn> | --apn <apn>, [str] Access Point Name\n"
	"\n"
	"Options for 'rsrp' command:\n"
	"  -s | --subscribe   [bool]  Subscribe for RSRP info\n"
	"  -u | --unsubscribe [bool]  Unsubscribe for RSRP info\n"
	"\n"
	"Options for 'disconnect' command:\n"
	"  -I <cid> | --cid <cid>, [int]   Use this option to disconnect specific PDN CID\n"
	"\n"
	;

 /* Specifying the expected options (both long and short): */
static struct option long_options[] = {
    {"apn",         required_argument, 0,  'a' },
    {"cid",         required_argument, 0,  'I' },
    {"subscribe",   no_argument,       0,  's' },
    {"unsubscribe", no_argument,       0,  'u' },
//    {"pwroff",      no_argument,       0,  '0' },
//    {"normal",      no_argument,       0,  '1' },
//    {"offline",     no_argument,       0,  '4' },
    {0,             0,                 0,   0  }
    };

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
	bool require_apn_or_pdn_cid = false;
	bool require_rsrp_subscribe = false;
	char *apn = NULL;
	int pdn_cid = 0;

	ltelc_shell_cmd_defaults_set(&ltelc_cmd_args);
	
	if (argc < 2) {
		goto show_usage;
	}
	
	// command = argv[0] = "ltelc"
	// sub-command = argv[1]
	if (strcmp(argv[1], "status") == 0) {
		ltelc_cmd_args.command = LTELC_CMD_STATUS;
	} else if (strcmp(argv[1], "rsrp") == 0) {
		require_rsrp_subscribe = true;
		ltelc_cmd_args.command = LTELC_CMD_RSRP;
	} else if (strcmp(argv[1], "connect") == 0) {
		require_apn = true;
		ltelc_cmd_args.command = LTELC_CMD_CONNECT;
	} else if (strcmp(argv[1], "disconnect") == 0) {
		require_apn_or_pdn_cid = true;
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
    
	int long_index = 0;
	int opt;

	while ((opt = getopt_long(argc, argv, "a:I:su", long_options, &long_index)) != -1) {
		int apn_len = 0;

		switch (opt) {
		//TODO: setting family for connect and print connections after connect and disconnect
		case 's': // subscribe for RSRP
			ltelc_cmd_args.rsrp_option = LTELC_RSRP_SUBSCRIBE;
			break;
		case 'u': // unsubscribe for RSRP
			ltelc_cmd_args.rsrp_option = LTELC_RSRP_UNSUBSCRIBE;
			break;
		case 'I': // PDN CID
			pdn_cid = atoi(optarg);
			if (pdn_cid == 0) {
				shell_error(
					shell,
					"PDN CID (%d) must be positive integer. "
					"Default PDN context (CID=0) cannot be given.",
					pdn_cid);
				return -EINVAL;
			}
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
		shell_error(shell, "Option -a | -apn MUST be given. See usage:");
		goto show_usage;
	} else if (require_apn_or_pdn_cid && apn == NULL && pdn_cid == 0) {
		shell_error(shell, "Either -a or -I MUST be given. See usage:");
		goto show_usage;
	} else if (require_rsrp_subscribe && ltelc_cmd_args.rsrp_option == LTELC_RSRP_NONE) {
		shell_error(shell, "Either -s or -u MUST be given. See usage:");
		goto show_usage;
	}

	int pdn_fd;
	char* apn_print;
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
			} else {
				shell_print(shell, "pdn socket = %d created and connected", pdn_fd);
			}
			break;
		case LTELC_CMD_DISCONNECT:
			err = ltelc_pdn_disconnect(apn, pdn_cid);
			apn_print = FTA_STRING_NULL_CHECK(apn);
			if (err < 0) {
				shell_error(shell, "Cannot disconnect with given apn='%s', pdn_cid=%d", apn_print, pdn_cid);
			} else {
				shell_print(shell, "Disconnected with given apn='%s', pdn_cid=%d", apn_print, pdn_cid);
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
