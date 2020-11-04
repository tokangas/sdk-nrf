#include <stdio.h>

#include <shell/shell.h>
#include <shell/shell_uart.h>
#include <unistd.h>

#include "utils/freebsd-getopt/getopt.h"

#include "ltelc.h"
#include "ltelc_api.h"
#include "ltelc_shell.h"

#define LTELC_SHELL_EDRX_VALUE_STR_LENGTH 4
#define LTELC_SHELL_EDRX_PTW_STR_LENGTH 4

typedef enum {
	LTELC_CMD_STATUS = 0,
	LTELC_CMD_RSRP,
	LTELC_CMD_CONNECT,
	LTELC_CMD_DISCONNECT,
	LTELC_CMD_FUNMODE,
	LTELC_CMD_SYSMODE,
	LTELC_CMD_EDRX,
	LTELC_CMD_HELP
} ltelc_shell_command;

typedef enum {
	LTELC_COMMON_NONE = 0,
	LTELC_COMMON_READ,
	LTELC_COMMON_ENABLE,
	LTELC_COMMON_DISABLE
} ltelc_shell_common_options;

typedef enum {
	LTELC_RSRP_NONE = 0,
	LTELC_RSRP_SUBSCRIBE, //TODO: replace with common enable
	LTELC_RSRP_UNSUBSCRIBE  //TODO: replace with common disable
} ltelc_shell_rsrp_options;

typedef struct {
	ltelc_shell_command command;
	ltelc_shell_rsrp_options rsrp_option;
	ltelc_shell_funmode_options funmode_option;
	ltelc_shell_common_options common_option;
	int sysmode_option;
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
	"  funmode [funmode options]:      Set/read functional modes of the modem\n"
	"  sysmode [sysmode options]:      Set/read system modes of the modem\n"
	"  edrx [eDRX options]:            Enable/disable eDRX with default or with custom parameters\n"
	"\n"
	"General options:\n"
	"  -a <apn> | --apn <apn>, [str] Access Point Name\n"
	"\n"
	"Options for 'rsrp' command:\n"
	"  -s | --subscribe,   [bool]  Subscribe for RSRP info\n"
	"  -u | --unsubscribe, [bool]  Unsubscribe for RSRP info\n"
	"\n"
	"Options for 'disconnect' command:\n"
	"  -I <cid> | --cid <cid>, [int]   Use this option to disconnect specific PDN CID\n"
	"\n"
	"Options for 'funmode' command:\n"
	"  -r | --read,       [bool]  Read modem functional mode\n"
	"  -0 | --pwroff,     [bool]  Set modem power off\n"
	"  -1 | --normal,     [bool]  Set modem normal mode\n"
	"  -4 | --flightmode, [bool]  Set modem offline\n"
	"\n"
	"Options for 'sysmode' command:\n"
	"  -r | --read,       [bool]  Read modem functional mode\n"
	"  -m | --ltem,       [bool]  LTE-M (LTE Cat-M1) system mode\n"
	"  -n | --nbiot,      [bool]  NB-IoT (LTE Cat-NB1) system mode\n"
	"  -g | --gps,        [bool]  GPS system mode\n"
	"  -M | --ltem_gps,   [bool]  LTE-M + GPS system mode\n"
	"  -N | --nbiot_gps,  [bool]  NB-IoT + GPS system mode\n"
	"\n"
	"Options for 'edrx' command:\n"
	"  -e | --enable,             [bool]   Enable eDRX\n"
	"  -d | --disable,            [bool]   Disable eDRX\n"
	"  -E | --edrx_value <value>, [string] Sets custom eDRX value to be requested when enabling eDRX.\n"
	"  -P | --ptw <value>,        [string] Sets custom Paging Time Window value to be requested when enabling eDRX.\n"
	"\n"
	;

 /* Specifying the expected options (both long and short): */
static struct option long_options[] = {
    {"apn",                     required_argument, 0,  'a' },
    {"cid",                     required_argument, 0,  'I' },
    {"subscribe",               no_argument,       0,  's' },
    {"unsubscribe",             no_argument,       0,  'u' },
    {"read",                    no_argument,       0,  'r' },
    {"pwroff",                  no_argument,       0,  '0' },
    {"normal",                  no_argument,       0,  '1' },
    {"flightmode",              no_argument,       0,  '4' },
    {"ltem",                    no_argument,       0,  'm' },
    {"nbiot",                   no_argument,       0,  'n' },
    {"gps",                     no_argument,       0,  'g' },
    {"ltem_gps",                no_argument,       0,  'M' },
    {"nbiot_gps",               no_argument,       0,  'N' },
    {"enable",                  no_argument,       0,  'e' },
    {"disable",                 no_argument,       0,  'd' },
    {"edrx_value",              required_argument, 0,  'E' },
    {"ptw",                 required_argument, 0,  'P' },
    {0,                         0,                 0,   0  }
};

static void ltelc_shell_print_usage(const struct shell *shell)
{
	shell_print(shell, "%s", ltelc_usage_str);
}

static void ltelc_shell_cmd_defaults_set(ltelc_shell_cmd_args_t *ltelc_cmd_args)
{
    memset(ltelc_cmd_args, 0, sizeof(ltelc_shell_cmd_args_t));
	ltelc_cmd_args->funmode_option = LTELC_FUNMODE_NONE;
	ltelc_cmd_args->sysmode_option = LTE_LC_SYSTEM_MODE_NONE;
}

/* *************************************************************************** */
struct mapping_tbl_item {
	int key;
	char *value_str;
};

static const char *ltelc_shell_map_to_string(struct mapping_tbl_item const *mapping_table, int mode, char *out_str_buff)
{
	bool found = false;
	int i;
	
	for (i = 0; mapping_table[i].key != -1; i++) {
		if (mapping_table[i].key == mode) {
			found = true;
			break;
		}
	}

	if (!found) {
		sprintf(out_str_buff, "%d", mode);
	} else {
		strcpy(out_str_buff, mapping_table[i].value_str);
	}
	return out_str_buff;
}

static const char *ltelc_shell_funmode_to_string(int funmode, char *out_str_buff) 
{
    struct mapping_tbl_item const mapping_table[] = {
		{LTELC_FUNMODE_PWROFF,     "power off"},
		{LTELC_FUNMODE_NORMAL,     "normal"},
		{LTELC_FUNMODE_FLIGHTMODE, "flightmode"},
		{LTELC_FUNMODE_NONE,       "unknown"},
		{-1, NULL}
	};
	return ltelc_shell_map_to_string(mapping_table, funmode, out_str_buff);
}

static const char *ltelc_shell_sysmode_to_string(int sysmode, char *out_str_buff){
    struct mapping_tbl_item const mapping_table[] = {
		{LTE_LC_SYSTEM_MODE_LTEM,      "LTE-M"},
		{LTE_LC_SYSTEM_MODE_NBIOT,     "NB-IoT"},
		{LTE_LC_SYSTEM_MODE_GPS,       "GPS"},
		{LTE_LC_SYSTEM_MODE_LTEM_GPS,  "LTE-M - GPS"},
		{LTE_LC_SYSTEM_MODE_NBIOT_GPS, "NB-IoT - GPS"},
		{-1, NULL}
	};
	
	return ltelc_shell_map_to_string(mapping_table, sysmode, out_str_buff);
}

//**************************************************************************

int ltelc_shell(const struct shell *shell, size_t argc, char **argv)
{
	int ret = 0;	
	bool require_apn = false;
	bool require_apn_or_pdn_cid = false;
	bool require_rsrp_subscribe = false;
	bool require_option = false;
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
		//TODO: setting family for connect and print connections after connect and disconnect
		require_apn = true;
		ltelc_cmd_args.command = LTELC_CMD_CONNECT;
	} else if (strcmp(argv[1], "disconnect") == 0) {
		require_apn_or_pdn_cid = true;
		ltelc_cmd_args.command = LTELC_CMD_DISCONNECT;
	} else if (strcmp(argv[1], "funmode") == 0) {
		require_option = true;
		ltelc_cmd_args.command = LTELC_CMD_FUNMODE;
	} else if (strcmp(argv[1], "sysmode") == 0) {
		require_option = true;
		ltelc_cmd_args.command = LTELC_CMD_SYSMODE;
	} else if (strcmp(argv[1], "edrx") == 0) {
		require_option = true;
		ltelc_cmd_args.command = LTELC_CMD_EDRX;
	} else if (strcmp(argv[1], "help") == 0) {
		ltelc_cmd_args.command = LTELC_CMD_HELP;
        goto show_usage;
	} else {
		shell_error(shell, "Unsupported command=%s\n", argv[1]);
		ret = -EINVAL;
		goto show_usage;
	}
	
	//We start from subcmd arguments
	optind = 2;
    
	int long_index = 0;
	int opt;

	char edrx_value_str[LTELC_SHELL_EDRX_VALUE_STR_LENGTH + 1];
	bool edrx_value_set = false;
	char ptw_bit_str[LTELC_SHELL_EDRX_PTW_STR_LENGTH + 1];
	bool edrx_ptw_set = false;

	while ((opt = getopt_long(argc, argv, "a:I:E:P:su014rmngMNed", long_options, &long_index)) != -1) {
		int apn_len = 0;

		switch (opt) {
		/* RSRP: */
		case 's':
			ltelc_cmd_args.rsrp_option = LTELC_RSRP_SUBSCRIBE;
			break;
		case 'u':
			ltelc_cmd_args.rsrp_option = LTELC_RSRP_UNSUBSCRIBE;
			break;

		/* Modem functional modes: */
		case '0':
			ltelc_cmd_args.funmode_option = LTELC_FUNMODE_PWROFF;
			break;
		case '1':
			ltelc_cmd_args.funmode_option = LTELC_FUNMODE_NORMAL;
			break;
		case '4':
			ltelc_cmd_args.funmode_option = LTELC_FUNMODE_FLIGHTMODE;
			break;

		/* eDRX specifics: */
		case 'E': //edrx_value
			if (strlen(optarg) == 4) {
				strcpy(edrx_value_str, optarg);
				edrx_value_set = true;
			}
			else {
				shell_error(shell, "eDRX value string length must be %d.", LTELC_SHELL_EDRX_VALUE_STR_LENGTH);
				return -EINVAL;
			}
			break;
		case 'P': //Paging Time Window
			if (strlen(optarg) == 4) {
				strcpy(ptw_bit_str, optarg);
				edrx_ptw_set = true;
			}
			else {
				shell_error(shell, "PTW string length must be %d.", LTELC_SHELL_EDRX_PTW_STR_LENGTH);
				return -EINVAL;
			}
			break;

		/* Modem system modes: */
		case 'm':
			ltelc_cmd_args.sysmode_option = LTE_LC_SYSTEM_MODE_LTEM;
			break;
		case 'n':
			ltelc_cmd_args.sysmode_option = LTE_LC_SYSTEM_MODE_NBIOT;
			break;
		case 'g':
			ltelc_cmd_args.sysmode_option = LTE_LC_SYSTEM_MODE_GPS;
			break;
		case 'M':
			ltelc_cmd_args.sysmode_option = LTE_LC_SYSTEM_MODE_LTEM_GPS;
			break;
		case 'N':
			ltelc_cmd_args.sysmode_option = LTE_LC_SYSTEM_MODE_NBIOT_GPS;
			break;

        /* Common options: */
		case 'e':
			ltelc_cmd_args.common_option = LTELC_COMMON_ENABLE;
			break;
		case 'd':
			ltelc_cmd_args.common_option = LTELC_COMMON_DISABLE;
			break;
		case 'r':
			ltelc_cmd_args.common_option = LTELC_COMMON_READ;
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
				ret = -EINVAL;
				goto show_usage;
			}
			apn = optarg;
			break;
		case '?':
		default:
			shell_error(shell, "Unknown option. See usage:");
			goto show_usage;
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
	} else if (require_option && ltelc_cmd_args.funmode_option == LTELC_FUNMODE_NONE && 
			   ltelc_cmd_args.sysmode_option == LTE_LC_SYSTEM_MODE_NONE &&
	           ltelc_cmd_args.common_option == LTELC_COMMON_NONE) {
		shell_error(shell, "Command needs option to be given. See usage:");
		goto show_usage;
	}

	char* apn_print;
	char snum[64];

	switch (ltelc_cmd_args.command) {
		case LTELC_CMD_STATUS:
			ltelc_api_modem_info_get_for_shell(shell);
			break;
		case LTELC_CMD_SYSMODE:
			if (ltelc_cmd_args.common_option == LTELC_COMMON_READ) {
				enum lte_lc_system_mode sys_mode_current = LTE_LC_SYSTEM_MODE_NONE;

				ret = lte_lc_system_mode_get(&sys_mode_current);
				if (ret < 0) {
					shell_error(shell, "cannot read system mode of the modem: %d", ret);
				} else {
					shell_print(shell, "System mode read successfully: %s", ltelc_shell_sysmode_to_string(sys_mode_current, snum));
				}
			} else {
				ret = lte_lc_system_mode_set(ltelc_cmd_args.sysmode_option);
				if (ret < 0) {
					shell_error(shell, "Cannot set system mode: %d", ret);
					ret = ltelc_func_mode_get();
					if (ret != LTELC_FUNMODE_FLIGHTMODE || ret != LTELC_FUNMODE_PWROFF) {
						shell_info(shell, "Setting 1st to flighmode might help by using: \"ltelc funmode --flighmode\"");
					}
				} else {
					shell_print(shell, "System mode set successfully: %s", ltelc_shell_sysmode_to_string(ltelc_cmd_args.sysmode_option, snum));
				}
			}
			break;
		case LTELC_CMD_FUNMODE:
			if (ltelc_cmd_args.common_option == LTELC_COMMON_READ) {
				ret = ltelc_func_mode_get();
				if (ret < 0) {
					shell_error(shell, "cannot get functional mode: %d", ret);
				} else {
					shell_print(shell, "Functional mode read successfully: %s", ltelc_shell_funmode_to_string(ret, snum));
				}
			} else {
				ret = ltelc_func_mode_set(ltelc_cmd_args.funmode_option);
				if (ret < 0) {
					shell_error(shell, "cannot set functional mode: %d", ret);
				} else {
					shell_print(shell, "Functional mode set successfully: %s", ltelc_shell_funmode_to_string(ltelc_cmd_args.funmode_option, snum));
				}
			}
			break;
		case LTELC_CMD_EDRX:
			if (ltelc_cmd_args.common_option == LTELC_COMMON_ENABLE) {
				if (edrx_value_set) {
					ret = lte_lc_edrx_param_set(edrx_value_str);
					if (ret < 0) {
						shell_error(shell, "cannot set eDRX value: %d", ret);
						return -EINVAL;
					}
				}
				if (edrx_ptw_set) {
					ret = lte_lc_ptw_set(ptw_bit_str);
					if (ret < 0) {
						shell_error(shell, "cannot set PTW value: %d", ret);
						return -EINVAL;
					}
				}

				ret = lte_lc_edrx_req(true);
				if (ret < 0) {
					shell_error(shell, "cannot enable eDRX: %d", ret);
				} else {
					shell_print(shell, "eDRX enabled");
				}
			}
			else if (ltelc_cmd_args.common_option == LTELC_COMMON_DISABLE) {
				ret = lte_lc_edrx_req(false);
				if (ret < 0) {
					shell_error(shell, "cannot disable eDRX: %d", ret);
				} else {
					shell_print(shell, "eDRX disabled");
				}
			}
			else {
				shell_error(shell, "Unknown option for edrx command. See usage:");
				goto show_usage;
			}
			break;

		case LTELC_CMD_RSRP:
			(ltelc_cmd_args.rsrp_option == LTELC_RSRP_SUBSCRIBE) ? ltelc_rsrp_subscribe(true) : ltelc_rsrp_subscribe(false); 
			break;
		case LTELC_CMD_CONNECT:
			ret = ltelc_pdn_init_and_connect(apn);
			if (ret < 0) {
				shell_error(shell, "cannot connect pdn socket: %d", ret);
			} else {
				shell_print(shell, "pdn socket = %d created and connected", ret);
			}
			break;
		case LTELC_CMD_DISCONNECT:
			ret = ltelc_pdn_disconnect(apn, pdn_cid);
			apn_print = FTA_STRING_NULL_CHECK(apn);
			if (ret < 0) {
				shell_error(shell, "Cannot disconnect with given apn='%s', pdn_cid=%d", apn_print, pdn_cid);
			} else {
				shell_print(shell, "Disconnected with given apn='%s', pdn_cid=%d", apn_print, pdn_cid);
			}
			break;
		default:
			shell_error(shell, "Internal error. Unknown ltelc command=%d", ltelc_cmd_args.command);
			ret = -EINVAL;
			break;
	}
	return ret;

show_usage:
	ltelc_shell_print_usage(shell);
	return ret;
}
