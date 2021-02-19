/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <stdio.h>

#include <shell/shell.h>
#include <shell/shell_uart.h>
#include <unistd.h>
#include <getopt.h>

#include <modem/at_cmd.h>

#include "ltelc.h"
#include "ltelc_api.h"
#include "ltelc_shell.h"
#include "ltelc_settings.h"

#define LTELC_SHELL_EDRX_VALUE_STR_LENGTH 4
#define LTELC_SHELL_EDRX_PTW_STR_LENGTH 4
#define LTELC_SHELL_PSM_PARAM_STR_LENGTH 8

typedef enum {
	LTELC_CMD_STATUS = 0,
	LTELC_CMD_CONEVAL,
	LTELC_CMD_DEFCONT,
	LTELC_CMD_DEFCONTAUTH,
	LTELC_CMD_RSRP,
	LTELC_CMD_CONNECT,
	LTELC_CMD_DISCONNECT,
	LTELC_CMD_FUNMODE,
	LTELC_CMD_SYSMODE,
	LTELC_CMD_NORMAL_MODE_AT,
	LTELC_CMD_EDRX,
	LTELC_CMD_PSM,
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

/******************************************************************************/
const char ltelc_usage_str[] =
	"Usage: ltelc <subcommand> [options]\n"
	"\n"
	"<subcommand> is one of the following:\n"
	"  <subcommand>:            Subcommand usage if options\n"
	"  help:                    Show this message (no options)\n"
	"  status:                  Show status of the current connection (no options)\n"
	"  coneval:                 Evaluate connection parameters (no options)\n"
	"  defcont:                 Set custom default PDP context config. Permanent between the sessions.\n"
	"                           Effective when going to normal mode.\n"
	"  defcontauth:             Set custom authentication parameters for the default PDP context.\n"
	"                           Permanent between the sessions. Effective when going to normal mode.\n"
	"  connect:                 Connect to given apn\n"
	"  disconnect:              Disconnect from given apn\n"
	"  rsrp:                    Subscribe/unsubscribe for RSRP signal info\n"
	"  funmode:                 Set/read functional modes of the modem\n"
	"  sysmode:                 Set/read system modes of the modem\n"
    "                           When set: permanent between the sessions. Effective when going to normal mode.\n"
	"  nmodeat:                 Set custom AT commmands that are run when going to normal mode\n"
	"  edrx:                    Enable/disable eDRX with default or with custom parameters\n"
	"  psm:                     Enable/disable Power Saving Mode (PSM) with default or with custom parameters\n"
	"\n"
	;

const char ltelc_defcont_usage_str[] =
	"Options for 'ltelc defcont' command:\n"
	"  -r, --read,       [bool] Read and print current config\n"
	"  -e, --enable,     [bool] Enable custom config for default PDP context\n"
	"  -d, --disable,    [bool] Disable custom config for default PDP context\n"
	"  -a, --apn,        [str]  Set default Access Point Name\n"
	"  -f, --family,     [str]  Address family: 'ipv4v6' (default), 'ipv4', 'ipv6'\n"
	"\n";

const char ltelc_defcontauth_usage_str[] =
	"Options for 'ltelc defcontauth' command:\n"
	"  -r, --read,       [bool] Read and print current config\n"
	"  -e, --enable,     [bool] Enable custom config for default PDP context\n"
	"  -d, --disable,    [bool] Disable custom config for default PDP context\n"
	"  -U, --uname,      [str]  Username\n"
	"  -P, --pword,      [str]  Password\n"
	"  -A, --prot,       [int]  Authentication protocol (Default: 0 (None), 1 (PAP), 2 (CHAP)\n"
	"\n";

const char ltelc_connect_usage_str[] =
	"Options for 'ltelc connect' command:\n"
	"  -a, --apn,        [str]  Access Point Name\n"
	"  -f, --family,     [str]  Address family: 'ipv4v6', 'ipv4', 'ipv6', 'packet'\n"
	"\n"
	"Options for 'ltelc disconnect' command:\n"
	"  -a, --apn,        [str]  Access Point Name\n"
	"  -I, --cid,        [int]  Use this option to disconnect specific PDN CID\n"
	"\n";

const char ltelc_sysmode_usage_str[] =
	"Options for 'ltelc sysmode' command:\n"
	"  -r, --read,       [bool] Read modem functional mode\n"
	"  -m, --ltem,       [bool] LTE-M (LTE Cat-M1) system mode\n"
	"  -n, --nbiot,      [bool] NB-IoT (LTE Cat-NB1) system mode\n"
	"  -g, --gps,        [bool] GPS system mode\n"
	"  -M, --ltem_gps,   [bool] LTE-M + GPS system mode\n"
	"  -N, --nbiot_gps,  [bool] NB-IoT + GPS system mode\n"
	"\n";

const char ltelc_funmode_usage_str[] =
	"Options for 'ltelc funmode' command:\n"
	"  -r, --read,       [bool] Read modem functional mode\n"
	"  -0, --pwroff,     [bool] Set modem power off\n"
	"  -1, --normal,     [bool] Set modem normal mode\n"
	"  -4, --flightmode, [bool] Set modem offline\n"
	"\n";

const char ltelc_normal_mode_at_usage_str[] =
	"Options for 'ltelc nmodeat' command:\n"
	"  -r, --read,       [bool] Read all set custom normal mode at commands\n"
	"      --mem[1-3],   [str]  Set at cmd to given memory slot, e.g. \"ltelc nmodeat --mem1 \"at%xbandlock=2,\\\"100\\\"\"\"\n"
	"                           To clear the given memslot by given the empty string: \"ltelc nmodeat --mem2 \"\"\"\n"
	"\n";

const char ltelc_edrx_usage_str[] =
	"Options for 'ltelc edrx' command:\n"
	"  -e, --enable,     [bool] Enable eDRX\n"
	"  -d, --disable,    [bool] Disable eDRX\n"
	"  -x, --edrx_value, [str]  Sets custom eDRX value to be requested when enabling eDRX with -e option.\n"
	"  -w, --ptw,        [str]  Sets custom Paging Time Window value to be requested when enabling eDRX -e option.\n"
	"\n";

const char ltelc_psm_usage_str[] =
	"Options for 'ltelc psm' command:\n"
	"  -e, --enable,     [bool] Enable PSM\n"
	"  -d, --disable,    [bool] Disable PSM\n"
	"  -p, --rptau,      [str]  Sets custom requested periodic TAU value to be requested when enabling PSM -e option.\n"
	"  -t, --rat,        [str]  Sets custom requested active time (RAT) value to be requested when enabling PSM -e option.\n"
	"\n";

const char ltelc_rsrp_usage_str[] =
	"Options for 'ltelc rsrp' command:\n"
	"  -s, --subscribe,  [bool] Subscribe for RSRP info\n"
	"  -u, --unsubscribe,[bool] Unsubscribe for RSRP info\n"
	"\n";

/******************************************************************************/

/* Following are not having short options: */
#define LTELC_SHELL_OPT_MEM_SLOT_1 1001
#define LTELC_SHELL_OPT_MEM_SLOT_2 1002
#define LTELC_SHELL_OPT_MEM_SLOT_3 1003

 /* Specifying the expected options (both long and short): */
static struct option long_options[] = {
    {"apn",                     required_argument, 0,  'a' },
    {"cid",                     required_argument, 0,  'I' },
    {"family",                  required_argument, 0,  'f' },
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
    {"edrx_value",              required_argument, 0,  'x' },
    {"ptw",                     required_argument, 0,  'w' },
    {"prot",                    required_argument, 0,  'A' },
    {"pword",                   required_argument, 0,  'P' },
    {"uname",                   required_argument, 0,  'U' },
    {"rptau",                   required_argument, 0,  'p' },
    {"rat",                     required_argument, 0,  't' },
    {"mem1",                    required_argument, 0,   LTELC_SHELL_OPT_MEM_SLOT_1 },
    {"mem2",                    required_argument, 0,   LTELC_SHELL_OPT_MEM_SLOT_2 },
    {"mem3",                    required_argument, 0,   LTELC_SHELL_OPT_MEM_SLOT_3 },
    {0,                         0,                 0,   0  }
};

/******************************************************************************/

static void ltelc_shell_print_usage(const struct shell *shell, ltelc_shell_cmd_args_t *ltelc_cmd_args)
{
		switch (ltelc_cmd_args->command) {
		case LTELC_CMD_DEFCONT:
			shell_print(shell, "%s", ltelc_defcont_usage_str);
			break;
		case LTELC_CMD_DEFCONTAUTH:
			shell_print(shell, "%s", ltelc_defcontauth_usage_str);
			break;
		case LTELC_CMD_CONNECT:
		case LTELC_CMD_DISCONNECT:
			shell_print(shell, "%s", ltelc_connect_usage_str);
			break;
		case LTELC_CMD_SYSMODE:
			shell_print(shell, "%s", ltelc_sysmode_usage_str);
			break;
		case LTELC_CMD_FUNMODE:
			shell_print(shell, "%s", ltelc_funmode_usage_str);
			break;
		case LTELC_CMD_NORMAL_MODE_AT:
			shell_print(shell, "%s", ltelc_normal_mode_at_usage_str);
			break;
		case LTELC_CMD_EDRX:
			shell_print(shell, "%s", ltelc_edrx_usage_str);
			break;
		case LTELC_CMD_PSM:
			shell_print(shell, "%s", ltelc_psm_usage_str);
			break;
		case LTELC_CMD_RSRP:
			shell_print(shell, "%s", ltelc_rsrp_usage_str);
			break;

		default:
			shell_print(shell, "%s", ltelc_usage_str);
			break;
		}
}

static void ltelc_shell_cmd_defaults_set(ltelc_shell_cmd_args_t *ltelc_cmd_args)
{
	memset(ltelc_cmd_args, 0, sizeof(ltelc_shell_cmd_args_t));
	ltelc_cmd_args->funmode_option = LTELC_FUNMODE_NONE;
	ltelc_cmd_args->sysmode_option = LTE_LC_SYSTEM_MODE_NONE;
}

/******************************************************************************/

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

static const char *ltelc_shell_sysmode_to_string(int sysmode, char *out_str_buff)
{
	struct mapping_tbl_item const mapping_table[] = {
		{LTE_LC_SYSTEM_MODE_NONE,      "None"},
		{LTE_LC_SYSTEM_MODE_LTEM,      "LTE-M"},
		{LTE_LC_SYSTEM_MODE_NBIOT,     "NB-IoT"},
		{LTE_LC_SYSTEM_MODE_GPS,       "GPS"},
		{LTE_LC_SYSTEM_MODE_LTEM_GPS,  "LTE-M - GPS"},
		{LTE_LC_SYSTEM_MODE_NBIOT_GPS, "NB-IoT - GPS"},
		{-1, NULL}
	};
	
	return ltelc_shell_map_to_string(mapping_table, sysmode, out_str_buff);
}

/******************************************************************************/

int ltelc_shell(const struct shell *shell, size_t argc, char **argv)
{
	ltelc_shell_cmd_args_t ltelc_cmd_args;
	int ret = 0;	
	bool require_apn = false;
	bool require_apn_or_pdn_cid = false;
	bool require_rsrp_subscribe = false;
	bool require_option = false;
	char *apn = NULL;
	char *family = NULL;
	int protocol = 0;
	bool protocol_given = false;
	char *username = NULL;
	char *password = NULL;
	int pdn_cid = 0;

	ltelc_shell_cmd_defaults_set(&ltelc_cmd_args);
	
	if (argc < 2) {
		goto show_usage;
	}
	
	/* command = argv[0] = "ltelc" */
	/* sub-command = argv[1]       */
	if (strcmp(argv[1], "status") == 0) {
		ltelc_cmd_args.command = LTELC_CMD_STATUS;
	} else if (strcmp(argv[1], "coneval") == 0) {
		ltelc_cmd_args.command = LTELC_CMD_CONEVAL;
	} else if (strcmp(argv[1], "rsrp") == 0) {
		require_rsrp_subscribe = true;
		ltelc_cmd_args.command = LTELC_CMD_RSRP;
	} else if (strcmp(argv[1], "connect") == 0) {
		require_apn = true;
		ltelc_cmd_args.command = LTELC_CMD_CONNECT;
	} else if (strcmp(argv[1], "disconnect") == 0) {
		require_apn_or_pdn_cid = true;
		ltelc_cmd_args.command = LTELC_CMD_DISCONNECT;
	} else if (strcmp(argv[1], "defcont") == 0) {
		ltelc_cmd_args.command = LTELC_CMD_DEFCONT;
	} else if (strcmp(argv[1], "defcontauth") == 0) {
		ltelc_cmd_args.command = LTELC_CMD_DEFCONTAUTH;
	} else if (strcmp(argv[1], "funmode") == 0) {
		require_option = true;
		ltelc_cmd_args.command = LTELC_CMD_FUNMODE;
	} else if (strcmp(argv[1], "sysmode") == 0) {
		require_option = true;
		ltelc_cmd_args.command = LTELC_CMD_SYSMODE;
	} else if (strcmp(argv[1], "nmodeat") == 0) {
		ltelc_cmd_args.command = LTELC_CMD_NORMAL_MODE_AT;
	} else if (strcmp(argv[1], "edrx") == 0) {
		require_option = true;
		ltelc_cmd_args.command = LTELC_CMD_EDRX;
	} else if (strcmp(argv[1], "psm") == 0) {
		require_option = true;
		ltelc_cmd_args.command = LTELC_CMD_PSM;
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
	int apn_len = 0;

	char edrx_value_str[LTELC_SHELL_EDRX_VALUE_STR_LENGTH + 1];
	bool edrx_value_set = false;
	char edrx_ptw_bit_str[LTELC_SHELL_EDRX_PTW_STR_LENGTH + 1];
	bool edrx_ptw_set = false;

	char psm_rptau_bit_str[LTELC_SHELL_PSM_PARAM_STR_LENGTH + 1];
	bool psm_rptau_set = false;
	char psm_rat_bit_str[LTELC_SHELL_PSM_PARAM_STR_LENGTH + 1];
	bool psm_rat_set = false;

	char *normal_mode_at_str = NULL;
	uint8_t normal_mode_at_mem_slot = 0;

	while ((opt = getopt_long(argc, argv, "a:I:f:x:w:p:t:A:P:U:su014rmngMNed", 
		long_options, &long_index)) != -1) {
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
		case 'x': //edrx_value
			if (strlen(optarg) == LTELC_SHELL_EDRX_VALUE_STR_LENGTH) {
				strcpy(edrx_value_str, optarg);
				edrx_value_set = true;
			}
			else {
				shell_error(shell, "eDRX value string length must be %d.", 
					LTELC_SHELL_EDRX_VALUE_STR_LENGTH);
				return -EINVAL;
			}
			break;
		case 'w': //Paging Time Window
			if (strlen(optarg) == LTELC_SHELL_EDRX_PTW_STR_LENGTH) {
				strcpy(edrx_ptw_bit_str, optarg);
				edrx_ptw_set = true;
			}
			else {
				shell_error(shell, "PTW string length must be %d.", 
					LTELC_SHELL_EDRX_PTW_STR_LENGTH);
				return -EINVAL;
			}
			break;

		/* PSM specifics: */
		case 'p': //rptau
			if (strlen(optarg) == LTELC_SHELL_PSM_PARAM_STR_LENGTH) {
				strcpy(psm_rptau_bit_str, optarg);
				psm_rptau_set = true;
			}
			else {
				shell_error(shell, "RPTAU bit string length must be %d.", 
					LTELC_SHELL_PSM_PARAM_STR_LENGTH);
				return -EINVAL;
			}
			break;
		case 't': //rat
			if (strlen(optarg) == LTELC_SHELL_PSM_PARAM_STR_LENGTH) {
				strcpy(psm_rat_bit_str, optarg);
				psm_rat_set = true;
			}
			else {
				shell_error(shell, "RAT bit string length must be %d.", 
					LTELC_SHELL_PSM_PARAM_STR_LENGTH);
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
		case 'I': /* PDN CID */
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
		case 'a': /* APN */
			apn_len = strlen(optarg);
			if (apn_len > LTELC_APN_STR_MAX_LENGTH) {
				shell_error(shell, 
					"APN string length %d exceeded. Maximum is %d.", 
						apn_len, LTELC_APN_STR_MAX_LENGTH);
				ret = -EINVAL;
				goto show_usage;
			}
			apn = optarg;
			break;
		case 'f': /* Address family */
			family = optarg;
			break;
		case 'A': /* defcont auth protocol */
			protocol = atoi(optarg);
			protocol_given = true;
			break;
		case 'U': /* defcont auth username */
			username = optarg;
			break;
		case 'P': /* defcont auth password */
			password = optarg;
			break;
		
		/* Options without short option: */
		case LTELC_SHELL_OPT_MEM_SLOT_1:
			normal_mode_at_str = optarg;
			normal_mode_at_mem_slot = 1;
			break;
		case LTELC_SHELL_OPT_MEM_SLOT_2:
			normal_mode_at_str = optarg;
			normal_mode_at_mem_slot = 2;
			break;
		case LTELC_SHELL_OPT_MEM_SLOT_3:
			normal_mode_at_str = optarg;
			normal_mode_at_mem_slot = 3;
			break;
		case '?':
			goto show_usage;
			break;
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
	} else if (require_rsrp_subscribe && 
		ltelc_cmd_args.rsrp_option == LTELC_RSRP_NONE) {
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
	enum lte_lc_system_mode sys_mode_current = LTE_LC_SYSTEM_MODE_NONE;
	bool online = false;

	switch (ltelc_cmd_args.command) {
		case LTELC_CMD_DEFCONT:
			if (ltelc_cmd_args.common_option == LTELC_COMMON_READ) {
				ltelc_sett_defcont_conf_shell_print(shell);
			}
			else if (ltelc_cmd_args.common_option == LTELC_COMMON_ENABLE) {
				ltelc_sett_save_defcont_enabled(true);
				}
			else if (ltelc_cmd_args.common_option == LTELC_COMMON_DISABLE) {
				static char cgdcont[] = "AT+CGDCONT=0";
				if (at_cmd_write(cgdcont, NULL, 0, NULL) != 0) {
					shell_warn(shell, "Disabling cannot be done.");
					shell_warn(shell, 
						"Please note that disabling can be only done in funmode flightmode.");
				}
				else {
					ltelc_sett_save_defcont_enabled(false);
					shell_print(shell, "Custom default context config disabled.");
				}
			}
			else if (ltelc_cmd_args.common_option == LTELC_COMMON_NONE && 
			         apn == NULL && family == NULL) {
				goto show_usage;
			}
			if (apn != NULL) {
				(void)ltelc_sett_save_defcont_apn(apn);
			}
			if (family != NULL) {
				(void)ltelc_sett_save_defcont_ip_family(family);
			}
			break;
		case LTELC_CMD_DEFCONTAUTH:
			if (ltelc_cmd_args.common_option == LTELC_COMMON_READ) {
				ltelc_sett_defcontauth_conf_shell_print(shell);
			} 
			else if (ltelc_cmd_args.common_option == LTELC_COMMON_ENABLE) {
					if (ltelc_sett_save_defcontauth_enabled(true) < 0) {
						shell_warn(shell, "Cannot enable authentication.");
					}
				}
			else if (ltelc_cmd_args.common_option == LTELC_COMMON_DISABLE) {
				static char cgauth[] = "AT+CGAUTH=0,0";
				if (at_cmd_write(cgauth, NULL, 0, NULL) != 0) {
					shell_warn(shell, "Disabling of auth cannot be done to modem.");
				}
				ltelc_sett_save_defcontauth_enabled(false);
			}
			else if (ltelc_cmd_args.common_option == LTELC_COMMON_NONE && 
			         !protocol_given && username == NULL && password == NULL) {
				goto show_usage;
			}

			if (protocol_given) {
				(void)ltelc_sett_save_defcontauth_prot(protocol);
			}
			if (username != NULL) {
				(void)ltelc_sett_save_defcontauth_username(username);
			}
			if (password != NULL) {
				(void)ltelc_sett_save_defcontauth_password(password);
			}
			break;

		case LTELC_CMD_STATUS:
			ret = lte_lc_system_mode_get(&sys_mode_current);
			if (ret >= 0)
				shell_print(shell, "Modem system mode: %s", ltelc_shell_sysmode_to_string(sys_mode_current, snum));

			ret = ltelc_func_mode_get();
			if (ret >= 0)
				shell_print(shell, "Modem functional mode: %s", ltelc_shell_funmode_to_string(ret, snum));

			if (ret == LTELC_FUNMODE_NORMAL)
				online = true;

			ltelc_api_modem_info_get_for_shell(shell, online);
			break;
		case LTELC_CMD_CONEVAL:
			ltelc_api_coneval_read_for_shell(shell);
			break;

		case LTELC_CMD_SYSMODE:
			if (ltelc_cmd_args.common_option == LTELC_COMMON_READ) {

				ret = lte_lc_system_mode_get(&sys_mode_current);
				if (ret < 0) {
					shell_error(shell, "Cannot read system mode of the modem: %d", ret);
				} else {
					shell_print(shell, "System mode read successfully from modem: %s", ltelc_shell_sysmode_to_string(sys_mode_current, snum));
				}
			} else if (ltelc_cmd_args.sysmode_option != LTE_LC_SYSTEM_MODE_NONE) {
				ret = lte_lc_system_mode_set(ltelc_cmd_args.sysmode_option);
				if (ret < 0) {
					shell_error(shell, "Cannot set system mode: %d", ret);
					ret = ltelc_func_mode_get();
					if (ret != LTELC_FUNMODE_FLIGHTMODE || ret != LTELC_FUNMODE_PWROFF) {
						shell_info(shell, "Setting 1st to flightmode might help by using: \"ltelc funmode --flightmode\"");
					}
				} else {
					shell_print(shell, "System mode set successfully to modem: %s", ltelc_shell_sysmode_to_string(ltelc_cmd_args.sysmode_option, snum));
					
					/* Save system modem: */
					(void)ltelc_sett_sysmode_save(ltelc_cmd_args.sysmode_option);
				}
			}
			else {
				goto show_usage;
			}
			break;
		case LTELC_CMD_FUNMODE:
			if (ltelc_cmd_args.common_option == LTELC_COMMON_READ) {
				ret = ltelc_func_mode_get();
				if (ret < 0) {
					shell_error(shell, "Cannot get functional mode: %d", ret);
				} else {
					shell_print(shell, "Functional mode read successfully: %s", ltelc_shell_funmode_to_string(ret, snum));
				}
			} else if (ltelc_cmd_args.funmode_option != LTELC_FUNMODE_NONE) {
				ret = ltelc_func_mode_set(ltelc_cmd_args.funmode_option);
				if (ret < 0) {
					shell_error(shell, "Cannot set functional mode: %d", ret);
				} else {
					shell_print(shell, "Functional mode set successfully: %s", ltelc_shell_funmode_to_string(ltelc_cmd_args.funmode_option, snum));
				}
			}
			else {
				goto show_usage;
			}
			break;
		case LTELC_CMD_NORMAL_MODE_AT:
			if (ltelc_cmd_args.common_option == LTELC_COMMON_READ) {
				ltelc_sett_normal_mode_at_cmds_shell_print(shell);
			}
			else if (normal_mode_at_str != NULL) {
				ret = ltelc_sett_save_normal_mode_at_cmd_str(normal_mode_at_str, normal_mode_at_mem_slot);
				if (ret < 0) {
					shell_error(shell, "Cannot set normal mode AT-command: \"%s\"", normal_mode_at_str);
				} else {
					shell_print(
						shell, 
						"Normal mode AT-command \"%s\" set successfully to memory slot %d.", 
							((strlen(normal_mode_at_str)) ? normal_mode_at_str: "<empty>"), 
						normal_mode_at_mem_slot);
				}
			}
			else {
				goto show_usage;
			}
			break;

		case LTELC_CMD_EDRX:
			if (ltelc_cmd_args.common_option == LTELC_COMMON_ENABLE) {
				char *value = NULL; /* Set with the defaults if not given */
				if (edrx_value_set) {
					value = edrx_value_str;
				}
				ret = lte_lc_edrx_param_set(value);
				if (ret < 0) {
					shell_error(shell, "Cannot set eDRX value %s, error: %d", ((value == NULL)? "NULL" : value), ret);
					return -EINVAL;
				}
				value = NULL;  /* Set with the defaults if not given */
				if (edrx_ptw_set) {
					value = edrx_ptw_bit_str;
				}
				ret = lte_lc_ptw_set(value);
				if (ret < 0) {
					shell_error(shell, "Cannot set PTW value %s, error: %d", ((value == NULL)? "NULL" : value), ret);
					return -EINVAL;
				}

				ret = lte_lc_edrx_req(true);
				if (ret < 0) {
					shell_error(shell, "Cannot enable eDRX: %d", ret);
				} else {
					shell_print(shell, "eDRX enabled");
				}
			}
			else if (ltelc_cmd_args.common_option == LTELC_COMMON_DISABLE) {
				ret = lte_lc_edrx_req(false);
				if (ret < 0) {
					shell_error(shell, "Cannot disable eDRX: %d", ret);
				} else {
					shell_print(shell, "eDRX disabled");
				}
			}
			else {
				shell_error(shell, "Unknown option for edrx command. See usage:");
				goto show_usage;
			}
			break;
		case LTELC_CMD_PSM:
			if (ltelc_cmd_args.common_option == LTELC_COMMON_ENABLE) {
				/* Set with the defaults if not given */
				char *rptau_bit_value = NULL;
				char *rat_bit_value = NULL;

				if (psm_rptau_set)
					rptau_bit_value = psm_rptau_bit_str;

				if (psm_rat_set)
					rat_bit_value = psm_rat_bit_str;

				ret = lte_lc_psm_param_set(rptau_bit_value, rat_bit_value);
				if (ret < 0) {
					shell_error(shell, "Cannot set PSM parameters: error %d", ret);
					shell_error(shell, "  rptau %s, rat %s", 
						((rptau_bit_value == NULL)? "NULL" : rptau_bit_value),
						((rat_bit_value == NULL)? "NULL" : rat_bit_value));
					return -EINVAL;
				}

				ret = lte_lc_psm_req(true);
				if (ret < 0) {
					shell_error(shell, "Cannot enable PSM: %d", ret);
				} else {
					shell_print(shell, "PSM enabled");
				}
			}
			else if (ltelc_cmd_args.common_option == LTELC_COMMON_DISABLE) {
				ret = lte_lc_psm_req(false);
				if (ret < 0) {
					shell_error(shell, "Cannot disable PSM: %d", ret);
				} else {
					shell_print(shell, "PSM disabled");
				}
			}
			else {
				shell_error(shell, "Unknown option for psm command. See usage:");
				goto show_usage;
			}
			break;

		case LTELC_CMD_RSRP:
			(ltelc_cmd_args.rsrp_option == LTELC_RSRP_SUBSCRIBE) ? ltelc_rsrp_subscribe(true) : ltelc_rsrp_subscribe(false); 
			break;
		case LTELC_CMD_CONNECT:
			ret = ltelc_pdn_init_and_connect(apn, family);
			if (ret < 0) {
				shell_error(shell, "Cannot connect pdn socket: %d", ret);
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
	ltelc_shell_print_usage(shell, &ltelc_cmd_args);
	return ret;
}
