/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <assert.h>

#include <sys/types.h>
#include <nrf9160.h>
#include <hal/nrf_gpio.h>

#include <shell/shell.h>
#include <shell/shell_uart.h>

#include <modem/modem_info.h>
#include <modem/lte_lc.h>


#include "lte_connection.h"

#if defined(CONFIG_MODEM_INFO)
#include <modem/at_cmd.h>
#include <modem/at_cmd_parser.h>
#include <modem/at_params.h>

#include <net/net_ip.h>

#include <posix/arpa/inet.h>

#include "utils/fta_net_utils.h"
#endif

static const struct shell *uart_shell;


#if defined(CONFIG_MODEM_INFO)
#define AT_CMD_BUFFER_LEN (CONFIG_AT_CMD_RESPONSE_MAX_LEN + 1)
#define AT_CMD_PDP_CONTEXT_READ	"AT+CGDCONT?"
#define AT_CMD_PDP_CONTEXT_READ_PARAM_COUNT 12
#define AT_CMD_PDP_CONTEXT_READ_CID_INDEX 1
#define AT_CMD_PDP_CONTEXT_READ_PDP_TYPE_INDEX 2
#define AT_CMD_PDP_CONTEXT_READ_APN_INDEX 3
#define AT_CMD_PDP_CONTEXT_READ_PDP_ADDR_INDEX 4
#define AT_CMD_PDP_CONTEXT_READ_PDP_TYPE_STR_MAX_LEN (6 + 1)
#define AT_CMD_PDP_CONTEXT_READ_APN_STR_MAX_LEN (255)
#define AT_CMD_PDP_CONTEXT_READ_IP_ADDR_STR_MAX_LEN (255)

typedef struct {
	uint32_t cid;
	char pdp_type_str[AT_CMD_PDP_CONTEXT_READ_PDP_TYPE_STR_MAX_LEN];
	char apn_str[AT_CMD_PDP_CONTEXT_READ_APN_STR_MAX_LEN];
	char ip_addr_str[AT_CMD_PDP_CONTEXT_READ_IP_ADDR_STR_MAX_LEN];
	struct sockaddr_in sin4;
	struct sockaddr_in6 sin6;
} pdp_context_info_t;


/* System work queue for getting the modem info that ain't in lte connection ind.
   TODO: things like these might be good to be in lte connection ind, 
   i.e. merge certain stuff from modem info to there? */

static struct k_work modem_info_work;

/* Work queue for signal info: */
static struct k_work modem_info_signal_work;
static int32_t modem_rsrp;

//**************************************************************************

static int modem_pdp_context_read(pdp_context_info_t *populated_info)
{
	int ret;
	struct at_param_list param_list = {0};
	size_t param_str_len;
	char at_response_str[MODEM_INFO_MAX_RESPONSE_SIZE];

	ret = at_cmd_write(AT_CMD_PDP_CONTEXT_READ, at_response_str, sizeof(at_response_str), NULL);
	if (ret) {
		shell_error(uart_shell, "at_cmd_write returned err: %d", ret);
		return ret;
	}
	//shell_print(uart_shell, "%s", at_response_str);

	//TODO: support for multiple contexts, i.e. multiline response, to be something like:
	//while ((ip_str_end = strstr(ip_str_end, AT_CMD_RSP_DELIM)) != NULL) {

	ret = at_params_list_init(&param_list, AT_CMD_PDP_CONTEXT_READ_PARAM_COUNT);
	if (ret) {
		shell_error(uart_shell, "Could init AT params list, error: %d", ret);
		return ret;
	}
	ret = at_parser_max_params_from_str(at_response_str, NULL, &param_list, AT_CMD_PDP_CONTEXT_READ_PARAM_COUNT);
	if (ret) {
		shell_error(uart_shell, "Could not parse AT response, error: %d", ret);
		goto clean_exit;
	}

	ret = at_params_int_get(&param_list, AT_CMD_PDP_CONTEXT_READ_CID_INDEX, &populated_info->cid);
	if (ret) {
		shell_error(uart_shell, "Could not parse CID, err: %d", ret);
		goto clean_exit;
	}

	//TODO: read len 1st and malloc??

	param_str_len = sizeof(populated_info->pdp_type_str);
	ret = at_params_string_get(&param_list,
				   AT_CMD_PDP_CONTEXT_READ_PDP_TYPE_INDEX,
				   populated_info->pdp_type_str,
				   &param_str_len);
	if (ret) {
		shell_error(uart_shell, "Could not parse pdp type, err: %d", ret);
		goto clean_exit;
	}
	populated_info->pdp_type_str[param_str_len] = '\0';

	param_str_len = sizeof(populated_info->apn_str);
	ret = at_params_string_get(&param_list,
				   AT_CMD_PDP_CONTEXT_READ_APN_INDEX,
				   populated_info->apn_str,
				   &param_str_len);
	if (ret) {
		shell_error(uart_shell, "Could not parse apn str, err: %d", ret);
		goto clean_exit;
	}
	populated_info->apn_str[param_str_len] = '\0';

	param_str_len = sizeof(populated_info->ip_addr_str);
	ret = at_params_string_get(&param_list,
				   AT_CMD_PDP_CONTEXT_READ_PDP_ADDR_INDEX,
				   populated_info->ip_addr_str,
				   &param_str_len);
	if (ret) {
		shell_error(uart_shell, "Could not parse apn str, err: %d", ret);
		goto clean_exit;
	}
	populated_info->ip_addr_str[param_str_len] = '\0';

	/* Parse IP addresses from space delimited string: */
	{
		// char **tokens;
		// const char sp = ' ';

		// tokens = str_split(populated_info->ip_addr_str, sp);
		// if (tokens) {

		// }
		char *tmp = malloc(strlen(populated_info->ip_addr_str) + 1);
		char *ip_address1, *ip_address2;

		strcpy(tmp, populated_info->ip_addr_str);

		/* Get 1st 2 IP addresses from a CGDCONT string: */
		ip_address1 = strtok(tmp, " ");
		ip_address2 = strtok(NULL, " ");

		if (ip_address1 != NULL) {
			int family = fta_net_utils_sa_family_from_ip_string(ip_address1);
			if (family == AF_INET) {
				struct sockaddr_in *sin = &populated_info->sin4;
				(void)inet_pton(AF_INET, ip_address1, &(sin->sin_addr));
				sin->sin_family = AF_INET;
			}
			else if (family == AF_INET6) {
				struct sockaddr_in6 *sin6 = &populated_info->sin6;

				(void)inet_pton(AF_INET6, ip_address1, &(sin6->sin6_addr));
				sin6->sin6_family = AF_INET6;
			}
		}
		if (ip_address2 != NULL) {
			/* note: if we are here, PDP_addr_2 should be IPv6, thus in following ipv4 branch should not 
			   be possible: */
			int family = fta_net_utils_sa_family_from_ip_string(ip_address2);
			if (family == AF_INET) {
				struct sockaddr_in *sin = &populated_info->sin4;
				(void)inet_pton(AF_INET, ip_address2, &(sin->sin_addr));
				sin->sin_family = AF_INET;
			}
			else if (family == AF_INET6) {
				struct sockaddr_in6 *sin6 = &populated_info->sin6;

				(void)inet_pton(AF_INET6, ip_address2, &(sin6->sin6_addr));
				sin6->sin6_family = AF_INET6;
			}
		}
		free(tmp);
	}


clean_exit:
	at_params_list_free(&param_list);

	return ret;
}
//**************************************************************************

static void modem_info_get(struct k_work *unused)
{
	int ret;
	char info_str[MODEM_INFO_MAX_RESPONSE_SIZE];
	pdp_context_info_t pdp_context_info;
	
	ARG_UNUSED(unused);

    k_sleep(K_MSEC(1500)); /* Seems that 1st info read fails without this. Thus, let modem have some time */

	ret = modem_info_string_get(MODEM_INFO_OPERATOR, info_str, sizeof(info_str));
	if (ret >= 0) {
		shell_print(uart_shell, "Operator: %s", info_str);
	} else {
		shell_error(uart_shell, "\nUnable to obtain modem operator parameters (%d)", ret);
	}

#ifdef RM_JH //not needed anymore as these are from CGDCONT
	ret = modem_info_string_get(MODEM_INFO_IP_ADDRESS, info_str, sizeof(info_str));
	if (ret >= 0) {
		shell_print(uart_shell, "IP address(es) from modem_info: %s", info_str);
	} else {
		shell_error(uart_shell, "\nUnable to obtain modem ip parameters (%d)", ret);
	}
#endif
#ifdef RM_JH //not needed anymore as these are from CGDCONT
	ret = modem_info_string_get(MODEM_INFO_APN, info_str, sizeof(info_str));
	if (ret >= 0) {
		shell_print(uart_shell, "APN: %s", info_str);
	} else {
		shell_error(uart_shell, "\nUnable to obtain modem ip parameters (%d)", ret);
	}
#endif
	ret = modem_info_string_get(MODEM_INFO_FW_VERSION, info_str, sizeof(info_str));
	if (ret >= 0) {
		shell_print(uart_shell, "Modem FW version: %s", info_str);
	} else {
		shell_error(uart_shell, "\nUnable to obtain modem ip parameters (%d)", ret);
	}

	ret = modem_pdp_context_read(&pdp_context_info);
	if (ret >= 0) {
		char ipv4_addr[NET_IPV4_ADDR_LEN];		
		char ipv6_addr[NET_IPV6_ADDR_LEN];

		inet_ntop(AF_INET,  &(pdp_context_info.sin4.sin_addr), ipv4_addr, sizeof(ipv4_addr));
		inet_ntop(AF_INET6, &(pdp_context_info.sin6.sin6_addr), ipv6_addr, sizeof(ipv6_addr));
		
		/* Parsed PDP context info: */	
		shell_print(uart_shell, 
					"Parsed PDP context info:\n"
					"  CID:                    %d\n"
					"  PDP type:               %s\n"
					"  APN:                    %s\n"
//					"  IP address(es) string:  %s\n"
					"  IPv4 address:           %s\n"
					"  IPv6 address:           %s",					
						pdp_context_info.cid, 
						pdp_context_info.pdp_type_str, 
						pdp_context_info.apn_str, 
//						pdp_context_info.ip_addr_str,
						(ipv4_addr != NULL) ? ipv4_addr : "N/A",
						(ipv6_addr != NULL) ? ipv6_addr : "N/A");
	} else {
		shell_error(uart_shell, "\nUnable to obtain pdp context info (%d)", ret);
	}

}
//**************************************************************************

static void modem_info_signal_handler(char rsrp_value)
{

	modem_rsrp = (int8_t)rsrp_value - MODEM_INFO_RSRP_OFFSET_VAL;
	//shell_print(uart_shell, "rsrp:%d", modem_rsrp);
	k_work_submit(&modem_info_signal_work);
}

//**************************************************************************

#define FTA_RSRP_UPDATE_INTERVAL_IN_SECS 5
static void modem_info_signal_update(struct k_work *work)
{
	static uint32_t timestamp_prev = 0;

	if ((timestamp_prev != 0) &&
	    (k_uptime_get_32() - timestamp_prev <
	     FTA_RSRP_UPDATE_INTERVAL_IN_SECS * MSEC_PER_SEC)) {
		return;
	}

	shell_print(uart_shell, "RSRP: %d", modem_rsrp);
	timestamp_prev = k_uptime_get_32();
}
#endif

void lte_connection_init(void)
{
#if defined(CONFIG_MODEM_INFO)
	k_work_init(&modem_info_work, modem_info_get);
	k_work_init(&modem_info_signal_work, modem_info_signal_update);
	modem_info_rsrp_register(modem_info_signal_handler);
#endif
}

void lte_connection_ind_handler(const struct lte_lc_evt *const evt)
{
	uart_shell = shell_backend_uart_get_ptr();
	switch (evt->type) {
	case LTE_LC_EVT_NW_REG_STATUS:
		switch (evt->nw_reg_status) {
		case LTE_LC_NW_REG_NOT_REGISTERED:
			shell_print(
				uart_shell,
				"Network registration status: not registered");
			break;
		case LTE_LC_NW_REG_SEARCHING:
			shell_print(uart_shell,
				   "Network registration status: searching");
			break;
		case LTE_LC_NW_REG_REGISTRATION_DENIED:
			shell_print(uart_shell,
				   "Network registration status: denied");
			break;
		case LTE_LC_NW_REG_UNKNOWN:
			shell_print(uart_shell,
				   "Network registration status: unknown");
			break;
		case LTE_LC_NW_REG_UICC_FAIL:
			shell_print(uart_shell,
				   "Network registration status: UICC fail");
			break;
		case LTE_LC_NW_REG_REGISTERED_HOME:
		case LTE_LC_NW_REG_REGISTERED_ROAMING:
			shell_print(
				uart_shell, "Network registration status: %s",
				evt->nw_reg_status ==
						LTE_LC_NW_REG_REGISTERED_HOME ?
					"Connected - home network" :
					"Connected - roaming");
#if defined(CONFIG_MODEM_INFO)
			k_work_submit(&modem_info_work);
#endif
		default:
			break;
		}
		break;
	case LTE_LC_EVT_CELL_UPDATE:
		shell_print(uart_shell, "LTE cell changed: Cell ID: %d, Tracking area: %d",
		       evt->cell.id, evt->cell.tac);
		break;
	default:
		break;
	}
}
