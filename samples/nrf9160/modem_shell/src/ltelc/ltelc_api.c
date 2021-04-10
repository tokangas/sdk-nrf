/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <assert.h>

#include <sys/types.h>
#include <shell/shell.h>

#include <modem/modem_info.h>

#include <posix/arpa/inet.h>
#include <net/net_ip.h>

#include "utils/net_utils.h"

#include "ltelc_shell.h"
#include "ltelc_api.h"

#if defined(CONFIG_AT_CMD)

#include <modem/at_cmd.h>
#include <modem/at_cmd_parser.h>
#include <modem/at_params.h>

#define AT_CMD_BUFFER_LEN (CONFIG_AT_CMD_RESPONSE_MAX_LEN + 1)
#define AT_CMD_PDP_CONTEXTS_READ "AT+CGDCONT?"
#define AT_CMD_PDP_CONTEXTS_READ_PARAM_COUNT 12
#define AT_CMD_PDP_CONTEXTS_READ_CID_INDEX 1
#define AT_CMD_PDP_CONTEXTS_READ_PDP_TYPE_INDEX 2
#define AT_CMD_PDP_CONTEXTS_READ_APN_INDEX 3
#define AT_CMD_PDP_CONTEXTS_READ_PDP_ADDR_INDEX 4

#define AT_CMD_PDP_CONTEXT_READ_INFO "AT+CGCONTRDP=%d" // Use sprintf to add CID into command
#define AT_CMD_PDP_CONTEXT_READ_INFO_PARAM_COUNT 20
#define AT_CMD_PDP_CONTEXT_READ_INFO_CID_INDEX 1
#define AT_CMD_PDP_CONTEXT_READ_INFO_DNS_ADDR_PRIMARY_INDEX 6
#define AT_CMD_PDP_CONTEXT_READ_INFO_DNS_ADDR_SECONDARY_INDEX 7
#define AT_CMD_PDP_CONTEXT_READ_INFO_MTU_INDEX                12

#define AT_CMD_PDP_CONTEXT_READ_RSP_DELIM "\r\n"

pdp_context_info_t* ltelc_api_get_pdp_context_info_by_pdn_cid(int pdn_cid)
{
	int ret;
	pdp_context_info_array_t pdp_context_info_tbl;
	pdp_context_info_t* pdp_context_info = NULL;

	ret = ltelc_api_pdp_contexts_read(&pdp_context_info_tbl);
	if (ret) {
		printf("cannot read current connection info: %d", ret);
		return NULL;
	}

	// Find PDP context info for requested CID
	for (int i = 0; i < pdp_context_info_tbl.size; i++) {
		if (pdp_context_info_tbl.array[i].cid == pdn_cid) {
			pdp_context_info = calloc(1, sizeof(pdp_context_info_t));
			memcpy(pdp_context_info, &(pdp_context_info_tbl.array[i]), sizeof(pdp_context_info_t));
			break;
		}
	}

	if (pdp_context_info_tbl.array != NULL) {
		free(pdp_context_info_tbl.array);
	}
	return pdp_context_info;
}

int ltelc_api_pdp_context_dynamic_params_get(pdp_context_info_t *populated_info)
{
	int ret = 0;
	struct at_param_list param_list = { 0 };
	size_t param_str_len;
	char *next_param_str;
	bool resp_continues = false;

	char at_response_str[CONFIG_AT_CMD_RESPONSE_MAX_LEN + 1];
	char *at_ptr = at_response_str;
	char *tmp_ptr = at_response_str;
	int lines = 0;
	int iterator = 0;

	char at_cmd_pdp_context_read_info_cmd_str[15];
	sprintf(at_cmd_pdp_context_read_info_cmd_str, AT_CMD_PDP_CONTEXT_READ_INFO, populated_info->cid);
	ret = at_cmd_write(at_cmd_pdp_context_read_info_cmd_str, at_response_str,
			   sizeof(at_response_str), NULL);
	if (ret) {
		printk("at_cmd_write returned err: %d for %s\n", ret, at_cmd_pdp_context_read_info_cmd_str);
		return ret;
	}
	//printf("\n%s\n", at_response_str);

	/* Check how many rows of info do we have: */
	while ((tmp_ptr = strstr(tmp_ptr, AT_CMD_PDP_CONTEXT_READ_RSP_DELIM)) != NULL) {
		++tmp_ptr;
		++lines;
	}
	
	//printf("Device contains %d lines of DNS info for CID=%d\n", lines, populated_info->cid);

	/* Parse the response: */ 
	{
		ret = at_params_list_init(&param_list,
					  AT_CMD_PDP_CONTEXT_READ_INFO_PARAM_COUNT);
		if (ret) {
			printk("Could not init AT params list, error: %d\n", ret);
			return ret;
		}

	// TODO: Make this a while loop
	parse:
		resp_continues = false;
		ret = at_parser_max_params_from_str(
			at_ptr, &next_param_str, &param_list, 13);
			//AT_CMD_PDP_CONTEXT_READ_PARAM_COUNT);
		if (ret == -EAGAIN) {
			//printf("EAGAIN, error: %d\n", ret);
			resp_continues = true;
		} else if (ret == -E2BIG) {
			printk("E2BIG, error: %d\n", ret);
		} else if (ret != 0) {
			printk("Could not parse AT response for %s, error: %d\n",
				at_cmd_pdp_context_read_info_cmd_str,
				ret);
			goto clean_exit;
		}

		// Read primary DNS address
		char dns_addr_str[AT_CMD_PDP_CONTEXT_READ_IP_ADDR_STR_MAX_LEN];
		param_str_len = sizeof(dns_addr_str);

		ret = at_params_string_get(
			&param_list,
			AT_CMD_PDP_CONTEXT_READ_INFO_DNS_ADDR_PRIMARY_INDEX,
			dns_addr_str,
			&param_str_len);
		if (ret) {
			printk("Could not parse dns str for cid %d, err: %d", 
				populated_info->cid, ret);
			goto clean_exit;
		}
		dns_addr_str[param_str_len] = '\0';
		//printf("Primary DNS address (%d): %s\n", param_str_len, dns_addr_str);

		if (dns_addr_str != NULL) {
			int family = net_utils_sa_family_from_ip_string(dns_addr_str);
			if (family == AF_INET) {
				struct in_addr *addr = &(populated_info->dns_addr4_primary);
				(void)inet_pton(AF_INET, dns_addr_str, addr);
			} else if (family == AF_INET6) {
				struct in6_addr *addr6 = &(populated_info->dns_addr6_primary);
				(void)inet_pton(AF_INET6, dns_addr_str, addr6);
			}
		}

		// Read secondary DNS address
		param_str_len = sizeof(dns_addr_str);

		ret = at_params_string_get(
			&param_list, 
			AT_CMD_PDP_CONTEXT_READ_INFO_DNS_ADDR_SECONDARY_INDEX,
			dns_addr_str,
			&param_str_len);
		if (ret) {
			printk("Could not parse dns str, err: %d", ret);
			goto clean_exit;
		}
		dns_addr_str[param_str_len] = '\0';
		//printf("Secondary DNS address (%d): %s\n", param_str_len, dns_addr_str);

		if (dns_addr_str != NULL) {
			int family = net_utils_sa_family_from_ip_string(dns_addr_str);
			if (family == AF_INET) {
				struct in_addr *addr = &(populated_info->dns_addr4_secondary);
				(void)inet_pton(AF_INET, dns_addr_str, addr);
			} else if (family == AF_INET6) {
				struct in6_addr *addr6 = &(populated_info->dns_addr6_secondary);
				(void)inet_pton(AF_INET6, dns_addr_str, addr6);
			}
		}

		/* Read link MTU if exists: */
		ret = at_params_int_get(&param_list,
					AT_CMD_PDP_CONTEXT_READ_INFO_MTU_INDEX,
					&(populated_info->mtu));
		if (ret) {
			/* Don't care if it fails: */
			ret = 0;
			populated_info->mtu = 0;
		}

		if (resp_continues) {
			at_ptr = next_param_str;
			iterator++;
			if (iterator >= lines) {
				/* Should not happen, just in case... TODO: add assert?*/
				ret = -666;
				goto clean_exit;
			}
			goto parse;
		}
	}

clean_exit:
	at_params_list_free(&param_list);

	return ret;
}

/* ****************************************************************************/
#define AT_CMD_CONEVAL "AT%CONEVAL"
#define AT_CMD_CONEVAL_RESP_PARAM_COUNT        18 /* 1 + actual 17 */

#define AT_CMD_CONEVAL_RESP_RESULT_INDEX        1
#define AT_CMD_CONEVAL_RESP_RRC_STATE_INDEX     2
#define AT_CMD_CONEVAL_RESP_QUALITY_INDEX       3
#define AT_CMD_CONEVAL_RESP_RSRP_INDEX          4
#define AT_CMD_CONEVAL_RESP_RSRQ_INDEX          5
#define AT_CMD_CONEVAL_RESP_SNR_INDEX           6
#define AT_CMD_CONEVAL_RESP_CELL_ID_STR_INDEX   7
#define AT_CMD_CONEVAL_RESP_PLMN_STR_INDEX      8
#define AT_CMD_CONEVAL_RESP_PHY_CELL_ID_INDEX   9
#define AT_CMD_CONEVAL_RESP_EARFCN_INDEX       10
#define AT_CMD_CONEVAL_RESP_BAND_INDEX         11
#define AT_CMD_CONEVAL_RESP_TAU_TRIG_INDEX     12
#define AT_CMD_CONEVAL_RESP_CE_LEVEL_INDEX     13
#define AT_CMD_CONEVAL_RESP_TX_PWR_INDEX       14
#define AT_CMD_CONEVAL_RESP_TX_REPET_INDEX     15
#define AT_CMD_CONEVAL_RESP_RX_REPET_INDEX     16
#define AT_CMD_CONEVAL_RESP_DL_PATHLOSS_INDEX  17

static int ltelc_api_coneval_read(lte_coneval_resp_t *coneval)
{
	int ret = 0;
	int i;
	int value;
	struct at_param_list param_list = { 0 };
	char at_response_str[CONFIG_AT_CMD_RESPONSE_MAX_LEN + 1];
	char str_buf[AT_CMD_CONEVAL_RESP_MAX_STR_LEN + 1];
	int len = sizeof(str_buf);


	memset(coneval, 0, sizeof(lte_coneval_resp_t));
	coneval->result = 7; /* unknown */

	ret = at_cmd_write(AT_CMD_CONEVAL, at_response_str, sizeof(at_response_str), NULL);
	if (ret) {
		printk("at_cmd_write for \"%s\" returned err: %d\n", AT_CMD_CONEVAL, ret);
		return ret;
	}
/*
	else {
		printk("%s", at_response_str);
	}
*/

	ret = at_params_list_init(&param_list, AT_CMD_CONEVAL_RESP_PARAM_COUNT);
	if (ret) {
		printk("Could not init AT params list for \"%s\", error: %d\n", AT_CMD_CONEVAL, ret);
		return ret;
	}

	ret = at_parser_params_from_str(at_response_str, NULL, &param_list);
	if (ret) {
		printk("Could not parse %s response, error: %d\n", AT_CMD_CONEVAL, ret);
		return ret;
	}

	for (i = 1;i < AT_CMD_CONEVAL_RESP_PARAM_COUNT;i++) {
		if (i == AT_CMD_CONEVAL_RESP_CELL_ID_STR_INDEX || i == AT_CMD_CONEVAL_RESP_PLMN_STR_INDEX) {
			ret = at_params_string_get(&param_list, i, str_buf, &len);
			if (ret) {
				printk("ltelc_api_coneval_read: Invalid AT string resp parameter at index %d, err: %d\n", 
					i, ret);
				return ret;
			}
			assert(len <= AT_CMD_CONEVAL_RESP_MAX_STR_LEN);
			str_buf[len] = '\0';
			if (i == AT_CMD_CONEVAL_RESP_CELL_ID_STR_INDEX) {
				strcpy(coneval->cell_id_str, str_buf);
			}
			else {
				assert(i == AT_CMD_CONEVAL_RESP_PLMN_STR_INDEX);
				strcpy(coneval->plmn_str, str_buf);
			}
		}
		else {
			ret = at_params_int_get(&param_list, i, &value);
			if (ret) {
				printk("ltelc_api_coneval_read: Invalid AT int resp parameter at index %d, err: %d\n", 
					i, ret);
				return ret;
			}

			switch (i) {
				case AT_CMD_CONEVAL_RESP_RESULT_INDEX:
					coneval->result = value;
					if (value != 0) {
						printk("ltelc_api_coneval_read: CONEVAL failed: %d\n", value);
						return -1;
					}
					break;
				case AT_CMD_CONEVAL_RESP_RRC_STATE_INDEX:
					coneval->rrc_state = value;
					break;
				case AT_CMD_CONEVAL_RESP_QUALITY_INDEX:
					coneval->quality = value;
					break;
				case AT_CMD_CONEVAL_RESP_RSRP_INDEX:
					coneval->rsrp = value;
					break;
				case AT_CMD_CONEVAL_RESP_RSRQ_INDEX:
					coneval->rsrq = value;
					break;
				case AT_CMD_CONEVAL_RESP_SNR_INDEX:
					coneval->snr = value;
					break;
				case AT_CMD_CONEVAL_RESP_PHY_CELL_ID_INDEX:
					coneval->phy_cell_id = value;
					break;
				case AT_CMD_CONEVAL_RESP_EARFCN_INDEX:
					coneval->earfcn = value;
					break;
				case AT_CMD_CONEVAL_RESP_BAND_INDEX:
					coneval->band = value;
					break;
				case AT_CMD_CONEVAL_RESP_TAU_TRIG_INDEX:
					coneval->tau_triggered = value;
					break;
				case AT_CMD_CONEVAL_RESP_CE_LEVEL_INDEX:
					coneval->ce_level = value;
					break;
				case AT_CMD_CONEVAL_RESP_TX_PWR_INDEX:
					coneval->tx_power = value;
					break;
				case AT_CMD_CONEVAL_RESP_TX_REPET_INDEX:
					coneval->tx_repetitions = value;
					break;
				case AT_CMD_CONEVAL_RESP_RX_REPET_INDEX:
					coneval->rx_repetitions = value;
					break;
				case AT_CMD_CONEVAL_RESP_DL_PATHLOSS_INDEX:
					coneval->dl_pathloss = value;
					break;
			}
		}
	}
	return 0;
}

/** SNR offset value that is used when mapping to dBs  */
#define LTELC_API_SNR_OFFSET_VALUE 25

void ltelc_api_coneval_read_for_shell(const struct shell *shell)
{
	lte_coneval_resp_t coneval_resp;
	static const char *coneval_result_strs[] = {
		"0: Connection evaluation successful",
		"1: Evaluation failed, no cell available",
		"2: Evaluation failed, UICC not available",
		"3: Evaluation failed, only barred cells available",
        "4: Evaluation failed, busy (e.g. GNSS activity)",
		"5: Evaluation failed, aborted because of higher priority operation",
		"6: Evaluation failed, unspecified"
	};
	static const char *coneval_rrc_state_strs[] = {
		"0: RRC connection in idle state during measurements",
		"1: RRC connection in connected state during measurements"
	};
	static const char *coneval_quality_strs[] = {
		"5: Radio link quality -2",
		"6: Radio link quality -1",
		"7: Radio link quality normal",
		"8: Radio link quality +1",
		"9: Radio link quality +2"
	};

	int ret = ltelc_api_coneval_read(&coneval_resp);
	if (ret) {
		shell_error(shell, "Cannot evaluate connection parameters, result: \"%s\", ret %d", 
			((coneval_resp.result <= 6)?coneval_result_strs[coneval_resp.result]:"unknown"), ret);
		return;
	}
	int cell_id = strtol(coneval_resp.cell_id_str, NULL, 16);

	shell_print(shell, "Evaluated connection parameters:");
	shell_print(shell, "  result:         \"%s\"", 
		((coneval_resp.result <= 6) ? coneval_result_strs[coneval_resp.result] : "unknown"));
	shell_print(shell, "  rrc_state:      %s", 
		((coneval_resp.rrc_state == 0 || coneval_resp.rrc_state == 1) ? 
			coneval_rrc_state_strs[coneval_resp.rrc_state] : "unknown"));
	shell_print(shell, "  quality:        %s", 
		((coneval_resp.quality >= 5 && coneval_resp.quality <= 9) ? 
			coneval_quality_strs[coneval_resp.quality - 5] : "unknown"));
	shell_print(shell, "  rsrp:           %d: %ddBm", 
		coneval_resp.rsrp, (coneval_resp.rsrp - MODEM_INFO_RSRP_OFFSET_VAL));
	shell_print(shell, "  rsrq:           %d", coneval_resp.rsrq);
	shell_print(shell, "  snr:            %d: %ddB",
		coneval_resp.snr, (coneval_resp.snr - LTELC_API_SNR_OFFSET_VALUE));

	shell_print(shell, "  cell_id:        \"%s\": %d", coneval_resp.cell_id_str, cell_id);
	shell_print(shell, "  plmn:           \"%s\"", coneval_resp.plmn_str);
	shell_print(shell, "  phy_cell_id:    %d", coneval_resp.phy_cell_id);
	shell_print(shell, "  earfcn:         %d", coneval_resp.earfcn);
	shell_print(shell, "  band:           %d", coneval_resp.band);
	shell_print(shell, "  tau_triggered:  %d", coneval_resp.tau_triggered);
	shell_print(shell, "  ce_level:       %d", coneval_resp.ce_level);
	shell_print(shell, "  tx_power:       %d", coneval_resp.tx_power);
	shell_print(shell, "  tx_repetitions: %d", coneval_resp.tx_repetitions);
	shell_print(shell, "  rx_repetitions: %d", coneval_resp.rx_repetitions);
	shell_print(shell, "  dl_pathloss:    %d", coneval_resp.dl_pathloss);
}
/* ****************************************************************************/

int ltelc_api_pdp_contexts_read(pdp_context_info_array_t *pdp_info)
{
	int ret = 0;
	struct at_param_list param_list = { 0 };
	size_t param_str_len;
	char *next_param_str;
	bool resp_continues = false;

	char at_response_str[CONFIG_AT_CMD_RESPONSE_MAX_LEN + 1];
	char *at_ptr = at_response_str;
	char *tmp_ptr = at_response_str;
	int pdp_cnt = 0;
	int iterator = 0;
	pdp_context_info_t *populated_info;

	memset(pdp_info, 0, sizeof(pdp_context_info_array_t));

	ret = at_cmd_write(AT_CMD_PDP_CONTEXTS_READ, at_response_str,
			   sizeof(at_response_str), NULL);
	if (ret) {
		printf("at_cmd_write returned err: %d", ret);
		return ret;
	}
	//printf("\n%s\n", at_response_str);

	/* Check how many rows/context do we have: */
	while ((tmp_ptr = strstr(tmp_ptr, AT_CMD_PDP_CONTEXT_READ_RSP_DELIM)) !=
	       NULL) {
		++tmp_ptr;
		++pdp_cnt;
	}
	
	//printf("Device contains %d contexts\n", pdp_cnt);

	/* Allocate array of PDP info accordingly: */
	pdp_info->array = calloc(pdp_cnt, sizeof(pdp_context_info_t));
	pdp_info->size = pdp_cnt;

	/* Parse the response: */ 
	{
		ret = at_params_list_init(&param_list,
					  AT_CMD_PDP_CONTEXTS_READ_PARAM_COUNT);
		if (ret) {
			printf("Could not init AT params list, error: %d\n", ret);
			return ret;
		}
		populated_info = pdp_info->array;

	parse:
		resp_continues = false;
		ret = at_parser_max_params_from_str(
			at_ptr, &next_param_str, &param_list,
			AT_CMD_PDP_CONTEXTS_READ_PARAM_COUNT);
		if (ret == -EAGAIN) {
			resp_continues = true;
		} else if (ret != 0 && ret != -EAGAIN) {
			printf("Could not parse AT response, error: %d\n", ret);
			goto clean_exit;
		}

		ret = at_params_int_get(&param_list,
					AT_CMD_PDP_CONTEXTS_READ_CID_INDEX,
					&populated_info[iterator].cid);
		if (ret) {
			printf("Could not parse CID, err: %d\n", ret);
			goto clean_exit;
		}

		//TODO: read len 1st and malloc??
		param_str_len = sizeof(populated_info[iterator].pdp_type_str);
		ret = at_params_string_get(
			&param_list, AT_CMD_PDP_CONTEXTS_READ_PDP_TYPE_INDEX,
			populated_info[iterator].pdp_type_str, &param_str_len);
		if (ret) {
			printf("Could not parse pdp type, err: %d\n", ret);
			goto clean_exit;
		} else {
			populated_info[iterator].pdp_type_str[param_str_len] =
				'\0';
				
			populated_info[iterator].pdp_type = PDP_TYPE_UNKNOWN;
			if (strcmp(populated_info[iterator].pdp_type_str,
				   "IPV4V6") == 0) {
				populated_info[iterator].pdp_type =
					PDP_TYPE_IP4V6;
			} else if (strcmp(populated_info[iterator].pdp_type_str,
					  "IPV6") == 0) {
				populated_info[iterator].pdp_type =
					PDP_TYPE_IPV6;
			} else if (strcmp(populated_info[iterator].pdp_type_str,
					  "IP") == 0) {
				populated_info[iterator].pdp_type =
					PDP_TYPE_IPV4;
			} else if (strcmp(populated_info[iterator].pdp_type_str,
					  "Non-IP") == 0) {
				populated_info[iterator].pdp_type =
					PDP_TYPE_NONIP;
			}

			//printf("pdp type: %c", populated_info[iterator].pdp_type);
		}

		param_str_len = sizeof(populated_info[iterator].apn_str);
		ret = at_params_string_get(&param_list,
					   AT_CMD_PDP_CONTEXTS_READ_APN_INDEX,
					   populated_info[iterator].apn_str,
					   &param_str_len);
		if (ret) {
			printf("Could not parse apn str, err: %d\n", ret);
			goto clean_exit;
		}
		populated_info[iterator].apn_str[param_str_len] = '\0';

		char ip_addr_str[AT_CMD_PDP_CONTEXT_READ_IP_ADDR_STR_MAX_LEN];

		param_str_len = sizeof(ip_addr_str);
		ret = at_params_string_get(
			&param_list, AT_CMD_PDP_CONTEXTS_READ_PDP_ADDR_INDEX,
			ip_addr_str, &param_str_len);
		if (ret) {
			printf("Could not parse apn str, err: %d\n", ret);
			goto clean_exit;
		}
		ip_addr_str[param_str_len] = '\0';

		/* Parse IP addresses from space delimited string: */
		{
			char *ip_address1, *ip_address2;

			/* Get 1st 2 IP addresses from a CGDCONT string.
			   Notice that ip_addr_str is slightly modified by strtok()*/
			ip_address1 = strtok(ip_addr_str, " ");
			ip_address2 = strtok(NULL, " ");

			if (ip_address1 != NULL) {
				int family =
					net_utils_sa_family_from_ip_string(
						ip_address1);
				if (family == AF_INET) {
					struct in_addr *addr4 =
						&populated_info[iterator].ip_addr4;
					(void)inet_pton(AF_INET, ip_address1, addr4);
				} else if (family == AF_INET6) {
					struct in6_addr *addr6 =
						&populated_info[iterator].ip_addr6;

					(void)inet_pton(AF_INET6, ip_address1, addr6);
				}
			}
			if (ip_address2 != NULL) {
				/* Note: If we are here, PDP_addr_2 should be IPv6,
				   thus in following ipv4 branch should not be possible: */
				int family =
					net_utils_sa_family_from_ip_string(
						ip_address2);
				if (family == AF_INET) {
					struct in_addr *addr4 =
						&populated_info[iterator].ip_addr4;
					(void)inet_pton(AF_INET, ip_address2,
							addr4);
				} else if (family == AF_INET6) {
					struct in6_addr *addr6 =
						&populated_info[iterator].ip_addr6;

					(void)inet_pton(AF_INET6, ip_address2,
							addr6);
				}
			}
		}
		/* Get DNS addresses etc.  for this IP context: */
		if (populated_info[iterator].pdp_type != PDP_TYPE_NONIP)
			(void)ltelc_api_pdp_context_dynamic_params_get(&(populated_info[iterator]));

		if (resp_continues) {
			at_ptr = next_param_str;
			iterator++;
			if (iterator >= pdp_cnt) {
				/* Should not happen, just in case... TODO: add assert?*/
				ret = -666;
				goto clean_exit;
			}
			goto parse;
		}
	}

clean_exit:
	at_params_list_free(&param_list);
	/* user need do free pdp_info->array also in case of error */ 

	return ret;
}

#endif /* CONFIG_AT_CMD */
/* *****************************************************************************/
#if defined(CONFIG_MODEM_INFO)
void ltelc_api_modem_info_get_for_shell(const struct shell *shell, bool online)
{
	pdp_context_info_array_t pdp_context_info_tbl;
	enum lte_lc_system_mode sys_mode_current;
	enum lte_lc_system_mode_preference sys_mode_preferred;
	enum lte_lc_lte_mode currently_active_mode;
	char info_str[MODEM_INFO_MAX_RESPONSE_SIZE + 1];
	int ret;

	(void)ltelc_shell_get_and_print_current_system_modes(
		shell, &sys_mode_current, &sys_mode_preferred, &currently_active_mode);

	ret = modem_info_string_get(MODEM_INFO_FW_VERSION, info_str,
				    sizeof(info_str));
	if (ret >= 0) {
		shell_print(shell, "Modem FW version: %s", info_str);
	} else {
		shell_error(shell,
			    "Unable to obtain modem FW version (%d)", ret);
	}

	if (online) {
		ret = modem_info_string_get(MODEM_INFO_OPERATOR, info_str,
						sizeof(info_str));
		if (ret >= 0) {
			shell_print(shell, "Operator: %s", info_str);
		} else {
			shell_error(shell,
					"Unable to obtain modem operator parameters (%d)",
					ret);
		}
		
		ret = modem_info_string_get(MODEM_INFO_DATE_TIME, info_str,
						sizeof(info_str));
		if (ret >= 0) {
			shell_print(shell, "Mobile network time and date: %s", info_str);
		}

#if defined(CONFIG_AT_CMD)
		ret = ltelc_api_pdp_contexts_read(&pdp_context_info_tbl);
		if (ret >= 0) {
			char ipv4_addr[NET_IPV4_ADDR_LEN];
			char ipv6_addr[NET_IPV6_ADDR_LEN];
			char ipv4_dns_addr_primary[NET_IPV4_ADDR_LEN];
			char ipv4_dns_addr_secondary[NET_IPV4_ADDR_LEN];
			char ipv6_dns_addr_primary[NET_IPV6_ADDR_LEN];
			char ipv6_dns_addr_secondary[NET_IPV6_ADDR_LEN];
			int i = 0;
			pdp_context_info_t *info_tbl = pdp_context_info_tbl.array;

			for (i = 0; i < pdp_context_info_tbl.size; i++) {
				inet_ntop(AF_INET, &(info_tbl[i].ip_addr4),
					ipv4_addr, sizeof(ipv4_addr));
				inet_ntop(AF_INET6, &(info_tbl[i].ip_addr6),
					ipv6_addr, sizeof(ipv6_addr));

				inet_ntop(AF_INET, &(info_tbl[i].dns_addr4_primary),
					ipv4_dns_addr_primary, sizeof(ipv4_dns_addr_primary));
				inet_ntop(AF_INET, &(info_tbl[i].dns_addr4_secondary),
					ipv4_dns_addr_secondary, sizeof(ipv4_dns_addr_secondary));

				inet_ntop(AF_INET6, &(info_tbl[i].dns_addr6_primary),
					ipv6_dns_addr_primary, sizeof(ipv6_dns_addr_primary));
				inet_ntop(AF_INET6, &(info_tbl[i].dns_addr6_secondary),
					ipv6_dns_addr_secondary, sizeof(ipv6_dns_addr_secondary));

				/* Parsed PDP context info: */
				shell_print(
					shell,
					"PDP context info %d:\n"
					"  CID:                    %d\n"
					"  PDP type:               %s\n"
					"  APN:                    %s\n"
					"  IPv4 MTU:               %d\n"
					"  IPv4 address:           %s\n"
					"  IPv6 address:           %s\n"
					"  IPv4 DNS address:       %s, %s\n"
					"  IPv6 DNS address:       %s, %s",
					(i + 1),
					info_tbl[i].cid, info_tbl[i].pdp_type_str,
					info_tbl[i].apn_str,
					info_tbl[i].mtu,
					ipv4_addr, ipv6_addr, ipv4_dns_addr_primary, ipv4_dns_addr_secondary, ipv6_dns_addr_primary, ipv6_dns_addr_secondary);
			}
		} else {
			shell_error(shell, "Unable to obtain pdp context info (%d)",
					ret);
		}
		if (pdp_context_info_tbl.array != NULL)
			free(pdp_context_info_tbl.array);
	#endif /* CONFIG_AT_CMD */
	}
}
#endif /* CONFIG_MODEM_INFO */
