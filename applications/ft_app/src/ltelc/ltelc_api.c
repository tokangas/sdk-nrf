/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <shell/shell.h>

#include <modem/modem_info.h>

#include <posix/arpa/inet.h>
#include <net/net_ip.h>

#include "utils/fta_net_utils.h"

#include "ltelc_api.h"

#if defined(CONFIG_AT_CMD)

#include <modem/at_cmd.h>
#include <modem/at_cmd_parser.h>
#include <modem/at_params.h>

#define AT_CMD_BUFFER_LEN (CONFIG_AT_CMD_RESPONSE_MAX_LEN + 1)
#define AT_CMD_PDP_CONTEXT_READ "AT+CGDCONT?"
#define AT_CMD_PDP_CONTEXT_READ_PARAM_COUNT 12
#define AT_CMD_PDP_CONTEXT_READ_CID_INDEX 1
#define AT_CMD_PDP_CONTEXT_READ_PDP_TYPE_INDEX 2
#define AT_CMD_PDP_CONTEXT_READ_APN_INDEX 3
#define AT_CMD_PDP_CONTEXT_READ_PDP_ADDR_INDEX 4

#define AT_CMD_PDP_CONTEXT_READ_INFO "AT+CGCONTRDP=%d" // Use sprintf to add CID into command
#define AT_CMD_PDP_CONTEXT_READ_INFO_PARAM_COUNT 20
#define AT_CMD_PDP_CONTEXT_READ_INFO_CID_INDEX 1
#define AT_CMD_PDP_CONTEXT_READ_INFO_DNS_ADDR_PRIMARY_INDEX 6
#define AT_CMD_PDP_CONTEXT_READ_INFO_DNS_ADDR_SECONDARY_INDEX 7

#define AT_CMD_PDP_CONTEXT_READ_RSP_DELIM "\r\n"

pdp_context_info_t* ltelc_api_get_pdp_context_info_by_pdn_cid(int pdn_cid)
{
	int ret;
	pdp_context_info_array_t pdp_context_info_tbl;
	pdp_context_info_t* pdp_context_info = NULL;

	ret = ltelc_api_default_pdp_context_read(&pdp_context_info_tbl);
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

int ltelc_api_default_pdp_context_read_info(pdp_context_info_t *populated_info)
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

	// TODO: This is only for context #0 ("AT+CGCONTRDP=0")
	char at_cmd_pdp_context_read_info_cmd_str[15];
	sprintf(at_cmd_pdp_context_read_info_cmd_str, AT_CMD_PDP_CONTEXT_READ_INFO, populated_info->cid);
	ret = at_cmd_write(at_cmd_pdp_context_read_info_cmd_str, at_response_str,
			   sizeof(at_response_str), NULL);
	if (ret) {
		printf("at_cmd_write returned err: %d\n", ret);
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
			printf("Could not init AT params list, error: %d\n", ret);
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
			printf("E2BIG, error: %d\n", ret);
		} else if (ret != 0) {
			printf("Could not parse AT response, error: %d\n", ret);
			goto clean_exit;
		}

		uint32_t cid;
		ret = at_params_int_get(&param_list,
					AT_CMD_PDP_CONTEXT_READ_CID_INDEX,
					&cid);
		if (ret) {
			printf("Could not parse CID, err: %d\n", ret);
			goto clean_exit;
		}

		// Read primary DNS address
		char dns_addr_str[AT_CMD_PDP_CONTEXT_READ_IP_ADDR_STR_MAX_LEN];
		param_str_len = sizeof(dns_addr_str);

		ret = at_params_string_get(
			&param_list, AT_CMD_PDP_CONTEXT_READ_INFO_DNS_ADDR_PRIMARY_INDEX, dns_addr_str, &param_str_len);
		if (ret) {
			printf("Could not parse dns str, err: %d", ret);
			goto clean_exit;
		}
		dns_addr_str[param_str_len] = '\0';
		//printf("Primary DNS address (%d): %s\n", param_str_len, dns_addr_str);

		if (dns_addr_str != NULL) {
			int family = fta_net_utils_sa_family_from_ip_string(dns_addr_str);
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
			&param_list, AT_CMD_PDP_CONTEXT_READ_INFO_DNS_ADDR_SECONDARY_INDEX, dns_addr_str, &param_str_len);
		if (ret) {
			printf("Could not parse dns str, err: %d", ret);
			goto clean_exit;
		}
		dns_addr_str[param_str_len] = '\0';
		//printf("Secondary DNS address (%d): %s\n", param_str_len, dns_addr_str);

		if (dns_addr_str != NULL) {
			int family = fta_net_utils_sa_family_from_ip_string(dns_addr_str);
			if (family == AF_INET) {
				struct in_addr *addr = &(populated_info->dns_addr4_secondary);
				(void)inet_pton(AF_INET, dns_addr_str, addr);
			} else if (family == AF_INET6) {
				struct in6_addr *addr6 = &(populated_info->dns_addr6_secondary);
				(void)inet_pton(AF_INET6, dns_addr_str, addr6);
			}
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

int ltelc_api_default_pdp_context_read(pdp_context_info_array_t *pdp_info)
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

	ret = at_cmd_write(AT_CMD_PDP_CONTEXT_READ, at_response_str,
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
	
	//printf("Device contains %d IP addresses\n", pdp_cnt);

	/* Allocate array of PDP info accordingly: */
	pdp_info->array = calloc(pdp_cnt, sizeof(pdp_context_info_t));
	pdp_info->size = pdp_cnt;

	/* Parse the response: */ 
	{
		ret = at_params_list_init(&param_list,
					  AT_CMD_PDP_CONTEXT_READ_PARAM_COUNT);
		if (ret) {
			printf("Could not init AT params list, error: %d\n", ret);
			return ret;
		}
		populated_info = pdp_info->array;

	parse:
		resp_continues = false;
		ret = at_parser_max_params_from_str(
			at_ptr, &next_param_str, &param_list,
			AT_CMD_PDP_CONTEXT_READ_PARAM_COUNT);
		if (ret == -EAGAIN) {
			resp_continues = true;
		} else if (ret != 0 && ret != -EAGAIN) {
			printf("Could not parse AT response, error: %d\n", ret);
			goto clean_exit;
		}

		ret = at_params_int_get(&param_list,
					AT_CMD_PDP_CONTEXT_READ_CID_INDEX,
					&populated_info[iterator].cid);
		if (ret) {
			printf("Could not parse CID, err: %d\n", ret);
			goto clean_exit;
		}

		//TODO: read len 1st and malloc??
		param_str_len = sizeof(populated_info[iterator].pdp_type_str);
		ret = at_params_string_get(
			&param_list, AT_CMD_PDP_CONTEXT_READ_PDP_TYPE_INDEX,
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
			}
			//printf("pdp type: %c", populated_info[iterator].pdp_type);
		}

		param_str_len = sizeof(populated_info[iterator].apn_str);
		ret = at_params_string_get(&param_list,
					   AT_CMD_PDP_CONTEXT_READ_APN_INDEX,
					   populated_info[iterator].apn_str,
					   &param_str_len);
		if (ret) {
			printf("Could not parse apn str, err: %d\n", ret);
			goto clean_exit;
		}
		populated_info[iterator].apn_str[param_str_len] = '\0';

		param_str_len = sizeof(populated_info[iterator].ip_addr_str);
		ret = at_params_string_get(
			&param_list, AT_CMD_PDP_CONTEXT_READ_PDP_ADDR_INDEX,
			populated_info[iterator].ip_addr_str, &param_str_len);
		if (ret) {
			printf("Could not parse apn str, err: %d\n", ret);
			goto clean_exit;
		}
		populated_info[iterator].ip_addr_str[param_str_len] = '\0';

		/* Parse IP addresses from space delimited string: */
		{
			char *tmp = malloc(
				strlen(populated_info[iterator].ip_addr_str) +
				1);
			char *ip_address1, *ip_address2;

			strcpy(tmp, populated_info[iterator].ip_addr_str);

			/* Get 1st 2 IP addresses from a CGDCONT string: */
			ip_address1 = strtok(tmp, " ");
			ip_address2 = strtok(NULL, " ");

			if (ip_address1 != NULL) {
				int family =
					fta_net_utils_sa_family_from_ip_string(
						ip_address1);
				if (family == AF_INET) {
					struct sockaddr_in *sin =
						&populated_info[iterator].sin4;
					(void)inet_pton(AF_INET, ip_address1,
							&(sin->sin_addr));
					sin->sin_family = AF_INET;
				} else if (family == AF_INET6) {
					struct sockaddr_in6 *sin6 =
						&populated_info[iterator].sin6;

					(void)inet_pton(AF_INET6, ip_address1,
							&(sin6->sin6_addr));
					sin6->sin6_family = AF_INET6;
				}
			}
			if (ip_address2 != NULL) {
				/* note: if we are here, PDP_addr_2 should be IPv6, thus in following ipv4 branch should not 
			   be possible: */
				int family =
					fta_net_utils_sa_family_from_ip_string(
						ip_address2);
				if (family == AF_INET) {
					struct sockaddr_in *sin =
						&populated_info[iterator].sin4;
					(void)inet_pton(AF_INET, ip_address2,
							&(sin->sin_addr));
					sin->sin_family = AF_INET;
				} else if (family == AF_INET6) {
					struct sockaddr_in6 *sin6 =
						&populated_info[iterator].sin6;

					(void)inet_pton(AF_INET6, ip_address2,
							&(sin6->sin6_addr));
					sin6->sin6_family = AF_INET6;
				}
			}
			free(tmp);
		}
		// TODO: This may not work for all use cases
		ret = ltelc_api_default_pdp_context_read_info(&(populated_info[iterator]));
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
	char info_str[MODEM_INFO_MAX_RESPONSE_SIZE + 1];
	int ret;

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
		} else {
			shell_error(shell,
					"Unable to obtain modem time (%d)", ret);
		}

	#if defined(CONFIG_AT_CMD)
		ret = ltelc_api_default_pdp_context_read(&pdp_context_info_tbl);
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
				inet_ntop(AF_INET, &(info_tbl[i].sin4.sin_addr),
					ipv4_addr, sizeof(ipv4_addr));
				inet_ntop(AF_INET6, &(info_tbl[i].sin6.sin6_addr),
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
					"  IPv4 address:           %s\n"
					"  IPv6 address:           %s\n"
					"  IPv4 DNS address:       %s, %s\n"
					"  IPv6 DNS address:       %s, %s",
					(i + 1),
					info_tbl[i].cid, info_tbl[i].pdp_type_str,
					info_tbl[i].apn_str,
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
