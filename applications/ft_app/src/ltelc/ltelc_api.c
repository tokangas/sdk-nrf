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
#define AT_CMD_PDP_CONTEXT_READ	"AT+CGDCONT?"
#define AT_CMD_PDP_CONTEXT_READ_PARAM_COUNT 12
#define AT_CMD_PDP_CONTEXT_READ_CID_INDEX 1
#define AT_CMD_PDP_CONTEXT_READ_PDP_TYPE_INDEX 2
#define AT_CMD_PDP_CONTEXT_READ_APN_INDEX 3
#define AT_CMD_PDP_CONTEXT_READ_PDP_ADDR_INDEX 4

int ltelc_api_default_pdp_context_read(pdp_context_info_t *populated_info)
{
	int ret = 0;
	struct at_param_list param_list = {0};
	size_t param_str_len;
	char at_response_str[MODEM_INFO_MAX_RESPONSE_SIZE];

	ret = at_cmd_write(AT_CMD_PDP_CONTEXT_READ, at_response_str, sizeof(at_response_str), NULL);
	if (ret) {
		printf("at_cmd_write returned err: %d", ret);
		return ret;
	}
	//printf("%s", at_response_str);

	//TODO: support for multiple contexts, i.e. multiline response, to be something like:
	//while ((ip_str_end = strstr(ip_str_end, AT_CMD_RSP_DELIM)) != NULL) {

	ret = at_params_list_init(&param_list, AT_CMD_PDP_CONTEXT_READ_PARAM_COUNT);
	if (ret) {
		printf("Could init AT params list, error: %d", ret);
		return ret;
	}
	ret = at_parser_max_params_from_str(at_response_str, NULL, &param_list, AT_CMD_PDP_CONTEXT_READ_PARAM_COUNT);
	if (ret) {
		printf("Could not parse AT response, error: %d", ret);
		goto clean_exit;
	}

	ret = at_params_int_get(&param_list, AT_CMD_PDP_CONTEXT_READ_CID_INDEX, &populated_info->cid);
	if (ret) {
		printf("Could not parse CID, err: %d", ret);
		goto clean_exit;
	}

	//TODO: read len 1st and malloc??

	param_str_len = sizeof(populated_info->pdp_type_str);
	ret = at_params_string_get(&param_list,
				   AT_CMD_PDP_CONTEXT_READ_PDP_TYPE_INDEX,
				   populated_info->pdp_type_str,
				   &param_str_len);
	if (ret) {
		printf("Could not parse pdp type, err: %d", ret);
		goto clean_exit;
	}
    else {
	    populated_info->pdp_type_str[param_str_len] = '\0';
        populated_info->pdp_type = PDP_TYPE_UNKNOWN;
        if (strcmp(populated_info->pdp_type_str, "IPV4V6") == 0) {
            populated_info->pdp_type = PDP_TYPE_IP4V6;
        }
        else if (strcmp(populated_info->pdp_type_str, "IPV6") == 0) {
            populated_info->pdp_type = PDP_TYPE_IPV6;
        }
        else if (strcmp(populated_info->pdp_type_str, "IPV4") == 0) {
            populated_info->pdp_type = PDP_TYPE_IPV4;
        }
        printf("pdp type: %c", populated_info->pdp_type);
    }


	param_str_len = sizeof(populated_info->apn_str);
	ret = at_params_string_get(&param_list,
				   AT_CMD_PDP_CONTEXT_READ_APN_INDEX,
				   populated_info->apn_str,
				   &param_str_len);
	if (ret) {
		printf("Could not parse apn str, err: %d", ret);
		goto clean_exit;
	}
	populated_info->apn_str[param_str_len] = '\0';

	param_str_len = sizeof(populated_info->ip_addr_str);
	ret = at_params_string_get(&param_list,
				   AT_CMD_PDP_CONTEXT_READ_PDP_ADDR_INDEX,
				   populated_info->ip_addr_str,
				   &param_str_len);
	if (ret) {
		printf("Could not parse apn str, err: %d", ret);
		goto clean_exit;
	}
	populated_info->ip_addr_str[param_str_len] = '\0';

	/* Parse IP addresses from space delimited string: */
	{
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

#endif /* CONFIG_AT_CMD */
/* *****************************************************************************/
#if defined(CONFIG_MODEM_INFO)
void ltelc_api_modem_info_get_for_shell(const struct shell *shell)
{
	int ret;
	char info_str[MODEM_INFO_MAX_RESPONSE_SIZE];

	pdp_context_info_t pdp_context_info;
	
	ret = modem_info_string_get(MODEM_INFO_OPERATOR, info_str, sizeof(info_str));
	if (ret >= 0) {
		shell_print(shell, "Operator: %s", info_str);
	} else {
		shell_error(shell, "\nUnable to obtain modem operator parameters (%d)", ret);
	}

	ret = modem_info_string_get(MODEM_INFO_FW_VERSION, info_str, sizeof(info_str));
	if (ret >= 0) {
		shell_print(shell, "Modem FW version: %s", info_str);
	} else {
		shell_error(shell, "\nUnable to obtain modem ip parameters (%d)", ret);
	}

#if defined(CONFIG_AT_CMD)
    memset(&pdp_context_info, 0, sizeof(pdp_context_info_t));
	ret = ltelc_api_default_pdp_context_read(&pdp_context_info);
	if (ret >= 0) {
		char ipv4_addr[NET_IPV4_ADDR_LEN];		
		char ipv6_addr[NET_IPV6_ADDR_LEN];

		inet_ntop(AF_INET,  &(pdp_context_info.sin4.sin_addr), ipv4_addr, sizeof(ipv4_addr));
		inet_ntop(AF_INET6, &(pdp_context_info.sin6.sin6_addr), ipv6_addr, sizeof(ipv6_addr));
		
		/* Parsed PDP context info: */	
		shell_print(shell, 
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
						ipv4_addr,
						ipv6_addr);
	} else {
		shell_error(shell, "\nUnable to obtain pdp context info (%d)", ret);
	}
#endif /* CONFIG_AT_CMD */

}
#endif /* CONFIG_MODEM_INFO */

