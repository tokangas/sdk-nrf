#ifndef LTE_CONNECTION_TOOLS_H
#define LTE_CONNECTION_TOOLS_H

#include <sys/types.h>
#include <net/net_ip.h>

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

#if defined(CONFIG_MODEM_INFO)
void lte_conn_modem_info_get_for_shell(const struct shell *shell);
#endif
#if defined(CONFIG_AT_CMD)
int lte_conn_pdp_context_read(pdp_context_info_t *populated_info);
#endif

#endif /* LTE_CONNECTION_TOOLS_H */
