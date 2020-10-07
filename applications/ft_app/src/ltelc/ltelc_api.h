#ifndef LTELC_API_H
#define LTELC_API_H

#include <sys/types.h>
#include <net/net_ip.h>
#include <shell/shell.h>

#define PDP_TYPE_UNKNOWN     0x00
#define PDP_TYPE_IPV4        0x01
#define PDP_TYPE_IPV6        0x02
#define PDP_TYPE_IP4V6       0x03

#define AT_CMD_PDP_CONTEXT_READ_PDP_TYPE_STR_MAX_LEN (6 + 1)
#define AT_CMD_PDP_CONTEXT_READ_APN_STR_MAX_LEN (255)
#define AT_CMD_PDP_CONTEXT_READ_IP_ADDR_STR_MAX_LEN (255)

typedef struct {
	uint32_t cid;
	char pdp_type_str[AT_CMD_PDP_CONTEXT_READ_PDP_TYPE_STR_MAX_LEN];
	char apn_str[AT_CMD_PDP_CONTEXT_READ_APN_STR_MAX_LEN];
	char ip_addr_str[AT_CMD_PDP_CONTEXT_READ_IP_ADDR_STR_MAX_LEN];
    char pdp_type;
	struct sockaddr_in sin4;
	struct sockaddr_in6 sin6;
} pdp_context_info_t;

typedef struct
{
    pdp_context_info_t *array;
    size_t size;
} pdp_context_info_array_t;

#if defined(CONFIG_MODEM_INFO)
void ltelc_api_modem_info_get_for_shell(const struct shell *shell);
#endif
#if defined(CONFIG_AT_CMD)
int ltelc_api_default_pdp_context_read(pdp_context_info_array_t *pdp_info);
#endif

#endif /* LTELC_API_H */
