/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#ifndef LTELC_API_H
#define LTELC_API_H

#include <sys/types.h>
#include <net/net_ip.h>
#include <shell/shell.h>

#include "mosh_defines.h"

#define PDP_TYPE_UNKNOWN     0x00
#define PDP_TYPE_IPV4        0x01
#define PDP_TYPE_IPV6        0x02
#define PDP_TYPE_IP4V6       0x03
#define PDP_TYPE_NONIP       0x04

#define AT_CMD_PDP_CONTEXT_READ_PDP_TYPE_STR_MAX_LEN (6 + 1)
#define AT_CMD_PDP_CONTEXT_READ_IP_ADDR_STR_MAX_LEN (255)

typedef struct {
	uint32_t cid;
	uint32_t mtu;
	char pdp_type_str[AT_CMD_PDP_CONTEXT_READ_PDP_TYPE_STR_MAX_LEN];
	char apn_str[FTA_APN_STR_MAX_LEN];
	char pdp_type;
	struct in_addr ip_addr4;
	struct in6_addr ip_addr6;
	struct in_addr dns_addr4_primary;
	struct in_addr dns_addr4_secondary;
	struct in6_addr dns_addr6_primary;
	struct in6_addr dns_addr6_secondary;
} pdp_context_info_t;

typedef struct
{
    pdp_context_info_t *array;
    size_t size;
} pdp_context_info_array_t;

#define AT_CMD_CONEVAL_RESP_MAX_STR_LEN 32
typedef struct {
	uint8_t result;
	uint8_t rrc_state;
	uint8_t quality;
	int16_t rsrp;
	int16_t rsrq;
	int8_t snr;
	char cell_id_str[AT_CMD_CONEVAL_RESP_MAX_STR_LEN + 1];
	char plmn_str[AT_CMD_CONEVAL_RESP_MAX_STR_LEN + 1];
	int16_t phy_cell_id;
	int16_t earfcn;
	uint8_t band;
	uint8_t tau_triggered;
	uint8_t ce_level;
	int8_t tx_power;
	uint16_t tx_repetitions;
	uint16_t rx_repetitions;
	uint16_t dl_pathloss;
} lte_coneval_resp_t;

#if defined(CONFIG_MODEM_INFO)
void ltelc_api_modem_info_get_for_shell(const struct shell *shell, bool online);
#endif
#if defined(CONFIG_AT_CMD)
void ltelc_api_coneval_read_for_shell(const struct shell *shell);

int ltelc_api_pdp_contexts_read(pdp_context_info_array_t *pdp_info);

/**
 * Return PDP context info for a given PDN CID.
 * 
 * @param[in] pdn_cid PDN CID.
 * 
 * @retval pdp_context_info_t structure. NULL if context info for given CID not found.
 *         Client is responsible for deallocating the memory of the returned pdp_context_info_t.
 */
pdp_context_info_t* ltelc_api_get_pdp_context_info_by_pdn_cid(int pdn_cid);
#endif

#endif /* LTELC_API_H */
