/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <zephyr.h>
#include <stdio.h>
#include <assert.h>

#include <net/ppp.h>

#include <net/net_ip.h>
#include <net/net_if.h>

#include <net/net_event.h>
#include <net/net_mgmt.h>

#include <posix/unistd.h>
#include <posix/netdb.h>

#include <posix/poll.h>
#include <posix/sys/socket.h>
#include <shell/shell.h>

#include "ltelc_api.h"

#include "ppp_mdm_data_snd.h"
#include "ppp_ctrl.h"

#if defined (CONFIG_FTA_PPP)

/* ppp globals: */
struct net_if *ppp_iface_global;
const struct shell* ppp_shell_global;
int ppp_modem_data_raw_socket_fd;

/* forward declarations: */

/* ********************************************************************/

static struct net_mgmt_event_callback ppp_ctrl_net_mgmt_event_ppp_cb;

static void ppp_ctrl_net_mgmt_event_handler(struct net_mgmt_event_callback *cb,
			  uint32_t mgmt_event, struct net_if *iface)
{
	if ((mgmt_event & (NET_EVENT_PPP_CARRIER_ON | NET_EVENT_PPP_CARRIER_OFF)) != mgmt_event) {
		return;
	}

	if (mgmt_event == NET_EVENT_PPP_CARRIER_ON) {
		shell_print(ppp_shell_global, "PPP carrier ON");
		return;
	}

	if (mgmt_event == NET_EVENT_PPP_CARRIER_OFF) {
		shell_print(ppp_shell_global, "PPP carrier OFF");
		return;
	}

}

static void ppp_ctrl_net_mgmt_events_subscribe()
{
	net_mgmt_init_event_callback(&ppp_ctrl_net_mgmt_event_ppp_cb, ppp_ctrl_net_mgmt_event_handler,
				     (NET_EVENT_PPP_CARRIER_ON | NET_EVENT_PPP_CARRIER_OFF));
	net_mgmt_add_event_callback(&ppp_ctrl_net_mgmt_event_ppp_cb);
}

/* ********************************************************************/

void ppp_ctrl_init()
{
	ppp_modem_data_raw_socket_fd = PPP_MODEM_DATA_RAW_SCKT_FD_NONE;
	//init iface
	//net_if_flag_set(ictx.iface, NET_IF_NO_AUTO_START);
	ppp_mdm_data_snd_init();
	ppp_ctrl_net_mgmt_events_subscribe();
}
/* ********************************************************************/

int ppp_ctrl_start(const struct shell *shell) {
	struct ppp_context *ctx;
	struct net_if *iface;
	#if defined(CONFIG_NET_IPV4)
	struct net_if_addr *ifaddr;
	struct net_if_ipv4 *ipv4;
#endif
	int idx = 0; //TODO: find PPP if according to name?
	pdp_context_info_t* pdp_context_info;
	ppp_shell_global = shell;

	if (ppp_modem_data_raw_socket_fd != PPP_MODEM_DATA_RAW_SCKT_FD_NONE) {
		shell_warn(shell, "PPP already up.\n");
		goto return_error;
	}

	ctx = net_ppp_context_get(idx);
	if (!ctx) {
		shell_error(shell, "PPP context not found.\n");
		goto return_error;
	}
	pdp_context_info = ltelc_api_get_pdp_context_info_by_pdn_cid(0);//TODO: multi context support
	if (pdp_context_info == NULL) {
		shell_error(shell, "PPP context not found.\n");
		goto return_error;
	}

	iface = ctx->iface;
	ppp_iface_global = iface;
	net_if_flag_set(iface, NET_IF_NO_AUTO_START);

	/* Couldn't find the way to set these for PPP in another way: TODO api to PPP for raw mode?*/
	memcpy(&(ctx->ipcp.my_options.address), &(pdp_context_info->sin4.sin_addr), sizeof(ctx->ipcp.my_options.address));
    memcpy(&ctx->ipcp.my_options.dns1_address, &pdp_context_info->dns_addr4_primary, sizeof(ctx->ipcp.my_options.dns1_address));
    memcpy(&ctx->ipcp.my_options.dns2_address, &pdp_context_info->dns_addr4_secondary, sizeof(ctx->ipcp.my_options.dns2_address));

	free(pdp_context_info);
	
	ppp_modem_data_raw_socket_fd = socket(AF_PACKET, SOCK_RAW, 0);
	if (ppp_modem_data_raw_socket_fd < 0) {
		shell_error(shell, "modem data socket creation failed: (%d)!!!!\n", -errno);
		goto return_error;
	}
	else {
		shell_info(shell, "modem data socket %d created for modem data", ppp_modem_data_raw_socket_fd);
	}

	net_if_up(iface);
	return 0;

return_error:
	return -1;
}

/* ********************************************************************/

void ppp_ctrl_stop()
{
	struct ppp_context *ctx;
	int idx = 0; //TODO: find PPP ifaccording to name?

	if (ppp_modem_data_raw_socket_fd != PPP_MODEM_DATA_RAW_SCKT_FD_NONE) {
		(void)close(ppp_modem_data_raw_socket_fd);
		ppp_modem_data_raw_socket_fd = PPP_MODEM_DATA_RAW_SCKT_FD_NONE;
	}

	ctx = net_ppp_context_get(idx);
	if (!ctx && !ctx->iface)
		return;

	net_if_down(ctx->iface);
}


/* *************************************************************************************/

#endif /* CONFIG_FTA_PPP */