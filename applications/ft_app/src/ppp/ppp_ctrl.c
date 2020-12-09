#include <zephyr.h>
#include <stdio.h>

#include <net/ppp.h>

#include <net/net_ip.h>
#include <net/net_if.h>

#include <net/net_event.h>
#include <net/net_mgmt.h>

#include <shell/shell.h>

#include "ppp_ctrl.h"

#if defined (CONFIG_FTA_PPP)
struct net_if *ppp_iface_global;
static const struct shell* shell_global;

typedef enum net_verdict (*ppp_l2_callback_t)(struct net_if *iface,
					      struct net_pkt *pkt);

void net_core_register_pkt_cb(ppp_l2_callback_t cb); /* found in net_core.c */

static enum net_verdict ppp_ctrl_data_recv(struct net_if *iface, struct net_pkt *pkt)
{
	printf("mosh: ppp_ctrl_data_recv\n");
	if (!pkt->buffer) {
		printf("MoSH: ppp_ctrl_data_recv: No data to recv!");
		goto drop;
	}
	if (ppp_iface_global != iface) {
		/* Tai globalin sijaan:
		net_if_l2(net_pkt_iface(pkt)) == &NET_L2_GET_NAME(PPP)) */
		printf("MoSH: ppp_ctrl_data_recv: not for ppp iface\n");
		return NET_CONTINUE;
	}
	char type = (NET_IPV6_HDR(pkt)->vtc & 0xf0);
	if (type != 0x40) {
		printf("MoSH: ppp_ctrl_data_recv: not IPv4 data\n");
		goto drop;
	}

	printf("MoSH: ppp_ctrl_data_recv: data received from PPP!\n");
#if 0
				raw_pkt = net_pkt_clone(pkt, CLONE_TIMEOUT);
				if (!raw_pkt) {
					goto drop;
				}

				if (conn->cb(conn, raw_pkt, ip_hdr,
					     proto_hdr, conn->user_data) ==
								NET_DROP) {
					net_stats_update_per_proto_drop(
							pkt_iface, proto);
					net_pkt_unref(raw_pkt);
				} else {
					net_stats_update_per_proto_recv(
						pkt_iface, proto);
				}
#endif
	//net_pkt_acknowledge_data(pkt, &ipv4_access);

	return NET_CONTINUE;

drop:
	return NET_DROP;
}
static void ppp_shell_set_ppp_carrier_on()
{
	const struct device *ppp_dev = device_get_binding(CONFIG_NET_PPP_DRV_NAME);
	const struct ppp_api *api;
	/* olisko parempi:
		iface = net_if_get_first_by_type(&NET_L2_GET_NAME(PPP));
	*/

	if (!ppp_dev) {
		printf("Cannot find PPP %s!", "device");
		return;
	}
	shell_print(shell_global, "Starting PPP");

	api = (const struct ppp_api *)ppp_dev->api;
	api->start(ppp_dev);
}
/* *******************************************/
static struct net_mgmt_event_callback mgmt_ip_cb;
static struct net_mgmt_event_callback mgmt_ppp_cb;

static void ppp_shell_net_event_handler(struct net_mgmt_event_callback *cb,
			  uint32_t mgmt_event, struct net_if *iface)
{
	printf("\nppp_shell_net_event_handler %d\n", mgmt_event);

	if ((mgmt_event & (NET_EVENT_PPP_CARRIER_ON
			   | NET_EVENT_PPP_CARRIER_OFF | NET_EVENT_IPV4_ADDR_DEL)) != mgmt_event) {
		return;
	}

	if (mgmt_event == NET_EVENT_PPP_CARRIER_ON) {
		printf("PPP carrier ON\n");
		return;
	}

	if (mgmt_event == NET_EVENT_PPP_CARRIER_OFF) {
		printf("PPP carrier OFF\n");
		return;
	}

	if (mgmt_event == NET_EVENT_IPV4_ADDR_DEL) {
		printf("NET_EVENT_IPV4_ADDR_DEL: somebody removed the ip from PPP intertfacen");
		return;
	}
}

static void ppp_shell_net_events_subscribe()
{
	net_mgmt_init_event_callback(&mgmt_ip_cb, ppp_shell_net_event_handler,
				     NET_EVENT_IPV4_ADDR_DEL);
	net_mgmt_add_event_callback(&mgmt_ip_cb);

	net_mgmt_init_event_callback(&mgmt_ppp_cb, ppp_shell_net_event_handler,
				     (NET_EVENT_PPP_CARRIER_ON | NET_EVENT_PPP_CARRIER_OFF));
	net_mgmt_add_event_callback(&mgmt_ppp_cb);
}

/* ****************************************/

/* *******************************************/
void ppp_ctrl_init()
{
	//init iface
	//net_if_flag_set(ictx.iface, NET_IF_NO_AUTO_START);

}
static struct in_addr my_ipv4_addr1 = { { { 166, 6, 6, 6 } } };
static struct in_addr my_dns_ipv4_addr1 = { { { 8, 8, 8, 8 } } };
static struct in_addr my_dns_ipv4_addr2 = { { { 8, 8, 4, 4 } } };

int ppp_ctrl_start(const struct shell *shell) {
	struct ppp_context *ctx;
	struct net_if *iface;
	struct net_if_addr *ifaddr;
	int idx = 0; //TODO: find PPP if according to name?
	struct net_if_ipv4 *ipv4;
	shell_global = shell;

	ppp_shell_net_events_subscribe();

	ctx = net_ppp_context_get(idx);
	if (!ctx) {
		shell_error(shell, "PPP context not found.\n");
		return -ENOEXEC;
	}
	iface = ctx->iface;
	ppp_iface_global = iface;
	net_if_flag_set(iface, NET_IF_NO_AUTO_START);
#if defined(CONFIG_NET_IPV4)
	if (net_if_config_ipv4_get(iface, &ipv4) < 0) {
		shell_info(shell, "no ip address\n");
	}
	else {
		bool removed = false;
		/* remove the current IPv4 addr before adding a new one.*/
		removed = net_if_ipv4_addr_rm(iface, &ctx->ipcp.my_options.address);
		shell_info(shell, "removed %d \n", removed);
	}
#endif

	/* Couldn't find the way to set these for PPP in another way: TODO api to PPP for raw mode?*/
	memcpy(&ctx->ipcp.my_options.address, &my_ipv4_addr1, sizeof(ctx->ipcp.my_options.address));
    memcpy(&ctx->ipcp.my_options.dns1_address, &my_dns_ipv4_addr1, sizeof(ctx->ipcp.my_options.dns1_address));	
    memcpy(&ctx->ipcp.my_options.dns2_address, &my_dns_ipv4_addr2, sizeof(ctx->ipcp.my_options.dns2_address));	
	
	/* Set the IP to netif: */
#if defined(CONFIG_NET_IPV4)
	shell_print(shell, "calling net_if_ipv4_addr_add...\n");
	ifaddr = net_if_ipv4_addr_add(iface, &my_ipv4_addr1, NET_ADDR_DHCP, 0);//ei vaikutusta ppp contextiin, ylläoleva memcpy tekee sen
	if (!ifaddr) {
		shell_error(shell, "Cannot add IPv4 address\n");
		goto return_error;
	}
	shell_print(shell, "calling ppp_shell_set_ppp_carrier_on...\n");
#endif

	ppp_shell_set_ppp_carrier_on();

	net_core_register_pkt_cb(ppp_ctrl_data_recv);
	return 0;

return_error:
	return -1;
}

void ppp_shell_set_ppp_carrier_off()
{
	struct ppp_context *ctx;
	int idx = 0; //TODO: find PPP ifaccording to name?

	printf("ppp_shell_set_ppp_carrier_off\n");
		
	ctx = net_ppp_context_get(idx);
	if (!ctx && !ctx->iface)
		return;

	const struct device *ppp_dev = net_if_get_device(ctx->iface);
	const struct ppp_api *api;
		
	api = (const struct ppp_api *)ppp_dev->api;
	api->stop(ppp_dev);
}


/* *************************************************************************************/
#if defined(CONFIG_NET_PROMISCUOUS_MODE)
#define PPP_RECEIVE_STACK_SIZE 2048
#define PPP_RECEIVE_PRIORITY 4

static void ppp_receive_handler()
{
	struct net_if *iface;
	int ret = 0;
	struct net_pkt *pkt;
	bool mode_set = false;

	shell_print(shell_global, "ppp_receive_handler\n");

	iface = net_if_get_first_by_type(&NET_L2_GET_NAME(PPP));
	
	while (!mode_set) {
		ret = net_promisc_mode_on(iface);
		if (ret < 0) {
			shell_print(shell_global, "Cannot set promiscuous mode for PPP interface %p (%d)\n",
				iface, ret);
			k_sleep(K_MSEC(1500));
		}
		else {
			shell_print(shell_global, "promiscuous mode set for PPP interface %p\n", iface);
			mode_set = true;
		}
	}

	while (1) {
		pkt = net_promisc_mode_wait_data(K_FOREVER);
		if (pkt) {
			shell_print(shell_global, "ppp_receive_handler: packet received\n");
		}

		net_pkt_unref(pkt);
	}
}

K_THREAD_DEFINE(ppp_receive_thread, PPP_RECEIVE_STACK_SIZE,
                ppp_receive_handler, NULL, NULL, NULL,
                PPP_RECEIVE_PRIORITY, 0, 0);
#endif

#endif /* CONFIG_FTA_PPP */