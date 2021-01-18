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

#include "ppp_ctrl.h"
#include "ppp_mdm_data_snd.h"

#if defined (CONFIG_FTA_PPP)

#define PPP_CTRL_UPLINK_WORKER 1

/* ppp globals: */
extern struct net_if *ppp_iface_global;
extern const struct shell* ppp_shell_global;
extern int ppp_modem_data_raw_socket_fd;

/* forward declarations: */
typedef enum net_verdict (*net_core_callback_t)(struct net_if *iface,
					      struct net_pkt *pkt);

void net_core_register_pkt_cb(net_core_callback_t cb); /* found in net_core.c */

static uint8_t buf_tx[CONFIG_NET_PPP_MTU_MRU];

static void ppp_mdm_data_snd(struct net_pkt *pkt)
{
	int ret = 0;
	int data_len = net_pkt_remaining_data(pkt);

	ret = net_pkt_read(pkt, buf_tx, data_len);
	net_pkt_unref(pkt); //TODO non blocking send?
	if (ret < 0) {
		shell_error(ppp_shell_global, "ppp_mdm_data_snd: cannot read packet: %d, from pkt %p", ret, pkt);
		net_pkt_unref(pkt);
	} else {	
		ret = send(ppp_modem_data_raw_socket_fd, buf_tx, data_len, 0);
		if (ret <= 0) {
			shell_error(ppp_shell_global, "ppp_mdm_data_snd: send() failed: (%d), data len: %d\n", -errno, data_len);
			net_pkt_unref(pkt);
		}
	}
}

#if defined(PPP_CTRL_UPLINK_WORKER)

#define UPLINK_WORKQUEUE_STACK_SIZE 1024
#define UPLINK_WORKQUEUE_PRIORITY   K_PRIO_COOP(10)/* -6 */

K_THREAD_STACK_DEFINE(uplink_stack_area, UPLINK_WORKQUEUE_STACK_SIZE);

struct k_work_q uplink_work_q;

static void ppp_ctrl_process_ppp_rx_packet(struct k_work *item)
{
	struct net_pkt *pkt;
	pkt = CONTAINER_OF(item, struct net_pkt, work);

	ppp_mdm_data_snd(pkt);
}
#endif

enum net_verdict ppp_mdm_data_snd_data_rcv_from_ppp(struct net_if *iface, struct net_pkt *pkt)
{
	//TODO?
	//iface not needed as parameter? set in pkt and can be get:	iface = net_pkt_iface(pkt);
	if (!pkt->buffer) {
		shell_info(ppp_shell_global,"MoSH: ppp_mdm_data_snd_data_rcv_from_ppp: No data to recv!");
		goto drop;
	}
	if (iface && iface != ppp_iface_global) {//&NET_L2_GET_NAME(PPP)
		shell_error(ppp_shell_global, "MoSH: ppp_mdm_data_snd_data_rcv_from_ppp: not for ppp iface\n");
		return NET_CONTINUE;
	}
	if (ppp_modem_data_raw_socket_fd == PPP_MODEM_DATA_RAW_SCKT_FD_NONE) {
		shell_error(ppp_shell_global, "MoSH: ppp_mdm_data_snd_data_rcv_from_ppp: no socket to modem\n");
		return NET_CONTINUE;
	}

	char type = (NET_IPV6_HDR(pkt)->vtc & 0xf0);
	if (type != 0x40) {
		shell_error(ppp_shell_global, "MoSH: ppp_mdm_data_snd_data_rcv_from_ppp: not IPv4 data\n");
		goto drop;
	}
#if defined(PPP_CTRL_UPLINK_WORKER)
	k_work_init(net_pkt_work(pkt), ppp_ctrl_process_ppp_rx_packet);
	k_work_submit_to_queue(&uplink_work_q, net_pkt_work(pkt));
#else
	int ret = 0;
	int data_len = net_pkt_remaining_data(pkt);

	ret = net_pkt_read(pkt, buf_tx, data_len);
	if (ret < 0) {
		shell_error(ppp_shell_global, "ppp_mdm_data_snd_data_rcv_from_ppp: cannot read packet: %d, from pkt %p", ret, pkt);
		goto drop;
	}
	ret = send(ppp_modem_data_raw_socket_fd, buf_tx, data_len, 0);
	if (ret <= 0) {
		shell_error(ppp_shell_global, "ppp_mdm_data_snd_data_rcv_from_ppp: send() failed: (%d), data len: %d\n", ret, data_len);
		goto drop;
	}
	net_pkt_unref(pkt);
#endif
	return NET_OK;

drop:
	return NET_DROP;
}

void ppp_mdm_data_snd_init()
{
#if defined(PPP_CTRL_UPLINK_WORKER)
	k_work_q_start(&uplink_work_q, uplink_stack_area,
		       K_THREAD_STACK_SIZEOF(uplink_stack_area),
		       UPLINK_WORKQUEUE_PRIORITY);
	k_thread_name_set(&uplink_work_q.thread, "mosh_uplink_work_q");
#endif
	net_core_register_pkt_cb(ppp_mdm_data_snd_data_rcv_from_ppp);
}
#endif /* CONFIG_FTA_PPP */