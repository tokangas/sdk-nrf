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

#define UPLINK_DATA_CLONE_TIMEOUT K_MSEC(1000)

/* ppp globals: */
extern struct net_if *ppp_iface_global;
extern const struct shell* ppp_shell_global;
extern int ppp_modem_data_raw_socket_fd;

/* forward declarations: */
typedef enum net_verdict (*net_core_offloaded_rcv_cb_t)(struct net_pkt *pkt);

/* found in zephyr net_core.c */
void net_core_register_offloaded_pkt_rcv_cb(net_core_offloaded_rcv_cb_t cb);

static uint8_t buf_tx[CONFIG_NET_PPP_MTU_MRU];

static void ppp_mdm_data_snd(struct net_pkt *pkt)
{
	int ret = 0;
	int data_len = 0;

	net_pkt_set_overwrite(pkt, true);
	net_pkt_cursor_init(pkt);

	data_len = net_pkt_remaining_data(pkt);

	ret = net_pkt_read(pkt, buf_tx, data_len);
	if (ret < 0) {
		shell_error(
			ppp_shell_global,
			"ppp_mdm_data_snd: cannot read packet: %d, from pkt %p", 
				ret, pkt);
	} else {	
		ret = send(ppp_modem_data_raw_socket_fd, buf_tx, data_len, 0);
			
		/* Note: no worth to handle partial sends for raw sockets */
		if (ret < 0) {
		shell_error(
			ppp_shell_global,
			"ppp_mdm_data_snd: send() failed: (%d), data len: %d\n", 
				-errno, data_len);
		}
		else if (ret != data_len) {
		shell_error(
			ppp_shell_global,
			"ppp_mdm_data_snd: only partially sent, only %d of original %d was sent",
				ret, data_len);
		}
	}
	net_pkt_unref(pkt);
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

enum net_verdict ppp_mdm_data_snd_data_rcv_from_ppp(struct net_pkt *pkt)
{
	struct net_if *iface = net_pkt_iface(pkt);

	if (!pkt->buffer) {
		shell_error(
			ppp_shell_global,
			"MoSH: ppp_mdm_data_snd_data_rcv_from_ppp: No data to recv!");
		goto drop;
	}
	if (iface && iface != ppp_iface_global) {
		shell_error(
			ppp_shell_global,
			"MoSH: ppp_mdm_data_snd_data_rcv_from_ppp: not for ppp iface\n");
		return NET_CONTINUE;
	}
	if (ppp_modem_data_raw_socket_fd == PPP_MODEM_DATA_RAW_SCKT_FD_NONE) {
		shell_error(
			ppp_shell_global,
			"MoSH: ppp_mdm_data_snd_data_rcv_from_ppp: no socket to modem\n");
		return NET_CONTINUE;
	}

	char type = (NET_IPV6_HDR(pkt)->vtc & 0xf0);
	if (type != 0x40) {
		shell_error(
			ppp_shell_global,
			"MoSH: ppp_mdm_data_snd_data_rcv_from_ppp: not IPv4 data\n");
		goto drop;
	}
#if defined(PPP_CTRL_UPLINK_WORKER)
	struct net_pkt *raw_pkt;
	raw_pkt = net_pkt_clone(pkt, UPLINK_DATA_CLONE_TIMEOUT);
	if (!raw_pkt) {
		shell_error(
			ppp_shell_global,
			"MoSH: ppp_mdm_data_snd_data_rcv_from_ppp: pkt not cloned, dropping\n");
		goto drop;
	}

	net_pkt_unref(pkt);
	
	k_work_init(net_pkt_work(raw_pkt), ppp_ctrl_process_ppp_rx_packet);
	k_work_submit_to_queue(&uplink_work_q, net_pkt_work(raw_pkt));
#else
	int ret = 0, data_len = 0;

	net_pkt_set_overwrite(pkt, true);
	net_pkt_cursor_init(pkt);
	
	data_len = net_pkt_remaining_data(pkt);

	ret = net_pkt_read(pkt, buf_tx, data_len);
	if (ret < 0) {
		shell_error(
			ppp_shell_global,
			"ppp_mdm_data_snd_data_rcv_from_ppp: cannot read packet: %d, from pkt %p", 
				ret, pkt);
		goto drop;
	}
	ret = send(ppp_modem_data_raw_socket_fd, buf_tx, data_len, 0);

	/* Note: partial sends not handled */
	if (ret <= 0) {
		shell_error(
			ppp_shell_global,
			"ppp_mdm_data_snd_data_rcv_from_ppp: send() failed: (%d), data len: %d\n", 
				ret, data_len);
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
	k_thread_name_set(&uplink_work_q.thread, "ppp_modem_ul_data_thread");
#endif
	net_core_register_offloaded_pkt_rcv_cb(ppp_mdm_data_snd_data_rcv_from_ppp);
}
#endif /* CONFIG_FTA_PPP */