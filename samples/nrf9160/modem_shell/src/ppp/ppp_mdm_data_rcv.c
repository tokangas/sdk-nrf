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

#include <posix/unistd.h>
#include <posix/netdb.h>

#include <posix/poll.h>
#include <posix/sys/socket.h>
#include <shell/shell.h>

#if defined (CONFIG_FTA_PPP)

/* ppp globals: */
extern const struct shell* ppp_shell_global;
extern int ppp_modem_data_raw_socket_fd;
extern struct net_if *ppp_iface_global;

#define PPP_MODEM_DATA_RCV_THREAD_STACK_SIZE        1024
#define PPP_MODEM_DATA_RCV_THREAD_PRIORITY          K_PRIO_COOP(10) /* -6 */
#define PPP_MODEM_DATA_RCV_POLL_TIMEOUT_MS          1000 /* Milliseconds */
#define PPP_MODEM_DATA_RCV_BUFFER_SIZE              CONFIG_NET_PPP_MTU_MRU
#define PPP_MODEM_DATA_RCV_PKT_BUF_ALLOC_TIMEOUT	K_MSEC(1000)

static char receive_buffer[PPP_MODEM_DATA_RCV_BUFFER_SIZE]; //TODO: from heap?

static void ppp_modem_dl_data_thread_handler()
{
	struct pollfd fds[1];
	struct net_if *iface;
	struct net_pkt *pkt;

	int ret = 0;
	int recv_data_len = 0;

	iface = net_if_get_first_by_type(&NET_L2_GET_NAME(PPP));
	assert(iface != NULL);
	
	while (true) {
		if (ppp_modem_data_raw_socket_fd < 0) {
			/* No raw socket to modem in use, so no use calling poll() */
			k_sleep(K_MSEC(PPP_MODEM_DATA_RCV_POLL_TIMEOUT_MS));
			continue;
		}
		else {
			fds[0].fd = ppp_modem_data_raw_socket_fd;
			fds[0].events = POLLIN;
			fds[0].revents = 0;

			ret = poll(fds, 1, PPP_MODEM_DATA_RCV_POLL_TIMEOUT_MS);
			if (ret > 0) {// && (fds[0].revents & POLLIN)
				recv_data_len = recv(ppp_modem_data_raw_socket_fd, receive_buffer, PPP_MODEM_DATA_RCV_BUFFER_SIZE, 0);
				if (recv_data_len > 0) {
					//shell_info(ppp_shell_global, "ppp_modem_dl_data_thread_handler: data received from modem, len %d", recv_data_len);

					pkt = net_pkt_alloc_with_buffer(iface, recv_data_len, AF_UNSPEC, 0, PPP_MODEM_DATA_RCV_PKT_BUF_ALLOC_TIMEOUT);
					if (!pkt) {
						printk("ppp_modem_dl_data_thread_handler: no buf available - dropped packet from modem of len %d", recv_data_len);
						//net_stats_update_processing_error(iface);
						//TODO: update iface stats for dropping
					} else {
						//memcpy(pkt->buffer->data, receive_buffer, recv_data_len);
						//net_buf_add(pkt->buffer, recv_data_len);
						if (net_pkt_write(pkt, (uint8_t *)receive_buffer, recv_data_len)) {
							printk("ppp_modem_dl_data_thread_handler: cannot write pkt %p - dropped packet", pkt);
							net_pkt_unref(pkt);
						} else {
							char type = (NET_IPV6_HDR(pkt)->vtc & 0xf0);
							
							switch (type) {
								case 0x60:
									net_pkt_set_family(pkt, AF_INET6);
									break;
								case 0x40:					
									net_pkt_set_family(pkt, AF_INET);
									break;
							}

							if (net_send_data(pkt) < 0) {
								printk("ppp_modem_dl_data_thread_handler: cannot send data pkt %p - dropped packet", pkt);
								net_pkt_unref(pkt);
							}						
						}
					}
				} else
				{
					printk("ppp_modem_dl_data_thread_handler: recv() failed %d", recv_data_len);
				}
			} else if (ret < 0) {
				printk("ppp_modem_dl_data_thread_handler: poll() failed %d", ret);
			}
		}
	}

}

K_THREAD_DEFINE(ppp_modem_dl_data_thread, PPP_MODEM_DATA_RCV_THREAD_STACK_SIZE,
                ppp_modem_dl_data_thread_handler, NULL, NULL, NULL,
                PPP_MODEM_DATA_RCV_THREAD_PRIORITY, 0, 0);

#endif /* CONFIG_FTA_PPP */