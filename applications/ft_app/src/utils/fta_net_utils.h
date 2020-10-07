#ifndef FTA_NET_UTILS_H
#define FTA_NET_UTILS_H

/*
 * Copyright (c) 2018 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

char *fta_net_utils_sckt_addr_ntop(const struct sockaddr *addr);
int fta_net_utils_sa_family_from_ip_string(const char *src);
int fta_net_utils_socket_apn_set(int fd, const char *apn);

#endif /* FTA_NET_UTILS_H */