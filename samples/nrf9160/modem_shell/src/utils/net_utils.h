/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef _NET_UTILS_H_
#define _NET_UTILS_H_

char *net_utils_sckt_addr_ntop(const struct sockaddr *addr);
int net_utils_sa_family_from_ip_string(const char *src);
int net_utils_socket_apn_set(int fd, const char *apn);

#endif /* _NET_UTILS_H_ */