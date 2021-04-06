/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#ifndef _NET_UTILS_H
#define _NET_UTILS_H

char *net_utils_sckt_addr_ntop(const struct sockaddr *addr);
int net_utils_sa_family_from_ip_string(const char *src);
int net_utils_socket_apn_set(int fd, const char *apn);

#endif /* MOSH_NET_UTILS_H */