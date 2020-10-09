/*
 * iperf, Copyright (c) 2014, 2017, The Regents of the University of
 * California, through Lawrence Berkeley National Laboratory (subject
 * to receipt of any required approvals from the U.S. Dept. of
 * Energy).  All rights reserved.
 *
 * If you have questions about your rights to use or distribute this
 * software, please contact Berkeley Lab's Technology Transfer
 * Department at TTD@lbl.gov.
 *
 * NOTICE.  This software is owned by the U.S. Department of Energy.
 * As such, the U.S. Government has been granted for itself and others
 * acting on its behalf a paid-up, nonexclusive, irrevocable,
 * worldwide license in the Software to reproduce, prepare derivative
 * works, and perform publicly and display publicly.  Beginning five
 * (5) years after the date permission to assert copyright is obtained
 * from the U.S. Department of Energy, and subject to any subsequent
 * five (5) year renewals, the U.S. Government is granted for itself
 * and others acting on its behalf a paid-up, nonexclusive,
 * irrevocable, worldwide license in the Software to reproduce,
 * prepare derivative works, distribute copies to the public, perform
 * publicly and display publicly, and to permit others to do so.
 *
 * This code is distributed under a BSD style license, see the LICENSE
 * file for complete information.
 */
#ifndef __NET_H
#define __NET_H
#include "iperf.h"/* FTA_IPERF3_INTEGRATION_CHANGE: added for passing test */

int timeout_connect(int s, const struct sockaddr *name, socklen_t namelen, int timeout);
int netdial(struct iperf_test *test, int domain, int proto, const char *local, int local_port, const char *server, int port, int timeout); /* FTA_IPERF3_INTEGRATION_CHANGE: added test */
int netannounce(int domain, int proto, const char *local, int port);
int Nread(int fd, char *buf, size_t count, int prot);
int Nwrite(int fd, const char *buf, size_t count, int prot) /* __attribute__((hot)) */;
int has_sendfile(void);
int Nsendfile(int fromfd, int tofd, const char *buf, size_t count) /* __attribute__((hot)) */;
int setnonblocking(int fd, int nonblocking);
#ifdef NOT_IN_FTA_IPERF3_INTEGRATION
int getsockdomain(int sock);
#endif
int parse_qos(const char *tos);

#define NET_SOFTERROR -1
#define NET_HARDERROR -2

#endif /* __NET_H */
