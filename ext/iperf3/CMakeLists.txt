#
# Copyright (c) 2020 Nordic Semiconductor
#
# SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
#

# CMakeLists.txt - iperf3 NCS integration

zephyr_library()
zephyr_include_directories(.) 
zephyr_library_include_directories(${ZEPHYR_BASE}/include/posix)
zephyr_library_sources(
	cjson.c
	dscp.c
	iperf_api.c
	iperf_auth.c
	iperf_client_api.c
	iperf_error.c
	iperf_locale.c
	iperf_main.c
	iperf_sctp.c
	iperf_server_api.c
	iperf_tcp.c
	iperf_time.c
	iperf_udp.c
	iperf_util.c
	net.c
	tcp_info.c
	timer.c
	units.c
)
