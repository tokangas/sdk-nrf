#
# Copyright (c) 2018 Nordic Semiconductor
#
# SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
#

cmake_minimum_required(VERSION 3.8.2)

#if(CONFIG_POSIX_API)
#  target_include_directories(posix_subsys INTERFACE ${ZEPHYR_BASE}/include/posix)
#endif()

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(NONE)
target_include_directories(app PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}/iperf
  ${CMAKE_CURRENT_SOURCE_DIR}/utils/getopt_port)
#TODO: flag iperf: add_subdirectory_ifdef(CONFIG_FTA_IPERF src/iperf)

#zephyr_include_directories(${ZEPHYR_BASE}/include/posix)
#zephyr_include_directories_ifdef(CONFIG_POSIX_API
#  ${ZEPHYR_BASE}/include/posix)
# zephyr_compile_definitions(_POSIX_C_SOURCE=200809L)
# target_compile_definitions(app INTERFACE REENTRANT_SYSCALLS_PROVIDED
#   MISSING_SYSCALL_NAMES)
# add_link_options(-specs=nosys.specs)
# target_link_options(app
#     INTERFACE
#       -specs=nosys.specs
# )
# NORDIC SDK APP START
target_sources(app PRIVATE src/main.c)
target_sources(app PRIVATE src/lte_connection.c)
target_sources(app PRIVATE src/shell.c)
target_sources(app PRIVATE src/socket.c)
target_sources(app PRIVATE src/icmp_ping.c)
target_sources(app PRIVATE src/utils/getopt_port/getopt.c)
# target_sources(app PRIVATE src/iperf/cJSON.c)
# target_sources(app PRIVATE src/iperf/dscp.c)
# target_sources(app PRIVATE src/iperf/iperf_api.c)
# target_sources(app PRIVATE src/iperf/iperf_auth.c)
# target_sources(app PRIVATE src/iperf/iperf_client_api.c)
# target_sources(app PRIVATE src/iperf/iperf_error.c)
# target_sources(app PRIVATE src/iperf/iperf_locale.c)
# target_sources(app PRIVATE src/iperf/iperf_main.c)
# target_sources(app PRIVATE src/iperf/iperf_sctp.c)
# target_sources(app PRIVATE src/iperf/iperf_server_api.c)
# target_sources(app PRIVATE src/iperf/iperf_tcp.c)
# target_sources(app PRIVATE src/iperf/iperf_time.c)
# target_sources(app PRIVATE src/iperf/iperf_udp.c)
# target_sources(app PRIVATE src/iperf/iperf_util.c)
# target_sources(app PRIVATE src/iperf/net.c)
# target_sources(app PRIVATE src/iperf/tcp_info.c)
# target_sources(app PRIVATE src/iperf/timer.c)
# target_sources(app PRIVATE src/iperf/units.c)

add_subdirectory(src/iperf)

# NORDIC SDK APP END

