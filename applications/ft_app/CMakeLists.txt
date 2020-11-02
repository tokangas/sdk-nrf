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
project(FTA)
target_include_directories(app PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}/iperf
  ${CMAKE_CURRENT_SOURCE_DIR}/ping
  ${CMAKE_CURRENT_SOURCE_DIR}/utils
  ${CMAKE_CURRENT_SOURCE_DIR}/utils/freebsd-getopt)

target_sources(app PRIVATE src/main.c)
target_sources(app PRIVATE src/shell.c)
target_sources(app PRIVATE src/utils/fta_net_utils.c)
target_sources(app PRIVATE src/utils/fta_time_utils.c)
target_sources(app PRIVATE src/utils/freebsd-getopt/getopt.c)
target_sources(app PRIVATE src/utils/freebsd-getopt/getopt_long.c)

add_subdirectory_ifdef(CONFIG_FTA_SOCK src/sock)
add_subdirectory_ifdef(CONFIG_FTA_LTELC src/ltelc)
add_subdirectory_ifdef(CONFIG_FTA_PING src/ping)
add_subdirectory_ifdef(CONFIG_FTA_CURL src/curl)
add_subdirectory_ifdef(CONFIG_FTA_IPERF3 src/iperf)
