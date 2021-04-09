#
# Copyright (c) 2020 Nordic Semiconductor
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#

cmake_minimum_required(VERSION 3.8.2)

#configuration for secure side
if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/spm.conf")
  set(spm_CONF_FILE
    prj.conf
    ${CMAKE_CURRENT_LIST_DIR}/spm.conf
  )
endif()

#if(CONFIG_POSIX_API)
#  target_include_directories(posix_subsys INTERFACE ${ZEPHYR_BASE}/include/posix)
#endif()

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(MOSH)
target_include_directories(app PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}/iperf
  ${CMAKE_CURRENT_SOURCE_DIR}/ping
  ${CMAKE_CURRENT_SOURCE_DIR}/utils)

target_sources(app PRIVATE src/main.c)
target_sources(app PRIVATE src/shell.c)
target_sources(app PRIVATE src/at/at_shell.c)

add_subdirectory(src/utils)
add_subdirectory_ifdef(CONFIG_MOSH_SOCK src/sock)
add_subdirectory_ifdef(CONFIG_MOSH_LTELC src/ltelc)
add_subdirectory_ifdef(CONFIG_MOSH_PING src/ping)
add_subdirectory_ifdef(CONFIG_MOSH_CURL src/curl)
add_subdirectory_ifdef(CONFIG_MOSH_GNSS src/gnss)
add_subdirectory_ifdef(CONFIG_MOSH_SMS src/sms)
add_subdirectory_ifdef(CONFIG_MOSH_PPP src/ppp)
add_subdirectory_ifdef(CONFIG_MOSH_FOTA src/fota)
