#
# Copyright (c) 2020 Nordic Semiconductor
#
# SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
#

zephyr_include_directories(.)

target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/gnss_shell.c)
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/gnss_common.c)
target_sources_ifdef(CONFIG_MOSH_GNSS_API_SOCKET app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/gnss_socket.c)
target_sources_ifdef(CONFIG_MOSH_GNSS_API_GPS_DRIVER app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/gnss_gps_driver.c)
target_sources_ifdef(CONFIG_SUPL_CLIENT_LIB app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/gnss_supl_support.c)
