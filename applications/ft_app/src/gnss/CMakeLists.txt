#
# Copyright (c) 2020 Nordic Semiconductor
#
# SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
#

zephyr_include_directories(.)

target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/gnss.c)
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/gnss_shell.c)