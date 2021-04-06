#
# Copyright (c) 2021 Nordic Semiconductor
#
# SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
#

zephyr_include_directories(.)

target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/net_utils.c)
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/time_utils.c)
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/str_utils.c)
