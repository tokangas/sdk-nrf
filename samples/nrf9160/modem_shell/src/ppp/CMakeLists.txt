#
# Copyright (c) 2020 Nordic Semiconductor
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#

zephyr_include_directories(.)

target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/ppp_shell.c)
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/ppp_ctrl.c)
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/ppp_mdm_data_rcv.c)
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/ppp_mdm_data_snd.c)
