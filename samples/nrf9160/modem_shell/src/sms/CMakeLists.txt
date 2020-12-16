#
# Copyright (c) 2020 Nordic Semiconductor
#
# SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
#

zephyr_include_directories(.)

target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/sms_shell.c)
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/sms.c)
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/string_conversion.c)
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/parser.c)
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/sms_deliver.c)
