#
# Copyright (c) 2021 Nordic Semiconductor
#
# SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
#

cmake_minimum_required(VERSION 3.13.1)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(sms_test)

# generate runner for the test
test_runner_generate(src/sms_test.c)

target_include_directories(app PRIVATE src)

cmock_handle(../../../include/modem/at_cmd.h)
zephyr_compile_definitions(CONFIG_AT_CMD_RESPONSE_MAX_LEN=2700)

#target_sources(app PRIVATE ${app_sources})
target_sources(app PRIVATE ../../../lib/at_notif/at_notif.c)

# add test file
target_sources(app PRIVATE src/sms_test.c)
