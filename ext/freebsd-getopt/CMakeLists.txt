#
# Copyright (c) 2020 Nordic Semiconductor
#
# SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
#

# CMakeLists.txt - Getopt Library for Zephyr

zephyr_include_directories(.)
zephyr_library()
zephyr_library_sources(
  getopt.c
  getopt_long.c
)
