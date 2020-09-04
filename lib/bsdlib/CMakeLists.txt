#
# Copyright (c) 2018 Nordic Semiconductor
#
# SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
#
if(CONFIG_POSIX_API)
  target_include_directories(posix_subsys INTERFACE ${ZEPHYR_BASE}/include/posix)
endif()

zephyr_library()
zephyr_library_sources(bsdlib.c)
zephyr_library_sources(bsd_os.c)
zephyr_library_sources(nrf91_sockets.c)
