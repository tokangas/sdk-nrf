#
# Copyright (c) 2018 Nordic Semiconductor
#
# SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
#
#b_jh
#if(CONFIG_POSIX_API)
#  target_include_directories(posix_subsys INTERFACE ${ZEPHYR_BASE}/include/posix)
#endif()



zephyr_library()
if(CONFIG_POSIX_API) 
  zephyr_library_include_directories(${ZEPHYR_BASE}/include/posix)
endif()
zephyr_library_sources(bsdlib.c)
zephyr_library_sources(bsd_os.c)
zephyr_library_sources(nrf91_sockets.c)
