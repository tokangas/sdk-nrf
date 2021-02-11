#
# Copyright (c) 2018 Nordic Semiconductor
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
#b_jh
#if(CONFIG_POSIX_API)
#  target_include_directories(posix_subsys INTERFACE ${ZEPHYR_BASE}/include/posix)
#endif()



zephyr_library()
zephyr_library_sources(nrf_modem_lib.c)
zephyr_library_sources(nrf_modem_os.c)
zephyr_library_sources(nrf91_sockets.c)
zephyr_library_sources(shmem_sanity.c)
