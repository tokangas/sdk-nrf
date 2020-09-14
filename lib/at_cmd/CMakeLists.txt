#
# Copyright (c) 2019 Nordic Semiconductor
#
# SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
#

if(CONFIG_AT_CMD)
    zephyr_library()
    #b_jh
    if(CONFIG_POSIX_API) 
        zephyr_library_include_directories(${ZEPHYR_BASE}/include/posix)
    endif()
    #if(CONFIG_POSIX_API)
    #  target_include_directories(posix_subsys INTERFACE ${ZEPHYR_BASE}/include/posix)
    #endif()    
    #e_jh
    zephyr_library_sources(at_cmd.c)
endif()
