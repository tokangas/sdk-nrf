#
# Copyright (c) 2020 Nordic Semiconductor
#
# SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
#

zephyr_library()
zephyr_library_sources(modem_fota.c)
zephyr_library_sources_ifdef(CONFIG_MODEM_FOTA_SHELL modem_fota_shell.c)
