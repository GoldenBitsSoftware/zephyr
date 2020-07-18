# SPDX-License-Identifier: Apache-2.0

zephyr_interface_library_named(authentication)
zephyr_library()

zephyr_library_sources(auth_lib.c auth_xport_common.c)

zephyr_library_sources_ifdef(CONFIG_BT_XPORT auth_xport_bt.c)

zephyr_library_sources_ifdef(CONFIG_SERIAL_XPORT auth_xport_serial.c)

zephyr_library_sources_ifdef(CONFIG_AUTH_CHALLENGE_RESPONSE auth_chalresp.c)

zephyr_library_sources_ifdef(CONFIG_AUTH_DTLS auth_tls.c)

