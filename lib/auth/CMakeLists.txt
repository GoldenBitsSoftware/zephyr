# SPDX-License-Identifier: Apache-2.0

zephyr_interface_library_named(authentication)
zephyr_library()

zephyr_library_sources(auth_lib.c)

zephyr_library_sources_ifdef(CONFIG_AUTH_CHALLENGE_RESPONSE auth_chalresp.c)

zephyr_library_sources_ifdef(CONFIG_AUTH_DTLS auth_tls.c)

