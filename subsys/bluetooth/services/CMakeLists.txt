# SPDX-License-Identifier: Apache-2.0


zephyr_sources_ifdef(CONFIG_BT_GATT_DIS dis.c)

zephyr_sources_ifdef(CONFIG_BT_GATT_BAS bas.c)

zephyr_sources_ifdef(CONFIG_BT_GATT_HRS hrs.c)

zephyr_sources_ifdef(CONFIG_BT_GATT_AUTHS auth_svc.c auth_common.c auth_tls.c auth_loopback.c auth_chalresp.c)

zephyr_sources_ifdef(CONFIG_BT_CENTRAL_AUTHENTICATION auth_svc.c auth_common.c auth_tls.c auth_loopback.c auth_chalresp.c)

# Is this the correct way to include Mbed tls module direcotry?
if(CONFIG_MBEDTLS)
    zephyr_include_directories($ENV{ZEPHYR_BASE}/../modules/crypto/mbedtls/include)
    zephyr_include_directories($ENV{ZEPHYR_BASE}/../modules/crypto/mbedtls/configs)
endif()
