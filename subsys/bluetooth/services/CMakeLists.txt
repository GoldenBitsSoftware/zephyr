# SPDX-License-Identifier: Apache-2.0


zephyr_sources_ifdef(CONFIG_BT_GATT_DIS dis.c)

zephyr_sources_ifdef(CONFIG_BT_GATT_BAS bas.c)

zephyr_sources_ifdef(CONFIG_BT_GATT_HRS hrs.c)

zephyr_sources_ifdef(CONFIG_BT_GATT_AUTHS auth_svc.c auth_common.c auth_tls.c)

zephyr_sources_ifdef(CONFIG_BT_CENTRAL_AUTHENTICATION auth_central.c auth_common.c auth_tls.c)
