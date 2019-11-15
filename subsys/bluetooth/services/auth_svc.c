/**
 *  @file  BLE Authentication Service.
 *
 *  @brief  BLE service to authenticate the BLE connection at the application layer.
 */

#include <zephyr/types.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <zephyr.h>
#include <init.h>

#define LOG_LEVEL CONFIG_BT_GATT_AUTHS_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(auths);




 */
#define BT_UUID_AUTH_CLIENT             BT_UUID_DECLARE_16(0x3015)
/** @def BT_UUID_AUTH_SERVER
 *  @brief Characteristic used to handle DTLS exchange as a server (ie BLE peripherial)
 */
#define BT_UUID_AUTH_SERVER             BT_UUID_DECLARE_16(0x3016)


/* Heart Rate Service Declaration */
BT_GATT_SERVICE_DEFINE(hrs_svc,
        BT_GATT_PRIMARY_SERVICE(BT_UUID_AUTH_SVC),
        BT_GATT_CHARACTERISTIC(BT_UUID_HRS_MEASUREMENT, BT_GATT_CHRC_NOTIFY,
                               BT_GATT_PERM_NONE, NULL, NULL, NULL),
        BT_GATT_CCC(hrmc_ccc_cfg_changed,
                    BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),
BT_GATT_CHARACTERISTIC(BT_UUID_HRS_BODY_SENSOR, BT_GATT_CHRC_READ,
        BT_GATT_PERM_READ, read_blsc, NULL, NULL),
BT_GATT_CHARACTERISTIC(BT_UUID_HRS_CONTROL_POINT, BT_GATT_CHRC_WRITE,
        BT_GATT_PERM_NONE, NULL, NULL, NULL),
);