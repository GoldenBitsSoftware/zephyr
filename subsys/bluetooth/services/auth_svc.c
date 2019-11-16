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

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/conn.h>
#include <bluetooth/uuid.h>
#include <bluetooth/gatt.h>

#define LOG_LEVEL CONFIG_BT_GATT_AUTHS_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(auths);


//client_ccc_cfg_changed
static void client_ccc_cfg_changed(const struct bt_gatt_attr *attr, u16_t value)
{
    ARG_UNUSED(attr);

    bool notif_enabled = (value == BT_GATT_CCC_NOTIFY);

    LOG_INF("Client notifications %s", notif_enabled ? "enabled" : "disabled");
}

uint8_t client_tx_buffer[10];

/**
 *
 * @param conn
 * @param attr
 * @param buf
 * @param len
 * @param offset
 * @return
 */
static ssize_t client_read(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                         void *buf, u16_t len, u16_t offset)
{
    return bt_gatt_attr_read(conn, attr, buf, len, offset, &client_tx_buffer,
                             sizeof(client_tx_buffer));
}




static u8_t  server_input_buffer[10];
static u8_t server_update;

/**
 * Write from client
 *
 * @param conn
 * @param attr
 * @param buf
 * @param len
 * @param offset
 * @param flags
 * @return
 */
static ssize_t client_write(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                        const void *buf, u16_t len, u16_t offset,
                        u8_t flags)
{
    u8_t *value = attr->user_data;

    if (offset + len > sizeof(server_input_buffer)) {
        return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
    }

    memcpy(value + offset, buf, len);
    server_update = 1U;

    return len;
}



/* AUTH Service Declaration */
BT_GATT_SERVICE_DEFINE(auth_svc,
        BT_GATT_PRIMARY_SERVICE(BT_UUID_AUTH_SVC),
        // client characteristic, used by server write/post a response to client.
        // Server sets response to this characterstic and sets
        // notification which causes the client to read this characteristic
        BT_GATT_CHARACTERISTIC(BT_UUID_AUTH_SVC_CLIENT, BT_GATT_CHRC_READ|BT_GATT_CHRC_NOTIFY,
                               BT_GATT_PERM_READ, client_read, NULL, NULL),
        BT_GATT_CCC(client_ccc_cfg_changed,
                    BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),
        // Server characteristic, written by client, read by the server
        BT_GATT_CHARACTERISTIC(BT_UUID_AUTH_SVC_SERVER, BT_GATT_CHRC_WRITE,
                               BT_GATT_PERM_READ, NULL, client_write, server_input_buffer),

);
