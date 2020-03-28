/**
 *  @file  auth_svc.c
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
#include <bluetooth/l2cap.h>

#define LOG_LEVEL CONFIG_BT_GATT_AUTHS_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(auth_svc, CONFIG_BT_GATT_AUTHS_LOG_LEVEL);

#include <bluetooth/services/auth_svc.h>

#include "auth_internal.h"



#if defined(CONFIG_BT_GATT_CLIENT)

/**
 * @see auth_internal.h
 */
u8_t auth_svc_gatt_central_notify(struct bt_conn *conn, struct bt_gatt_subscribe_params *params,
                                   const void *data, u16_t length)
{
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)bt_con_get_context(conn);

    if(auth_conn == NULL) {
        LOG_ERR("auth_svc_gatt_central_notify: NULL auth_conn.");
        return BT_GATT_ITER_CONTINUE;
    }

    LOG_DBG("num bytes received: %d", length);

    /* This happens when the connection is dropped */
    if(length == 0) {
        /* TODO: signal input buff is ready */
        return BT_GATT_ITER_CONTINUE;
    }

    int numbytes = auth_svc_buffer_put(&auth_conn->rx_buf, data, length);


    if((numbytes < 0) || (numbytes != length)) {
        LOG_ERR("Failed to set all received bytes, err: %d", numbytes);
        return BT_GATT_ITER_CONTINUE;
    }

    return BT_GATT_ITER_CONTINUE;
}


/**
 * @see auth_internal.h
 */
int auth_svc_central_recv(struct authenticate_conn *auth_conn, unsigned char *buf, size_t len)
{
    /* copy bytes, returns the number of bytes actually copied */
    int err = auth_svc_buffer_get(&auth_conn->rx_buf, buf,  len);

    return err;
}

/**
 * @see auth_internal.h
 */
int auth_svc_central_recv_timeout(struct authenticate_conn *auth_conn, unsigned char *buf, size_t len, uint32_t timeout_msec)
{
    int err = 0;

    err = auth_svc_buffer_get_wait(&auth_conn->rx_buf, buf, len, timeout_msec);

    return err;
}

/**
 * @see auth_internal.h
 */
static void gatt_central_write_cb(struct bt_conn *conn, u8_t err, struct bt_gatt_write_params *params)
{
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)bt_con_get_context(conn);

    if(err) {
        LOG_ERR("gatt write failed, err: %d", err);
    } else {
        LOG_DBG("gatt write success, num bytes: %d", params->length);
    }

    auth_conn->write_att_err = err;

    k_sem_give(&auth_conn->auth_central_write_sem);
}

/**
 * @see auth_internal.h
 */
int auth_svc_central_tx(struct authenticate_conn *auth_conn, const unsigned char *buf, size_t len)
{
    int err = 0;
    u16_t write_count;
    int total_write_cnt = 0;
    struct bt_gatt_write_params write_params;

    write_params.func   = gatt_central_write_cb;
    write_params.handle = auth_conn->server_char_handle;
    write_params.offset = 0;


    /* if necessary break up the write */
    while(len != 0) {

        write_count = MIN(auth_conn->payload_size, len);

        write_params.data = buf;
        write_params.length = write_count;

        err = bt_gatt_write(auth_conn->conn, &write_params);

        if(err) {
            LOG_ERR("Failed to write to peripheral, err: %d", err);
            return err;
        }

        /* wait on semaphore for write completion */
        err = k_sem_take(&auth_conn->auth_central_write_sem, K_MSEC(3000));

        if(err) {
            LOG_ERR("Failed to take semaphore, err: %d", err);
            return err;
        }

        /* Was ther an ATT error code in the call back? */
        if(auth_conn->write_att_err != 0) {
            LOG_ERR("ATT write error occured, err: 0x%x", auth_conn->write_att_err);
            return -1;
        }

        total_write_cnt += write_count;
        buf += write_count;
        len -= write_count;
    }

    LOG_DBG("Central - num bytes sent: %d", total_write_cnt);

    return total_write_cnt;
}

#endif  /* CONFIG_BT_GATT_CLIENT */

/**
 * Called when the Central has ACK'd receiving data
 * Function is called in the System workqueue context
 *
 * @param conn   BLE connection
 * @param attr   Attribute
 * @param err    GATT error
 */
static void auth_svc_peripheral_indicate(struct bt_conn *conn,
                                               const struct bt_gatt_attr *attr,
                                               u8_t err)
{
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)bt_con_get_context(conn);

    // set error
    auth_conn->indicate_err = err;

    // signal semaphore that chunk fo data was received from the peripheral
    k_sem_give(&auth_conn->auth_indicate_sem);

    LOG_DBG("Peripheral indication, err: %d", err);
}

/**
 * @see auth_internal.h
 */
int auth_svc_peripheral_tx(struct authenticate_conn *auth_conn, const unsigned char *buf, size_t len)
{
    int ret = 0;
    int total_bytes_sent = 0;
    bool done = false;
    size_t send_cnt = 0;

    /* Check the payload_size, if not set correctly then set. Future enhancement
     * should include a callback to notify the peripheral if the MTU has
     * changed. */
    if(auth_conn->payload_size == 0) {
        auth_conn->payload_size = bt_gatt_get_mtu(auth_conn->conn) - BLE_LINK_HEADER_BYTES;
    }


    LOG_DBG("auth_svc_peripheral_tx(), sending %d bytes.", len);


    /* Setup the indicate params.  The client will use BLE indications vs.
     * notifications.  This enables the client to know when the central has
     * read the attribute and send another packet of data. */
    struct bt_gatt_indicate_params indicate_params;

    /* setup indicate params */
    memset(&indicate_params, 0, sizeof(indicate_params));


    indicate_params.uuid = BT_UUID_AUTH_SVC_CLIENT_CHAR;
    indicate_params.attr = auth_conn->auth_client_attr;
    indicate_params.func = auth_svc_peripheral_indicate;

    while (!done)
    {
        send_cnt = MIN(len, auth_conn->payload_size);

        indicate_params.data = buf;
        indicate_params.len = send_cnt;  /* bytes to send */

        ret = bt_gatt_indicate(auth_conn->conn, &indicate_params);

        if(ret) {
            LOG_ERR("bt_gatt_indicate failed, error: 0x%x", ret);
        }

        /* wait on semaphore before sending next chunk */
        ret = k_sem_take(&auth_conn->auth_indicate_sem, 3000 /* TODO: Make this a #define */);

        /* on wakeup check if error occurred */
        if(ret) {
            LOG_ERR("Wait for central indicated failed, err: %d", ret);
            break;
        }

        /* update buffer pointer and count */
        total_bytes_sent += send_cnt;
        len -= send_cnt;
        buf += send_cnt;

        /* are we done sending? */
        if(len == 0) {
            ret = total_bytes_sent;
            break;
        }

    }

    /* TODO:  Return Mbed tls error code */
    return ret;
}

/**
 * @see auth_internal.h
 */
int auth_svc_peripheral_recv_timeout(struct authenticate_conn *auth_conn, unsigned char *buf, size_t len, uint32_t timeout)
{
    int err = auth_svc_buffer_get_wait(&auth_conn->rx_buf, buf,  len, timeout);

    return err;
}

/**
 * @see auth_internal.h
 */
int auth_svc_peripheral_recv(struct authenticate_conn *auth_conn, unsigned char *buf, size_t len)
{
    int err = auth_svc_peripheral_recv_timeout(auth_conn, buf, len, K_NO_WAIT);

    return err;
}


/**
 * Called when client notification is (dis)enabled by the Central
 *
 * @param attr    GATT attribute.
 * @param value   BT_GATT_CCC_NOTIFY if changes are notified.
 */
static void client_ccc_cfg_changed(const struct bt_gatt_attr *attr, u16_t value)
{
    ARG_UNUSED(attr);

    bool notif_enabled = (value == BT_GATT_CCC_NOTIFY) ? true : false;

    LOG_INF("Client notifications %s", notif_enabled ? "enabled" : "disabled");
}



/**
 *  Write callback function when Central writes to Peripheral characteristic.
 *
 * @param conn    BLE connection struct.
 * @param attr    Attribute written to.
 * @param buf     Bytes written
 * @param len     Number of bytes.
 * @param offset
 * @param flags
 *
 * @return
 */
static ssize_t client_write(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                        const void *buf, u16_t len, u16_t offset, u8_t flags)
{
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)bt_con_get_context(conn);

    LOG_DBG("client write called, len: %d", len);

    /* put bytes into buffer */
    int err = auth_svc_buffer_put(&auth_conn->rx_buf, (const uint8_t*)buf,  len);

    /* return number of bytes writen */
    /* TODO: Test case where only a partial write occured */
    return err;
}


/* AUTH Service Declaration */
BT_GATT_SERVICE_DEFINE(auth_svc,
        BT_GATT_PRIMARY_SERVICE(BT_UUID_AUTH_SVC),

        /**
         *    Central (client role) bt_gatt_write()  ---> server characteristic --> bt_gatt_read() Peripheral (server role)
         *
         *                Central    <---  Notification (client characteristic)  <--- Peripheral
         *
         */

        /**
         * Client characteristic, used by the peripheral (server role) to write messages authentication messages
         * to the central (client role).  The peripheral needs to alert the central a message is
         * ready to be read.
         */
        BT_GATT_CHARACTERISTIC(BT_UUID_AUTH_SVC_CLIENT_CHAR, BT_GATT_CHRC_INDICATE,
                                   (BT_GATT_PERM_READ|BT_GATT_PERM_WRITE), NULL, NULL, NULL),
        BT_GATT_CCC(client_ccc_cfg_changed,
                                    BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),

        /**
         * Server characteristic, used by the central (client role) to write authentication messages to.
         * to the server (peripheral)
         */
        BT_GATT_CHARACTERISTIC(BT_UUID_AUTH_SVC_SERVER_CHAR, BT_GATT_CHRC_WRITE,
                               (BT_GATT_PERM_READ|BT_GATT_PERM_WRITE), NULL, client_write, NULL),
);

// DAG DEBUG BEG
void  dump_attr_info(const struct bt_gatt_attr *svc_attr)
{
    uint16_t value_hdl;
    const char *uuid_str;
    do
    {
        uuid_str = bt_uuid_str_real(svc_attr->uuid);

        if(uuid_str == NULL) {
            uuid_str = "<unknown>";
        }

        value_hdl =  bt_gatt_attr_value_handle(svc_attr);

        LOG_ERR("** attr, uuid: %s, value handle: 0x%x, handle: 0x%x", log_strdup(uuid_str), value_hdl, svc_attr->handle);

        svc_attr = bt_gatt_attr_next(svc_attr);

    } while(svc_attr != NULL);
}

// DAG DEBUG END

/**
* @see auth_internal.h
 */
int auth_svc_get_peripheral_attributes(struct authenticate_conn *auth_conn)
{
    auth_conn->auth_svc_attr = &auth_svc.attrs[0];

    auth_conn->auth_client_attr = &auth_svc.attrs[1];

    auth_conn->auth_server_attr = &auth_svc.attrs[2];

    // DAG DEBUG BEG
    // iterate through all of the attributes
    for(uint32_t cnt = 0; cnt < auth_svc.attr_count; cnt++)
    {
        LOG_ERR("** attr number: %d", cnt);
        dump_attr_info(&auth_svc.attrs[cnt]);
    }


    // DAG DEBUG END

    return AUTH_SUCCESS;
}


