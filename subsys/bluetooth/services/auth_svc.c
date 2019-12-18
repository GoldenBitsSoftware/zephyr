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

#define LOG_LEVEL CONFIG_BT_GATT_AUTHS_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(AUTH_SERVICE_LOG_MODULE);

#include <bluetooth/services/auth_svc.h>


/**
 * Called when Central receives data from the peripheral
 */
u8_t auth_svc_gatt_central_notify(struct bt_conn *conn, struct bt_gatt_subscribe_params *params,
                                   const void *data, u16_t length)
{
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)bt_con_get_context(conn);

    if(auth_conn == NULL) {
        /* TODO: Log an error */
        return BT_GATT_ITER_CONTINUE;
    }

    printk("** num bytes received: %d\n", length);

    /* This happens when the connection is dropped */
    if(length == 0) {
        /* TODO: signal input buff is ready */
        return BT_GATT_ITER_CONTINUE;
    }

    int numbytes = auth_svc_buffer_put(&auth_conn->rx_buf, data, length);

    /* signal semaphore */
    k_sem_give(&auth_conn->auth_indicate_sem);

    if((numbytes < 0) || (numbytes != length)) {
        /* log an error */
        LOG_ERR("Failed to set all received bytes, err: %d\n", numbytes);
        return BT_GATT_ITER_CONTINUE;
    }

    return BT_GATT_ITER_CONTINUE;
}


int auth_svc_central_recv(void *ctx, unsigned char *buf, size_t len)
{
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)ctx;

    /* check if input buffer has the data we want */
    if(auth_svc_buffer_bytecount(&auth_conn->rx_buf) > 0) {

        /* copy bytes, returns the number of bytes actually copied */
        return auth_svc_buffer_get(&auth_conn->rx_buf, buf,  len);
    }

    /* no bytes avail */
    return 0;
}


int auth_svc_central_recv_timeout(void *ctx, unsigned char *buf, size_t len, uint32_t timeout)
{
    int err = 0;
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)ctx;

    /* check byte count */
    while(true) {

        if(auth_svc_buffer_bytecount(&auth_conn->rx_buf) != 0) {

            /* copy bytes */
            return auth_svc_central_recv(ctx, buf, len);
        }

        /* Wait on semaphore, but reset first since the Indicate function
         * may have previously given the semaphore. Note there is a slight
         * race condition where before k_sem_reset() is called, the semaphore
         * is given by auth_svc_gatt_central_notify().  That's OK as this code
         * check if the buffer has been filled, even on a time out. */
        k_sem_reset(&auth_conn->auth_indicate_sem);
        err = k_sem_take(&auth_conn->auth_indicate_sem, K_MSEC(timeout));

        /* check if data was written regardless of an error or timeout. */
        if(auth_svc_buffer_bytecount(&auth_conn->rx_buf) != 0) {

            /* copy bytes */
            return auth_svc_central_recv(ctx, buf, len);
        }

        /* timed out or error*/
        if(err) {
            return err;
        }
    }

    return -1;
}

static void gatt_write_cb(struct bt_conn *conn, u8_t err, struct bt_gatt_write_params *params)
{
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)bt_con_get_context(conn);

    if(err) {
        LOG_ERR("gatt write failed, err: %d\n", err);
    } else {
        LOG_INF("gatt write success.\n");
    }

    k_sem_give(&auth_conn->auth_io_sem);
}

int auth_svc_central_tx(void *ctx, const unsigned char *buf, size_t len)
{
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)ctx;
    int err = 0;
    u16_t write_count;
    int total_write_cnt = 0;
    struct bt_gatt_write_params write_params;

    write_params.func   = gatt_write_cb;
    write_params.handle = auth_conn->server_char_handle;
    write_params.offset = 0;


    /* if necessary break up the write */
    while(len != 0) {

        write_count = MIN(auth_conn->mtu, len);

        write_params.data = buf;
        write_params.length = write_count;

        bt_gatt_write(auth_conn->conn, &write_params);

        /* wait on semaphore for write completion */
        err = k_sem_take(&auth_conn->auth_io_sem, K_MSEC(3000));

        if(err) {
            LOG_ERR("Failed to take semaphore, err: %d\n", err);
            break;
        }

        total_write_cnt += write_count;
        buf += write_count;
        len -= write_count;
    }

    return total_write_cnt;
}



/**
 * Called when central has ACK'd receiving data
 * Function is called in the System workqueue context
 *
 * @param conn
 * @param attr
 * @param err
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
}

int auth_svc_peripheral_tx(void *ctx, const unsigned char *buf, size_t len)
{
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)ctx;
    int ret = 0;
    int total_bytes_sent = 0;
    bool done = false;
    size_t send_cnt = 0;
    size_t mtu = auth_conn->mtu;


    /* Setup the indicate params.  The client will use BLE indications vs.
     * notifications.  This enables the client to know when the central has
     * read the attribute and send another packet of data. */
    struct bt_gatt_indicate_params indicate_params;


    while (!done)
    {
        if(len > mtu) {
            send_cnt = mtu;
        }

        // setup indicate params
        memset(&indicate_params, 0, sizeof(indicate_params));

        //indicate_params.uuid ??
        indicate_params.attr = auth_conn->auth_client_attr;
        indicate_params.func = auth_svc_peripheral_indicate;
        indicate_params.data = buf;
        indicate_params.len = send_cnt;  /* bytes to send */

        ret = bt_gatt_indicate(auth_conn->conn, &indicate_params);

        // wait on semaphore before sending next chunk
        ret = k_sem_take(&auth_conn->auth_indicate_sem, 3000 /* TODO: Make this a #define */);

        // on wakeup check if error occurred
        if(ret != 0) {
            printk("Wait for central indicated failed, err: %d\n", ret);
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


int auth_svc_peripheral_recv(void *ctx,unsigned char *buf, size_t len)
{
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)ctx;

    (void)auth_conn;
    //bt_gatt_read()

    return -1;
}


int auth_svc_peripheral_recv_timeout(void *ctx, unsigned char *buf, size_t len, uint32_t timeout)
{
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)ctx;

    (void)auth_conn;


    //bt_gatt_read()
    return -1;
}


//client_ccc_cfg_changed
static void client_ccc_cfg_changed(const struct bt_gatt_attr *attr, u16_t value)
{
    ARG_UNUSED(attr);

    bool notif_enabled = (value == BT_GATT_CCC_NOTIFY);

    LOG_INF("Client notifications %s", notif_enabled ? "enabled" : "disabled");
}



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
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)bt_con_get_context(conn);

    u8_t *value = attr->user_data;

    (void)auth_conn;
     (void)value;

    /* TODO: Need to figure out how this works. */

    return len;
}



// TODO:  Need to make the input buffer per-connection.
// use bt_gatt_service_register() to dynamically register a buffer vs. static buffer
// Or we can iterate through the attributes and set a buffer for the server input
// buffer.  see: bt_gatt_attr_next()
static uint8_t server_input_buffer[100];

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
                               BT_GATT_PERM_READ, NULL, client_write, server_input_buffer),

);

/**
*
* @return
 */
int auth_svc_get_peripheral_attributes(struct authenticate_conn *auth_con)
{
    auth_con->auth_svc_attr = &auth_svc.attrs[0];

    auth_con->auth_client_attr = &auth_svc.attrs[1];

    auth_con->auth_server_attr = &auth_svc.attrs[2];

    return AUTH_SUCCESS;
}


