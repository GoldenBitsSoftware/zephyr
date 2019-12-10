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


static u8_t server_update;

uint8_t client_tx_buffer[10];


/**
 * Called when Central receives data from the peripheral
 */
u8_t *auth_svc_gatt_central_notify(struct bt_conn *conn, struct bt_gatt_subscribe_params *params,
                                   const void *data, u16_t length)
{
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)bt_con_get_context(conn);

    if(auth_conn == NULL)
    {
        return NULL;
    }

    // TODO:  Fill up server rx buffer
    //        Need to lock access to it.
    //       server_input_buffer

    return NULL;
}




int auth_svc_central_tx(void *ctx, const unsigned char *buf, size_t len)
{
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)ctx;
    int ret = 0;

    (void)ret;
    (void)auth_conn;

    //central write:
    //bt_gatt_write(


    return ret;
}



int auth_svc_central_recv(void *ctx, unsigned char *buf, size_t len)
{
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)ctx;

    (void)auth_conn;

    // TODO:  Lock access to server/peripheral input buffer
    ///       Is buffer ready to forward up the Mbed TLS stack?

    //central getting notification of data from periph
    //central read:
    //bt_gatt_subscribe(callack)

    return -1;
}


int auth_svc_central_recv_timeout(void *ctx, unsigned char *buf, size_t len, uint32_t timeout)
{
    // TODO
    return -1;
}


/**
 * Called when central has ACK'd receiving data
 * Function is called in the System workqueue context
 *
 * @param conn
 * @param attr
 * @param err
 */
static void auth_svc_central_indicate(struct bt_conn *conn,
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
        indicate_params.func = auth_svc_central_indicate;
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

    if (offset + len > sizeof(auth_conn->central_rx_buf)) {
        return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
    }

    memcpy(value + offset, buf, len);
    server_update = 1U;

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
         *    Central (client role) bt_gatt_write()  ---> client characteristic --> Peripheral (server role)
         *
         *                Central    <---  Notification  <--- Peripheral
         *        Central   bt_gatt_read() <----------- Peripheral
         */

        /**
         * Client characteristic, used by the peripheral (server role) to write messages authentication messages
         * to the central (client role).  The peripheral needs to alert the central a message is
         * ready to be read.
         */
        BT_GATT_CHARACTERISTIC(BT_UUID_AUTH_SVC_CLIENT_CHAR, BT_GATT_CHRC_WRITE|BT_GATT_CHRC_INDICATE,
                               BT_GATT_PERM_READ, client_read, NULL, NULL),
        BT_GATT_CCC(client_ccc_cfg_changed,
                    BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),

        /**
         * Server characteristic, used by the central (client role) to write authentication messages to.
         * to the server (peripheral)
         */
        BT_GATT_CHARACTERISTIC(BT_UUID_AUTH_SVC_SERVER_CHAR, BT_GATT_CHRC_WRITE,
                               BT_GATT_PERM_READ, NULL, client_write, server_input_buffer),

);
