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

#include "auth_lib.h"
#include "auth_xport.h"


#define LOG_LEVEL CONFIG_AUTH_LOGLEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(auth_bt_xport, CONFIG_BT_GATT_AUTHS_LOG_LEVEL);

#include <bluetooth/services/auth_svc.h>


/**
 * All of the necessary info for a BT connection.
 */
struct auth_xp_bt_connection {

    boot is_central;

    /* BT connection  */
    struct bt_conn *conn;

    /* Peripheral (server) characteristic value handle.  Used by the
     * Central (client) to send data. */
    uint16_t server_char_hdl;

    /* The Central (client) attribute, used by the Peripheral (server)
     * to send data to the Central.
     */
    const struct bt_gatt_attr *client_attr;

    /* Used to wait for central write completion before
     * sending more data */
    struct k_sem auth_central_write_sem;

    volatile u8_t write_att_err;

    /* Semaphore used when processing peripheral indications */
    struct k_sem auth_indicate_sem;
    uint32_t indicate_err;

    uint16_t payload_size;  /* BLE Link MTU less struct bt_att_write_req */
};

/**
 * Maps transport handle to a BT connection.
 */
struct auth_xport_map {

    auth_xport_hdl_t xporthdl;

    /* details for bt connection */
    struct auth_xp_bt_connection bt_xport_conn;
};


static struct auth_xport_map[CONFIG_BT_MAX_CONN];

typedef int(*send_xport_t)(auth_xport_hdl_t xport_hdl, const uint8_t *data, const size_t len);

/**
 *  Called by the Central (Client( to send bytes to the peripheral (server)
 *
 * @param xport_hdl
 * @param data
 * @param len
 * @return
 */
static int auth_xp_bt_central_send(auth_xport_hdl_t xport_hdl, const uint8_t *data, const size_t len)
{
    /* get the Xport BT connection info from the xport handle */
    struct auth_xp_bt_connection *bt_xp_conn = auth_xport_get_context(xport_hdl);

    /* sanity check */
    if(bt_xp_conn == NULL) {
        LOG_E("Missing bt transport connection context.");
        return AUTH_ERROR_INTERNAL;
    }

    int ret = auth_xp_bt_central_tx(bt_xp_conn, data, len);

    return ret;
}

/**
 *
 * @param xport_hdl
 * @param data
 * @param len
 * @return
 */
static int auth_xp_bt_peripheral_send(auth_xport_hdl_t xport_hdl, const uint8_t *data, const size_t len)
{
    /* get the Xport BT connection info from the xport handle */
    struct auth_xp_bt_connection *bt_xp_conn = auth_xport_get_context(xport_hdl);

    /* sanity check */
    if(bt_xp_conn == NULL) {
        LOG_E("Missing bt transport connection context.");
        return AUTH_ERROR_INTERNAL;
    }

    int ret = auth_xp_bt_peripheral_tx(bt_xp_conn, data, len);

    return ret;
}

/**
 * Given a BT connection, return the xport connection info.
 */
static struct auth_xp_bt_connection *auth_xp_bt_getconn(struct bt_conn *conn)
{
    u8_t index = bt_conn_index(conn);

    if(index > CONFIG_BT_MAX_CONN) {
        return NULL;
    }

    return &auth_xport_map[index].bt_xport_conn;
}

// DAG DEBUG BEG
int auth_dtls_receive_frame(struct authenticate_conn *auth_conn, const uint8_t *buffer, size_t buflen);
// DAG DEBUG END

/**
 *
 */
int auth_xp_bt_init(const auth_xport_hdl_t xport_hdl, uint32_t flags, void *xport_parms)
{
    struct auth_bt_xport_params *bt_params = (struct auth_bt_xport_params*)xport_parms;

    if(parms == NULL) {
        return AUTH_ERROR_INVALID_PARAM;
    }

    /* set direct call function */
    if(bt_params->is_central) {
        auth_xport_set_sendfunc(xport_hdl, auth_xp_bt_central_send);
    } else {
        auth_xport_set_sendfunc(xport_hdl, auth_xp_bt_peripheral_send);
    }


    u8_t index = bt_conn_index(bt_params->conn);

    auth_xport_map[index].bt_xport_conn.is_central = bt_params->is_central;
    auth_xport_map[index].bt_xport_conn.conn = bt_params->conn;
    auth_xport_map[index].bt_xport_conn.xporthdl = xport_hdl;
    auth_xport_map[index].bt_xport_conn.payload_size = 0;


    if(bt_params->is_central) {
        auth_xport_map[index].bt_xport_conn.server_char_hdl = bt_params->server_char_hdl;

        /* init central write semaphore */
        k_sem_init(&auth_xport_map[index].bt_xport_conn.auth_central_write_sem, 1);

        /* QUESTION:  If we try to re-init a previously initialized semaphore,
         * will k_sem_init() return an error? */

        auth_xport_map[index].bt_xport_conn.write_att_err = 0;

    } else {

        auth_xport_map[index].bt_xport_conn.client_attr = bt_params->client_attr;

        /* init peripheral indicate semaphore */
        k_sem_init(&auth_xport_map[index].bt_xport_conn.auth_indicate_sem, 1);
        auth_xport_map[index].bt_xport_conn.indicate_err = 0;
    }

    /* Set the BT xport connection struct into the xport handle */
    auth_xport_set_context(xport_hdl, &auth_xport_map[index].bt_xport_conn);

    return AUTH_SUCCESS;
}

/**
 *
 */
int auth_xp_bt_deinit(const auth_xport_hdl_t xport_hdl)
{
    /* get xport context which is where the BT connection is saved */
    struct bt_connection *conn = auth_xport_get_context(xport_hdl);

    if(conn == NULL) {
        LOG_ERR("Missing bt connection");
        return AUTH_ERROR_INTERNAL;
    }

    u8_t index = bt_conn_index(conn);

    /* sanity check, bt connection should match what is
     * saved in the map */
    if(auth_xport_map[index].conn != conn) {
        LOG_ERR("Xport map entry invalid.");
        return AUTH_ERROR_INTERNAL;
    }

    /* clear out auth_xport_map entry */
    auth_xport_map[index].xporthdl = NULL;
    auth_xport_map[index].bt_xport_conn.is_central = false;
    auth_xport_map[index].bt_xport_conn.conn = NULL;
    auth_xport_map[index].bt_xport_conn.xporthdl = NULL;
    auth_xport_map[index].bt_xport_conn.payload_size = 0;
    auth_xport_map[index].bt_xport_conn.server_char_hdl = 0;
    auth_xport_map[index].bt_xport_conn.client_attr = NULL;

    /* QUES: How should semaphores be handled?  Should
     * they be reset here? */

    auth_xport_set_sendfunc(xport_hdl, NULL);
    auth_xport_set_context(xport_hdl, NULL);

    return AUTH_SUCCESS;
}




int auth_xport_put_recv_bytes(const auth_xport_hdl_t xporthdl, const uint8_t *buff, size_t buflen);





#if defined(CONFIG_BT_GATT_CLIENT)

/**
 * @see auth_internal.h
 */
u8_t auth_xp_bt_gatt_central_notify(struct bt_conn *conn, struct bt_gatt_subscribe_params *params,
                                   const void *data, u16_t length)
{
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)bt_con_get_context(conn);

    if(auth_conn == NULL) {
        LOG_ERR("auth_svc_gatt_central_notify: NULL auth_conn.");
        return BT_GATT_ITER_CONTINUE;
    }

    //LOG_DBG("num bytes received: %d", length);


    /* This happens when the connection is dropped */
    if(length == 0) {
        /* TODO: signal input buff is ready */
        return BT_GATT_ITER_CONTINUE;
    }

// DAG DEBUG BEG
    int numbytes = auth_dtls_receive_frame(auth_conn, (const uint8_t*)data, length);
    //int numbytes = auth_svc_buffer_put(&auth_conn->rx_buf, data, length);

    if(numbytes < 0)  {
        LOG_ERR("Failed to set all received bytes, err: %d", numbytes);
    }

// DAG DEBUG END

    return BT_GATT_ITER_CONTINUE;
}


#if 0
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
#endif


/**
 *
 */
static void auth_xp_bt_central_write_cb(struct bt_conn *conn, u8_t err, struct bt_gatt_write_params *params)
{
    struct auth_xp_bt_connection *bt_xp_conn = auth_xp_bt_getconn(conn);

    if(err) {
        LOG_ERR("gatt write failed, err: %d", err);
    } else {
        LOG_DBG("gatt write success, num bytes: %d", params->length);
    }

    bt_xp_conn->write_att_err = err;

    k_sem_give(&bt_xp_conn->auth_central_write_sem);
}



/**
 * @see
 */
int auth_xp_bt_central_tx(struct auth_xp_bt_connection *bt_xp_conn, const unsigned char *buf, size_t len)
{
    int err = 0;
    u16_t write_count;
    int total_write_cnt = 0;
    struct bt_gatt_write_params write_params;

    write_params.func   = auth_xp_bt_central_write_cb;
    write_params.handle = bt_xp_conn->server_char_hdl;
    write_params.offset = 0;


    /* if necessary break up the write */
    while(len != 0) {

        write_count = MIN(bt_xp_conn->payload_size, len);

        write_params.data = buf;
        write_params.length = write_count;

        err = bt_gatt_write(conn, &write_params);

        if(err) {
            LOG_ERR("Failed to write to peripheral, err: %d", err);
            return err;
        }

        // DAG DEBUG BEG
       // LOG_ERR("**** wrote %d bytes.", write_count);
        // DAG DEBGUG END

        /* wait on semaphore for write completion */
        err = k_sem_take(&bt_xp_conn->auth_central_write_sem, K_MSEC(10000));

        if(err) {
            LOG_ERR("Failed to take semaphore, err: %d", err);
            return err;
        }

        /* Was ther an ATT error code in the call back? */
        if(bt_xp_conn->write_att_err != 0) {
            LOG_ERR("ATT write error occured, err: 0x%x", bt_xp_conn->write_att_err);
            return -1;
        }

        total_write_cnt += write_count;
        buf += write_count;
        len -= write_count;
    }

    LOG_DBG("Central - num bytes sent: %d", total_write_cnt);

    return total_write_cnt;
}

#else  /* CONFIG_BT_GATT_CLIENT */

/**
 * Called when the Central has ACK'd receiving data
 * Function is called in the System workqueue context
 *
 * @param conn   BLE connection
 * @param attr   Attribute
 * @param err    GATT error
 */
static void auth_xp_bt_peripheral_indicate(struct bt_conn *conn,
                                               const struct bt_gatt_attr *attr,
                                               u8_t err)
{
    struct auth_xp_bt_connection *bt_xp_conn = auth_xp_bt_getconn(conn);

    // set error
    bt_xp_conn->indicate_err = err;

    // signal semaphore that chunk fo data was received from the peripheral
    k_sem_give(&bt_xp_conn->auth_indicate_sem);

    /* if an error occured */
    if(err != 0) {
	    LOG_DBG("Peripheral indication, err: %d", err);
    }
}

/**
 * @see auth_internal.h
 */
int auth_xp_bt_peripheral_tx(struct auth_xp_bt_connection *bt_xp_conn, const unsigned char *buf, size_t len)
{
    int ret = 0;
    int total_bytes_sent = 0;
    bool done = false;
    size_t send_cnt = 0;

    /* Check the payload_size, if not set correctly then set. Future enhancement
     * should include a callback to notify the peripheral if the MTU has
     * changed. */
    if(bt_xp_conn->payload_size == 0) {
        bt_xp_conn->payload_size = bt_gatt_get_mtu(auth_conn->conn) - BLE_LINK_HEADER_BYTES;
    }


    /* a little too verbose */
    /* LOG_DBG("auth_svc_peripheral_tx(), sending %d bytes.", len); */


    /* Setup the indicate params.  The client will use BLE indications vs.
     * notifications.  This enables the client to know when the central has
     * read the attribute and send another packet of data. */
    struct bt_gatt_indicate_params indicate_params;

    /* setup indicate params */
    memset(&indicate_params, 0, sizeof(indicate_params));


    indicate_params.uuid = BT_UUID_AUTH_SVC_CLIENT_CHAR;
    indicate_params.attr = bt_xp_conn->auth_client_attr;
    indicate_params.func = auth_xp_bt_peripheral_indicate;

    while (!done)
    {
        send_cnt = MIN(len, bt_xp_conn->payload_size);

        indicate_params.data = buf;
        indicate_params.len = send_cnt;  /* bytes to send */

        ret = bt_gatt_indicate(bt_xp_conn->conn, &indicate_params);

        if(ret) {
            LOG_ERR("bt_gatt_indicate failed, error: 0x%x", ret);
        }

        /* wait on semaphore before sending next chunk */
        ret = k_sem_take(&bt_xp_conn->auth_indicate_sem, 3000 /* TODO: Make this a #define */);

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

    return ret;
}

#endif /* CONFIG_BT_GATT_CLIENT */

#if 0
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
#endif

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
static ssize_t auth_xp_bt_central_write(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                        const void *buf, u16_t len, u16_t offset, u8_t flags)
{
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)bt_con_get_context(conn);

    LOG_DBG("client write called, len: %d", len);


// DAG DEBUG BEG
    // handle framing....
    /* returns 0 on success, else negative on failure */
    int err = auth_dtls_receive_frame(auth_conn, buf, len);
    //int numbytes = auth_svc_buffer_put(&auth_conn->rx_buf, data, length);

    /* if no error, need to return num of bytes handled. */
    if(err >= 0) {
         err = len;
    }

    /* put bytes into buffer */
    //int err = auth_svc_buffer_put(&auth_conn->rx_buf, (const uint8_t*)buf,  len);
// DAG DEBUG END


    /* return number of bytes writen */
    /* TODO: Test case where only a partial write occured */
    return err;
}



// DAG DEBUG BEG
void dump_attr_info(const struct bt_gatt_attr *svc_attr)
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




