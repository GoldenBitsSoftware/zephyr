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

#include <auth/auth_lib.h>
#include <auth/auth_xport.h>


#define LOG_LEVEL CONFIG_AUTH_LOGLEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(auth_bt_xport, CONFIG_BT_GATT_AUTHS_LOG_LEVEL);





/**
 * Maps transport handle to a BT connection.
 */
struct auth_xport_connection_map {

    /* Opaque transport handle */
    auth_xport_hdl_t xporthdl;

    /* details for bt connection */
    bool is_central;

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


static struct auth_xport_connection_map bt_conn_map[CONFIG_BT_MAX_CONN];

typedef int(*send_xport_t)(auth_xport_hdl_t xport_hdl, const uint8_t *data, const size_t len);

/**
 *  Forward declarations
 */
int auth_xp_bt_central_tx(struct auth_xport_connection_map *bt_xp_conn, const unsigned char *buf, size_t len);
int auth_xp_bt_peripheral_tx(struct auth_xport_connection_map *bt_xp_conn, const unsigned char *buf, size_t len);


/**
 * Given a BT connection, return the xport connection info.
 */
static struct auth_xport_connection_map *auth_xp_bt_getconn(struct bt_conn *conn)
{
    u8_t index = bt_conn_index(conn);

    if(index > CONFIG_BT_MAX_CONN) {
        return NULL;
    }

    return &bt_conn_map[index];
}


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
    struct auth_xport_connection_map *bt_xp_conn = auth_xport_get_context(xport_hdl);

    /* sanity check */
    if(bt_xp_conn == NULL) {
        LOG_ERR("Missing bt transport connection context.");
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
    struct auth_xport_connection_map *bt_xp_conn = auth_xport_get_context(xport_hdl);

    /* sanity check */
    if(bt_xp_conn == NULL) {
        LOG_ERR("Missing bt transport connection context.");
        return AUTH_ERROR_INTERNAL;
    }

    int ret = auth_xp_bt_peripheral_tx(bt_xp_conn, data, len);

    return ret;
}



/**
 *  @see auth_xport.h
 */
int auth_xp_bt_init(const auth_xport_hdl_t xport_hdl, uint32_t flags, void *xport_param)
{
    struct auth_xp_bt_params *bt_params = (struct auth_xp_bt_params *)xport_param;
    struct auth_xport_connection_map *bt_xp_conn;

    if(bt_params == NULL) {
        return AUTH_ERROR_INVALID_PARAM;
    }

#if defined(CONFIG_BT_GATT_CLIENT)
    if(!bt_params->is_central)
    {
        LOG_ERR("Invalid config, is_central is false for GATT client");
        return AUTH_ERROR_INVALID_PARAM;
    }

    /* set direct call function */
    auth_xport_set_sendfunc(xport_hdl, auth_xp_bt_central_send);
#else
    if(!bt_params->is_central)
    {
        LOG_ERR("Invalid config, is_central is set for GATT server");
        return AUTH_ERROR_INVALID_PARAM;
    }

    /* set direct call function */
    auth_xport_set_sendfunc(xport_hdl, auth_xp_bt_peripheral_send);
#endif


    bt_xp_conn = auth_xp_bt_getconn(bt_params->conn);

    if(bt_xp_conn == NULL) {
        LOG_ERR("Failed to get transport map entry.");
        return AUTH_ERROR_INTERNAL;
    }

    /* Is this entry inuse?  Check conn param */
    if(bt_xp_conn->conn != NULL) {
        LOG_WRN("BT transport entry in use.");
    }

    bt_xp_conn->is_central = bt_params->is_central;
    bt_xp_conn->conn = bt_params->conn;
    bt_xp_conn->xporthdl = xport_hdl;
    bt_xp_conn->payload_size = 0;


    if(bt_params->is_central) {
        bt_xp_conn->server_char_hdl = bt_params->server_char_hdl;

        /* init central write semaphore */
        k_sem_init(&bt_xp_conn->auth_central_write_sem, 0, 1);

        /* QUESTION:  If we try to re-init a previously initialized semaphore,
         * will k_sem_init() return an error? */
        bt_xp_conn->write_att_err = 0;

    } else {

        bt_xp_conn->client_attr = bt_params->client_attr;

        /* init peripheral indicate semaphore */
        k_sem_init(&bt_xp_conn->auth_indicate_sem, 0, 1);
        bt_xp_conn->indicate_err = 0;
    }

    /* Set the BT xport connection struct into the xport handle */
    auth_xport_set_context(xport_hdl, bt_xp_conn);

    return AUTH_SUCCESS;
}

/**
 *
 */
int auth_xp_bt_deinit(const auth_xport_hdl_t xport_hdl)
{
    /* get xport context which is where the BT connection is saved */
    struct auth_xport_connection_map *bt_xp_conn = auth_xport_get_context(xport_hdl);

    if(bt_xp_conn == NULL) {
        LOG_ERR("Missing BT connection");
        return AUTH_ERROR_INTERNAL;
    }


    /* clear out auth_xport_map entry */
    bt_xp_conn->xporthdl = NULL;
    bt_xp_conn->is_central = false;
    bt_xp_conn->conn = NULL;
    bt_xp_conn->payload_size = 0;
    bt_xp_conn->server_char_hdl = 0;
    bt_xp_conn->client_attr = NULL;

    /* QUES: How should semaphores be handled?  Should
     * they be reset here? */

    auth_xport_set_sendfunc(xport_hdl, NULL);
    auth_xport_set_context(xport_hdl, NULL);

    return AUTH_SUCCESS;
}

/**
 * @see auth_xport.h
 */
int auth_xp_bt_event(const auth_xport_hdl_t xporthdl, struct auth_xport_evt *event)
{
    // stub for now
    return AUTH_SUCCESS;
}

#if defined(CONFIG_BT_GATT_CLIENT)

/**
 * @see auth_internal.h
 */
u8_t auth_xp_bt_central_notify(struct bt_conn *conn, struct bt_gatt_subscribe_params *params,
                                   const void *data, u16_t length)
{
    struct auth_xport_connection_map *bt_xp_conn = auth_xp_bt_getconn(conn);

    if(bt_xp_conn == NULL) {
        LOG_ERR("Failed to get BT connection map.");
        return BT_GATT_ITER_CONTINUE;
    }

    //LOG_DBG("num bytes received: %d", length);

    /* This happens when the connection is dropped */
    if(length == 0) {
        /* TODO: signal input buff is ready */
        return BT_GATT_ITER_CONTINUE;
    }

    // put the received bytes into the receive queue
    int err = auth_xport_put_recv_bytes(bt_xp_conn->xporthdl, data, length);

    /* if no error, need to return num of bytes handled. */
    /* Ques: What if only able to put partial bytes b/c recv queue is full? */
    if(err >= 0) {
         err = length;
    }

    if(length < 0)  {
        LOG_ERR("Failed to set all received bytes, err: %d", length);
    }

    return BT_GATT_ITER_CONTINUE;
}


/**
 *
 */
static void auth_xp_bt_central_write_cb(struct bt_conn *conn, u8_t err, struct bt_gatt_write_params *params)
{
    struct auth_xport_connection_map *bt_xp_conn = auth_xp_bt_getconn(conn);

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
int auth_xp_bt_central_tx(struct auth_xport_connection_map *bt_xp_conn, const unsigned char *buf, size_t len)
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

        err = bt_gatt_write(bt_xp_conn->conn, &write_params);

        if(err) {
            LOG_ERR("Failed to write to peripheral, err: %d", err);
            return err;
        }


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
    struct auth_xport_connection_map *bt_xp_conn = auth_xp_bt_getconn(conn);

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
 * @see
 */
int auth_xp_bt_peripheral_tx(struct auth_xport_connection_map *bt_xp_conn, const unsigned char *buf, size_t len)
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

/**
 * @see auth_xport.h
 */
int auth_xp_ble_event(const auth_xport_hdl_t xporthdl, struct auth_xport_evt *event)
{
    // stub for now
    return AUTH_SUCCESS;
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
ssize_t auth_xp_bt_central_write(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                        const void *buf, u16_t len, u16_t offset, u8_t flags)
{
    struct auth_xport_connection_map *bt_xp_conn = auth_xp_bt_getconn(conn);

    LOG_DBG("client write called, len: %d", len);

    // put the received bytes into the receive queue
    int err = auth_xport_put_recv_bytes(bt_xp_conn->xporthdl, buf, len);

    /* if no error, need to return num of bytes handled. */
    if(err >= 0) {
         err = len;
    }

    /* return number of bytes writen */
    /* TODO: Test case where only a partial write occurred */
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




