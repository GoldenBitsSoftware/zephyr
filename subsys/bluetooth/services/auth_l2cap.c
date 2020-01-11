/**
 *  @file  auth_l2cap.c
 *
 *  @brief  Handles L2CAP layer interface for the Central and Peripheral
 */

#include <zephyr/types.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <zephyr.h>
#include <init.h>

#include <net/net_pkt.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/conn.h>
#include <bluetooth/uuid.h>
#include <bluetooth/gatt.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/services/auth_svc.h>

#define LOG_LEVEL CONFIG_BT_GATT_AUTHS_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_DECLARE(auth_svc, CONFIG_BT_GATT_AUTHS_LOG_LEVEL);

#include "auth_internal.h"


#define AUTH_L2CAP_CHAN_CONNECT_TIMEOUT      K_MSEC(2000)  /* in msecs */

/* buffer pool defines */
#define AUTH_BUF_POOL_NAME          auth_buf_pool
#define AUTH_BUF_POOL_COUNT         10
#define AUTH_BUF_POOL_SIZE          300

/* define the net buffer pool */
NET_BUF_POOL_DEFINE(AUTH_BUF_POOL_NAME, AUTH_BUF_POOL_COUNT, AUTH_BUF_POOL_SIZE, 0, NULL);


/* ====================== Local static functions ===============*/

/**
 * Function called when timer exprired, means the L2CAP channel
 * creation timed our for some reason.
 *
 * @note Called in an ISR context
 *
 * @param timer  Pointer to timer.
 */
static void auth_create_chan_expired(struct k_timer *timer)
{
    struct authenticate_conn *auth_conn =
            CONTAINER_OF(timer, struct authenticate_conn, chan_connect_timer);

    if(!auth_conn) {
        LOG_ERR("auth connection not present.");
        return;
    }

    /* set status */
    auth_svc_set_status(auth_conn, AUTH_STATUS_FAILED);

    LOG_ERR("L2CAP channel connection timed out.");
}

/**
 * Function called when timer is stopped.
 *
 * @param timer Pointer to timer
 */
static void auth_create_chan_stop(struct k_timer *timer)
{
    /* Nothing to do, L2CAP channel created, timer stopped */
}


static struct net_buf *auth_l2cap_alloc_buf(struct bt_l2cap_chan *chan)
{
    NET_DBG("Channel %p requires buffer", chan);

    return net_buf_alloc(&AUTH_BUF_POOL_NAME, K_FOREVER);
}


static int auth_l2cap_recv(struct bt_l2cap_chan *chan, struct net_buf *buf)
{
    struct authenticate_conn *auth_conn = bt_con_get_context(chan->conn);

    LOG_DBG("Incoming data channel %p len %zu", chan,
            net_buf_frags_len(buf));

    if(!auth_conn) {
        LOG_ERR("Missing authenticate context.");
        return AUTH_ERROR_INVALID_PARAM;
    }

    /* Check if the buffer is fragmented, should not be the case.*/
    if(buf->flags & NET_BUF_FRAGS) {
        LOG_ERR("Buffer is unexpectedly fragmented.");
        return AUTH_ERROR_INVALID_PARAM;
    }

    /* check the length*/
    if(buf->b.len == 0u) {
        LOG_WRN("Received buffer is empty");
        return 0;  /* TODO: is returning 0 correct here? */
    }

    /* add data to receive buffer */
    int err = auth_svc_buffer_put(&auth_conn->rx_buf, (const uint8_t *)buf->b.data, buf->b.len);

    if(err) {
        LOG_ERR("Failed to save recv buffer, error: %d", err);
    }

    return err;
}

static void auth_l2cap_connected(struct bt_l2cap_chan *chan)
{
    struct authenticate_conn *auth_conn = bt_con_get_context(chan->conn);

    /* stop channel creation timer */
    k_timer_stop(&auth_conn->chan_connect_timer);

    LOG_INF("L2CAP channel connected.");

    /* start auth thread */
    int err = auth_svc_start_thread(auth_conn);

    if(err) {
        LOG_ERR("Failed to start authentication thread, err: %d", err);
    }
}

static void auth_l2cap_disconnected(struct bt_l2cap_chan *chan)
{
    /* stop auth process */
    /* TODO: */
}

static struct bt_l2cap_chan_ops auth_l2cap_ops = {
        .alloc_buf	  = auth_l2cap_alloc_buf,
        .recv		  = auth_l2cap_recv,
        .connected	  = auth_l2cap_connected,
        .disconnected = auth_l2cap_disconnected,
};



/* ==================== L2CAP I/O funcs ====================== */

/**
 * @see auth_internal.h
 */
int auth_svc_l2cap_init(struct authenticate_conn *auth_conn)
{
    memset(&auth_conn->l2cap_channel, 0, sizeof(auth_conn->l2cap_channel));

    auth_conn->l2cap_channel.chan.ops = &auth_l2cap_ops;
    auth_conn->l2cap_channel.chan.required_sec_level = BT_SECURITY_L1;

    /* init timer */
    k_timer_init(&auth_conn->chan_connect_timer, auth_create_chan_expired, auth_create_chan_stop);

    return AUTH_SUCCESS;
}

/**
 * @see auth_internal.h
 */
int auth_svc_l2cap_connect(struct authenticate_conn *auth_conn)
{
    int err = bt_l2cap_chan_connect(auth_conn->conn, (struct bt_l2cap_chan *)&auth_conn->l2cap_channel,
                                    AUTH_L2CAP_CHANNEL_PSM);

    if(err) {
        LOG_ERR("Failed to connect L2CAP, err: %d", err);
    } else {
        /* start one-shot timer, if channel not created then time-out */
        k_timer_start(&auth_conn->chan_connect_timer, AUTH_L2CAP_CHAN_CONNECT_TIMEOUT, 0);
    }

    return err;
}


/**
 * Question:  If we're using L2CAP, can we drop the use of authentication attributes?
 */
int auth_svc_tx_l2cap(void *ctx, const unsigned char *buf, size_t len)
{
    int ret = 0;
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)ctx;

    (void)auth_conn; // fix compiler warning

    return ret -1;
}


int auth_svc_recv_l2cap(void *ctx,
                        unsigned char *buf,
                        size_t len )
{
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)ctx;

    (void)auth_conn; // fix compiler warning

    return -1;
}


int auth_svc_recv_over_l2cap_timeout(void *ctx,
                                     unsigned char *buf,
                                     size_t len,
                                     uint32_t timeout )
{
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)ctx;

    (void)auth_conn; // fix compiler warning

    return -1;
}
