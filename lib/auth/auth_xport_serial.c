/**
 *  @file  auth_xport_serial.c
 *
 *  @brief  Lower serial transport layer.
 */

#include <zephyr/types.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <zephyr.h>
#include <init.h>
#include <atomic.h>
#include <uart.h>

#include <auth/auth_lib.h>
#include <auth/auth_xport.h>

#include "auth_internal.h"


#define LOG_LEVEL CONFIG_AUTH_LOGLEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(auth_serial_xport, CONFIG_AUTH_LOG_LEVEL);


#define SERIAL_LINK_MTU             (1024u)
#define SERIAL_XP_BUFFER_LEN        SERIAL_LINK_MTU
#define NUM_BUFFERS                 (6u)
#define TX_TIMEOUT_MSEC             (2000u)

#define MAX_SERIAL_INSTANCES        (3u)

/* Lower transport instance */
struct serial_xp_instance
{
    bool in_use;
    struct device *uart_dev;
    auth_xport_hdl_t xport_hdl;

    /* Current transmit buffer */
    uint8_t *tx_buf;
    uint16_t tx_bytes;

    /* Current Rx buffer */
    uint8_t *rx_buf;
    uint16_t rx_curr_cnt;

    /* receive thread info */
    k_tid_t serial_rx_tid;
    struct k_thread serial_xp_rx_thrd_data;

};

/**
 * Work queue item, used to queue frame onto work queue.  The purpose
 * is to avoid writing to the transport input queue in an ISR context
 */
struct serial_xp_rxframe_workitem {
    struct k_work work;
    uint8_t *buffer;     /* buffer beg */
    uint16_t rx_offset;  /* Offset into buffer to frame */
    uint16_t rx_len;     /* number of bytes in frame */
    auth_xport_hdl_t xport_hdl;  /* trasport handle for this buffer */
};

/* Buffer used for TX/RX */
struct serial_xp_buffer
{
    bool in_use;
    uint32_t bufidx;         /* Buffer index */
    struct serial_xp_rxframe_workitem rx_work_item;  /* used to queue frame on work queue */
    uint8_t buffer[SERIAL_XP_BUFFER_LEN];
};


static struct serial_xp_instance serial_xp_inst[MAX_SERIAL_INSTANCES];


/* Atomic bits to determine if a buffer is in use */
ATOMIC_DEFINE(buffer_in_use, NUM_BUFFERS);

static struct serial_xp_buffer serial_xp_bufs[NUM_BUFFERS] = {
    { .in_use = false, .bufidx = 0 },
    { .in_use = false, .bufidx = 1 },
    { .in_use = false, .bufidx = 2 },
    { .in_use = false, .bufidx = 3 },
    { .in_use = false, .bufidx = 4 },
    { .in_use = false, .bufidx = 5 },
};



static struct serial_xp_buffer *serial_xp_buffer_info(const uint8_t *buf)
{
    if(buf == NULL) {
        return NULL;
    }

    /* get pointer to containing struct*/
    struct serial_xp_buffer *xp_buf =
           (struct serial_xp_buffer *)CONTAINER_OF(buf, struct serial_xp_buffer, buffer);

    return xp_buf;
}


static uint8_t *serial_get_xp_buffer(uint32_t buflen)
{
    int cnt;

    if(buflen > SERIAL_LINK_MTU) {
        LOG_ERR("Buffer request too large: %d", buflen);
        return NULL;
    }

    /* check array of tx buffers */
    for(cnt = 0; cnt < NUM_BUFFERS; cnt++) {
        if(!atomic_test_and_set_bit(buffer_in_use, cnt)) {
            serial_xp_bufs[cnt].in_use = true;
            return serial_xp_bufs[cnt].buffer;
        }
    }

    return NULL;
}

static void serial_free_xp_buffer(const uint8_t *buffer)
{
    struct serial_xp_buffer *xp_buffer = serial_xp_buffer_info(buffer);

    if(xp_buffer != NULL) {
        xp_buffer->in_use = false;
        atomic_clear_bit(buffer_in_use, xp_buffer->bufidx);
    }
}



/**
 *
 * @return
 */
static struct serial_xp_instance *auth_xp_serial_get_instance(void)
{
    uint32_t cnt;
    for(cnt = 0; cnt < MAX_SERIAL_INSTANCES; cnt++) {

        if(!serial_xp_inst[cnt].in_use) {
            serial_xp_inst[cnt].in_use = true;
            return &serial_xp_inst[cnt];
        }
    }

    return NULL;
}


static void auth_xp_serial_free_instance(struct serial_xp_instance *serial_inst)
{
    if(serial_inst != NULL) {
        serial_inst->in_use = false;
        serial_inst->uart_dev = NULL;
        serial_inst->xport_hdl = NULL;
    }
}

/*
 * Puts incoming frames into receive queue.
 */
static void serial_xp_rxbuf_work_func(struct k_work *work_item)
{
    struct serial_xp_rxframe_workitem *wrk;
    int err;

    /* put buffer into transport receive queue */
    wrk = (struct serial_xp_rxframe_workitem *)CONTAINER_OF(work_item, struct serial_xp_rxframe_workitem, work);

    /* sanity check */
    if(wrk == NULL) {
        return;
    }

    /* put frame into receive queue */
    err = auth_xport_put_recv_bytes(wrk->xport_hdl, wrk->buffer + wrk->rx_offset,
                                    wrk->rx_len);

    if(err) {
        LOG_ERR("Failed to set frame into receive queue.");
    }

    /* free buffer */
    serial_free_xp_buffer(wrk->buffer);
}

/**
 * For interrupt driven IO
 *
 * @param user_data
 */
static void auth_xp_serial_irq_cb(void *user_data)
{
    int num_bytes;
    uint16_t frame_beg_offset;
    uint16_t frame_bytes;
    uint16_t remaining_buffer_bytes;
    int total_cnt = 0;
    uint8_t *new_rxbuf;
    enum uart_rx_stop_reason rx_stop;
    struct serial_xp_instance *xp_inst = (struct serial_xp_instance *) user_data;
    struct device *uart_dev = xp_inst->uart_dev;

    uart_irq_update(uart_dev);

    /* did an error happen */
    rx_stop = uart_err_check(uart_dev);

    if(rx_stop != 0){
        /* handle error */
        //UART_ERROR_OVERRUN
        //UART_ERROR_PARITY
       // UART_ERROR_FRAMING
        //UART_ERROT_BREAK
        LOG_ERR("UART error: %d", rx_stop);
        return;
    }

    /* read any chars first */
    while(uart_irq_rx_ready(uart_dev) && xp_inst->rx_buf != NULL) {

        num_bytes = uart_fifo_read(uart_dev, xp_inst->rx_buf + xp_inst->rx_curr_cnt,
                                   SERIAL_XP_BUFFER_LEN - xp_inst->rx_curr_cnt);
        total_cnt += num_bytes;

        xp_inst->rx_curr_cnt += num_bytes;

        /* Is there a full frame? */
        if(auth_xport_fullframe(xp_inst->rx_buf, xp_inst->rx_curr_cnt,
                                &frame_beg_offset, &frame_bytes)) {

            /* A full frame is present in the input buffer starting
             * at frame_beg_offset and frame_bytes.  It's possible to
             * have the beginning of a second frame following the first frame. */

            /* get new rx buffer */
            new_rxbuf = serial_get_xp_buffer(SERIAL_XP_BUFFER_LEN);

            /* if there's garbage before the frame start,then skip.  If there
             * is another frame or partial frame following then copy to new buffer.
             * 'remaining_buffer_bytes' is the number of valid bytes after the current
             * frame. */
            remaining_buffer_bytes = xp_inst->rx_curr_cnt - frame_beg_offset - frame_bytes;

            /* If frame bytes are less than the current, then the buffer contains bytes
             * for the next fame */
            if((remaining_buffer_bytes != 0) && (new_rxbuf != NULL)) {
                /* copy extra bytes to new buffer */
                memcpy(new_rxbuf, xp_inst->rx_buf + frame_beg_offset + frame_bytes,
                       remaining_buffer_bytes);
            }

            /* Put frame onto work queue, will be added to the input queue, but
             * most importantly, not in the context of an ISR. */
            struct serial_xp_buffer *xp_buf = serial_xp_buffer_info(xp_inst->rx_buf);

            xp_buf->rx_work_item.buffer = xp_inst->rx_buf;
            xp_buf->rx_work_item.rx_offset = frame_beg_offset;
            xp_buf->rx_work_item.rx_len = frame_bytes;
            xp_buf->rx_work_item.xport_hdl = xp_inst->xport_hdl;

            // TODO: Verify if there's a problem w/reinitialzing workitem
            k_work_init(&xp_buf->rx_work_item.work, serial_xp_rxbuf_work_func);

            k_work_submit(&xp_buf->rx_work_item.work);

            /* now setup new RX frame */
            if(new_rxbuf != NULL) {
                xp_inst->rx_buf = new_rxbuf;
                xp_inst->rx_curr_cnt = remaining_buffer_bytes;
            }
            else {
                /* no free buffers */
                xp_inst->rx_buf = NULL;
                xp_inst->rx_curr_cnt = 0;
            }
        }

        /* Is the current rx buffer completely full? If so, then there is
         * no valid frame, just garbage.  Reset the current offset */
        if(xp_inst->rx_curr_cnt == SERIAL_XP_BUFFER_LEN) {
            LOG_ERR("Dropping %d bytes.",  xp_inst->rx_curr_cnt);
            xp_inst->rx_curr_cnt = 0;
        }

    }

    LOG_ERR("Read %d bytes", total_cnt);

    /* put data into rx buffer */
    /* NOTE: this grabs a lock, should not do this in an irq, start
     * work item to fill RX buffer */

    /* Any data ready to send? */
    if(xp_inst->tx_bytes == 0) {
        return;
    }

    total_cnt = 0;
    while(uart_irq_tx_ready(uart_dev) && xp_inst->tx_buf != NULL) {

        num_bytes = uart_fifo_fill(uart_dev, xp_inst->tx_buf + total_cnt, xp_inst->tx_bytes);

        /* check return can this be an error? */
        xp_inst->tx_bytes -= num_bytes;

        total_cnt += num_bytes;

        /* if not more data to send, then break */
        if(xp_inst->tx_bytes == 0) {
            break;
        }
    }

    /* we're done sending */
    if(xp_inst->tx_bytes == 0) {
        serial_free_xp_buffer(xp_inst->tx_buf);
        xp_inst->tx_buf = NULL;
    }

    //LOG_ERR("Send %d bytes", total_cnt);

}





static int auth_xp_serial_send(auth_xport_hdl_t xport_hdl, const uint8_t *data, const size_t len)
{
    if(len > SERIAL_LINK_MTU) {
        LOG_ERR("Too many bytes to send.");
        return AUTH_ERROR_INVALID_PARAM;
    }

    struct serial_xp_instance *serial_inst = (struct serial_xp_instance *)auth_xport_get_context(xport_hdl);


    /* is there a pending TX operation?  If so return busy error */
    if(serial_inst->tx_buf != NULL) {
        LOG_ERR("TX operation in process.");
        return -1;
    }


    /* get free buffer for tx */
    serial_inst->tx_buf = serial_get_xp_buffer(len);

    if(serial_inst->tx_buf == NULL) {
        LOG_ERR("No free TX buffer.");
        return AUTH_ERROR_NO_RESOURCE;
    }


    /* fill buffer, set as _in use */
    memcpy(serial_inst->tx_buf, data, len);
    serial_inst->tx_bytes = len;

    /* should kick of an interrupt */
    uart_irq_tx_enable(serial_inst->uart_dev);

    LOG_INF("Started TX operation");

    return 0;
}

/**
 * @see auth_xport.h
 */
int auth_xp_serial_init(const auth_xport_hdl_t xport_hdl, uint32_t flags, void *xport_param)
{
    struct auth_xp_serial_params *serial_param = (struct auth_xp_serial_params *)xport_param;

    struct serial_xp_instance *serial_inst = auth_xp_serial_get_instance();

    if(serial_inst == NULL) {
        LOG_ERR("No free serial xport instances.");
        return AUTH_ERROR_NO_RESOURCE;
    }

    serial_inst->xport_hdl = xport_hdl;
    serial_inst->uart_dev = serial_param->uart_dev;

    //  serial_param->payload_size  ??

    /* set serial irq callback */
    uart_irq_callback_user_data_set(serial_inst->uart_dev, auth_xp_serial_irq_cb, serial_inst);

    /* set context into xport handle */
    auth_xport_set_context(xport_hdl, serial_inst);

    auth_xport_set_sendfunc(xport_hdl, auth_xp_serial_send);

    /* get rx buffer */
    serial_inst->rx_buf = serial_get_xp_buffer(SERIAL_XP_BUFFER_LEN);
    serial_inst->rx_curr_cnt = 0;

    uart_irq_rx_enable(serial_inst->uart_dev);

    /* enable error irq */
    uart_irq_err_enable(serial_inst->uart_dev);

    return AUTH_SUCCESS;
}


int auth_xp_serial_deinit(const auth_xport_hdl_t xport_hdl)
{
    struct serial_xp_instance *serial_inst = auth_xport_get_context(xport_hdl);

    auth_xp_serial_free_instance(serial_inst);

    auth_xport_set_context(xport_hdl, NULL);

    return AUTH_SUCCESS;
}



int auth_xp_serial_event(const auth_xport_hdl_t xporthdl, struct auth_xport_evt *event)
{
    return AUTH_ERROR_INTERNAL;
}

int auth_xp_serial_get_max_payload(const auth_xport_hdl_t xporthdl)
{
    return SERIAL_LINK_MTU;
}