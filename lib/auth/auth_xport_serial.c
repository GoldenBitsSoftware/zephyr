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


#define LOG_LEVEL CONFIG_AUTH_LOGLEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(auth_serial_xport, CONFIG_AUTH_LOG_LEVEL);


#define SERIAL_LINK_MTU             (1024u)
#define NUM_BUFFERS                 (4u)
#define TX_TIMEOUT_MSEC             (2000u)

#define MAX_SERIAL_INSTANCES        (3u)

/* Lower transport instance */
struct serial_xp_instance
{
    bool in_use;
    struct device *serial_dev;
    auth_xport_hdl_t xport_hdl;
};

/* Buffer used for TX/RX */
struct serial_xp_buffer
{
    bool in_use;
    uint32_t num_bytes_req;  /* number tx/rx bytes requested */
    uint32_t bufidx;         /* Buffer index */
    uint8_t buffer[SERIAL_LINK_MTU];
};


static struct serial_xp_instance serial_xp_inst[MAX_SERIAL_INSTANCES];


/* Atomic bits to determine if a buffer is in use */
ATOMIC_DEFINE(buffer_in_use, NUM_BUFFERS);

static struct serial_xp_buffer serial_xp_bufs[NUM_BUFFERS] = {
    { .in_use = false, .bufidx = 0 },
    { .in_use = false, .bufidx = 1 },
    { .in_use = false, .bufidx = 2 },
    { .in_use = false, .bufidx = 3 }
};


static struct serial_xp_buffer *serial_xp_buffer_info(const uint8_t *buf)
{
    /* get pointer to containing struct*/
    struct serial_xp_buffer *xp_buf =
           (struct serial_xp_buffer *)CONTAINER_OF(buf, struct serial_xp_buffer, buffer);

    return xp_buf;
}

static void serial_set_xp_buffer_setreq_len(const uint8_t *buf, uint32_t len)
{
    if(buf != NULL) {
        struct serial_xp_buffer *xp_buf = serial_xp_buffer_info(buf);
        xp_buf->num_bytes_req = len;
    }
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
            return serial_xp_bufs[cnt].buffer;
        }
    }

    return NULL;
}

static void serial_free_xp_buffer(const uint8_t *buffer)
{
    struct serial_xp_buffer *xp_buffer = serial_xp_buffer_info(buffer);

    if(xp_buffer != NULL) {
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
        serial_inst->serial_dev = NULL;
        serial_inst->xport_hdl = NULL;
    }
}

static void auth_xp_uart_cb(struct uart_event *evt, void *user_data)
{
    int err;
    struct serial_xp_instance *serial_inst = (struct serial_xp_instance *)user_data;

    switch(evt->type) {

        case UART_TX_DONE:
        {
            struct serial_xp_buffer *xp_buffer = serial_xp_buffer_info(evt->data.tx.buf);

            /* if bytes remaining to be send, resend remaining bytes */
            if(evt->data.tx.len != xp_buffer->num_bytes_req) {
                // TODO:.....
            } else {
                serial_free_xp_buffer(evt->data.tx.buf);
            }
            break;
        }


        case UART_TX_ABORTED:
        {
            /* free tx buffer */
            serial_free_xp_buffer(evt->data.tx.buf);
            break;
        }

        case UART_RX_RDY:
        {
            /* NOTE: Might have to change if receiver byte at a time. */
            err = auth_xport_put_recv_bytes(serial_inst->xport_hdl,
                                            evt->data.rx.buf + evt->data.rx.offset,
                                            evt->data.rx.len);
            break;
        }

        case UART_RX_BUF_REQUEST:
        {
            uint8_t *newbuf = serial_get_xp_buffer(SERIAL_LINK_MTU);
            serial_set_xp_buffer_setreq_len(newbuf, SERIAL_LINK_MTU);

            if(newbuf != NULL) {
                uart_rx_buf_rsp(serial_inst->serial_dev, newbuf, SERIAL_LINK_MTU);
            } else {
                LOG_ERR("Failed to get free buffer.");
            }

            break;
        }

        case UART_RX_BUF_RELEASED:
        {
            serial_free_xp_buffer(evt->data.rx_buf.buf);
            break;
        }

        case UART_RX_DISABLED:
        {
            /* restart RX?? */
            break;
        }

        case UART_RX_STOPPED:
        {
            /* free RX buffers */
            serial_free_xp_buffer(evt->data.rx_stop.data.buf);
            break;
        }

        default:
            break;
    }

}

static int auth_xp_serial_send(auth_xport_hdl_t xport_hdl, const uint8_t *data, const size_t len)
{
    if(len > SERIAL_LINK_MTU) {
        LOG_ERR("Too many bytes to send.");
        return AUTH_ERROR_INVALID_PARAM;
    }

    struct serial_xp_instance *serial_inst = (struct serial_xp_instance *)auth_xport_get_context(xport_hdl);

    /* get free buffer for tx */
    uint8_t *tx_buf = serial_get_xp_buffer(len);

    if(tx_buf == NULL) {
        LOG_ERR("No free TX buffer.");
        return AUTH_ERROR_NO_RESOURCE;
    }

    /* set the number of bytes requested to send */
    serial_set_xp_buffer_setreq_len(tx_buf, len);

    /* fill buffer, set as _in use */
    memcpy(tx_buf, data, len);

    int err = uart_tx(serial_inst->serial_dev, tx_buf, len, TX_TIMEOUT_MSEC);

    if(err) {
        LOG_ERR("Failed to send tx, err: %d", err);
    }

    return err;
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

    serial_inst->serial_dev = serial_param->serial_dev;
    //  serial_param->payload_size  ??

    /* set serial event callback */
    uart_callback_set(serial_inst->serial_dev, auth_xp_uart_cb, serial_inst);

    /* set context into xport handle */
    auth_xport_set_context(xport_hdl, serial_inst);

    auth_xport_set_sendfunc(xport_hdl, auth_xp_serial_send);

    /* enable receiving */
    uint8_t *rx_buf = serial_get_xp_buffer(SERIAL_LINK_MTU);
    serial_set_xp_buffer_setreq_len(rx_buf, SERIAL_LINK_MTU);
    uart_rx_enable(serial_inst->serial_dev, rx_buf, SERIAL_LINK_MTU, 2000 /* make define */);

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