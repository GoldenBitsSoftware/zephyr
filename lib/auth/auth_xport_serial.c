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


#define SERIAL_LINK_MTU                     (600u)
#define SERIAL_XP_BUFFER_LEN                SERIAL_LINK_MTU
#define NUM_BUFFERS                         (6u)
#define MSGQ_RX_FRAG_COUNT                  (4)     /* Length of message queue for receiving message
                                                    * fragments from ISR */

#define MAX_SERIAL_INSTANCES                (3u)
#define SERIAL_XP_RECV_THRD_PRIORITY        (0)
#define SERIAL_XP_RECV_STACK_SIZE           (4096)

#define SERIAL_TX_WAIT_MSEC                 (1000u)


struct serial_msgfrag_recv {
    uint8_t *rx_buf;
    uint16_t frag_offset;
    uint16_t frag_len;
};

/* Serial transport instance */
struct serial_xp_instance
{
    bool in_use;
    struct device *uart_dev;
    auth_xport_hdl_t xport_hdl;

    /* Current transmit buffer */
    uint8_t *tx_buf;
    uint16_t tx_bytes;  /* number of bytes to send */
    uint16_t curr_tx_cnt;  /* current tx send count */

    /* Receive thread vars */
    k_tid_t serial_xp_tid;
    struct k_thread serial_xp_thrd_data;

    /* Semaphore for TX */
    struct k_sem tx_sem;

#if defined(CONFIG_AUTH_FRAGMENT)
    /* current rx buffer */
    uint8_t *rx_buf;
    uint16_t curr_rx_cnt;

    /* message queue used to send fragment to recv thread */
    struct k_msgq frag_rx_queue;
    uint8_t __aligned(4) frag_rx_queue_buf[sizeof(struct serial_msgfrag_recv) * MSGQ_RX_FRAG_COUNT];
#else
    /* IO is handled as stream of bytes with no message boundary */
    struct auth_ringbuf ring_buf;
#endif

};


/* Buffer used for TX/RX */
struct serial_xp_buffer {
    bool in_use;
    uint32_t bufidx;    /* Buffer bit index. */
    uint8_t buffer[SERIAL_XP_BUFFER_LEN];
};


static struct serial_xp_instance serial_xp_inst[CONFIG_NUM_AUTH_INSTANCES];


K_THREAD_STACK_DEFINE(serial_recv_thread_stack_area_1, SERIAL_XP_RECV_STACK_SIZE);

/* Atomic bits to determine if a buffer is in use.  If bit is set
 * buffer is in use. */
ATOMIC_DEFINE(buffer_in_use, NUM_BUFFERS);

/**
 * Serial buffer pool, used across all serial instances.
 */
static struct serial_xp_buffer serial_xp_bufs[NUM_BUFFERS] = {
    { .in_use = false, .bufidx = 0 },
    { .in_use = false, .bufidx = 1 },
    { .in_use = false, .bufidx = 2 },
    { .in_use = false, .bufidx = 3 },
    { .in_use = false, .bufidx = 4 },
    { .in_use = false, .bufidx = 5 },
};


/**
 * Returns information about a serial buffer.
 *
 * @param buf Pointer to buffer.
 *
 * @return  Pointer to serial buffer info.
 */
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


/**
 * Gets a free buffer.
 *
 * @param buflen  Requested buffer size, if too large NULL return.
 *
 * @return  Pointer to buffer, else NULL on error.
 */
static uint8_t *serial_xp_get_buffer(uint32_t buflen)
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


/**
 * Free buffer.
 *
 * @param buffer  Buffer to free.
 */
static void serial_xp_free_buffer(const uint8_t *buffer)
{
    if(buffer == NULL ) {
        return;
    }
    struct serial_xp_buffer *xp_buffer = serial_xp_buffer_info(buffer);

    xp_buffer->in_use = false;
    atomic_clear_bit(buffer_in_use, xp_buffer->bufidx);
}


/**
 * Gets a serial transport instance.
 *
 * @return Pointer to serial transport, else NULL on error.
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

/**
 * Free serial transport instance.
 *
 * @param serial_inst  Pointer to serial transport instance.
 */
static void auth_xp_serial_free_instance(struct serial_xp_instance *serial_inst)
{
    if(serial_inst != NULL) {

        serial_inst->in_use = false;
        serial_inst->uart_dev = NULL;
        serial_inst->xport_hdl = NULL;

        /* free tx and rx buffers */
        if(serial_inst->tx_buf != NULL) {
            serial_xp_free_buffer(serial_inst->tx_buf);
            serial_inst->tx_buf = NULL;
        }

        if(serial_inst->rx_buf != NULL) {
            serial_xp_free_buffer(serial_inst->rx_buf);
            serial_inst->rx_buf = NULL;
        }

        serial_inst->tx_bytes = 0;
        serial_inst->curr_tx_cnt = 0;
        serial_inst->curr_rx_cnt = 0;
    }
}

static void auth_xp_serial_recv_thrd(void *arg1, void *arg2, void *arg3)
{
    struct serial_xp_instance *xp_inst = (struct serial_xp_instance *)arg1;

    while (true) {

#if defined(CONFIG_AUTH_FRAGMENT)
        struct serial_msgfrag_recv frag_msg;

        if(k_msgq_get(&xp_inst->frag_rx_queue, &frag_msg, K_FOREVER) == 0) {
            auth_message_assemble(xp_inst->xport_hdl, frag_msg.rx_buf + frag_msg.frag_offset,
                                  frag_msg.frag_len);

            /* free RX buffer */
            serial_xp_free_buffer(frag_msg.rx_buf);
        }
#else
        uint8_t rx_byte;
        if(auth_ringbuf_get_byte(&xp_inst->ringbuf, &rx_byte)) {
            auth_xport_put_recv(xp_inst->xport_hdl, &rx_byte, sizeof(rx_byte));
                }
#endif  /* CONFIG_AUTH_FRAGMENT */
    }
}


/**
 * Serial transport receive...
 * @param serial_inst
 */
static void auth_xp_serial_start_recvthread(struct serial_xp_instance *serial_inst)
{

    /* add to linked list of serial xports */

    // TODO:  Get thread stack from stack pool?
    serial_inst->serial_xp_tid = k_thread_create(&serial_inst->serial_xp_thrd_data, serial_recv_thread_stack_area_1,
                                          K_THREAD_STACK_SIZEOF(serial_recv_thread_stack_area_1),
                                          auth_xp_serial_recv_thrd, serial_inst, NULL, NULL,
                                          SERIAL_XP_RECV_THRD_PRIORITY,
                                          0,  // options
                                          K_NO_WAIT);

}

/**
 * Reads bytes from UART into a rx buffer.  When enough bytes have accumulated to fill a
 * message fragment, put fragment onto message queue.  The serial RX thread will
 * read this message and forward bytes to upper layer transport.
 * This function is called in an ISR context.
 *
 * @param xp_inst  Pointer to serial transport instance.
 *
 */
static void auth_xp_serial_irq_recv_fragment(struct serial_xp_instance *xp_inst)
{
    int num_bytes;
    int total_cnt;
    uint8_t *new_rxbuf = NULL;
    uint16_t frag_beg_offset;
    uint16_t frag_bytes;
    uint16_t remaining_buffer_bytes;
    struct serial_msgfrag_recv frag_msg;
    // DAG DEBUG BEG
    static int dag_total_cnt;
    // DAG DEBUG END

    if(xp_inst->rx_buf == NULL) {
        /* try to allocate buffer */
        xp_inst->rx_buf = serial_xp_get_buffer(SERIAL_XP_BUFFER_LEN);
        xp_inst->curr_rx_cnt = 0;

        if(xp_inst->rx_buf == NULL) {
            return;
        }
    }

    num_bytes = uart_fifo_read(xp_inst->uart_dev, xp_inst->rx_buf + xp_inst->curr_rx_cnt,
                               SERIAL_XP_BUFFER_LEN - xp_inst->curr_rx_cnt);
    total_cnt += num_bytes;

    xp_inst->curr_rx_cnt += num_bytes;

    // DAG DEBUG BEG
    dag_total_cnt += num_bytes;
    // DAG DEBUG END


    /* Is there a full frame? */
    if(auth_message_get_fragment(xp_inst->rx_buf, xp_inst->curr_rx_cnt,
                                &frag_beg_offset, &frag_bytes)) {

        // DAG DEBUG BEG
        LOG_ERR("** recv total bytes: %d", dag_total_cnt);
        // DAG DEBUG END

        /* A full message fragment is present in the input buffer starting
         * at frag_beg_offset and frag_bytes in length.  It's possible to
         * have the beginning of a second fragment following this first fragment. */

        /* get new rx buffer */
        new_rxbuf = serial_xp_get_buffer(SERIAL_XP_BUFFER_LEN);

        /* If there's garbage before the frame start,then skip.  If there
         * is another fragment or partial fragment following then copy to new buffer.
         * 'remaining_buffer_bytes' is the number of valid bytes after the current
         * fragment. */
        remaining_buffer_bytes = xp_inst->curr_rx_cnt - frag_beg_offset - frag_bytes;

        /* If fragment bytes are less than the current, then the buffer contains bytes
         * for the next fragment. */
        if((remaining_buffer_bytes != 0) && (new_rxbuf != NULL)) {
            /* copy extra bytes to new buffer */
            memcpy(new_rxbuf, xp_inst->rx_buf + frag_beg_offset + frag_bytes,
                   remaining_buffer_bytes);
        }


        frag_msg.rx_buf = xp_inst->rx_buf;
        frag_msg.frag_offset = frag_beg_offset;
        frag_msg.frag_len = frag_bytes;

        /* send fragment to receive thread via message queue */
        while(k_msgq_put(&xp_inst->frag_rx_queue, &frag_msg, K_NO_WAIT) != 0) {
              /* an error occurred, purge message queue */
              k_msgq_purge(&xp_inst->frag_rx_queue);
        }

        /* now setup new RX fragment */
        if(new_rxbuf != NULL) {
            xp_inst->rx_buf = new_rxbuf;
            xp_inst->curr_rx_cnt = remaining_buffer_bytes;
        }
        else {
            /* no free buffers */
            xp_inst->rx_buf = NULL;
            xp_inst->curr_rx_cnt = 0;
        }
    }

    /* Is the current rx buffer completely full? If so, then there is
     * no valid fragment, just garbage.  Reset the current offset */
    if(xp_inst->curr_rx_cnt == SERIAL_XP_BUFFER_LEN) {
        LOG_ERR("Dropping %d bytes.",  xp_inst->curr_rx_cnt);
        xp_inst->curr_rx_cnt = 0;
    }
}

/**
 * For interrupt driven IO for serial link.
 *
 * @param user_data
 */
static void auth_xp_serial_irq_cb(void *user_data)
{
    int num_bytes;
    static int total_cnt = 0;

#if !defined(CONFIG_AUTH_FRAGMENT)
    /* temp buff used to accumulate bytes */
    uint8_t temp_byte_rx[100];
#endif

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
        //UART_ERROR_BREAK
        LOG_ERR("UART error: %d", rx_stop);
        return;
    }

    /* read any chars first */
    while(uart_irq_rx_ready(uart_dev) ) {

#if defined(CONFIG_AUTH_FRAGMENT)
        auth_xp_serial_irq_recv_fragment(xp_inst);
#else
        /* If not fragmenting, then just put bytes into ring buffer */
        num_bytes = uart_fifo_read(uart_dev, temp_byte_rx, sizeof(temp_byte_rx))

        for (cnt = 0; cnt < num_bytes; cnt++) {
            auth_ringbuf_put_byte(&xp_inst->ring_buf, temp_byte_rx[cnt]);
        }
#endif  /* CONFIG_AUTH_FRAGMENT */
    }

    /* Any data ready to send? */
    if(xp_inst->tx_bytes == 0) {
        /* check if we can disable TX */
        if(uart_irq_tx_complete(uart_dev)) {
            uart_irq_tx_disable(uart_dev);
        }

        return;
    }

    total_cnt = 0;
    while(uart_irq_tx_ready(uart_dev) && xp_inst->tx_buf != NULL) {

        num_bytes = uart_fifo_fill(uart_dev, xp_inst->tx_buf + xp_inst->curr_tx_cnt, xp_inst->tx_bytes);

        /* check return can this be an error? */
        xp_inst->tx_bytes -= num_bytes;
        xp_inst->curr_tx_cnt += num_bytes;

        total_cnt += num_bytes;

        /* if not more data to send, then break */
        if(xp_inst->tx_bytes == 0) {
            LOG_INF("Sent tx buffer, bytes: %d.", xp_inst->curr_tx_cnt);
            break;
        }
    }

    /* we're done sending */
    if((xp_inst->tx_bytes == 0) && (xp_inst->tx_buf != NULL)) {
        serial_xp_free_buffer(xp_inst->tx_buf);
        xp_inst->tx_buf = NULL;
        xp_inst->curr_tx_cnt = 0;

        /* signal TX complete */
        k_sem_give(&xp_inst->tx_sem);
    }
}


/**
 * Send bytes on the serial link.
 *
 * @param xport_hdl  Transport handle.
 * @param data       Bytes to send.
 * @param len        Number of bytes to send.
 *
 * @return  Number of bytes sent on success, else negative error value.
 */
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
        return -EAGAIN;
    }

    /* get free buffer for tx */
    serial_inst->tx_buf = serial_xp_get_buffer(len);

    if(serial_inst->tx_buf == NULL) {
        LOG_ERR("No free TX buffer.");
        serial_inst->tx_bytes = 0;
        serial_inst->curr_tx_cnt = 0;
        return AUTH_ERROR_NO_RESOURCE;
    }

    /* fill buffer, set as _in use */
    memcpy(serial_inst->tx_buf, data, len);
    serial_inst->tx_bytes = len;
    serial_inst->curr_tx_cnt = 0;

    // DAG DEBUG BEG
    LOG_ERR("Send %d bytes", len);
    // DAG DEBUG END

    /* should kick of an interrupt */
    uart_irq_tx_enable(serial_inst->uart_dev);

    LOG_INF("Started TX operation");

    /* Wait on semaphore for TX to complete */
    int ret = k_sem_take(&serial_inst->tx_sem, K_MSEC(SERIAL_TX_WAIT_MSEC));

    if(ret) {
        return ret;
    }

    return (int)len;
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

#if defined(CONFIG_AUTH_FRAGMENT)
    k_msgq_init(&serial_inst->frag_rx_queue, serial_inst->frag_rx_queue_buf,
                sizeof(struct serial_msgfrag_recv), MSGQ_RX_FRAG_COUNT);
#else
    auth_ringbuf_init(&serial_inst->ring_buf);
#endif


    serial_inst->xport_hdl = xport_hdl;
    serial_inst->uart_dev = serial_param->uart_dev;

    //  serial_param->payload_size  ??

    /* set serial irq callback */
    uart_irq_callback_user_data_set(serial_inst->uart_dev, auth_xp_serial_irq_cb, serial_inst);

    /* set context into xport handle */
    auth_xport_set_context(xport_hdl, serial_inst);

    auth_xport_set_sendfunc(xport_hdl, auth_xp_serial_send);

    /* Init semaphore used to wait for TX to complete. */
    k_sem_init(&serial_inst->tx_sem, 0, 1);

    /* reset tx vars */
    serial_inst->tx_buf = NULL;
    serial_inst->tx_bytes = 0;
    serial_inst->curr_tx_cnt = 0;

    /* get rx buffer */
    serial_inst->rx_buf = serial_xp_get_buffer(SERIAL_XP_BUFFER_LEN);
    serial_inst->curr_rx_cnt = 0;

    auth_xp_serial_start_recvthread(serial_inst);

    /* enable rx interrupts */
    uart_irq_rx_enable(serial_inst->uart_dev);

    /* enable error irq */
    uart_irq_err_enable(serial_inst->uart_dev);

    return AUTH_SUCCESS;
}

/**
 * @see auth_xport.h
 */
int auth_xp_serial_deinit(const auth_xport_hdl_t xport_hdl)
{
    struct serial_xp_instance *serial_inst = auth_xport_get_context(xport_hdl);

    auth_xp_serial_free_instance(serial_inst);

    auth_xport_set_context(xport_hdl, NULL);

    return AUTH_SUCCESS;
}


/**
 * @see auth_xport.h
 */
int auth_xp_serial_event(const auth_xport_hdl_t xporthdl, struct auth_xport_evt *event)
{
    /* stub for now */
    return AUTH_ERROR_INTERNAL;
}

/**
 * @see auth_xport.h
 */
int auth_xp_serial_get_max_payload(const auth_xport_hdl_t xporthdl)
{
    return SERIAL_LINK_MTU;
}