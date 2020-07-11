/**
 *  @file  auth_xport_common.c
 *
 *  @brief  Common transport routines.
 */

#include <zephyr/types.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <zephyr.h>
#include <init.h>

#include "auth_lib.h"
#include "auth_xport.h"


#define AUTH_SVC_IOBUF_LEN      (4096u)

/**
 * @brief Circular buffer used to save received data.
 */
struct auth_xport_io_buffer {
    struct k_mutex buf_mutex;
    struct k_sem buf_sem;

    uint32_t head_index;
    uint32_t tail_index;
    uint32_t num_valid_bytes;

    uint8_t io_buffer[AUTH_SVC_IOBUF_LEN];
};


// ---------------- API ---------------------
struct auth_xport_instance
{
    struct auth_xport_io_buffer send_buf;
    struct auth_xport_io_buffer recv_buf;

    void *xport_ctx; /* transport specific context */

    /* If the lower transport has a send function */
    send_xport_t send_func;

};

// allocate instances??
static struct auth_xport_instance xport_inst[1];


/* ================ local static funcs ================== */
/**
 *
 */
static int auth_xport_iobuffer_init(struct auth_xport_io_buffer *iobuf)
{
    /* init mutex*/
    k_mutex_init(&iobuf->buf_mutex);

    /* init semaphore */
    k_sem_init(&iobuf->buf_sem, 0, 1);

    iobuf->head_index = 0;
    iobuf->tail_index = 0;
    iobuf->num_valid_bytes = 0;

    return AUTH_SUCCESS;
}


/**
 * @see auth_internal.h
 */
static int auth_xport_buffer_put(struct auth_io_buffer *iobuf, const uint8_t *in_buf, size_t num_bytes)
{
    // Is the buffer full?
    if(iobuf->num_valid_bytes == AUTH_SVC_IOBUF_LEN) {
        return AUTH_ERROR_IOBUFF_FULL;
    }

    /* don't put negative or zero bytes */
    if(num_bytes <= 0) {
        return 0;
    }


    /* lock mutex */
    int err = k_mutex_lock(&iobuf->buf_mutex, K_FOREVER);
    if(err) {
        return err;
    }

    uint32_t free_space = AUTH_SVC_IOBUF_LEN - iobuf->num_valid_bytes;
    uint32_t copy_cnt = MIN(free_space, num_bytes);
    uint32_t total_copied = 0;
    uint32_t byte_cnt;

    if(iobuf->head_index < iobuf->tail_index) {
        // only enough room from head to tail, don't over-write
        uint32_t max_copy_cnt = iobuf->tail_index - iobuf->head_index;

        copy_cnt = MIN(max_copy_cnt, copy_cnt);

        memcpy(iobuf->io_buffer + iobuf->head_index, in_buf, copy_cnt);

        total_copied += copy_cnt;
        iobuf->head_index += copy_cnt;
        iobuf->num_valid_bytes += copy_cnt;

    } else {

        // copy from head to end of buffer
        byte_cnt = AUTH_SVC_IOBUF_LEN - iobuf->head_index;

        if(byte_cnt > copy_cnt) {
            byte_cnt = copy_cnt;
        }

        memcpy(iobuf->io_buffer + iobuf->head_index, in_buf, byte_cnt);

        total_copied += byte_cnt;
        in_buf += byte_cnt;
        copy_cnt -= byte_cnt;
        iobuf->head_index += byte_cnt;

        iobuf->num_valid_bytes += byte_cnt;

        // if wrapped, then copy from beginning of buffer
        if(copy_cnt > 0) {
            memcpy(iobuf->io_buffer, in_buf, copy_cnt);

            total_copied += copy_cnt;
            iobuf->num_valid_bytes += copy_cnt;
            iobuf->head_index = copy_cnt;
        }
    }

    /* unlock */
    k_mutex_unlock(&iobuf->buf_mutex);

    /* after putting data into buffer, signal semaphore */
    k_sem_give(&iobuf->buf_sem);

    return (int)total_copied;
}



static int auth_xport_buffer_get(struct auth_io_buffer *iobuf, uint8_t *out_buf, size_t num_bytes)
{
    // if no valid bytes, just return zero
    if(iobuf->num_valid_bytes == 0) {
        return 0;
    }

    /* lock mutex */
    int err = k_mutex_lock(&iobuf->buf_mutex, K_FOREVER);
    if(err) {
        return err;
    }

    // number bytes to copy
    uint32_t copy_cnt = MIN(iobuf->num_valid_bytes, num_bytes);
    uint32_t total_copied = 0;
    uint32_t byte_cnt = 0;

    if(iobuf->head_index <= iobuf->tail_index) {
        // how may bytes are available
        byte_cnt = AUTH_SVC_IOBUF_LEN - iobuf->tail_index;

        if(byte_cnt > copy_cnt) {
            byte_cnt = copy_cnt;
        }

        // copy from tail to end of buffer
        memcpy(out_buf, iobuf->io_buffer + iobuf->tail_index, byte_cnt);

        // update tail index
        iobuf->tail_index += byte_cnt;
        out_buf += byte_cnt;
        total_copied += byte_cnt;

        // update copy count and num valid bytes
        copy_cnt -= byte_cnt;
        iobuf->num_valid_bytes -= byte_cnt;

        // wrapped around, copy from beginning of buffer until
        // copy_count is satisfied
        if(copy_cnt > 0) {
            memcpy(out_buf, iobuf->io_buffer, copy_cnt);

            iobuf->tail_index = copy_cnt;
            iobuf->num_valid_bytes -= copy_cnt;
            total_copied += copy_cnt;
        }

    } else if(iobuf->head_index > iobuf->tail_index) {

        byte_cnt = iobuf->head_index - iobuf->tail_index;

        if(byte_cnt > copy_cnt) {
            byte_cnt = copy_cnt;
        }

        memcpy(out_buf, iobuf->io_buffer + iobuf->tail_index, byte_cnt);

        total_copied += byte_cnt;
        copy_cnt -= byte_cnt;
        iobuf->tail_index += byte_cnt;
        iobuf->num_valid_bytes -= byte_cnt;
    }

    /* unlock */
    k_mutex_unlock(&iobuf->buf_mutex);

    return (int)total_copied;
}



static int auth_xport_buffer_get_wait(struct auth_io_buffer *iobuf, uint8_t *out_buf,  int num_bytes, int waitmsec)
{
    /* return any bytes that might be sitting in the buffer */
    int bytecount = auth_xport_buffer_get(iobuf, out_buf, num_bytes);

    if(bytecount > 0) {
        /* bytes are avail, return them */
        return bytecount;
    }

    do
    {
        int err = k_sem_take(&iobuf->buf_sem, K_MSEC(waitmsec));

        if (err) {
            return err;  /* timed out -EAGAIN or error */
        }

        /* return byte count or error (bytecount < 0) */
        bytecount = auth_xport_buffer_get(iobuf, out_buf, num_bytes);

    } while(bytecount == 0);

    return bytecount;
}


static int auth_xport_buffer_bytecount(struct auth_io_buffer *iobuf)
{
    int err = k_mutex_lock(&iobuf->buf_mutex, K_FOREVER);

    if(!err) {
        err = (int)iobuf->num_valid_bytes;
    }

    /* unlock */
    k_mutex_unlock(&iobuf->buf_mutex);

    return err;
}


/* ==================== Non static funcs ================== */

/**
 * @see auth_xport.h
 */
int auth_xport_init(auth_xport_hdl_t *xporthdl, uint32_t flags, void* xport_params);
{
    int ret = 0;

    *xporthdl = &xport_inst[0];


    /* init IO buffers */
    auth_xport_iobuffer_init(&xport_inst[0].send_buf);
    auth_xport_iobuffer_init(&xport_inst[0].recv_buf);

#if CONFIG_BT_XPORT
    ret = auth_xp_bt_init(*xporthdl, 0, xport_params);
#elif CONFIG_SERIAL_XPORT
    ret = auth_xp_serial_init(*xporthdl, 0, xport_params);
#else
#error No lower transport defined.
#endif


    return ret;
}

/**
 * @see auth_xport.h
 */
int auth_xport_deinit(const auth_xport_hdl_t xporthdl)
{
    int ret = 0;
#if CONFIG_BLE_XPORT
    ret = auth_xp_ble_deinit(xporthdl, 0);
#elif CONFIG_SERIAL_XPORT
    ret = auth_xp_serial_deinit(xporthdl, 0);
#else
#error No lower transport defined.
#endif

    return ret;
}


/**
 * @see auth_xport.h
 */
int auth_xport_send(const auth_xport_hdl_t xporthdl, const uint8_t *data, size_t len)
{
    const struct auth_xport_instance *xp_inst = (auth_xport_instance_t *)xporthdl;

    int ret;
    int frame_bytes;
    int payload_bytes;
    int send_count = 0;
    int num_frames = 0;
    int tx_ret;
    struct auth_tls_frame frame;
    const uint16_t max_frame = MIN(sizeof(frame), auth_conn->payload_size);
    const uint16_t max_payload = max_frame - sizeof(frame.frame_hdr);

    /* sanity check */
    if(xp_inst == NULL) {
        return AUTH_ERROR_INVALID_PARAM;
    }

    /* set frame header */
    frame.frame_hdr = TLS_FRAME_SYNC_BITS|TLS_FRAME_BEGIN;



    /* Break up data to fit into lower transport MTU */
    while (len > 0)  {

        /* if the lower transport set a send function, call it */
        if (xp_inst->send_func != NULL)
        {
            return xp_inst->send_func(xp_inst->xport_ctx, data, len);
        }

        /* queue the send bytes into tx buffer */
        ret = auth_xport_buffer_put(&xp_inst->send_buf, data, len);
    }

    return ret;
}

/**
 * @see auth_xport.h
 */
int auth_xport_recv(const auth_xport_hdl_t xporthdl, uint8_t *buff, uint32_t buf_len, uint32_t timeoutMsec)
{
    const struct auth_xport_instance *xp_inst = (auth_xport_instance_t *)xporthdl;

    if(xp_inst == NULL) {
        return AUTH_ERROR_INVALID_PARAM;
    }

    int ret = auth_xport_buffer_get_wait(&xp_inst->recv_buf, buf, buf_len, timeoutMsecs);

    return ret;
}

/**
 * @see auth_xport.h
 */
int auth_xport_getnum_send_queued_bytes(const auth_xport_hdl_t xporthdl)
{
    const struct auth_xport_instance *xp_inst = (auth_xport_instance_t *)xporthdl;

    if(xp_inst == NULL) {
        return AUTH_ERROR_INVALID_PARAM;
    }

    int numbytes = auth_xport_buffer_bytecount( &xp_inst->send_buf);

    return numbytes;
}

/**
 * @see auth_xport.h
 */
int auth_xport_put_recv_bytes(const auth_xport_hdl_t xporthdl, cosnt uint8_t *buff, size_t buflen)
{
    const struct auth_xport_instance *xp_inst = (auth_xport_instance_t *)xporthdl;

    if(xp_inst == NULL) {
        return AUTH_ERROR_INVALID_PARAM;
    }

static uint8_t rx_buf[600];
static uint32_t rx_curr_offset;
static bool rx_first_frame = true;
int auth_dtls_receive_frame(struct authenticate_conn *auth_conn, const uint8_t *buffer, size_t buflen)
{
}

    int ret = auth_xport_buffer_put(&xp_inst->recv_buf, in_buf, buflen);

    return ret;
}

/**
 * @see auth_xport.h
 */
void auth_xport_set_sendfunc(auth_xport_hdl_t xporthdl, send_xport_t send_func)
{
    const struct auth_xport_instance *xp_inst = (auth_xport_instance_t *)xporthdl;

    if(xp_inst == NULL) {
        return AUTH_ERROR_INVALID_PARAM;
    }

    xp_inst->send_func = send_func;
}






