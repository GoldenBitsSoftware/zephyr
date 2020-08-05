/**
 *  @file  auth_xport_common.c
 *
 *  @brief  Common transport routines.
 */

#include <zephyr/types.h>
#include <sys/byteorder.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <zephyr.h>
#include <init.h>

#define LOG_LEVEL CONFIG_AUTH_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_DECLARE(auth_lib, CONFIG_AUTH_LOG_LEVEL);

#include <auth/auth_lib.h>
#include <auth/auth_xport.h>


#define XPORT_IOBUF_LEN      (4096u)

/*
 * When sending a frame, use Big Endian or Network byte ordering
 */

#define XPORT_HOST_TO_NET_16(val)     sys_cpu_to_be16(val)
#define XPORT_NET_TO_HOST_16(val)     sys_be16_to_cpu(val)

/**
 * @brief Circular buffer used to save received data.
 */
struct auth_xport_io_buffer {
    struct k_mutex buf_mutex;
    struct k_sem buf_sem;

    uint32_t head_index;
    uint32_t tail_index;
    uint32_t num_valid_bytes;

    uint8_t io_buffer[XPORT_IOBUF_LEN];
};


#define XPORT_FRAME_SIZE          256u  /* should be at least as large as the MTU */

#define XPORT_FRAME_SYNC_BYTE_HIGH   (0xA5)
#define XPORT_FRAME_SYNC_BYTE_LOW    (0x90)
#define XPORT_FRAME_LOWBYTE_MASK     (0xF0)  /* bits 3-0 for flags */

#define XPORT_FRAME_SYNC_BITS     ((XPORT_FRAME_SYNC_BYTE_HIGH << 8) | XPORT_FRAME_SYNC_BYTE_LOW)
#define XPORT_FRAME_SYNC_MASK     0xFFF0
#define XPORT_FRAME_BEGIN         0x1
#define XPORT_FRAME_NEXT          0x2
#define XPORT_FRAME_END           0x4

#define XPORT_FRAME_HDR_BYTECNT     (sizeof(struct auth_xport_frame_hdr))
#define XPORT_MIN_FRAME             XPORT_FRAME_HDR_BYTECNT

#pragma pack(push, 1)

struct auth_xport_frame_hdr {
    /* bits 15-4  are for frame sync, bits 3-0 are flags */
    uint16_t sync_flags;   /* bytes to insure we're at a frame */
    uint16_t payload_len;   /* number of bytes in the payload, does not include the heaer. */
};

struct auth_xport_frame {
    struct auth_xport_frame_hdr hdr;
    uint8_t frame_payload[XPORT_FRAME_SIZE];
};
#pragma pack(pop)


// ---------------- API ---------------------
struct auth_xport_instance
{
    struct auth_xport_io_buffer send_buf;
    struct auth_xport_io_buffer recv_buf;

    void *xport_ctx; /* transport specific context */

    /* If the lower transport has a send function */
    send_xport_t send_func;

    /* vars used for re-assembling frames into a packet */
    uint8_t rx_buf[600];  // TODO:  Make 600 this a CONFIG_ param
    uint32_t rx_curr_offset;
    bool rx_first_frame;
    uint32_t payload_size;  // TODO, need to set/check how used.

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
 * Reset queue counters
 *
 * @param iobuf
 * @return
 */
static int auth_xport_iobuffer_reset(struct auth_xport_io_buffer *iobuf)
{
    iobuf->head_index = 0;
    iobuf->tail_index = 0;
    iobuf->num_valid_bytes = 0;

    return AUTH_SUCCESS;
}


/**
 * @see auth_internal.h
 */
static int auth_xport_buffer_put(struct auth_xport_io_buffer *iobuf, const uint8_t *in_buf, size_t num_bytes)
{
    // Is the buffer full?
    if(iobuf->num_valid_bytes == XPORT_IOBUF_LEN) {
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

    uint32_t free_space = XPORT_IOBUF_LEN - iobuf->num_valid_bytes;
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
        byte_cnt = XPORT_IOBUF_LEN - iobuf->head_index;

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



static int auth_xport_buffer_get(struct auth_xport_io_buffer *iobuf, uint8_t *out_buf, size_t num_bytes)
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
        /* How may bytes are available? */
        byte_cnt = XPORT_IOBUF_LEN - iobuf->tail_index;

        if(byte_cnt > copy_cnt) {
            byte_cnt = copy_cnt;
        }

        /* copy from tail to end of buffer */
        memcpy(out_buf, iobuf->io_buffer + iobuf->tail_index, byte_cnt);

        /* update tail index */
        iobuf->tail_index += byte_cnt;
        out_buf += byte_cnt;
        total_copied += byte_cnt;

        /* update copy count and num valid bytes */
        copy_cnt -= byte_cnt;
        iobuf->num_valid_bytes -= byte_cnt;

        /* wrapped around, copy from beginning of buffer until
           copy_count is satisfied */
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


static int auth_xport_buffer_get_wait(struct auth_xport_io_buffer *iobuf, uint8_t *out_buf,  int num_bytes, int waitmsec)
{
    /* return any bytes that might be sitting in the buffer */
    int bytecount = auth_xport_buffer_get(iobuf, out_buf, num_bytes);

    if(bytecount > 0) {
        /* bytes are avail, return them */
        return bytecount;
    }

    do {
        int err = k_sem_take(&iobuf->buf_sem, K_MSEC(waitmsec));

        if (err) {
            return err;  /* timed out -EAGAIN or error */
        }

        /* return byte count or error (bytecount < 0) */
        bytecount = auth_xport_buffer_get(iobuf, out_buf, num_bytes);

    } while(bytecount == 0);

    return bytecount;
}


static int auth_xport_buffer_bytecount(struct auth_xport_io_buffer *iobuf)
{
    int err = k_mutex_lock(&iobuf->buf_mutex, K_FOREVER);

    if(!err) {
        err = (int)iobuf->num_valid_bytes;
    }

    /* unlock */
    k_mutex_unlock(&iobuf->buf_mutex);

    return err;
}


static int auth_xport_buffer_avail_bytes(struct auth_xport_io_buffer *iobuf)
{
    return sizeof(iobuf->io_buffer) - auth_xport_buffer_bytecount(iobuf);
}

/**
 * Internal function to send data to peer
 *
 * @param xporthdl  Transport handle
 * @param data      Buffer to send.
 * @param len       Number of bytes to send.
 *
 * @return  Number of bytes sent on success, can be less than requested.
 *          On error, negative error code.
 */
static int auth_xport_internal_send(const auth_xport_hdl_t xporthdl, const uint8_t *data, size_t len)
{
    struct auth_xport_instance *xp_inst = (struct auth_xport_instance *)xporthdl;

    /* if the lower transport set a send function, call it */
    if (xp_inst->send_func != NULL) {
        return xp_inst->send_func(xporthdl, data, len);
    }

    /* queue the send bytes into tx buffer */
    return auth_xport_buffer_put(&xp_inst->send_buf, data, len);
}


/* ==================== Non static funcs ================== */

/**
 * @see auth_xport.h
 */
int auth_xport_init(auth_xport_hdl_t *xporthdl, uint32_t flags, void* xport_params)
{
    int ret = 0;

    // TODO: Need to handle multiple instances of xport
    *xporthdl = &xport_inst[0];

    /* init IO buffers */
    auth_xport_iobuffer_init(&xport_inst[0].send_buf);
    auth_xport_iobuffer_init(&xport_inst[0].recv_buf);

    xport_inst[0].rx_first_frame = true;
    xport_inst[0].rx_curr_offset = 0;

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
    struct auth_xport_instance *xp_inst = (struct auth_xport_instance *)xporthdl;

    if(xp_inst == NULL) {
        return AUTH_ERROR_INVALID_PARAM;
    }

    /* reset queues */
    auth_xport_iobuffer_reset(&xp_inst->send_buf);
    auth_xport_iobuffer_reset(&xp_inst->recv_buf);

    xport_inst->rx_first_frame = true;
    xport_inst->rx_curr_offset = 0;

#if CONFIG_BT_XPORT
    ret = auth_xp_bt_deinit(xporthdl);
#elif CONFIG_SERIAL_XPORT
    ret = auth_xp_serial_deinit(xporthdl);
#else
#error No lower transport defined.
#endif

    return ret;
}

/**
 * @see auth_xport.h
 */
int auth_xport_event(const auth_xport_hdl_t xporthdl, struct auth_xport_evt *event)
{
    int ret = 0;

#if CONFIG_BT_XPORT
    ret = auth_xp_bt_event(xporthdl, event);
#elif CONFIG_SERIAL_XPORT
    ret = auth_xp_serial_event(xporthdl, event);
#else
#error No lower transport defined.
#endif

    return ret;
}

int auth_xport_get_max_payload(const auth_xport_hdl_t xporthdl)
{
    int mtu = 0;

#if CONFIG_BT_XPORT
   mtu = auth_xp_bt_get_max_payload(xporthdl);
#elif CONFIG_SERIAL_XPORT
    mtu = auth_xp_serial_get_max_payload(xporthdl);
#else
#error No lower transport defined.
#endif
    return mtu;
}

/**
 * @see auth_xport.h
 */
int auth_xport_send(const auth_xport_hdl_t xporthdl, const uint8_t *data, size_t len)
{
    struct auth_xport_instance *xp_inst = (struct auth_xport_instance *)xporthdl;
    bool do_framing = true;  /* always true for now */
    int frame_bytes;
    int payload_bytes;
    int send_count = 0;
    int num_frames = 0;
    int send_ret = AUTH_SUCCESS;
    struct auth_xport_frame frame;

    /* If the lower transport MTU size isn't set, get it.  This can happen
     * when the the MTU is negotiated after the initial connection. */
    if(xp_inst->payload_size == 0) {
	    xp_inst->payload_size = auth_xport_get_max_payload(xporthdl);
    }

    const uint16_t max_frame = MIN(sizeof(frame), xp_inst->payload_size);
    const uint16_t max_payload = max_frame - XPORT_FRAME_HDR_BYTECNT;

    /* sanity check */
    if(xp_inst == NULL) {
        return AUTH_ERROR_INVALID_PARAM;
    }

    /* if we're not framing */
    if(!do_framing) {
        return auth_xport_internal_send(xporthdl, data, len);
    }

    /* set frame header */
    frame.hdr.sync_flags = XPORT_FRAME_SYNC_BITS|XPORT_FRAME_BEGIN;

    /* Break up data to fit into lower transport MTU */
    while (len > 0) {

        /* get payload bytes */
        payload_bytes = MIN(max_payload, len);

        frame_bytes = payload_bytes + XPORT_FRAME_HDR_BYTECNT;

        /* is this the last frame? */
        if((len - payload_bytes) == 0) {

            frame.hdr.sync_flags = XPORT_FRAME_SYNC_BITS|XPORT_FRAME_END;

            /* now check if we're only sending one frame, then set
             * the frame begin flag */
            if(num_frames == 0) {
                frame.hdr.sync_flags |= XPORT_FRAME_BEGIN;
            }
        }

        /* copy body */
        memcpy(frame.frame_payload, data, payload_bytes);
        frame.hdr.payload_len = payload_bytes;

        /* convert header to Big Endian, network byte order */
        frame.hdr.sync_flags = sys_cpu_to_be16(frame.hdr.sync_flags);
        frame.hdr.payload_len = sys_cpu_to_be16(frame.hdr.payload_len);

        /* send frame */
        send_ret = auth_xport_internal_send(xporthdl, (const uint8_t*)&frame, frame_bytes);

        if(send_ret < 0) {
            LOG_ERR("Failed to send xport frame, error: %d", send_ret);
            return AUTH_ERROR_XPORT_SEND;
        }

        /* verify all bytes were sent */
        if(send_ret != frame_bytes) {
            LOG_ERR("Failed to to send all bytes, send: %d, requested: %d", send_ret, frame_bytes);
            return AUTH_ERROR_XPORT_SEND;
        }

        /* set next flags */
        frame.hdr.sync_flags = XPORT_FRAME_SYNC_BITS|XPORT_FRAME_NEXT;

        len -= payload_bytes;
        data += payload_bytes;
        send_count += payload_bytes;
        num_frames++;
   }

    return send_count;
}

/**
 * @see auth_xport.h
 */
int auth_xport_recv(const auth_xport_hdl_t xporthdl, uint8_t *buf, uint32_t buf_len, uint32_t timeoutMsec)
{
    struct auth_xport_instance *xp_inst = (struct auth_xport_instance *)xporthdl;

    if(xp_inst == NULL) {
        return AUTH_ERROR_INVALID_PARAM;
    }

    int ret = auth_xport_buffer_get_wait(&xp_inst->recv_buf, buf, buf_len, timeoutMsec);

    return ret;
}

/**
 * @see auth_xport.h
 */
int auth_xport_getnum_send_queued_bytes(const auth_xport_hdl_t xporthdl)
{
    struct auth_xport_instance *xp_inst = (struct auth_xport_instance *)xporthdl;

    if(xp_inst == NULL) {
        return AUTH_ERROR_INVALID_PARAM;
    }

    int numbytes = auth_xport_buffer_bytecount(&xp_inst->send_buf);

    return numbytes;
}
/**
 * @see auth_xport.h
 */
bool auth_xport_fullframe(const uint8_t *buffer, uint16_t buflen, uint16_t *frame_beg_offset, uint16_t *frame_byte_cnt)
{
    uint16_t cur_offset;
    uint16_t temp_payload_len;
    struct auth_xport_frame_hdr *frm_hdr;

    /* quick check */
    if(buflen < XPORT_MIN_FRAME)
    {
        return false;
    }

    /* look for sync bytes  */
    for(cur_offset = 0; cur_offset < buflen; cur_offset++, buffer++) {
        /* look for the first sync byte */
        if(*buffer == XPORT_FRAME_SYNC_BYTE_HIGH) {
            if (cur_offset + 1 < buflen) {
                if((*(buffer + 1) & XPORT_FRAME_LOWBYTE_MASK) == XPORT_FRAME_SYNC_BYTE_LOW) {
                    /* found sync bytes */
                    break;
                }
            }
        }
    }

    if(cur_offset == buflen) {
        return false;
    }

    /* should have a full header, check frame len */
    frm_hdr = (struct auth_xport_frame_hdr *)buffer;

    /* convert from be to cpu */
    temp_payload_len = sys_be16_to_cpu(frm_hdr->payload_len);

    if(temp_payload_len > (buflen - cur_offset)) {
        /* not enough bytes for a full frame */
        return false;
    }

    /* Put header vars into CPU byte order. */
    frm_hdr->sync_flags = sys_be16_to_cpu(frm_hdr->sync_flags);
    frm_hdr->payload_len = sys_be16_to_cpu(frm_hdr->payload_len);

    /* Have a full frame*/
    *frame_beg_offset = cur_offset;
    *frame_byte_cnt = frm_hdr->payload_len;

    return true;
}

/**
 * @see auth_xport.h
 */
int auth_xport_put_recv_bytes(const auth_xport_hdl_t xporthdl, const uint8_t *buf, size_t buflen)
{
    struct auth_xport_instance *xp_inst = (struct auth_xport_instance *)xporthdl;
    struct auth_xport_frame *rx_frame;
    int free_buf_space;
    int recv_ret = 0;
    bool do_framing = true;

    if(xp_inst == NULL) {
        return AUTH_ERROR_INVALID_PARAM;
    }

    /* If max payload size isn't set, get it from the lower transport.
     * This can happen if the lower transports frame/MTU size is set
     * after an initial connection. */
    if(xp_inst->payload_size == 0) {
	     xp_inst->payload_size = auth_xport_get_max_payload(xporthdl);
    }

    /* If not framing, then just put the data into the receive buffer */
    if(!do_framing) {
        return auth_xport_buffer_put(&xp_inst->recv_buf, buf, buflen);
     }


    /* Reassemble packet from frames */
    /* read a frame from the peer */
    rx_frame = (struct auth_xport_frame *)buf;

    /* check for start flag */
    if(xp_inst->rx_first_frame) {

        xp_inst->rx_first_frame = false;

        if(!(rx_frame->hdr.sync_flags & XPORT_FRAME_BEGIN)) {
            /* reset vars */
            xp_inst->rx_curr_offset = 0;
            xp_inst->rx_first_frame = true;

            LOG_ERR("RX-Missing beginning frame");
            return AUTH_ERROR_XPORT_FRAME;
        }

        LOG_DBG("RX-Got BEGIN frame.");
    }

    /* check frame sync bytes */
    if((rx_frame->hdr.sync_flags & XPORT_FRAME_SYNC_MASK) != XPORT_FRAME_SYNC_BITS) {
        /* reset vars */
        xp_inst->rx_curr_offset = 0;
        xp_inst->rx_first_frame = true;

        LOG_ERR("RX-Invalid frame.");
        return AUTH_ERROR_XPORT_FRAME;
    }

    /* Subtract out frame header */
    buflen -= sizeof(rx_frame->hdr);

    /* move beyond frame header */
    buf += sizeof(rx_frame->hdr);

    /* sanity check, if zero or negative */
    if(buflen <= 0) {
        /* reset vars */
        xp_inst->rx_curr_offset = 0;
        xp_inst->rx_first_frame = true;
        LOG_ERR("RX-Empty frame!!");
        return AUTH_ERROR_XPORT_FRAME;
    }

    /* ensure there's enough free space in our temp buffer */
    free_buf_space = sizeof(xp_inst->rx_buf) - xp_inst->rx_curr_offset;

    if(free_buf_space < buflen) {
        /* reset vars */
        xp_inst->rx_curr_offset = 0;
        xp_inst->rx_first_frame = true;
        LOG_ERR("RX-not enough free space");
        return AUTH_ERROR_XPORT_FRAME;
    }

    /* copy payload bytes */
    memcpy(xp_inst->rx_buf + xp_inst->rx_curr_offset, buf, buflen);

    xp_inst->rx_curr_offset += buflen;

    /* returned the number of bytes queued */
    recv_ret = buflen;

    /* Is this the last frame? */
    if(rx_frame->hdr.sync_flags & XPORT_FRAME_END) {

        /* log number payload bytes received, don't include dtls header */
        LOG_DBG("RX-Got LAST frame, total bytes: %d", xp_inst->rx_curr_offset);

        int free_bytes = auth_xport_buffer_avail_bytes(&xp_inst->recv_buf);

        /* Is there enough free space to write record? */
        if(free_bytes >= xp_inst->rx_curr_offset) {

            /* copy into receive buffer */
            recv_ret = auth_xport_buffer_put(&xp_inst->recv_buf, xp_inst->rx_buf,
                                             xp_inst->rx_curr_offset);

        } else {
            int need = xp_inst->rx_curr_offset - free_bytes;
            LOG_ERR("Not enough room in RX buffer, free: %d, need %d bytes.", free_bytes, need);
        }

        /* reset vars */
        xp_inst->rx_curr_offset = 0;
        xp_inst->rx_first_frame = true;
    }

    return recv_ret;
}

/**
 * @see auth_xport.h
 */
void auth_xport_set_sendfunc(auth_xport_hdl_t xporthdl, send_xport_t send_func)
{
    struct auth_xport_instance *xp_inst = (struct auth_xport_instance *)xporthdl;

    xp_inst->send_func = send_func;
}

/**
 * @see auth_xport.h
 */
void auth_xport_set_context(auth_xport_hdl_t xporthdl, void *context)
{
    struct auth_xport_instance *xp_inst = (struct auth_xport_instance *)xporthdl;

    xp_inst->xport_ctx = context;
}

/**
 * @see auth_xport.h
 */
void *auth_xport_get_context(auth_xport_hdl_t xporthdl)
{
    struct auth_xport_instance *xp_inst = (struct auth_xport_instance *)xporthdl;

    return xp_inst->xport_ctx;
}






