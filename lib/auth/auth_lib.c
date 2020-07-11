/**
 *  @file  auth_lib.c
 *
 *  @brief  Authentication Library functions used to authenticate a
 *          connection between a client and server.
 */

#include <zephyr/types.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <zephyr.h>
#include <init.h>
#include <stdint.h>


#include <logging/log_ctrl.h>
#include <logging/log.h>
LOG_MODULE_DECLARE(AUTH_LIB_LOG_MODULE, CONFIG_AUTH_LOG_LEVEL);

#include "auth_lib.h"
#include "auth_internal.h"


#define HANDSHAKE_THRD_STACK_SIZE       4096
#define HANDSHAKE_THRD_PRIORITY         0


/**
 * Have to come up with a way to re-use stack.  Maybe statically alloc two stacks
 * and use them among multiple connections?  Maybe track how many active handshake
 * threads have been started and if hit max then return wait?
 */
K_THREAD_STACK_DEFINE(auth_thread_stack_area_1, HANDSHAKE_THRD_STACK_SIZE);

/* TODO: Move these to auth_svc.h and wrap in #define */
void auth_dtls_thead(void *arg1, void *arg2, void *arg3);
void auth_looback_thread(void *arg1, void *arg2, void *arg3);
void auth_chalresp_thread(void *arg1, void *arg2, void *arg3);



/* ========================== local functions ========================= */

static bool auth_lib_checkflags(uint32_t flags)
{
    /* stub for now */
    /* TODO: Add code to check for conflicting flags */

    return true;
}


/**
 * Invokes the status callback from the system work queue
 *
 * @param work Pointer to wor item.
 */
static void auth_lib_status_work(struct k_work *work)
{
    struct authenticate_conn *auth_conn =
           CONTAINER_OF(work, struct authenticate_conn, auth_status_work);

    if(!auth_conn) {
        LOG_ERR("Failed to get auth conn struct.");
        return;
    }

    /* invoke callback */
    auth_conn->status_cb(auth_conn, auth_conn->curr_status, auth_conn->callback_context);
}


/* ========================= Internal  API ============================ */

int auth_lib_start_thread(struct authenticate_conn *auth_conn)
{
    // TODO:  Get thread stack from stack pool?
    auth_conn->auth_tid = k_thread_create(&auth_conn->auth_thrd_data, auth_thread_stack_area_1,
                                          K_THREAD_STACK_SIZEOF(auth_thread_stack_area_1),
                                          auth_conn->auth_thread_func, auth_conn, NULL, NULL, HANDSHAKE_THRD_PRIORITY,
                                          0,  // options
                                          K_NO_WAIT);

    return AUTH_SUCCESS;
}



/* ========================= external API ============================ */


/**
 * @see auth_lib.h
 */
int auth_lib_init(struct authenticate_conn *auth_conn, auth_status_cb_t status_func, void *context, uint32_t auth_flags)
{
    int err;

    /* check input params */
    if(status_func == NULL) {
        LOG_ERR("Error, status function is NULL.");
        return AUTH_ERROR_INVALID_PARAM;
    }

    /* check auth flags */
    if(!auth_lib_checkflags(auth_flags)) {
        LOG_ERR("Invalid auth flags.");
        return AUTH_ERROR_INVALID_PARAM;
    }

#ifdef CONFIG_AUTH_DTLS
    /* save off pointer to cert container if set */
    struct auth_cert_container *certs = auth_conn->cert_cont;
#endif

    /* init the struct to zero */
    memset(auth_conn, 0, sizeof(struct authenticate_conn));

#ifdef CONFIG_AUTH_DTLS
    /* Restore if not NULL*/
    if(certs) {
        auth_conn->cert_cont = certs;
    }
#endif


#if 0
    /* init mutexes */
    k_sem_init(&auth_conn->auth_indicate_sem, 0, 1);
    k_sem_init(&auth_conn->auth_central_write_sem, 0, 1);
#endif

    // setup the status callback
    auth_conn->status_cb = status_func;
    auth_conn->callback_context = context;

    /* init the work item used to post authentication status */
    k_work_init(&auth_conn->auth_status_work, auth_svc_status_work);

    auth_conn->is_client = (auth_flags & AUTH_CONN_CLIENT) ? true : false;

    /* Initialize RX buffer */
    //auth_svc_buffer_init(&auth_conn->rx_buf);




#ifdef CONFIG_AUTH_DTLS
    auth_conn->auth_thread_func = auth_dtls_thead;

    // init TLS layer
    err = auth_init_dtls_method(auth_conn);

    if(err) {
        LOG_ERR("Failed to initialize MBed TLS, err: %d", err);
        return err;
    }
#endif

#ifdef CONFIG_AUTH_CHALLENGE_RESPONSE
    auth_conn->auth_thread_func = auth_chalresp_thread;
#endif

#ifdef CONFIG_LOOPBACK_TEST
    auth_conn->auth_thread_func = auth_looback_thread;
#endif

    return AUTH_SUCCESS;
}

/**
 * @see auth_lib.h
 */
int auth_lib_start(struct authenticate_conn *auth_conn)
{
    int err;

    /* Start the authentication thread */
    err = auth_lib_start_thread(auth_conn);

    if(err) {
        LOG_ERR("Failed to start authentication thread, err: %d", err);

        auth_lib_set_status(auth_conn, AUTH_STATUS_FAILED);
    }

    return AUTH_SUCCESS;
}



/**
 * @see auth_svc.h
 */
const char *auth_lib_getstatus_str(auth_status_t status)
{
    switch(status) {
        case AUTH_STATUS_STARTED:
            return "Authentication started";
            break;

        case AUTH_STATUS_IN_PROCESS:
            return "In process";
            break;

        case AUTH_STATUS_CANCELED:
            return "Canceled";
            break;

        case AUTH_STATUS_FAILED:
            return "Failure";
            break;

        case AUTH_STATUS_AUTHENTICATION_FAILED:
            return "Authentication Failed";
            break;

        case AUTH_STATUS_SUCCESSFUL:
            return "Authentication Successful";
            break;

        default:
            break;
    }

    return "unknown";
}

/**
 * @see auth_lib.h
 */
auth_status_t auth_lib_get_status(struct authenticate_conn *auth_conn)
{
    return auth_conn->curr_status;
}

/**
 * @see auth_lib.h
 */
void auth_lib_set_status(struct authenticate_conn *auth_conn, auth_status_t status)
{
    auth_conn->curr_status = status;

    if(auth_conn->status_cb) {

        /* submit work item */
        k_work_submit(&auth_conn->auth_status_work);
    }
}

#if defined(CONFIG_AUTH_DTLS)
/**
 * @see auth_svc.h
 */
void auth_svc_set_tls_certs(struct authenticate_conn *auth_conn, struct auth_cert_container *certs)
{
    auth_conn->cert_cont = certs;
}
#endif

/**
 * @brief  Routines to Tx/Rx.
 */

#if defined(CONFIG_AUTH_CLIENT)

/**
 * @see auth_internal.h
 */
int auth_client_tx(struct authenticate_conn *conn, const unsigned char *data, size_t len)
{
    int numbytes_err = auth_svc_central_tx(conn, data, len);

    return numbytes_err;
}

/**
 * @see auth_internal.h
 */
int auth_client_rx(struct authenticate_conn *conn, uint8_t *buf, size_t rxbytes)
{
    int err = auth_svc_central_recv_timeout(conn, buf, rxbytes, AUTH_SVC_IO_TIMEOUT_MSEC);

    return err;
}
#else

/**
 * @see auth_internal.h
 */
int auth_server_tx(struct authenticate_conn *conn, const unsigned char *data, size_t len)
{
    int err = auth_svc_peripheral_tx(conn, data, len);

    return err;
}

/**
 * @see auth_internal.h
 */
int auth_server_rx(struct authenticate_conn *conn, uint8_t *buf, size_t len)
{
    int err = auth_svc_peripheral_recv_timeout(conn, buf, len, AUTH_SVC_IO_TIMEOUT_MSEC);

    return err;
}
#endif  /* CONFIG_AUTH_CLIENT */



/* Routines to handle buffer io */

/**
 * @see auth_internal.h
 */
int auth_buffer_init(struct auth_io_buffer *iobuf)
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
int auth_buffer_put(struct auth_io_buffer *iobuf, const uint8_t *in_buf,  int num_bytes)
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

/**
 * @see auth_internal.h
 */
int auth_buffer_get_wait(struct auth_io_buffer *iobuf, uint8_t *out_buf,  int num_bytes, int waitmsec)
{
    /* return any bytes that might be sitting in the buffer */
    int bytecount = auth_svc_buffer_get(iobuf, out_buf, num_bytes);

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
        bytecount = auth_svc_buffer_get(iobuf, out_buf, num_bytes);

    } while(bytecount == 0);

    return bytecount;
}

#if 0
#define PACKET_SYNC_BYTES       0x8EFA
typedef struct
{
    uint16_t sync_bytes;
    uint16_t len;
} packet_hdr_t;

int auth_svc_buffer_get_wait(struct auth_io_buffer *iobuf, uint8_t *out_buf,  int num_bytes, int waitmsec)
{
    packet_hdr_t pkt_hdr;

    int bytescnt = auth_svc_buffer_peek(iobuf, &pkt_hdr, sizeof(pkt_hdr));

    if(bytescnt == 0)

}
#endif


/**
 * @see auth_internal.h
 */
int auth_buffer_get(struct auth_io_buffer *iobuf, uint8_t *out_buf,  int num_bytes)
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

/**
 * @see auth_internal.h
 */
int auth_buffer_bytecount(struct auth_io_buffer *iobuf)
{
    int err = k_mutex_lock(&iobuf->buf_mutex, K_FOREVER);

    if(!err) {
        err = (int)iobuf->num_valid_bytes;
    }

    /* unlock */
    k_mutex_unlock(&iobuf->buf_mutex);

    return err;
}

/**
 * @see auth_internal.h
 */
int auth_buffer_bytecount_wait(struct auth_io_buffer *iobuf, uint32_t waitmsec)
{
    int bytecount = auth_svc_buffer_bytecount(iobuf);

    if(bytecount == 0) {
        /* wait until bytes present */
        int err = k_sem_take(&iobuf->buf_sem, K_MSEC(waitmsec));

        if(err) {
            return err;  /* timed out -EAGAIN or error */
        }
    }

    return auth_svc_buffer_bytecount(iobuf);
}

/**
 * @see auth_internal.h
 */
int auth_buffer_avail_bytes(struct auth_io_buffer *iobuf)
{
    return (AUTH_SVC_IOBUF_LEN -  auth_svc_buffer_bytecount(iobuf));
}

/**
 * @see auth_internal.h
 */
bool auth_buffer_isfull(struct auth_io_buffer *iobuf)
{
    return (auth_svc_buffer_bytecount(iobuf) == AUTH_SVC_IOBUF_LEN) ? true : false;
}

/**
 * @see auth_internal.h
 */
int auth_buffer_clear(struct auth_io_buffer *iobuf) {

    int err = k_mutex_lock(&iobuf->buf_mutex, K_FOREVER);

    if(!err) {
        iobuf->num_valid_bytes = 0;
        iobuf->head_index = 0;
        iobuf->tail_index = 0;
    }

    return err;
}



