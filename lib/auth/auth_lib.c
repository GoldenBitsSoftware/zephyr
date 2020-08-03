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
LOG_MODULE_REGISTER(auth_lib, CONFIG_AUTH_LOG_LEVEL);

#include <auth/auth_lib.h>
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
int auth_lib_init(struct authenticate_conn *auth_conn, auth_status_cb_t status_func,
                  void *context, uint32_t auth_flags)
{
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



    // setup the status callback
    auth_conn->status_cb = status_func;
    auth_conn->callback_context = context;

    /* init the work item used to post authentication status */
    k_work_init(&auth_conn->auth_status_work, auth_lib_status_work);

    auth_conn->is_client = (auth_flags & AUTH_CONN_CLIENT) ? true : false;

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
int auth_lib_deinit(struct authenticate_conn *auth_conn)
{
    /* TBD: Free any resources */

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
 * @see auth_lib.h
 */
const char *auth_lib_getstatus_str(enum auth_status status)
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
enum auth_status auth_lib_get_status(struct authenticate_conn *auth_conn)
{
    return auth_conn->curr_status;
}

/**
 * @see auth_lib.h
 */
void auth_lib_set_status(struct authenticate_conn *auth_conn, enum auth_status status)
{
    auth_conn->curr_status = status;

    if(auth_conn->status_cb) {

        /* submit work item */
        k_work_submit(&auth_conn->auth_status_work);
    }
}

#if defined(CONFIG_AUTH_DTLS)
/**
 * @see auth_lib.h
 */
void auth_lib_set_tls_certs(struct authenticate_conn *auth_conn, struct auth_cert_container *certs)
{
    auth_conn->cert_cont = certs;
}
#endif

/* ============ Simple ring buffer routines */

void auth_ringbuf_init(struct auth_ringbuf *ringbuf)
{
    k_sem_init(&ringbuf->rx_sem, 0, AUTH_RING_BUFLEN);

    auth_ringbuf_reset(ringbuf);
}

void auth_ringbuf_reset(struct auth_ringbuf *ringbuf)
{
    atomic_set(&ringbuf->head_idx, 0);
    atomic_set(&ringbuf->did_overflow, 0);
    atomic_set(&ringbuf->tail_idx, 0);

    k_sem_reset(&ringbuf->rx_sem);
}


void auth_ringbuf_put_byte(struct auth_ringbuf *ringbuf, uint8_t one_byte)
{
    atomic_val_t old_idx = atomic_inc(&ringbuf->head_idx);
    ringbuf->buf[old_idx] = one_byte;

    /* check if head index beyond fx buffer */
    atomic_cas(&ringbuf->head_idx, AUTH_RING_BUFLEN, 0);

    /* did an overflow occur? */
    if (old_idx == atomic_get(&ringbuf->tail_idx)) {
        atomic_set(&ringbuf->did_overflow, 1);
    }

    /* inc semaphore */
    k_sem_give(&ringbuf->rx_sem);
}

/**
 * Returns true if more bytes avail
 *
 * @param ringbuf
 * @param byte
 * @return
 */
bool auth_ringbuf_get_byte(struct auth_ringbuf *ringbuf, uint8_t *one_byte)
{
    /* inc semaphore */
    k_sem_take(&ringbuf->rx_sem, K_MSEC(2000));

    if (atomic_get(&ringbuf->head_idx) == atomic_get(&ringbuf->tail_idx)) {
        return false;
    }

    *one_byte = ringbuf->buf[atomic_inc(&ringbuf->tail_idx)];

    atomic_cas(&ringbuf->tail_idx, AUTH_RING_BUFLEN, 0);

    return true;
}


bool auth_ringbuf_overflow(struct auth_ringbuf *ringbuf)
{
    return atomic_get(&ringbuf->did_overflow) == 0 ? true : false;
}




