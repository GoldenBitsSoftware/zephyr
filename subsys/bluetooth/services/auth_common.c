/**
 *  @file  BLE Authentication Service.
 *
 *  @brief  Common routines used for the authentication service.
 *
 */

#include <zephyr/types.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <zephyr.h>
#include <init.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/conn.h>
#include <bluetooth/uuid.h>
#include <bluetooth/gatt.h>
#include <bluetooth/auth_svc.h>

#define LOG_LEVEL CONFIG_BT_GATT_AUTHS_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(auths);


#define HANDSHAKE_THRD_STACK_SIZE       1024
#define HANDSHAKE_THRD_PRIORITY         5


/**
 * Have to come up with a way to re-use stack.  Maybe statically alloc two stacks
 * and use them among muliptle connections?  Maybe track how many active handshake
 * threads have been started and if hit max then return wait?
 */
K_THREAD_STACK_DEFINE(auth_thread_stack_area_1, HANDSHAKE_THRD_STACK_SIZE);

// forward declaration
void auth_dtls_thead(void *arg1, void *arg2, void *arg3);
static void challenge_response_auth_thead(void *arg1, void *arg2, void *arg3);


/* ========================== local functions ========================= */


/* ======= internal function, not for external use API can change ===== */

/**
 *
 * @param auth_con
 * @param status
 */
void auth_internal_status_callback(struct authenticate_conn *auth_con , auth_status_t status)
{
    if(auth_con->status_cb_func)
    {
        auth_con->status_cb_func(status, auth_con->callback_context);
    }
}

/*
 * Add ability to not use authentication attributes if using L2CAP.
 * Change configuration menu to this:
 *     BLE Module
 *        - Authentication
 *            - Use Authentication GATT Service
 *            - Use L2CAP
 *     GATT Services
 *        - Use Authentiction GATT service (should be selected if selected under Authentiction)
 */

/* ========================= external API ============================ */


auth_error_t auth_svc_init(struct authenticate_conn *auth_con, struct auth_connection_params *con_params,
                            k_auth_status_cb_t status_func, void *context, uint32_t auth_flags)
{
    /* init the struct to zero */
    memset(auth_con, 0, sizeof(struct authenticate_conn));

    // init mutex
    k_sem_init(&auth_con->auth_sem, 1, 1);

    // setup the status callback
    auth_con->status_cb_func = status_func;
    auth_con->callback_context = context;

    auth_con->is_central = (auth_flags & AUTH_CONN_CENTRAL) ? true : false;

    if(auth_flags & AUTH_CONN_USE_L2CAP)
    {
        auth_con->use_gatt_attribute = false;
    }
    else
    {
        auth_con->use_gatt_attribute = true;
    }


    k_thread_entry_t auth_thread_func = NULL;

#ifdef CONFIG_DTLS_AUTH_METHOD
    auth_thread_func = auth_dtls_thead;

    // init TLS layer
    auth_init_dtls_method(auth_con)
#endif

#ifdef CONFIG_CHALLENGE_RESP_AUTH_METHOD
    return AUTH_ERROR_INVALID_PARAM;  // not implmeneted
#endif


    return 0
}



// optional callback w/status
auth_error_t auth_svc_start(struct authenticate_conn *auth_con, )
{

    // TODO:  Get thread stack from stack pool?

    // Take the semaphore, give it back when auth completed
    k_sem_take(&auth_con->auth_sem, K_NO_WAIT);

    auth_con->auth_tid = k_thread_create(&auth_con->auth_thrd_data, auth_thread_stack_area_1,
                                              K_THREAD_STACK_SIZEOF(auth_thread_stack_area_1),
                                              auth_thread_func, auth_con, NULL, NULL, HANDSHAKE_THRD_PRIORITY,
                                              K_NO_WAIT);

    // status callback
    auth_status_callback(auth_con, AUTH_STARTED);


    return AUTH_SUCCESS;
}

/**
 * Returns success if handshake complete
 *
 * @param auth_con
 * @param timeoutMsec
 * @return
 */
auth_error_t auth_svc_wait(struct authenticate_conn *auth_con, uint32_t timeoutMsec, auth_status_t *status)
{
    int ret;

    /* check input params */
    if(auth_con == NULL || status == NULL)
    {
        return AUTH_ERROR_INVALID_PARAM;
    }

    ret = k_sem_take(&auth_con->auth_sem, timeoutMsec);

    /* Auth process has completed, return success */
    if(ret == 0)
    {
        k_sem_give(&auth_con->auth_sem);
        *status = auth_con->curr_status;
        return AUTH_SUCCESS;
    }

    *status = auth_con->curr_status;

    // return timeout error
    return AUTH_ERROR_TIMEOUT;
}



/**
 * If performing a simple challenge response
 * @param arg1
 * @param arg2
 * @param arg3
 */
static void challenge_response_auth_thead(void *arg1, void *arg2, void *arg3)
{
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)arg1;

    // if client start handshake

    // if server wait for connection response
}
