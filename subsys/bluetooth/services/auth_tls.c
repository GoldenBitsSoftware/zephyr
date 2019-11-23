/**
 *  @file  BLE Authentication using DTLS
 *
 *  @brief  DTLS authentication code using Mbed DTLS
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

#if defined(CONFIG_MBEDTLS)
#if !defined(CONFIG_MBEDTLS_CFG_FILE)
#include "mbedtls/config.h"
#else
#include CONFIG_MBEDTLS_CFG_FILE
#endif /* CONFIG_MBEDTLS_CFG_FILE */

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cookie.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>
#endif /* CONFIG_MBEDTLS */

#define LOG_LEVEL CONFIG_BT_GATT_AUTHS_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(auths);

#define MAX_MBEDTLS_CONTEXT     5

/**
 * Keep list of internal structs which
 */

struct mbed_tls_context {
    bool in_use;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    mbedtls_timing_delay_context timer;
};

static struct mbed_tls_context[MAX_MBEDTLS_CONTEXT];


void auth_internal_status_callback(struct authenticate_conn *auth_con , auth_status_t status);


/* ===================== local functions =========================== */



static int auth_send_over_ble(void *ctx, const unsigned char *buf, size_t len)
{
    int ret = 0;
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)ctx;

    if(auth_conn->is_central)
    {
        ret = auth_ble_central_write(auth_conn);
        return ret;
    }

    // peripheral, write but need to set
    ret = auth_ble_peripheral_write(auth_conn)

    return ret ;
}


static int auth_recv_over_ble(void *ctx,
                              unsigned char *buf,
                              size_t len )
{
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)ctx;


    return -1;
}


static int auth_recv_over_ble_timeout(void *ctx,
                                      unsigned char *buf,
                                      size_t len,
                                      uint32_t timeout )
{
    retun -1;
}


/* ==================== L2CAP I/O funcs ====================== */

/**
 * Question:  If we're using L2CAP, can we drop the use of authentication attributes?
 */
static int auth_send_l2cap_ble(void *ctx, const unsigned char *buf, size_t len)
{
    int ret = 0;
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)ctx;

    return ret -1;
}


static int auth_recv_l2cap_ble(void *ctx,
                              unsigned char *buf,
                              size_t len )
{
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)ctx;


    return -1;
}


static int auth_recv_over_l2cap_timeout(void *ctx,
                                      unsigned char *buf,
                                      size_t len,
                                      uint32_t timeout )
{
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)ctx;

    retun -1;
}

#if 0

// return NULL if unable to get context
static struct mbed_tls_context *auth_get_mbedcontext(void)
{
    // use mutex lock to protect accessing list
    mbed_ctx->in_use = true;

    return mbed_tls_context[0]
}

static void auth_free_mbedcontext(struct mbed_tls_context *mbed_ctx)
{
    mbed_ctx->in_use = false;
}

#endif




/* ================= external/internal funcs ==================== */
/**
  * do all of the mbed init stuff here
 * @param auth_conn
 * @return
 */
auth_error_t auth_init_dtls_method(struct authenticate_conn *auth_conn)
{
#if 0
    struct mbed_tls_context *mbed_ctx;

    // set conext pointer
    mbed_ctx = auth_get_mbedcontext();

    if(mbed_ctx == NULL)
    {
        Log error
        return resouce out error
    }

    auth_conn->internal_obj = mbed_ctx;

    int endpoint = auth_conn->is_central ? MBEDTLS_SSL_IS_CLIENT : MBEDTLS_SSL_IS_SERVER;

    mbedtls_ssl_config_defaults( &mbed_ctx->conf,
                               endpoint,
                               MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                               MBEDTLS_SSL_PRESET_DEFAULT);


    if(auth_conn->use_gatt_attributes)
    {
        mbedtls_ssl_set_bio( &mbed_ctx->ssl, auth_conn,
                            auth_send_over_ble, auth_recv_over_ble, NULL );
    }
    else
    {
        /* Use L2CAP layer */
        mbedtls_ssl_set_bio( &mbed_ctx->ssl, auth_conn,
                    auth_send_over_l2cap, auth_recv_over_l2cap, NULL );

    }

    /* OPTIONAL is usually a bad choice for security, but makes interop easier
     * in this simplified example, in which the ca chain is hardcoded.
     * Production code should set a proper ca chain and use REQUIRED. */
    //mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
    mbedtls_ssl_conf_authmode( &mbed_ctx->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain( &mbed_ctx->conf, &cacert, NULL );
    mbedtls_ssl_conf_rng( &mbed_ctx->conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_conf_dbg( &mbed_ctx->conf, my_debug, stdout );

    if( ( ret = mbedtls_ssl_setup( &mbed_ctx->ssl, &mbed_ctx->conf ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
        goto exit;
    }

    // TODO: Need to setup timers w/Zepher

    // TODO:  Use Nordic TRNG for entropy

      mbedtls_debug_set_threshold(3);

#endif

    return AUTH_SUCCESS;
}


/**
 * If performing a DLTS handshake
 * @param arg1
 * @param arg2
 * @param arg3
 */
void auth_dtls_thead(void *arg1, void *arg2, void *arg3)
{
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)arg1;

    struct mbed_tls_context *mbed_ctx = (struct mbed_tls_context *)auth_conn->internal_obj


        /**
         * For the peripheral (server) we can start the handshake, the code will continue to
         * read looking for a "Client Hello".  So we'll just stay at the  MBEDTLS_SSL_CLIENT_HELLO
         * state until the central sends the "Client Hello"
         *
         * For the central (client), a client hello will be sent immediately.
         */

        // start
        do {
            // do handshake step
            ret = mbedtls_ssl_handshake( &mbed_ctx->ssl );

            // check return and post status
            //auth_internal_status_callback(struct authenticate_conn *auth_con , auth_status_t status)

            // Check if we should cancel
            // if(auth_conn->cancel)
            // {
            //    set status to cancel
            //    break;
            // }

        } while( ret == MBEDTLS_ERR_SSL_WANT_READ ||
                 ret == MBEDTLS_ERR_SSL_WANT_WRITE );

        // final status
        //      AUTH_CANCELED,
        //     AUTH_FAILED,
        //     AUTH_SUCCESSFUL
        //auth_internal_status_callback(struct authenticate_conn *auth_con , auth_status_t status)

        // give semaphore, any threads waiting for handshake to complete will be
        // woken up.
        k_sem_give(&auth_conn->auth_sem);

        // terminate thread
        return;
    }



}

