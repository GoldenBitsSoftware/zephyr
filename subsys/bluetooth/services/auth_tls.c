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
#include <bluetooth/services/auth_svc.h>

#if defined(CONFIG_MBEDTLS)
#if !defined(CONFIG_MBEDTLS_CFG_FILE)
#include "mbedtls/config.h"
#else
#include CONFIG_MBEDTLS_CFG_FILE
#endif
#endif /* CONFIG_MBEDTLS_CFG_FILE */

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cookie.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/timing.h>

#define LOG_LEVEL CONFIG_BT_GATT_AUTHS_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_DECLARE(auth_svc, CONFIG_BT_GATT_AUTHS_LOG_LEVEL);

#include "auth_internal.h"

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

static struct mbed_tls_context tlscontext[MAX_MBEDTLS_CONTEXT];


void auth_svc_internal_status_callback(struct authenticate_conn *auth_con , auth_status_t status);


/* ===================== local functions =========================== */



// return NULL if unable to get context
static struct mbed_tls_context *auth_get_mbedcontext(void)
{
    // use mutex lock to protect accessing list
    for(int cnt = 0; cnt < MAX_MBEDTLS_CONTEXT; cnt++) {

        if(!tlscontext[cnt].in_use) {
            tlscontext[cnt].in_use = true;
            return &tlscontext[cnt];
        }
    }

    return NULL;
}

static void auth_free_mbedcontext(struct mbed_tls_context *mbed_ctx)
{
    mbed_ctx->in_use = false;
}

/**
 * Mbed debug levels:   0 No debug
                        1 Error
                        2 State change
                        3 Informational
                        4 Verbose

 * @param ctx
 * @param level
 * @param file
 * @param line
 * @param str
 */
static void auth_mbed_debug(void *ctx, int level, const char *file,
                            int line, const char *str)
{
    const char *p, *basename;

    ARG_UNUSED(ctx);

    if (!file || !str) {
        return;
    }

    /* Extract basename from file */
    for (p = basename = file; *p != '\0'; p++) {
        if (*p == '/' || *p == '\\') {
            basename = p + 1;
        }
    }
#if 0
    switch(level)
    {
        case 0:
            break;

        case 1:
            LOG_ERROR()
            break;
    }

    NET_DBG("%s:%04d: |%d| %s", basename, line, level,
            log_strdup(str));
#endif
}


/* ================= external/internal funcs ==================== */
/**
  * do all of the mbed init stuff here
 * @param auth_conn
 * @return
 */
int auth_init_dtls_method(struct authenticate_conn *auth_conn)
{
    struct mbed_tls_context *mbed_ctx;
    int ret;

    LOG_DBG("Initializing Mbed");

    // set conext pointer
    mbed_ctx = auth_get_mbedcontext();

    if(mbed_ctx == NULL)
    {
        LOG_ERR("Unable to allocate Mbed TLS context.");
        return AUTH_ERROR_NO_RESOURCE;
    }

    /* Save MBED tls context as internal object. The intent of using a void
     * 'internal_obj' is to provide a var in the struct authentication_conn to
     * store different authentication methods.  Instead of Mbed, it maybe a
     * Challenge-Response.*/
    auth_conn->internal_obj = mbed_ctx;

    int endpoint = auth_conn->is_central ? MBEDTLS_SSL_IS_CLIENT : MBEDTLS_SSL_IS_SERVER;

    mbedtls_ssl_config_defaults( &mbed_ctx->conf,
                               endpoint,
                               MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                               MBEDTLS_SSL_PRESET_DEFAULT);

    // MBed bios function pointers
    mbedtls_ssl_send_t *send_func;
    mbedtls_ssl_recv_t *recv_func;
    mbedtls_ssl_recv_timeout_t *recv_timeout_func;


    /**
     * Setup the correct functions to Tx/Rx over BLE.
     */
    if(auth_conn->is_central)
    {
        if(auth_conn->use_gatt_attributes)
        {
            send_func         =  auth_svc_central_tx;
            recv_func         = auth_svc_central_recv;
            recv_timeout_func = auth_svc_central_recv_timeout;
        }
        else
        {
            /* Use L2CAP layer */
            send_func         = auth_svc_tx_l2cap;
            recv_func         = auth_svc_recv_l2cap;
            recv_timeout_func = auth_svc_recv_over_l2cap_timeout;
        }
    }
    else
    {
        // peripheral
        if(auth_conn->use_gatt_attributes)
        {
            send_func         = auth_svc_peripheral_tx;
            recv_func         = auth_svc_peripheral_recv;
            recv_timeout_func = auth_svc_peripheral_recv_timeout;
        }
        else
        {
            /* Use L2CAP layer */
            send_func         = auth_svc_tx_l2cap;
            recv_func         = auth_svc_recv_l2cap;
            recv_timeout_func = auth_svc_recv_over_l2cap_timeout;
        }
    }

    // set the lower layer transport functions
    mbedtls_ssl_set_bio( &mbed_ctx->ssl, auth_conn, send_func, recv_func, NULL /*recv_timeout_func*/ );

    /* OPTIONAL is usually a bad choice for security, but makes interop easier
     * in this simplified example, in which the ca chain is hardcoded.
     * Production code should set a proper ca chain and use REQUIRED. */
    //mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
    mbedtls_ssl_conf_authmode( &mbed_ctx->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain( &mbed_ctx->conf, &mbed_ctx->cacert, NULL );
    mbedtls_ssl_conf_rng( &mbed_ctx->conf, mbedtls_ctr_drbg_random, &mbed_ctx->ctr_drbg );
    mbedtls_ssl_conf_dbg( &mbed_ctx->conf, auth_mbed_debug,  auth_conn);

    if( ( ret = mbedtls_ssl_setup( &mbed_ctx->ssl, &mbed_ctx->conf ) ) != 0 )
    {
        auth_free_mbedcontext(mbed_ctx);
        LOG_ERR( "mbedtls_ssl_setup returned %d", ret );
        return AUTH_ERROR_DTLS_INIT_FAILED;
    }

    // TODO: Need to setup timers w/Zepher

    // TODO:  Use Nordic TRNG for entropy

      mbedtls_debug_set_threshold(3); // Should be KConfig option


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
    struct mbed_tls_context *mbed_ctx = (struct mbed_tls_context *)auth_conn->internal_obj;


    /**
     * For the peripheral (server) we can start the handshake, the code will continue to
     * read looking for a "Client Hello".  So we'll just stay at the  MBEDTLS_SSL_CLIENT_HELLO
     * state until the central sends the "Client Hello"
     *
     * For the central (client), a client hello will be sent immediately.
     */

    int ret = 0;
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
    k_sem_give(&auth_conn->auth_handshake_sem);

}

