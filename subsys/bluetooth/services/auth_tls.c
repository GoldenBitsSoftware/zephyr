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
#include <bluetooth/l2cap.h>
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

    //mbedtls_entropy_context entropy;  TODO: Investigate if needed
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt device_cert;
    mbedtls_pk_context device_private_key;
    mbedtls_timing_delay_context timer;
};

static struct mbed_tls_context tlscontext[MAX_MBEDTLS_CONTEXT];


void auth_svc_internal_status_callback(struct authenticate_conn *auth_con , auth_status_t status);


/* ===================== local functions =========================== */

#if defined(CONFIG_BT_GATT_CLIENT)

static int auth_central_tx_tls(void *ctx, const unsigned char *buf, size_t len)
{
    return auth_central_tx((struct authenticate_conn*)ctx, buf, len);
}

static int auth_central_rx_tls(void *ctx, unsigned char *buf, size_t len)
{
    return auth_central_rx((struct authenticate_conn*)ctx, buf, len);
}

#else

static int auth_periph_tx_tls(void *ctx, const unsigned char *buf, size_t len)
{
    return auth_periph_tx((struct authenticate_conn*)ctx, buf, len);
}

static int auth_periph_rx_tls(void *ctx, unsigned char *buf, size_t len)
{
    return auth_periph_rx((struct authenticate_conn*)ctx, buf, len);
}

#endif /* CONFIG_BT_GATT_CLIENT */

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

    /* Free any MBed tls resources */
    mbedtls_x509_crt_free(&mbed_ctx->cacert);
    mbedtls_x509_crt_free(&mbed_ctx->device_cert);
    mbedtls_pk_free(&mbed_ctx->device_private_key);
    mbedtls_ssl_free(&mbed_ctx->ssl);
    mbedtls_ssl_config_free(&mbed_ctx->conf);
    mbedtls_ctr_drbg_free(&mbed_ctx->ctr_drbg);
    //mbedtls_entropy_free(&mbed_ctx->entropy);  TODO: Investigate if needed
}


static void auth_init_context(struct mbed_tls_context *mbed_ctx)
{
    mbedtls_ssl_init(&mbed_ctx->ssl);
    mbedtls_ssl_config_init(&mbed_ctx->conf);
    mbedtls_x509_crt_init(&mbed_ctx->cacert);
    mbedtls_x509_crt_init(&mbed_ctx->device_cert);
    mbedtls_pk_init(&mbed_ctx->device_private_key);

    //mbedtls_entropy_init(&mbed_ctx->entropy);  TODO: Investigate if needed.
    mbedtls_ctr_drbg_init(&mbed_ctx->ctr_drbg);
}


/**
 * Timer functions
 */
static unsigned long auth_tls_timing_get_timer( struct mbedtls_timing_hr_time *val, int reset )
{
    unsigned long delta;
    unsigned long *mssec = (unsigned long*) val;
    unsigned long cur_msg = k_uptime_get_32();

    if( reset )
    {
        *mssec = cur_msg;
        return ( 0 );
    }

    delta = cur_msg - *mssec;

    return ( delta );
}

/*
 * Set delays to watch
 */
static void auth_tls_timing_set_delay( void *data, uint32_t int_ms, uint32_t fin_ms )
{
    mbedtls_timing_delay_context *ctx = (mbedtls_timing_delay_context *) data;

    ctx->int_ms = int_ms;
    ctx->fin_ms = fin_ms;

    if( fin_ms != 0 )
        (void) auth_tls_timing_get_timer( &ctx->timer, 1 );
}

/*
 * Get number of delays expired
 */
static int auth_tls_timing_get_delay( void *data )
{
    mbedtls_timing_delay_context *ctx = (mbedtls_timing_delay_context *) data;
    unsigned long elapsed_ms;

    if( ctx->fin_ms == 0 )
        return( -1 );

    elapsed_ms = auth_tls_timing_get_timer( &ctx->timer, 0 );

    if( elapsed_ms >= ctx->fin_ms )
        return( 2 );

    if( elapsed_ms >= ctx->int_ms )
        return( 1 );

    return( 0 );
}

static int auth_tls_drbg_random(void *ctx, unsigned char *rand_buf, size_t number)
{
    // TODO: Use sys_csrand_get() instead?
    sys_rand_get(rand_buf, number);

    return 0;
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

    /**
     * @brief   Need to define const string here vs. const char *fmt = "[%s:%d] %s"
     *          because the LOG_ERR(), LOG_* macros can't handle pointer.
     */
#define LOG_FMT  "[%s:%d] %s"

    (void)ctx;

    if (!file || !str) {
        return;
    }

    /* Extract basename from file */
    for (p = basename = file; *p != '\0'; p++) {
        if (*p == '/' || *p == '\\') {
            basename = p + 1;
        }
    }


    switch(level)
    {
        case 0:
        {
            LOG_ERR(LOG_FMT, log_strdup(basename), line, log_strdup(str));
            break;
        }

        case 1:
        {
            LOG_WRN(LOG_FMT, log_strdup(basename), line, log_strdup(str));
            break;
         }

        case 2:
         {
            LOG_INF(LOG_FMT,  log_strdup(basename), line, log_strdup(str));
            break;
          }

        case 3:
        default:
         {
            LOG_DBG(LOG_FMT, log_strdup(basename), line, log_strdup(str));
            break;
         }
    }
    
}


/* ================= external/internal funcs ==================== */
/**
 * @see auth_internal.h
 *
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

    if(auth_conn->cert_cont == NULL) {
        LOG_ERR("Device certs not set.");
        return AUTH_ERROR_INVALID_PARAM;
    }

    /* Init mbed context */
    auth_init_context(mbed_ctx);

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
#if defined(CONFIG_BT_GATT_CLIENT)

    if(!auth_conn->is_central)
    {
        /* Invalid config */
        return AUTH_ERROR_INVALID_PARAM;
    }

    send_func         = auth_central_tx_tls;
    recv_func         = auth_central_rx_tls;
    recv_timeout_func = NULL;

#else

    /* peripheral */
    if(auth_conn->is_central)
    {
        // Invalid config
        return AUTH_ERROR_INVALID_PARAM;
    }

    send_func         = auth_periph_tx_tls;
    recv_func         = auth_periph_rx_tls;
    recv_timeout_func = NULL;

#endif  /* CONFIG_BT_GATT_CLIENT */

    // set the lower layer transport functions
    mbedtls_ssl_set_bio( &mbed_ctx->ssl, auth_conn, send_func, recv_func, recv_timeout_func);

    /* OPTIONAL is usually a bad choice for security, but makes interop easier
     * in this simplified example, in which the ca chain is hardcoded.
     * Production code should set a proper ca chain and use REQUIRED. */
    mbedtls_ssl_conf_authmode( &mbed_ctx->conf, MBEDTLS_SSL_VERIFY_REQUIRED);

    ret = mbedtls_pk_parse_key(&mbed_ctx->device_private_key, auth_conn->cert_cont->device_cert->private_key,
                               auth_conn->cert_cont->device_cert->key_len, NULL, 0);

    if(ret) {
        auth_free_mbedcontext(mbed_ctx);
        LOG_ERR("Failed to parse device private key, error: 0x%x", ret);
        return AUTH_ERROR_DTLS_INIT_FAILED;
    }

    /**
     * @brief Setup device certs, the CA chain followed by the end device cert.
     */
    if(auth_conn->cert_cont->num_ca_certs == 0u) {
        /* log a warning, this maybe intentional */
        LOG_WRN("No CA certs.");
    }

    for(uint8_t cnt = 0; cnt < auth_conn->cert_cont->num_ca_certs; cnt++) {
        /* Check if this is a device cert */
        if(auth_conn->cert_cont->ca_certs[cnt].cert_type == AUTH_CERT_END_DEVICE) {
            LOG_WRN("End-Device cert being used as CA cert.");
        }

        /* Parse and set the CA certs */
        ret = mbedtls_x509_crt_parse(&mbed_ctx->cacert, auth_conn->cert_cont->ca_certs[cnt].cert_data,
                                     auth_conn->cert_cont->ca_certs[cnt].cert_len);

        if(ret) {
            auth_free_mbedcontext(mbed_ctx);
            LOG_ERR("Failed to parse CA cert, error: 0x%x", ret);
            return AUTH_ERROR_DTLS_INIT_FAILED;
        }
    }

    /* set CA certs into context */
    mbedtls_ssl_conf_ca_chain(&mbed_ctx->conf, &mbed_ctx->cacert, NULL);

    /* Parse and set the device cert */
    ret = mbedtls_ssl_conf_own_cert(&mbed_ctx->conf, &mbed_ctx->device_cert, &mbed_ctx->device_private_key);

    if(ret) {
        auth_free_mbedcontext(mbed_ctx);
        LOG_ERR("Failed to set device cert and key, error: 0x%x", ret);
        return AUTH_ERROR_DTLS_INIT_FAILED;
    }


    /* setup call to Zephyr random API */
    mbedtls_ssl_conf_rng( &mbed_ctx->conf, auth_tls_drbg_random, &mbed_ctx->ctr_drbg );
    mbedtls_ssl_conf_dbg( &mbed_ctx->conf, auth_mbed_debug, auth_conn);

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(3); // Should be KConfig option
#endif

    ret = mbedtls_ssl_setup(&mbed_ctx->ssl, &mbed_ctx->conf);

    if(ret) {
        auth_free_mbedcontext(mbed_ctx);
        LOG_ERR( "mbedtls_ssl_setup returned %d", ret );
        return AUTH_ERROR_DTLS_INIT_FAILED;
    }

    /* Setup timers */
    mbedtls_ssl_set_timer_cb(&mbed_ctx->ssl, &mbed_ctx->timer, auth_tls_timing_set_delay,
                             auth_tls_timing_get_delay );


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

// DAG DEBUG BEG
    LOG_ERR("** ret is: 0x%x", ret);
// DAG DEBUG END

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

}

