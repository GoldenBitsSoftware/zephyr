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

#define TLS_FRAME_SIZE          256u

#define TLS_FRAME_SYNC_BITS     0xA590
#define TLS_FRAME_SYNC_MASK     0xFFF0
#define TLS_FRAME_BEGIN         0x01
#define TLS_FRAME_NEXT          0x02
#define TLS_FRAME_END           0x04

#pragma pack(push, 1)
struct auth_tls_frame {
    /* bits 15-4  are for frame sync, bits 3-0 are flags */
    uint16_t frame_hdr;  /// bytes to insure we're at a frame
    uint8_t frame_payload[TLS_FRAME_SIZE];  /* TODO: Create #define for this */
};
#pragma pack(pop)



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
    mbedtls_ssl_cookie_ctx cookie_ctx;
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
    mbedtls_ssl_cookie_init(&mbed_ctx->cookie_ctx);

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


/**
 * Mbed routine to send data, called by Mbed TLS library.
 *
 * @param ctx   Context pointer, pointer to struct authenticate_conn
 * @param buf   Buffer to send.
 * @param len   Number of bytes to send.
 *
 * @return  Number of bytes sent, else Mbed tls error.
 */
static int auth_mbedtls_tx(void *ctx, const uint8_t *buf, size_t len)
{
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)ctx;
    int frame_bytes;
    int payload_bytes;
    int send_count = 0;
    int tx_ret;
    struct auth_tls_frame frame;
    const uint16_t max_frame = MIN(sizeof(frame), auth_conn->payload_size);
    const uint16_t max_payload = max_frame - sizeof(frame.frame_hdr);

    /* set frame header */
    frame.frame_hdr = TLS_FRAME_SYNC_BITS|TLS_FRAME_BEGIN;

    while (len > 0) {

        /* get payload bytes */
        payload_bytes = MIN(max_payload, len);

        frame_bytes = payload_bytes + sizeof(frame.frame_hdr);

        /* is this the last frame? */
        if((len - payload_bytes) == 0) {
            frame.frame_hdr = TLS_FRAME_SYNC_BITS|TLS_FRAME_END;
        }

        /* copy body */
        memcpy(frame.frame_payload, buf, payload_bytes);

#if defined(CONFIG_BT_GATT_CLIENT)
        /* send frame */
        tx_ret = auth_central_tx(auth_conn, (const uint8_t*)&frame, frame_bytes);
#else
        /* send frame */
        tx_ret = auth_periph_tx(auth_conn, (const uint8_t*)&frame, frame_bytes);
#endif
        

        if(tx_ret < 0) {
            LOG_ERR("Failed to send TLS frame, error: %d", tx_ret);
            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }

        /* verify all bytes were sent */
        if(tx_ret != frame_bytes) {
            LOG_ERR("Failed to to send all bytes, send: %d, requested: %d", tx_ret, frame_bytes);
            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }

        /* set next flags */
        frame.frame_hdr = TLS_FRAME_SYNC_BITS|TLS_FRAME_NEXT;

        len -= payload_bytes;
        buf += payload_bytes;
        send_count += payload_bytes;
    }

    LOG_INF("Bytes sent: %d", send_count);

    return send_count;
}


/**
 *  MBed TLS receive function, called by the MBed library to receive data.
 *
 * @param ctx      Context pointer, pointer to struct authenticate_conn
 * @param buffer   Buffer to copy received bytes.
 * @param len      Byte sizeof buffer.
 *
 * @return         Number of bytes copied into the buffer or MBED error.
 */
static int auth_mbedtls_rx(void *ctx, uint8_t *buffer, size_t len)
{
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)ctx;
    bool last_frame = false;
    bool first_frame = true;
    int rx_bytes;
    int receive_cnt = 0;
    struct auth_tls_frame frame;

    while(!last_frame && len != 0U) {

        rx_bytes = MIN(sizeof(frame.frame_payload), len) + sizeof(frame.frame_hdr);

#if defined(CONFIG_BT_GATT_CLIENT)
        rx_bytes = auth_central_rx(auth_conn, (uint8_t*)&frame, rx_bytes);
#else
        rx_bytes = auth_periph_rx(auth_conn, (uint8_t*)&frame, rx_bytes);
#endif

        /* check for error */
        if(rx_bytes < 0) {
            LOG_ERR("Failed to receive TLS frame, error: %d", rx_bytes);

            if(rx_bytes == -EAGAIN) {
                return MBEDTLS_ERR_SSL_TIMEOUT;
            }

            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }

        /* check for start flag */
        if(first_frame) {
            first_frame = false;
            if(!(frame.frame_hdr & TLS_FRAME_BEGIN)) {
                LOG_ERR("Missing beginning frame");
                return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
            }
        }

        /* check frame sync bytes */
        if((frame.frame_hdr & TLS_FRAME_SYNC_MASK) != TLS_FRAME_SYNC_BITS) {
            LOG_ERR("Invalid frame.");
            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }

        /* Subtract out frame header */
        rx_bytes -= sizeof(frame.frame_hdr);

        /* sanity check, if zero or negative */
        if(rx_bytes <= 0) {
            LOG_ERR("Empty frame!!");
            return receive_cnt;
        }

        /* copy payload bytes */
        memcpy(buffer, frame.frame_payload, rx_bytes);
        

        len -= rx_bytes;
        receive_cnt += rx_bytes;
        buffer += rx_bytes;

        /* Is this the last frame? */
        if(frame.frame_hdr & TLS_FRAME_END) {
            last_frame = true;
        }
    }

    if(len == 0U && !last_frame) {
        LOG_ERR("Receive buffer from Mbed not large enough.");
        return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
    }

    LOG_DBG("Received %d bytes.", receive_cnt);

    return receive_cnt;
}

/**
 * Set the DTLS cookie.
 *
 * @param auth_conn   Pointer to auth connectoin
 *
 * @return 0 on success, else error code.
 */
static int auth_tls_set_cookie(struct authenticate_conn *auth_conn)
{
    struct bt_conn_info conn_info;
    uint8_t *cookie_info;
    size_t cookie_len;


    int ret = bt_conn_get_info(auth_conn->conn, &conn_info);

    if(ret) {
        return ret;
    }

    struct mbed_tls_context *mbed_ctx = (struct mbed_tls_context *)auth_conn->internal_obj;

    // should not be NULL!!
    if(!mbed_ctx) {
        LOG_ERR("No MBED context.");
        return AUTH_ERROR_INVALID_PARAM;
    }

    if(BT_CONN_TYPE_LE & conn_info.type) {
        cookie_info = (uint8_t*)conn_info.le.local->a.val;
        cookie_len = sizeof(conn_info.le.local->a.val);
    } else {
        cookie_info = (uint8_t*)conn_info.br.dst->val;
        cookie_len = sizeof(conn_info.br.dst->val);
    }

    ret = mbedtls_ssl_set_client_transport_id(&mbed_ctx->ssl, cookie_info, cookie_len);

    return ret;
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

    if (mbed_ctx == NULL) {
        LOG_ERR("Unable to allocate Mbed TLS context.");
        return AUTH_ERROR_NO_RESOURCE;
    }

    if (auth_conn->cert_cont == NULL) {
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

    mbedtls_ssl_config_defaults(&mbed_ctx->conf,
                                endpoint,
                                MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                MBEDTLS_SSL_PRESET_DEFAULT);


    /* set the lower layer transport functions */
    mbedtls_ssl_set_bio(&mbed_ctx->ssl, auth_conn, auth_mbedtls_tx, auth_mbedtls_rx, NULL);

    /* set max record len */
    mbedtls_ssl_conf_max_frag_len(&mbed_ctx->conf, MBEDTLS_SSL_MAX_FRAG_LEN_512);

    /* Set the DTLS time out */
    /* TODO: Make these KConfig vars */
    mbedtls_ssl_conf_handshake_timeout(&mbed_ctx->conf, 2000u, 15000u);

    /* OPTIONAL is usually a bad choice for security, but makes interop easier
     * in this simplified example, in which the ca chain is hardcoded.
     * Production code should set a proper ca chain and use REQUIRED. */
    mbedtls_ssl_conf_authmode(&mbed_ctx->conf, MBEDTLS_SSL_VERIFY_REQUIRED);

    ret = mbedtls_pk_parse_key(&mbed_ctx->device_private_key, auth_conn->cert_cont->device_cert->private_key,
                               auth_conn->cert_cont->device_cert->key_len, NULL, 0);

    if (ret) {
        auth_free_mbedcontext(mbed_ctx);
        LOG_ERR("Failed to parse device private key, error: 0x%x", ret);
        return AUTH_ERROR_DTLS_INIT_FAILED;
    }

    /**
     * @brief Setup device certs, the CA chain followed by the end device cert.
     */
    if (auth_conn->cert_cont->num_ca_certs == 0u) {
        /* log a warning, this maybe intentional */
        LOG_WRN("No CA certs.");
    }

    for (uint8_t cnt = 0; cnt < auth_conn->cert_cont->num_ca_certs; cnt++) {
        /* Check if this is a device cert */
        if (auth_conn->cert_cont->ca_certs[cnt].cert_type == AUTH_CERT_END_DEVICE) {
            LOG_WRN("End-Device cert being used as CA cert.");
        }

        /* Parse and set the CA certs */
        ret = mbedtls_x509_crt_parse(&mbed_ctx->cacert, auth_conn->cert_cont->ca_certs[cnt].cert_data,
                                     auth_conn->cert_cont->ca_certs[cnt].cert_len);

        if (ret) {
            auth_free_mbedcontext(mbed_ctx);
            LOG_ERR("Failed to parse CA cert, error: 0x%x", ret);
            return AUTH_ERROR_DTLS_INIT_FAILED;
        }
    }

    /* set CA certs into context */
    mbedtls_ssl_conf_ca_chain(&mbed_ctx->conf, &mbed_ctx->cacert, NULL);

    /* Parse the device cert */
    ret = mbedtls_x509_crt_parse(&mbed_ctx->device_cert,
                                 (const unsigned char *) auth_conn->cert_cont->device_cert->cert_data,
                                 auth_conn->cert_cont->device_cert->cert_len);

    if (ret) {
        auth_free_mbedcontext(mbed_ctx);
        LOG_ERR("Failed to parse device cert, error: 0x%x", ret);
        return AUTH_ERROR_DTLS_INIT_FAILED;
    }

    /* Parse and set the device cert */
    ret = mbedtls_ssl_conf_own_cert(&mbed_ctx->conf, &mbed_ctx->device_cert, &mbed_ctx->device_private_key);

    if (ret) {
        auth_free_mbedcontext(mbed_ctx);
        LOG_ERR("Failed to set device cert and key, error: 0x%x", ret);
        return AUTH_ERROR_DTLS_INIT_FAILED;
    }


    /* setup call to Zephyr random API */
    mbedtls_ssl_conf_rng(&mbed_ctx->conf, auth_tls_drbg_random, &mbed_ctx->ctr_drbg);
    mbedtls_ssl_conf_dbg(&mbed_ctx->conf, auth_mbed_debug, auth_conn);

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(3); // Should be KConfig option
#endif

    if (!auth_conn->is_central) {

        ret = mbedtls_ssl_cookie_setup(&mbed_ctx->cookie_ctx, mbedtls_ctr_drbg_random, &mbed_ctx->ctr_drbg);

        if(ret) {
            auth_free_mbedcontext(mbed_ctx);
            LOG_ERR("Failed to setup dtls cookies, error: 0x%x", ret);
            return AUTH_ERROR_DTLS_INIT_FAILED;
        }

        mbedtls_ssl_conf_dtls_cookies(&mbed_ctx->conf, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check,
                                      &mbed_ctx->cookie_ctx);

    }


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
void auth_dtls_thead(void *arg1, void *arg2, void *arg3) {

    struct authenticate_conn *auth_conn = (struct authenticate_conn *) arg1;
    struct mbed_tls_context *mbed_ctx = (struct mbed_tls_context *) auth_conn->internal_obj;


    /**
     * For the peripheral (server) we can start the handshake, the code will continue to
     * read looking for a "Client Hello".  So we'll just stay at the  MBEDTLS_SSL_CLIENT_HELLO
     * state until the central sends the "Client Hello"
     *
     * For the central (client), a client hello will be sent immediately.
     */

    if (!auth_conn->is_central) {

        /**
         * For the peripheral (acting as a the DTLS server), use the connection handle
         * as the
         */
        int ret = auth_tls_set_cookie(auth_conn);

        if(ret) {
            LOG_ERR("Failed to get connection info for DTLS cookie, auth failed, error: 0x%x", ret);
            auth_svc_set_status(auth_conn, AUTH_STATUS_AUTHENTICATION_FAILED);
            return;
        }

        int bytecount = auth_svc_buffer_bytecount_wait(&auth_conn->rx_buf, 15000u);

        if(bytecount <= 0) {
            LOG_ERR("Peripheral did not receive initial Client Hello, auth failed, error: %d", bytecount);
            auth_svc_set_status(auth_conn, AUTH_STATUS_AUTHENTICATION_FAILED);
            return;
        }

        LOG_DBG("Peripheral received initial Client Hello from central.");
    }

    /*  Check if th payload size has been set*/
    if(auth_conn->payload_size == 0U) {
        auth_conn->payload_size = bt_gatt_get_mtu(auth_conn->conn) - BLE_LINK_HEADER_BYTES;
    }

    /* Set the max MTU for DTLS */
    mbedtls_ssl_set_mtu(&mbed_ctx->ssl, auth_conn->payload_size);


    int ret = 0;
    // start
    do {

        // do handshake step
        ret = mbedtls_ssl_handshake( &mbed_ctx->ssl );

        // check return and post status
        //auth_internal_status_callback(struct authenticate_conn *auth_con , auth_status_t status)

        if(ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {

            /* restart handshake to process client cookie */
            LOG_DBG("Restarting handshake, need client cookie.");

            mbedtls_ssl_session_reset(&mbed_ctx->ssl);

            /* reset cookie info */
            ret = auth_tls_set_cookie(auth_conn);

            if(ret) {
                LOG_ERR("Failed to reset cookie information, error: 0x%x", ret);
                ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
            } else {
                ret = MBEDTLS_ERR_SSL_WANT_READ;
            }
        }

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

    //            auth_svc_set_status(auth_conn, AUTH_STATUS_AUTHENTICATION_FAILED);

    return;
}

