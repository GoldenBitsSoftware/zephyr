/**
 *  @file  BLE Authentication using DTLS
 *
 *  @brief  DTLS authentication code using Mbed DTLS
 *
 */

#include <zephyr/types.h>
#include <sys/byteorder.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <zephyr.h>
#include <init.h>


#include <net/tls_credentials.h>

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

#define LOG_LEVEL CONFIG_AUTH_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_DECLARE(auth_lib, CONFIG_AUTH_LOG_LEVEL);

#include <auth/auth_lib.h>
#include "auth_internal.h"


#define MAX_MBEDTLS_CONTEXT     2


#define USE_DTLS  1  /* TODO: Make this a KConfig var */


#ifdef USE_DTLS
#define DTLS_PACKET_SYNC_BYTES      0x45B8
#define DTLS_HEADER_BYTES           (sizeof(struct dtls_packet_hdr))

/**
 * Header identifying a DTLS packet (aka datagram).  Unlike TLS, DTLS packets
 * must be forwarded to Mbedtls as one or more complete packets.  TLS is
 * design to handle an incoming byte stream.
 */
#pragma pack(push, 1)
struct dtls_packet_hdr {
    uint16_t sync_bytes;    /* use magic number to identify header */
    uint16_t packet_len;    /* size of DTLS datagram */
};
#pragma pack(pop)
#endif


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

#ifdef USE_DTLS
    /* Temp buffer used to assemble full frame when sending. */
    uint8_t temp_dtlsbuf[CONFIG_MBEDTLS_SSL_MAX_CONTENT_LEN];
#endif
};

static struct mbed_tls_context tlscontext[MAX_MBEDTLS_CONTEXT];


/* ===================== local functions =========================== */

/* return NULL if unable to get context */
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
 * Return the handshake state name, helpful for debug purposes.
 *
 * @param state  The state enumeration.
 *
 * @return  Pointer to handshake string name.
 */
static const char *auth_tls_handshake_state(const mbedtls_ssl_states state)
{
    switch(state) {

        case MBEDTLS_SSL_HELLO_REQUEST:
            return "MBEDTLS_SSL_HELLO_REQUEST";
            break;

        case MBEDTLS_SSL_CLIENT_HELLO:
            return "MBEDTLS_SSL_CLIENT_HELLO";
            break;

        case MBEDTLS_SSL_SERVER_HELLO:
            return "MBEDTLS_SSL_SERVER_HELLO";
            break;

        case MBEDTLS_SSL_SERVER_CERTIFICATE:
            return "MBEDTLS_SSL_SERVER_CERTIFICATE";
            break;

        case MBEDTLS_SSL_SERVER_KEY_EXCHANGE:
            return "MBEDTLS_SSL_SERVER_KEY_EXCHANGE";
            break;

        case MBEDTLS_SSL_CERTIFICATE_REQUEST:
            return "MBEDTLS_SSL_CERTIFICATE_REQUEST";
            break;

        case MBEDTLS_SSL_SERVER_HELLO_DONE:
            return "MBEDTLS_SSL_SERVER_HELLO_DONE";
            break;

        case MBEDTLS_SSL_CLIENT_CERTIFICATE:
            return "MBEDTLS_SSL_CLIENT_CERTIFICATE";
            break;

        case MBEDTLS_SSL_CLIENT_KEY_EXCHANGE:
            return "MBEDTLS_SSL_CLIENT_KEY_EXCHANGE";
            break;

        case MBEDTLS_SSL_CERTIFICATE_VERIFY:
            return "MBEDTLS_SSL_CERTIFICATE_VERIFY";
            break;

        case MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC:
            return "MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC";
            break;

        case MBEDTLS_SSL_CLIENT_FINISHED:
            return "MBEDTLS_SSL_CLIENT_FINISHED";
            break;

        case MBEDTLS_SSL_SERVER_CHANGE_CIPHER_SPEC:
            return "MBEDTLS_SSL_SERVER_CHANGE_CIPHER_SPEC";
            break;

        case MBEDTLS_SSL_SERVER_FINISHED:
            return "MBEDTLS_SSL_SERVER_FINISHED";
            break;

        case MBEDTLS_SSL_FLUSH_BUFFERS:
            return "MBEDTLS_SSL_FLUSH_BUFFERS";
            break;

        case MBEDTLS_SSL_HANDSHAKE_WRAPUP:
            return "MBEDTLS_SSL_HANDSHAKE_WRAPUP";
            break;

        case MBEDTLS_SSL_HANDSHAKE_OVER:
            return "MBEDTLS_SSL_HANDSHAKE_OVER";
            break;

        case MBEDTLS_SSL_SERVER_NEW_SESSION_TICKET:
            return "MBEDTLS_SSL_SERVER_NEW_SESSION_TICKET";
            break;

        case MBEDTLS_SSL_SERVER_HELLO_VERIFY_REQUEST_SENT:
            return "MBEDTLS_SSL_SERVER_HELLO_VERIFY_REQUEST_SENT";
            break;

        default:
            break;
    }

    return "unknown";
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
 * Function called by Mbed stack to print debug messages.
 *
 *
 * @param ctx     Context
 * @param level   Debug level
 * @param file    Source filename of debug log entry.
 * @param line    Line number of debug log entry.
 * @param str     Debug/Log message.
 */
static void auth_mbed_debug(void *ctx, int level, const char *file,
                            int line, const char *str)
{
    const char *p, *basename;

    /**
     * @brief   Need to define const string here vs. const char *fmt = "[%s:%d] %s"
     *          because the LOG_ERR(), LOG_* macros can't handle a pointer.
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
    int send_cnt;
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)ctx;

    if(auth_conn == NULL) {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

#ifdef USE_DTLS
    struct dtls_packet_hdr *dtls_hdr;
    struct mbed_tls_context *mbedctx = (struct mbed_tls_context *)auth_conn->internal_obj;

    if(mbedctx == NULL) {
        LOG_ERR("Missing Mbed context.");
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    dtls_hdr = (struct dtls_packet_hdr *)mbedctx->temp_dtlsbuf;

    /**
     * DTLS is targeted for the UDP datagram protocol, as such the Mbed stack
     * expects a full DTLS packet (ie datagram) to be receive vs. a partial
     * packet. When sending, add a header to enable the receiving side
     * to determine when a full DTLS packet has been recevid.
     */

    /* Check the temp buffer is large enough */
    if( (sizeof(mbedctx->temp_dtlsbuf) - DTLS_HEADER_BYTES) < len) {
        return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
    }

    /* set byte order to Big Endian when sending over lower transport. */
    dtls_hdr->sync_bytes = sys_cpu_to_be16(DTLS_PACKET_SYNC_BYTES);
    dtls_hdr->packet_len = sys_cpu_to_be16((uint16_t)len);  /* does not include header */

    /* Combine the header with the payload.  This maximizes the lower transport
     * throughput vs. sending the DTLS header separately then sending the body. */
    memcpy(&mbedctx->temp_dtlsbuf[DTLS_HEADER_BYTES], buf, len);

    /* send to peripheral */
    send_cnt = auth_xport_send(auth_conn->xport_hdl, mbedctx->temp_dtlsbuf, len + DTLS_HEADER_BYTES);
#else
    /* TLS - just send, no need to worry about DTLS IP packet boundary.
     * TLS can handle a steam of bytes. */
    send_cnt = auth_xport_send(auth_conn->xport_hdl, buf, len);
#endif

    if(send_cnt < 0) {
        LOG_ERR("Failed to send, err: %d", send_cnt);
        return -1;  /* TODO: Return the correct MBED error code */
    }

    LOG_INF("Send %d byes.", send_cnt);

    /* return number bytes sent, do not include the DTLS header */
    return (send_cnt - DTLS_HEADER_BYTES);
}


static int auth_mbedtls_rx(void *ctx, uint8_t *buffer, size_t len)
{
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)ctx;
    int rx_bytes = 0;

#ifndef USE_DTLS
    /* For TLS just copy bytes, no need to handle DTLS packet boundary. */
    rx_bytes = auth_xport_recv(auth_conn->xport_hdl, buffer, len, 30000);

    if(rx_bytes < 0) {
        /* some error, return correct MBedtls code */
        /* might be just a simple time-out */
        return 0;
    }

    return rx_bytes;

#else

    struct dtls_packet_hdr dtls_hdr;
    uint16_t packet_len = 0;

    /**
     * DTLS is targeted for the UDP datagram protocol, as such the Mbed stack
     * expects a full DTLS packet (ie datagram) to be receive vs. a partial
     * packet.  For the lower transports, a full datagram packet maybe broken
     * up into multiple fragments.  The receive queue may contain a partial
     * DTLS frame.  The code here waits until a full DTLS packet is received.
     */

     /* Will wait until a full DTLS packet is received. */
    while(true) {

        rx_bytes = auth_xport_getnum_recvqueue_bytes_wait(auth_conn->xport_hdl, 1000u);

        /* Check for canceld flag */
        if(auth_conn->cancel_auth) {
            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }

        /* no bytes or timed out */
        if(rx_bytes == 0 || rx_bytes == -EAGAIN) {
            continue;
        }

        /* an error */
        if(rx_bytes < 0) {
            /* an error occurred */
            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }

        if(rx_bytes < DTLS_HEADER_BYTES) {
            continue;
        }

        /* peek into receive queue */
        auth_xport_recv_peek(auth_conn->xport_hdl, (uint8_t*)&dtls_hdr, sizeof(struct dtls_packet_hdr));

        /* check for sync bytes */
        if(sys_be16_to_cpu(dtls_hdr.sync_bytes) != DTLS_PACKET_SYNC_BYTES) {
            // read bytes and try to peek again
            auth_xport_recv(auth_conn->xport_hdl, (uint8_t*)&dtls_hdr, sizeof(struct dtls_packet_hdr), 1000u);
            continue;
        }

        // have valid DTLS packet header, check packet length
        dtls_hdr.packet_len = sys_be16_to_cpu(dtls_hdr.packet_len);

        /* Is there enough room to copy into Mbedtls buffer? */
        if(dtls_hdr.packet_len > len)  {
            return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
        }

        /* Zero length packet, ignore */
        if(dtls_hdr.packet_len == 0u) {
            LOG_ERR("Empty DTLS packet.");
            /* Read the DTLS header and return */
            auth_xport_recv(auth_conn->xport_hdl, (uint8_t*)&dtls_hdr, sizeof(struct dtls_packet_hdr), 1000u);
            return 0;
        }

        /* rx_bytes must be at least DTLS_HEADER_BYTES in length here.  Enough
         * to fill a complete DTLS packet. */
        if((int)dtls_hdr.packet_len <= (rx_bytes - (int)DTLS_HEADER_BYTES)) {

            packet_len = dtls_hdr.packet_len;

            /* copy packet into mbed buffers */
            /* read header, do not forward to Mbed */
            auth_xport_recv(auth_conn->xport_hdl, (uint8_t*)&dtls_hdr, sizeof(struct dtls_packet_hdr), 1000u);

            /* read packet into mbed buffer*/
            rx_bytes = auth_xport_recv(auth_conn->xport_hdl, buffer, packet_len, 1000u);

            if(rx_bytes <= 0) {
                /* an error occurred */
                return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
            }

            len -= rx_bytes;
            buffer += rx_bytes;

           /* we're done with one DTLS packet, return */
           return rx_bytes;
        }

        /**
         * If we're here it means we have a partial DTLS packet,
         * wait for more data until there is enough to fill a
         * complete DTLS packet.
         */
         LOG_DBG("Waiting for more bytes to fill DTLS packet.");
    }

    return 0;
#endif
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
    void *cred_val;
    size_t cred_len;

    LOG_DBG("Initializing Mbed");

    // set conext pointer
    mbed_ctx = auth_get_mbedcontext();

    if (mbed_ctx == NULL) {
        LOG_ERR("Unable to allocate Mbed TLS context.");
        return AUTH_ERROR_NO_RESOURCE;
    }


    /* Init mbed context */
    auth_init_context(mbed_ctx);

    /* Save MBED tls context as internal object. The intent of using a void
     * 'internal_obj' is to provide a var in the struct authentication_conn to
     * store different authentication methods.  Instead of Mbed, it maybe a
     * Challenge-Response.*/
    auth_conn->internal_obj = mbed_ctx;

    int endpoint = auth_conn->is_client ? MBEDTLS_SSL_IS_CLIENT : MBEDTLS_SSL_IS_SERVER;

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
    mbedtls_ssl_conf_handshake_timeout(&mbed_ctx->conf, 10000u, 30000u);

    /* OPTIONAL is usually a bad choice for security, but makes interop easier
     * in this simplified example, in which the ca chain is hardcoded.
     * Production code should set a proper ca chain and use REQUIRED. */
    mbedtls_ssl_conf_authmode(&mbed_ctx->conf, MBEDTLS_SSL_VERIFY_REQUIRED);

    /**
     * Get pointer to device private key.
     */
    ret = tls_credential_get_info(AUTH_DEVICE_CERT_TAG, TLS_CREDENTIAL_PRIVATE_KEY, &cred_val, &cred_len);

    if(ret) {
        auth_free_mbedcontext(mbed_ctx);
        LOG_ERR("Failed to get device private key, error: %d\n", ret);
        return AUTH_ERROR_DTLS_INIT_FAILED;
    }


    ret = mbedtls_pk_parse_key(&mbed_ctx->device_private_key, cred_val, cred_len, NULL, 0);

    if (ret) {
        auth_free_mbedcontext(mbed_ctx);
        LOG_ERR("Failed to parse device private key, error: 0x%x", ret);
        return AUTH_ERROR_DTLS_INIT_FAILED;
    }

    /**
     * @brief Setup device certs, the CA chain followed by the end device cert.
     */
    ret = tls_credential_get_info(AUTH_CERT_CA_CHAIN_TAG, TLS_CREDENTIAL_CA_CERTIFICATE, &cred_val, &cred_len);

    if(ret) {
        auth_free_mbedcontext(mbed_ctx);
        LOG_ERR("Failed to get cert CA chain, error: %d\n", ret);
        return AUTH_ERROR_DTLS_INIT_FAILED;
    }

    /* Parse and set the CA certs */
    ret = mbedtls_x509_crt_parse(&mbed_ctx->cacert, cred_val, cred_len);

    if (ret) {
        auth_free_mbedcontext(mbed_ctx);
        LOG_ERR("Failed to parse CA cert, error: 0x%x", ret);
        return AUTH_ERROR_DTLS_INIT_FAILED;
    }

    /* set CA certs into context */
    mbedtls_ssl_conf_ca_chain(&mbed_ctx->conf, &mbed_ctx->cacert, NULL);

    /* Get and parse the device cert */
    ret = tls_credential_get_info(AUTH_DEVICE_CERT_TAG, TLS_CREDENTIAL_SERVER_CERTIFICATE, &cred_val, &cred_len);

    if(ret) {
        auth_free_mbedcontext(mbed_ctx);
        LOG_ERR("Failed to get device cert, error: %d\n", ret);
        return AUTH_ERROR_DTLS_INIT_FAILED;
    }

    ret = mbedtls_x509_crt_parse(&mbed_ctx->device_cert,
                                 (const unsigned char *)cred_val, cred_len);


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
    mbedtls_debug_set_threshold(CONFIG_MBEDTLS_DEBUG_LEVEL);
#endif

    if (!auth_conn->is_client) {

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
void auth_dtls_thead(struct authenticate_conn *auth_conn) {

    struct mbed_tls_context *mbed_ctx = (struct mbed_tls_context *) auth_conn->internal_obj;


    /* Set status */
    auth_lib_set_status(auth_conn, AUTH_STATUS_STARTED);

    /**
     * For the server we can noty start the handshake, the code will continue to
     * read looking for a "Client Hello".  So we'll just stay at the  MBEDTLS_SSL_CLIENT_HELLO
     * state until the central sends the "Client Hello"
     *
     * For the client, a client hello will be sent immediately.
     */

    if (!auth_conn->is_client) {

        /**
         * For the the DTLS server, use the auth connection handle as the cookie.
         */
        int ret = auth_tls_set_cookie(auth_conn);

        if(ret) {
            LOG_ERR("Failed to get connection info for DTLS cookie, auth failed, error: 0x%x", ret);
            auth_lib_set_status(auth_conn, AUTH_STATUS_FAILED);
            return;
        }

        int bytecount = 0;
        while(bytecount == 0) {

            /* Server wait for client hello */
            bytecount = auth_xport_getnum_recvqueue_bytes_wait(auth_conn->xport_hdl, 15000u);

            if (bytecount < 0) {
                LOG_ERR("Server, error when waiting for client hello, error: %d", bytecount);
                auth_lib_set_status(auth_conn, AUTH_STATUS_FAILED);
                return;
            }
        }

        LOG_INF("Server received initial Client Hello from client.");
    }

    /* Set status */
    auth_lib_set_status(auth_conn, AUTH_STATUS_IN_PROCESS);

    int ret = 0;

    /* start handshake */
    do {

        while(mbed_ctx->ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER &&
              !auth_conn->cancel_auth)
        {
            // DAG DEBUG BEG
            LOG_INF("** STARTING Handshake state: %s", auth_tls_handshake_state(mbed_ctx->ssl.state));
            // DAG DEBUG END

            // do handshake step
            ret = mbedtls_ssl_handshake_step(&mbed_ctx->ssl);

            if(ret != 0) {
                break;
            }
        }


        if(auth_conn->cancel_auth) {
            LOG_INF("Authentication canceled.");
            break;
        }

        if(ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {

            /* restart handshake to process client cookie */
            LOG_INF("Restarting handshake, need client cookie.");

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

        if(auth_conn->cancel_auth) {
            LOG_INF("Authentication canceled.");
            break;
        }

    } while( ret == MBEDTLS_ERR_SSL_WANT_READ ||
             ret == MBEDTLS_ERR_SSL_WANT_WRITE );


    if(mbed_ctx->ssl.state == MBEDTLS_SSL_HANDSHAKE_OVER) {
        LOG_INF("DTLS Handshake success.");
        ret = AUTH_SUCCESS;
    } else {
        LOG_ERR("DTLS Handshake failed, error: 0x%x", -ret);
    }


    enum auth_status auth_status;

    switch(ret) {
        case MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE:
        case MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY:
            auth_status = AUTH_STATUS_AUTHENTICATION_FAILED;
            break;

        case AUTH_SUCCESS:
            auth_status = AUTH_STATUS_SUCCESSFUL;
            break;

        default:
            auth_status = AUTH_STATUS_FAILED;
            break;
    }

    /* now check if cancel occurred */
    if(auth_conn->cancel_auth) {
        auth_status = AUTH_STATUS_CANCELED;
    }

    /* Call status */
    auth_lib_set_status(auth_conn, auth_status);

    return;
}



