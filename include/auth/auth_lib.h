/**
 * @file auth_lib.h
 *
 * @brief  Authentication library functions
 */

#ifndef ZEPHYR_INCLUDE_AUTH_LIB_H_
#define ZEPHYR_INCLUDE_AUTH_LIB_H_


#ifdef __cplusplus
extern "C" {
#endif

#include <auth/auth_xport.h>

/* TODO: Add to Kconfig for BLE authentication service */
//#define CONFIG_DTLS_AUTH_METHOD
//#define CONFIG_CHALLENGE_RESP_AUTH_METHOD
//#define CONFIG_USE_L2CAP
//#define CONFIG_LOOPBACK_TEST    1

/**
 * Should be large enough to hold one TLS record
 */
#define CENTRAL_RX_BUFFER_LEN               500

#define AUTH_SUCCESS                        0
#define AUTH_ERROR_BASE                     (-200)
#define AUTH_ERROR_INVALID_PARAM            (AUTH_ERROR_BASE - 1)
#define AUTH_ERROR_NO_MEMORY                (AUTH_ERROR_BASE - 2)
#define AUTH_ERROR_TIMEOUT                  (AUTH_ERROR_BASE - 3)
#define AUTH_ERROR_NO_RESOURCE              (AUTH_ERROR_BASE - 4)
#define AUTH_ERROR_DTLS_INIT_FAILED         (AUTH_ERROR_BASE - 5)
#define AUTH_ERROR_IOBUFF_FULL              (AUTH_ERROR_BASE - 6)
#define AUTH_ERROR_INTERNAL                 (AUTH_ERROR_BASE - 7)
#define AUTH_ERROR_XPORT_SEND               (AUTH_ERROR_BASE - 8)
#define AUTH_ERROR_XPORT_FRAME              (AUTH_ERROR_BASE - 9)
#define AUTH_CRYPTO_ERROR		    (AUTH_ERROR_BASE - 10)


/**
 * Flags used when initializing authentication connection
 */
#define AUTH_CONN_SERVER                    0x0001
#define AUTH_CONN_CLIENT                    0x0002
#define AUTH_CONN_DTLS_AUTH_METHOD          0x0004
#define AUTH_CONN_CHALLENGE_AUTH_METHOD     0x0008




/**
 *  Authentication status enums
 */
enum auth_status {
     AUTH_STATUS_STARTED,
     AUTH_STATUS_IN_PROCESS,
     AUTH_STATUS_CANCEL_PENDING,   /* Authentication is stopping */
     AUTH_STATUS_CANCELED,
     AUTH_STATUS_FAILED,      /* an internal failure of some type */
     AUTH_STATUS_AUTHENTICATION_FAILED,
     AUTH_STATUS_SUCCESSFUL
 };



/**
  * Enums of cert types.
  */
typedef enum
{
    AUTH_CERT_ROOT,         ///< The root certificate
    AUTH_CERT_CA_CHAIN,     ///< The root CA chain, including the root certificate.
    AUTH_CERT_INTERMEDIATE, ///< Intermediate CA.
    AUTH_CERT_END_DEVICE    ///< End device cert, either server (Peripheral) or client (Central)
} auth_cert_type_t;

/**
 * @brief  Used to set X.509 certs for TLS/DTLS authentication.
 *
 * @note  Storing pointers to the certs in this struct vs. using tls_credentials.c.
 *        No need to include unnecessary network code.  Also, the tls_credential_get() function
 *        copies the cert into a buffer which is not needed.
 */
struct auth_tls_certs
{
    auth_cert_type_t  cert_type;
    const char *cert_data;
    uint32_t cert_len;

    /**
     * @brief  Optional key.  Set with the ATUH_CERT_END_DEVICE cert. For CA certs, should be NULL.
     */
    const char *private_key;    ///< Pointer to key in PEM format.
    uint32_t key_len;
};

/* Container for all of the certs used */
struct auth_cert_container
{
    /** @brief Count and pointer to array of CA certs.  The
     *         order of the certs should match the cert chain, meaning the
     *         root CA should be first followed by any intermediate CA
     *         certs.
     */
    uint8_t num_ca_certs;   ///< number certs of 1 if passing a cert chain
    struct auth_tls_certs *ca_certs;

    /* either the server or client cert */
    struct auth_tls_certs *device_cert;
};

 /* Forward declaration */
struct authenticate_conn;

 /**
  * Authentication callback status function
  */
typedef void (*auth_status_cb_t)(struct authenticate_conn *auth_conn, enum auth_status status, void *context);



/**
 * @brief  Used to manage one authentication session with peer.  It is possible
 *         to have multiple concurrent authentication sessions. For example if
 *         a device is acting as a Central and Peripheral concurrently.
 */
struct authenticate_conn
{
    struct bt_conn *conn;

    bool is_client;  /* True if client */

    /* lower transport opaque handle */
    auth_xport_hdl_t xport_hdl;

    /* current status of the authentication process */
    enum auth_status curr_status;

    /* status callback func */
    auth_status_cb_t status_cb;
    void *callback_context;

    /* Work queue used to return status. Important if authentication
     * status changes/fails in an ISR context */
    struct k_work auth_status_work;

    // thread stuff
    k_tid_t auth_tid;  // handshake thread id
    struct k_thread auth_thrd_data;

    /* authentication thread for this connection */
    k_thread_entry_t auth_thread_func;


    /* Pointer to internal details, do not touch!!! */
    //void *internal_obj;

#if defined(CONFIG_AUTH_DTLS)
    /* @brief Struct used to keep/point to all of the certs needed
     * by the BLE device. */
    struct auth_cert_container *cert_cont;
#endif
};



/**
 *  Initializes authentication library
 *
 * @param auth_conn     Authentication connection struct, initialized by this call.
 * @param status_func  Status function callback.
 * @param context      Optional context used in status callback.
 * @param auth_flags   Authentication flags.
 *
 * @return 0 on success else one of AUTH_ERROR_* values.
 */
int auth_lib_init(struct authenticate_conn *auth_conn,
                  auth_status_cb_t status_func, void *context, uint32_t auth_flags);

/**
 * Frees up any previously allocated resources.
 *
 * @param auth_conn  Pointer to Authentication connection struct.
 *
 * @return  0 on success else one of AUTH_ERROR_* values.
 */
int auth_lib_deinit(struct authenticate_conn *auth_conn);

#if defined(CONFIG_AUTH_DTLS)
/**
 * For TLS/DLTS authentication sets the necessary certificates.  All certs should be
 * in PEM format.  The point should be valid during runtime.
 *
 * @param auth_conn   Pointer to Authentication connection struct.
 * @param certs       Pointer to certificates.  Pointer should be valid at all times.
 *
 */
void auth_svc_set_tls_certs(struct authenticate_conn *auth_conn, struct auth_cert_container *certs);
#endif

/**
 * Starts the authentication process
 *
 * @param auth_conn  Authentication connection struct.
 *
 * @return  0 on success else one of AUTH_ERROR_* values.
 */
int auth_lib_start(struct authenticate_conn *auth_conn);

/**
 * Returns the current status of the authentication process.
 *
 * @param auth_conn  Authentication connection struct.
 *
 * @return One of AUTH_STATUS_*
 */
enum auth_status auth_lib_get_status(struct authenticate_conn *auth_conn);

/**
 * Helper routine to return string corresponding to status
 *
 * @param   status  Authentication status value.
 *
 * @return  Pointer to string representing the status.
 */
const char *auth_lib_getstatus_str(enum auth_status status);

/**
 * Set the current authentication status, will also invoke the callback
 * to post status to the calling code.
 *
 * @param auth_conn   Authentication connection struct.
 * @param status      Authentication status.
 */
void auth_svc_lib_status(struct authenticate_conn *auth_conn, enum auth_status status);

/**
 * Cancels the authentication process.  Must wait until the AUTH_STATUS_CANCELED
 * status is returned.
 *
 * @param auth_conn  Authentication connection struct.
 *
 * @return One of AUTH_STATUS_*
 */
int auth_lib_cancel(struct authenticate_conn *auth_conn);




void auth_lib_set_status(struct authenticate_conn *auth_conn, enum auth_status status);

#ifdef __cplusplus
}
#endif


#endif /* ZEPHYR_INCLUDE_AUTH_LIB_H_ */
