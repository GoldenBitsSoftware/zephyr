/**
 * @file auth_svc.h
 *
 * @brief  BLE Authentication Service functions
 */

#ifndef ZEPHYR_INCLUDE_BLUETOOTH_SERVICES_AUTH_H_
#define ZEPHYR_INCLUDE_BLUETOOTH_SERVICES_AUTH_H_

/**
 * @brief  Authentication Service (AUTH_SVC)
 * @defgroup bt_gatt_auths  Authentication Service (AUTH_SVC)
 * @ingroup bluetooth
 * @{
 *
 * [Experimental] Users should note that the APIs can change
 * as a part of ongoing development.
 */


#ifdef __cplusplus
extern "C" {
#endif

/* TODO: Add to Kconfig for BLE authentication service */
#define CONFIG_DTLS_AUTH_METHOD
//#define CONFIG_CHALLENGE_RESP_AUTH_METHOD
//#define CONFIG_USE_L2CAP
//#define CONFIG_LOOPBACK_TEST    1

/**
 * Should be large enough to hold one TLS record
 */
#define CENTRAL_RX_BUFFER_LEN               500

#define BLE_LINK_HEADER_BYTES               (2u + 1u)  /**< two bytes for header, not sure about extra byte */


#define AUTH_SUCCESS                        0
#define AUTH_BASE_ERROR                     -200
#define AUTH_ERROR_INVALID_PARAM            (AUTH_BASE_ERROR - 1)
#define AUTH_ERROR_NO_MEMORY                (AUTH_BASE_ERROR - 2)
#define AUTH_ERROR_TIMEOUT                  (AUTH_BASE_ERROR - 3)
#define AUTH_ERROR_NO_RESOURCE              (AUTH_BASE_ERROR - 4)
#define AUTH_ERROR_DTLS_INIT_FAILED         (AUTH_BASE_ERROR - 5)
#define AUTH_ERROR_IOBUFF_FULL              (AUTH_BASE_ERROR - 6)


/**
 * Flags used when initializing authentication connection
 */
#define AUTH_CONN_PERIPHERAL                0x0001
#define AUTH_CONN_CENTRAL                   0x0002
#define AUTH_CONN_DTLS_AUTH_METHOD          0x0004
#define AUTH_CONN_CHALLENGE_AUTH_METHOD     0x0008


/**
 * L2CAP PSM numbers
 * 0x01 - 0x3F are reseved
 *
 */
#define AUTH_L2CAP_CHANNEL_PSM              0x85  /* hopefully doesn't conflict w/anything */

/* Log module for the BLE authentication service. */
#define AUTH_SERVICE_LOG_MODULE             auth_svc


/**
 *  Authentication status enums
 */
 typedef enum  {
     AUTH_STATUS_STARTED,
     AUTH_STATUS_IN_PROCESS,
     AUTH_STATUS_CANCEL_PENDING,   /* Authentication is stopping */
     AUTH_STATUS_CANCELED,
     AUTH_STATUS_FAILED,      /* an internal failure of some type */
     AUTH_STATUS_AUTHENTICATION_FAILED,
     AUTH_STATUS_SUCCESSFUL
 } auth_status_t;


#define AUTH_SVC_IOBUF_LEN      (4096u)

 /**
  * @brief Circular buffer used to save received data.
  */
 struct auth_io_buffer {
    struct k_mutex buf_mutex;
    struct k_sem buf_sem;

    uint32_t head_index;
    uint32_t tail_index;
    uint32_t num_valid_bytes;

    uint8_t io_buffer[AUTH_SVC_IOBUF_LEN];
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
typedef void (*auth_status_cb_t)(struct authenticate_conn *auth_conn, auth_status_t status, void *context);


/**
 * @brief  Used to manage one authentication session with peer.  It is possible
 *         to have multiple concurrent authentication sessions. For example if
 *         a device is acting as a Central and Peripheral concurrently.
 */
struct authenticate_conn
{
    struct bt_conn *conn;

    bool is_central;  /* True if connection is for central role */

    /* current status of the authentication process */
    auth_status_t curr_status;

    /* status callback func */
    auth_status_cb_t status_cb;
    void *callback_context;

    /* Work queue used to return status. Important if authentication
     * status changes/fails in an ISR context */
    struct k_work auth_status_work;

    // thread stuff'
    k_tid_t auth_tid;  // handshake thread id
    struct k_thread auth_thrd_data;

    /* authentication thread for this connection */
    k_thread_entry_t auth_thread_func;

    /* Semaphore used when waiting for write (for central) to complete */
    struct k_sem auth_central_write_sem;

    /* Semaphore used when processing peripheral indications */
    struct k_sem auth_indicate_sem;
    uint32_t indicate_err;

    volatile u8_t write_att_err;

    /* Server characteristic handle, used by the Central to send
     * authentication messages to the Peripheral */
    uint16_t server_char_handle;

    uint16_t payload_size;  /* BLE Link MTU less struct bt_att_write_req */

    /* Attributes, these should be used by the Peripheral, not used by the Central. */
    const struct bt_gatt_attr *auth_svc_attr;    /* service attribute */
    const struct bt_gatt_attr *auth_client_attr; /* Client attribute */
    const struct bt_gatt_attr *auth_server_attr; /* Server attribute */


#if defined(CONFIG_BT_GATT_CLIENT)
    /* Timer when connecting L2CAP channel. If channel not connected by
     * N number of seconds, then timeout error status is returned */
    struct k_timer chan_connect_timer;
#endif

    /* IO buffer used by the Central and Peripheral */
    struct auth_io_buffer rx_buf;

    /* Pointer to internal details, do not touch!!! */
    void *internal_obj;

#if defined(CONFIG_DTLS_AUTH_METHOD)
    /* @brief Struct used to keep/point to all of the certs needed
     * by the BLE device. */
    struct auth_cert_container *cert_cont;
#endif
};



/**
 *  Initializes authentication service.
 *
 * @param auth_conn     Authentication connection struct, initialized by this call.
 * @param con_params   (DROP THIS?) Optional connection params.
 * @param status_func  Status function callback.
 * @param context      Optional context used in status calllback.
 * @param auth_flags   Authentication flags.
 *
 * @return 0 on success else one of AUTH_ERROR_* values.
 */
int auth_svc_init(struct authenticate_conn *auth_conn,
                  auth_status_cb_t status_func, void *context, uint32_t auth_flags);

/**
 * Frees up any previously allocated resources.
 *
 * @param auth_conn  Pointer to Authentication connection struct.
 *
 * @return  0 on success else one of AUTH_ERROR_* values.
 */
int auth_svc_deinit(struct authenticate_conn *auth_conn);

#if defined(CONFIG_DTLS_AUTH_METHOD)
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
int auth_svc_start(struct authenticate_conn *auth_conn);

/**
 * Returns the current status of the authentication process.
 *
 * @param auth_conn  Authentication connection struct.
 *
 * @return One of AUTH_STATUS_*
 */
auth_status_t auth_svc_get_status(struct authenticate_conn *auth_conn);


/**
 * Set the current authentication status, will also invoke the callback
 * to post status to the calling code.
 *
 * @param auth_conn   Authentication connection struct.
 * @param status      Authentication status.
 */
void auth_svc_set_status(struct authenticate_conn *auth_conn, auth_status_t status);

/**
 * Cancels the authentication process.  Must wait until the AUTH_STATUS_CANCELED
 * status is returned.
 *
 * @param auth_conn  Authentication connection struct.
 *
 * @return One of AUTH_STATUS_*
 */
int auth_svc_cancel(struct authenticate_conn *auth_conn);

/**
 * Helper routine to return string corresponding to status
 *
 * @param   status  Authentication status value.
 *
 * @return  Pointer to string representing the status.
 */
const char *auth_svc_getstatus_str(auth_status_t status);



/**  Called when central receives data from the peripheral.  Callback function set in
 * bt_gatt_subscribe_parsm structure when calling bt_gatt_subscribe()
 *
 * @param conn      BLE connection struct.
 * @param params    GATT subscription params.
 * @param data      Pointer to data bytes received from the Peripheral.
 * @param length    Number of bytes received
 *
 * @return  BT_GATT_ITER_STOP to unsubscribe from peripheral Notifications/Indications.
 *          BT_GATT_ITER_CONTINUE  to continue receiving Notifications/Indications.
 */
u8_t auth_svc_gatt_central_notify(struct bt_conn *conn, struct bt_gatt_subscribe_params *params,
                                  const void *data, u16_t length);


#ifdef __cplusplus
}
#endif

/**
 * @}
 */
#endif /* ZEPHYR_INCLUDE_BLUETOOTH_SERVICES_AUTH_H_ */
