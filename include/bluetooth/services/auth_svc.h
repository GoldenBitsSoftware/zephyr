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
//#define CONFIG_DTLS_AUTH_METHOD
#define CONFIG_CHALLENGE_RESP_AUTH_METHOD
//#define CONFIG_LOOPBACK_TEST    1

/**
 * Should be large enoough to hold one TLS record
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
#define AUTH_CONN_USE_L2CAP                 0x0010

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


#define AUTH_SVC_IOBUF_LEN      (300u)

 struct auth_io_buffer {
    struct k_mutex buf_mutex;
    struct k_sem buf_sem;

    uint32_t head_index;
    uint32_t tail_index;
    uint32_t num_valid_bytes;

    uint8_t io_buffer[AUTH_SVC_IOBUF_LEN];
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

    /**
     * True if using GATT to authenticate, else using L2CAP
     */
    bool use_gatt_attributes;

    bool is_central;  /* True if connection is for central role */

    // current status of the authentication process
    auth_status_t curr_status;

    // status callback func
    auth_status_cb_t status_cb_func;
    void *callback_context;

    // thread stuff'
    k_tid_t auth_tid;  // handshake thread id
    struct k_thread auth_thrd_data;

    /* authentication thread for this connection */
    k_thread_entry_t auth_thread_func;

    // semaphore to optionally wait on handshake completion
    struct k_sem auth_handshake_sem;

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


    // BLE L2CAP info

    /* IO buffer used by the Central and Peripheral */
    struct auth_io_buffer rx_buf;

    // Pointer to internal details, do not touch!!!
    void *internal_obj;

    // TLS context?
};



/**
 *  Initializes authentication service.
 *
 * @param auth_con     Authentication connection struct, initialized by this call.
 * @param con_params   (DROP THIS?) Optional connection params.
 * @param status_func  Status function callback.
 * @param context      Optional context used in status calllback.
 * @param auth_flags   Authentication flags.
 *
 * @return 0 on success else one of AUTH_ERROR_* values.
 */
int auth_svc_init(struct authenticate_conn *auth_con, struct auth_connection_params *con_params,
                          auth_status_cb_t status_func, void *context, uint32_t auth_flags );

/**
 * Frees up any previously allocated resources.
 *
 * @param auth_con  Authentication connection struct.
 *
 * @return  0 on success else one of AUTH_ERROR_* values.
 */
int auth_svc_deinit(struct authenticate_conn *auth_con);

/**
 * Starts the authentication process
 *
 * @param auth_con  Authentication connection struct.
 *
 * @return  0 on success else one of AUTH_ERROR_* values.
 */
int auth_svc_start(struct authenticate_conn *auth_con);

/**
 * Returns the current status of the authentication process.
 *
 * @return One of AUTH_STATUS_*
 */
auth_status_t auth_svc_status(void);

/**
 * Cancels the authentication process.  Must wait until the AUTH_STATUS_CANCELED
 * status is returned.
 *
 * @return One of AUTH_STATUS_*
 */
int auth_svc_cancel(void);

/**
 * Helper routine to return string corresponding to status
 *
 * @param   status  Authentication status value.
 *
 * @return  Pointer to string representing the status.
 */
const char *auth_svc_getstatus_str(auth_status_t status);


/**
 * Function to block until authentication is complete or a timeout has occuured.
 *
 * @param auth_con       Authentication connection struct.
 * @param timeout_mec    Time to wait in msecs, 0 == wait forever.
 * @param status         Status returned in var.
 *
 * @return  0 on success else one of AUTH_ERROR_* values.
 */
int auth_svc_wait(struct authenticate_conn *auth_con, uint32_t timeout_mec, auth_status_t *status);




#ifdef __cplusplus
}
#endif

/**
 * @}
 */
#endif /* ZEPHYR_INCLUDE_BLUETOOTH_SERVICES_AUTH_H_ */
