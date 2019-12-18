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

//#define CONFIG_DTLS_AUTH_METHOD
//#define CONFIG_CHALLENGE_RESP_AUTH_METHOD
#define CONFIG_LOOPBACK_TEST    1

/**
 * Should be large enoough to hold one TLS record
 */
#define CENTRAL_RX_BUFER_LEN        1024


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
     AUTH_STAT_STARTED,
     AUTH_STAT_TLS_CERT_INVALID,
     AUTH_STAT_TLS_KEY_EXCHANGE,
     AUTH_STAT_TLS_SIGNATURE_FAILED,
     AUTH_STAT_CHALLENGE_FAILED,
     AUTH_STAT_NO_RESPONSE,
     AUTH_STAT_CANCELED,
     AUTH_STAT_FAILED,
     AUTH_STAT_SUCCESSFUL
 } auth_status_t;


#define AUTH_SVC_IOBUF_LEN      (300u)

 struct auth_io_buffer {
    struct k_mutex buf_mutex;

    uint32_t head_index;
    uint32_t tail_index;
    uint32_t num_valid_bytes;

    uint8_t io_buffer[AUTH_SVC_IOBUF_LEN];
 };

struct authenticate_conn;

 /**
  * Authentication callback status function
  */
typedef void (*k_auth_status_cb_t)(struct authenticate_conn *auth_conn, auth_status_t status, void *context);


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
    k_auth_status_cb_t status_cb_func;
    void *callback_context;

    // thread stuff'
    k_tid_t auth_tid;  // handshake thread id
    struct k_thread auth_thrd_data;

    /* authentication thread for this connection */
    k_thread_entry_t auth_thread_func;

    // semaphore to optionally wait on handshake completion
    struct k_sem auth_handshake_sem;

    /* Semaphore used when waiting for write (for central) and read (for peripheral)*/
    struct k_sem auth_io_sem;

    /* Semaphore used when processing peripheral indications */
    struct k_sem auth_indicate_sem;
    uint32_t indicate_err;

    /* Server characteritic handle, used by the Central to send
     * authentication messages to the Peripheral */
    uint16_t server_char_handle;

    uint16_t mtu;  /* mtu len for the BLE link */

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

struct auth_connection_params
{
    uint8_t *buf;
    uint32_t mtu_size;
    bool use_l2cap;

    uint32_t timeout;

};


// setup certs, underlying IO funcs
// called on kernel init.  ARre you client or server?
// set MTU to large chunk
int auth_svc_init(struct authenticate_conn *auth_con, struct auth_connection_params *con_params,
                          k_auth_status_cb_t status_func, void *context, uint32_t auth_flags );

// frees ups any allocated resouces
int auth_svc_deinit(struct authenticate_conn *auth_con);

// optional callback w/status
int auth_svc_start(struct authenticate_conn *auth_con);

// returns auth status
int auth_svc_status(void);

int auth_svc_cancel(void);

/// wait for completion w/timeout
// 0 == wait forever
int auth_svc_wait(struct authenticate_conn *auth_con, uint32_t timeoutMsec, auth_status_t *status);

int auth_svc_get_peripheral_attributes(struct authenticate_conn *auth_con);

/**
 * Routines to read/write from Authentication service attributes
 */

/*  called when central receives data from the peripheral.  Callback function set in
 * bt_gatt_subscribe_parsm structure when calling bt_gatt_subscribe() */
u8_t auth_svc_gatt_central_notify(struct bt_conn *conn, struct bt_gatt_subscribe_params *params,
                                  const void *data, u16_t length);


int auth_svc_central_tx(void *ctx, const unsigned char *buf, size_t len);
int auth_svc_central_recv(void *ctx, unsigned char *buf, size_t len);
int auth_svc_central_recv_timeout(void *ctx, unsigned char *buf, size_t len, uint32_t timeout);
int auth_svc_peripheral_tx(void *ctx, const unsigned char *buf, size_t len);
int auth_svc_peripheral_recv(void *ctx,unsigned char *buf, size_t len);
int auth_svc_peripheral_recv_timeout(void *ctx, unsigned char *buf, size_t len, uint32_t timeout);


/**
 * Routines to read/write over L2CAP
 */
int auth_svc_tx_l2cap(void *ctx, const unsigned char *buf, size_t len);
int auth_svc_recv_l2cap(void *ctx, unsigned char *buf, size_t len);
int auth_svc_recv_over_l2cap_timeout(void *ctx, unsigned char *buf,
                                     size_t len, uint32_t timeout);


/**
 * Buffer routines
 */
int auth_svc_buffer_init(struct auth_io_buffer *iobuf);
int auth_svc_buffer_put(struct auth_io_buffer *iobuf, const uint8_t *in_buf,  int num_bytes);
int auth_svc_buffer_get(struct auth_io_buffer *iobuf, uint8_t *out_buf,  int num_bytes);
int auth_svc_buffer_bytecount(struct auth_io_buffer *iobuf);
bool auth_svc_buffer_isfull(struct auth_io_buffer *iobuf);
int auth_svc_buffer_clear(struct auth_io_buffer *iobuf);




#ifdef __cplusplus
}
#endif

/**
 * @}
 */
#endif /* ZEPHYR_INCLUDE_BLUETOOTH_SERVICES_AUTH_H_ */
