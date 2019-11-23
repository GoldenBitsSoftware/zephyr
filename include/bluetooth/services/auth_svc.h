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

typedef enum  {
    AUTH_SUCCESS                = 0,
    AUTH_ERROR_INVALID_PARAM    = 1,
    AUTH_ERROR_NO_MEMORY        = 2,
    AUTH_ERROR_TIMEOUT          = 3
} auth_error_t;

/**
 * Flags used when initializing authentication connection
 */
#define AUTH_CONN_PERIPHERAL                0x0001
#define AUTH_CONN_CENTRAL                   0x0002
#define AUTH_CONN_DTLS_AUTH_METHOD          0x0004
#define AUTH_CONN_CHALLENGE_AUTH_METHOD     0x0008
#defien AUTH_CONN_USE_L2CAP                 0x0010


/**
 *  Authentication status enums
 */
 typedef enum  {
     AUTH_STARTED,
     AUTH_TLS_CERT_INVALID,
     AUTH_TLS_KEY_EXCHANGE,
     AUTH_TLS_SIGNATURE_FAILED
     AUTH_CHALLENGE_FAILED,
     AUTH_NO_RESPONSE,
     AUTH_CANCELED,
     AUTH_FAILED,
     AUTH_SUCCESSFUL
 } auth_status_t;

 /**
  * Authentication callback status function
  */
typedef void (*auth_status_cb_t)(auth_status_t status, void *context);


struct authenticate_conn
{
    struct bt_conn *conn;

    bool use_gatt_attributes;

    bool is_central;  // True if connection is for central role

    // current status of the authentication process
    auth_status_t curr_status;

    // status callback func
    k_auth_status_cb_t status_cb_func;
    void *callback_context;

    // thread stuff'
    k_tid_t auth_tid;  // handshake thread id
    struct k_thread auth_thrd_data;

    // semaphore to optionally wait on handshake completion
    struct k_sem auth_sem;

    // BLE GATT info


    // BLE L2CAP info


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
auth_error_t auth_svc_init(struct authenticate_conn *auth_con, struct auth_connection_params *con_params,
                          k_auth_status_cb_t status_func, void *context, uint32_t auth_flags );

// frees ups any allocated resouces
auth_error_t auth_svc_deinit(struct authenticate_conn *auth_con);

// optional callback w/status
auth_error_t auth_svc_start(struct authenticate_conn *auth_con);

// returns auth status
auth_status_t auth_svc_status(void);

auth_error_t auth_svc_cancel(void);

/// wait for completion w/timeout
// 0 == wait forever
auth_error_t auth_svc_wait(struct authenticate_conn *auth_con, uint32_t timeoutMsec, auth_status_t *status);


#ifdef __cplusplus
}
#endif

/**
 * @}
 */
#endif /* ZEPHYR_INCLUDE_BLUETOOTH_SERVICES_AUTH_H_ */
