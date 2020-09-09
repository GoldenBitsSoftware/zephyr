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

    
/**
 *  Determine number of auth instances, each instance performs
 *  authentication over a given hardware transport such as Bluetooth
 *  or serial.  It is possible to configure the authentication
 *  library to authenticate over BLE and Serial.  Or if the device
 *  is a Bluetooth central, then two instances can be used to authenticate
 *  two different peripherals.
 */
#if (CONFIG_NUM_AUTH_INSTANCES == 0)
#error Error at least one Authentication instance must be defined.
#endif

#if (CONFIG_NUM_AUTH_INSTANCES > 0)
#define AUTH_INSTANCE_1
#endif

#if (CONFIG_NUM_AUTH_INSTANCES > 1)
#define AUTH_INSTANCE_2
#endif


/**
 * Auth instance id enuma=s
 */
enum auth_instance_id {

#if defined(AUTH_INSTANCE_1)
    AUTH_INST_1_ID = 0,
#endif

#if defined(AUTH_INSTANCE_2)
    AUTH_INST_2_ID = 1,
#endif

    AUTH_MAX_INSTANCES
};


#include <auth/auth_xport.h>

/* TODO: Add to Kconfig for BLE authentication service */
//#define CONFIG_DTLS_AUTH_METHOD
//#define CONFIG_CHALLENGE_RESP_AUTH_METHOD
//#define CONFIG_USE_L2CAP

/**
 * Should be large enough to hold one TLS record
 */

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
#define AUTH_CRYPTO_ERROR                   (AUTH_ERROR_BASE - 10)


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
 * Defines used for DTLS/TLS authentication.
 */
#define AUTH_CERT_CA_CHAIN_TAG          1  /* Chain of certs to root cert, in PEM format */
#define AUTH_DEVICE_CERT_TAG            2  /* Client or server cert, end entity. */



 /* Forward declaration */
struct authenticate_conn;

/**
 * Authentication function prototype
 */
typedef void (*auth_instance_func_t)(volatile struct authenticate_conn *);

 /**
  * Authentication callback status function
  */
typedef void (*auth_status_cb_t)(struct authenticate_conn *auth_conn, enum auth_instance_id instance,
                                 enum auth_status status, void *context);


/**
 * @brief  Used to manage one authentication instance with a peer.  It is possible
 *         to have multiple concurrent authentication instances. For example if
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

    /* The auth instance ID for this connection */
    enum auth_instance_id instance;

    /* status callback func */
    auth_status_cb_t status_cb;
    void *callback_context;

    /* Work queue used to return status. Important if authentication
     * status changes/fails in an ISR context */
    struct k_work auth_status_work;


    /* authentication function, performs the actual authentication */
    auth_instance_func_t auth_func;

    /* cancel the authentication  */
    volatile bool cancel_auth;

    /* Pointer to internal details, do not touch!!! */
    void *internal_obj;
};



/**
 *  Initializes authentication library
 *
 * @param auth_conn    Authentication connection struct, initialized by this call.
 * @param status_func  Status function callback.
 * @param instance     The instance ID.
 * @param context      Optional context used in status callback.
 * @param auth_flags   Authentication flags.
 *
 * @return 0 on success else one of AUTH_ERROR_* values.
 */
int auth_lib_init(struct authenticate_conn *auth_conn, auth_status_cb_t status_func,
                  enum auth_instance_id instance, void *context, uint32_t auth_flags);

/**
 * Frees up any previously allocated resources.
 *
 * @param auth_conn  Pointer to Authentication connection struct.
 *
 * @return  0 on success else one of AUTH_ERROR_* values.
 */
int auth_lib_deinit(struct authenticate_conn *auth_conn);


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
 * Cancels the authentication process.  Must wait until the AUTH_STATUS_CANCELED
 * status is returned.
 *
 * @param auth_conn  Authentication connection struct.
 *
 * @return One of AUTH_STATUS_*
 */
int auth_lib_cancel(struct authenticate_conn *auth_conn);


/**
 * Set the authentication status.
 *
 * @param auth_conn   Authentication connection struct.
 * @param status      Authentication status.
 */
void auth_lib_set_status(struct authenticate_conn *auth_conn, enum auth_status status);

#ifdef __cplusplus
}
#endif


#endif /* ZEPHYR_INCLUDE_AUTH_LIB_H_ */
