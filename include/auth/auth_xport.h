/**
 * @file auth_xport.h
 *
 * @brief
 */

#ifndef ZEPHYR_INCLUDE_AUTH_XPORT_H_
#define ZEPHYR_INCLUDE_AUTH_XPORT_H_

#ifdef CONFIG_BT_XPORT
#include <bluetooth/gatt.h>
#endif


/**
 * Transport functions and defines.
 */


/**
 * Handle to lower transport, should be treated as opaque object.
 *
 * @note A typedef is use here because the transport handle is intended to
 *       be an opaque object to the lower transport layers and to the
 *       upper layers calling into the transport.  This use satisfies
 *       the Linux coding standards.
 */
typedef void * auth_xport_hdl_t;



/**
 * Transport event type.
 */
enum auth_xport_evt_type
{
    XP_EVT_NONE = 0,
    XP_EVT_CONNECT,
    XP_EVT_DISCONNECT,
    XP_EVT_RECONNECT,

    /* transport specific events */
    XP_EVT_SERIAL_BAUDCHANGE
};

/**
 * Transport event structure
 */
struct auth_xport_evt
{
    enum auth_xport_evt_type event;

    /* transport specific event information */
    void *xport_ctx;
};

/**
 * Callback invoked when sending data asynchronously.
 *
 * @param err       Error code, 0 == success.
 * @param numbytes  Number of bytes sent, can be 0.
 */
typedef void(*send_callback_t)(int err, uint16_t numbytes);


/**
 * Function for sending data directly to the lower layer transport
 * instead of putting data on an output queue. Some lower transport
 * layers have the ability to queue outbound data, no need to double
 * buffer.
 *
 * @param  xport_hdl    Opaque transport handle.
 * @param  data         Data to send.
 * @param  len          Number of bytes to send
 *
 * @reutrn Number of bytes sent, on error negative error value.
 */
typedef int(*send_xport_t)(auth_xport_hdl_t xport_hdl, const uint8_t *data, const size_t len);


/**
 * Initializes the lower transport layer.
 *
 * @param xporthdl
 * @param flags
 *
 * @return
 */
int auth_xport_init(auth_xport_hdl_t *xporthdl,  uint32_t flags, void *xport_params);

/**
 * De-initializes the transport.  The lower layer transport should
 * free any allocated resources.
 *
 * @param xporthdl
 *
 * @return AUTH_SUCCESS or negative error value.
 */
int auth_xport_deinit(const auth_xport_hdl_t xporthdl);

/**
 * Forwards event to lower transport layer.
 *
 * @param xporthdl   Transport handle.
 * @param event      Event
 *
 * @return AUTH_SUCCESS or negative error value.
 */
int auth_xport_event(const auth_xport_hdl_t xporthdl, struct auth_xport_evt *event);


/**
 * Sends packet of data to peer.
 *
 * @param xporthdl  Transport handle
 * @param data      Buffer to send.
 * @param len       Number of bytes to send.
 *
 * @return  Number of bytes sent on success, can be less than requested.
 *          On error, negative error code.
 */
int auth_xport_send(const auth_xport_hdl_t xporthdl, const uint8_t *data, size_t len);


/**
 * Receive data from the lower transport.
 *
 * @param xporthdl  Transport handle
 * @param buff      Buffer to read bytes into.
 * @param buf_len   Size of buffer.
 * @param timeoutMsec   Wait timeout in milliseconds.  If no bytes available, then
 *                      wait timeoutMec milliseconds.  If 0, then will not wait.
 *
 * @return Negative on error or timeout, else number of bytes received.
 */
int auth_xport_recv(const auth_xport_hdl_t xporthdl, uint8_t *buff, uint32_t buf_len, uint32_t timeoutMsec);


/**
 * Get the number of bytes queued for sending.
 *
 * @param xporthdl  Transport handle.
 *
 * @return  Number of queued bytes, negative value on error.
 */
int auth_xport_getnum_send_queued_bytes(const auth_xport_hdl_t xporthdl);

/**
 * Used by lower transport to put received bytes into recv queue.  The upper
 * layer auth code reads from this queue.
 *
 * @param xporthdl  Transport handle.
 * @param buff      Pointer to buffer to queue.
 * @param buflen    Number of bytes to queue.
 *
 * @return The number of bytes queued, can be less than requested.
 *         On error, negative value is returned.
 */
int auth_xport_put_recv_bytes(const auth_xport_hdl_t xporthdl, const uint8_t *buff, size_t buflen);


/**
 * Sets a direct send function to the lower transport layer instead of
 * queuing bytes into an output buffer.  Some lower transports can handle
 * all of the necessary output queuing while others (serial UARTs for example)
 * may not have the ability to queue outbound byes.
 *
 * @param xporthdl   Transport handle.
 * @param send_func  Lower transport send function.
 */
void auth_xport_set_sendfunc(auth_xport_hdl_t xporthdl, send_xport_t send_func);


/**
 * Used by the lower transport to set a context for a given transport handle.  To
 * clear a previously set context, use NULL as context pointer.
 *
 * @param xporthdl   Transport handle.
 * @param context    Context pointer to set.
 *
 */
void auth_xport_set_context(auth_xport_hdl_t xporthdl, void *context);

/**
 * Returns pointer to context.
 *
 * @param xporthdl   Transport handle.
 *
 * @return  Pointer to transport layer context, else NULL
 */
void *auth_xport_get_context(auth_xport_hdl_t xporthdl);

/**
 * Get the application max payload the lower transport can handle in one
 * in one frame.  The common transport functions will break up a larger
 * application packet into multiple frames.
 *
 * @param xporthdl   Transport handle.
 *
 * @return The max payload, or negative error number.
 */
int auth_xport_get_max_payload(const auth_xport_hdl_t xporthdl);


#ifdef CONFIG_BT_XPORT

struct auth_xp_bt_params
{
    struct bt_conn *conn;
    bool is_central;

    /* The BT value handle used by the Central to send to the Peripheral.
     * Not used by the Peripheral. */
    uint16_t server_char_hdl;

    /* Client attribute, used by peripheral to indicate data for client.
     * Not used by the Central (client) */
    const struct bt_gatt_attr *client_attr;
};

/**
 * Initialize Bluetooth transport
 */
int auth_xp_bt_init(const auth_xport_hdl_t xport_hdl, uint32_t flags, void *xport_param);


/**
 * Deinit
 */
int auth_xp_bt_deinit(const auth_xport_hdl_t xport_hdl);

/*
 * Called when the Central (client) writes to a Peripheral (server) characteristic.
 */
ssize_t auth_xp_bt_central_write(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                                   const void *buf, u16_t len, u16_t offset, u8_t flags);



/**
 * Called on the Central (client) when a Peripheral (server) writes/updates a characteristic.
 * This function is called by the Central BT stack when data is received by the Peripheral (server)
 */
u8_t auth_xp_bt_central_notify(struct bt_conn *conn, struct bt_gatt_subscribe_params *params,
                                   const void *data, u16_t length);


/**
 * Sends Bluetooth event to lower Bluetooth transport.
 *
 * @param xporthdl   Transport handle.
 * @param event      The event.
 *
 * @return AUTH_SUCCESS, else negative error code.
 */
int auth_xp_bt_event(const auth_xport_hdl_t xporthdl, struct auth_xport_evt *event);

/**
 * Gets the maximum payload for the lower transport.  This is the
 * usable payload by the application.
 *
 * @param xporthdl   Transport handle.
 *
 * @return Max application payload.
 */
int auth_xp_bt_get_max_payload(const auth_xport_hdl_t xporthdl);

#endif

#ifdef CONFIG_SERIAL_XPORT
#endif


#endif  /* ZEPHYR_INCLUDE_AUTH_XPORT_H_ */