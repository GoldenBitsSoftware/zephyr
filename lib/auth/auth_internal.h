/**
 * @file auth_internal.h
 *
 * @brief
 */

#ifndef ZEPHYR_INCLUDE_AUTH_INTERNAL_H_
#define ZEPHYR_INCLUDE_AUTH_INTERNAL_H_

/**
 * @brief  Timeout in Msec when waiting for GATT or L2CAP read/write to complete.
 */

// DAG DEBUG BEG
//#define AUTH_SVC_IO_TIMEOUT_MSEC            (15000u)
#define AUTH_SVC_IO_TIMEOUT_MSEC            (60000u)
// DAG DEBUG END


#define AUTH_RING_BUFLEN         (200u)

/**
 * Simple ring buffer used between UART ISR and the transport input
 * queue.  The transport receive queue uses a mutex to control access.
 * Can not hold a mutex in an ISR, the solution is to use a simple queue
 * using atomic vars.
 */
struct auth_ringbuf {
    /* rx buffer */
    uint8_t buf[AUTH_RING_BUFLEN];
    struct k_sem rx_sem;
    atomic_t head_idx;
    atomic_t tail_idx;
    atomic_t did_overflow;
};



/**
 * Starts the authentication thread.
 *
 * @param auth_conn Pointer to Authentication connection struct.
 *
 * @return  0 on success else negative error number.
 */
int auth_start_thread(struct authenticate_conn *auth_conn);


/**
 * Initializes DTLS authentication method.
 *
 * @param auth_conn Pointer to Authentication connection struct.
 *
 * @return  0 on success else one of AUTH_ERROR_* values.
 */
int auth_init_dtls_method(struct authenticate_conn *auth_conn);


/**
 * Routines to read/write from Authentication service attributes
 */


/**
 *  Used by the client to send data bytes to the Peripheral.
 *  If necessary, will break up data into several sends depending
 *  on the MTU size.
 *
 * @param auth_conn   Pointer to Authentication connection struct.
 * @param buf         Buffer to send.
 * @param len         Buffer size.
 *
 * @return  Number of bytes sent or negative error value.
 */
int auth_client_tx(struct authenticate_conn *auth_conn, const unsigned char *buf, size_t len);

/**
 * Used by the client to read data from the receive buffer.  Will not
 * block, if no bytes are available from the Peripheral returns 0.
 *
 * @param auth_conn  Pointer to Authentication connection struct.
 * @param buf        Buffer to copy byes into.
 * @param len        Buffer length.
 *
 * @return  Number of bytes returned, 0 if no bytes returned, or negative if
 *          an error occurred.
 */
int auth_client_recv(struct authenticate_conn *auth_conn, unsigned char *buf, size_t len);

/**
 * Used by the Central to receive data from the Peripheral.  Will block until data is
 * received or a timeout has occurred.
 *
 * @param auth_conn  Pointer to Authentication connection struct.
 * @param buf        Buffer to copy byes into.
 * @param len        Buffer length.
 * @param timeout    Wait time in msecs for data, K_FOREVER or K_NO_WAIT.
 *
 * @return  Number of bytes returned, 0 if no bytes returned, or negative if
 *          an error occurred.
 */
int auth_client_recv_timeout(struct authenticate_conn *auth_conn, unsigned char *buf, size_t len, uint32_t timeout);

/**
 * Used by the server to send data to the Central. Will break up buffer to max MTU
 * sizes if necessary and send multiple PDUs.  Uses Write Indications to get acknowledgement
 * from the Central before sending additional packet.
 *
 * @param auth_conn Pointer to Authentication connection struct.
 * @param buf       Data to send
 * @param len       Data length.
 *
 * @return  Number of bytes send, or negative if an error occurred.
 */
int auth_server_tx(struct authenticate_conn *auth_conn, const unsigned char *buf, size_t len);

/**
 * Used by the server to read data from the receive buffer. Non-blocking.
 *
 * @param auth_conn Context, pointer to Authentication connection struct.
 * @param buf       Buffer to copy bytes into.
 * @param len       Number of bytes requested.
 *
 * @return Number of bytes returned, 0 if no bytes, of negative if an error occurred.
 */
int auth_server_recv(struct authenticate_conn *auth_conn, unsigned char *buf, size_t len);

/**
 * Used by the server to read data from the receive buffer.  Blocking call.
 *
 * @param auth_conn  Context, pointer to Authentication connection struct.
 * @param buf        Buffer to copy bytes into.
 * @param len        Number of bytes requested.
 * @param timeout    Wait time in msecs for data, K_FOREVER or K_NO_WAIT.
 *
 * @return  Number of bytes returned, or -EAGAIN if timed out.
 */
int auth_server_recv_timeout(struct authenticate_conn *auth_conn, unsigned char *buf, size_t len, uint32_t timeout);


/**
 * Used by the client to send data to Peripheral.
 *
 * @param conn  Pointer to Authentication connection struct.
 * @param data  Data to send.
 * @param len   Byte length of data.
 *
 * @return Number of bytes sent, negative number on error.
 */
int auth_client_tx(struct authenticate_conn *conn, const unsigned char *data, size_t len);

/**
 * Used by the client to receive data to Peripheral.
 *
 * @param conn     Pointer to Authentication connection struct.
 * @param buf      Buffer to copy received bytes into.
 * @param rxbytes  Number of bytes requested.
 *
 * @return Number of bytes copied into the buffer. On error, negative error number.
 */
int auth_client_rx(struct authenticate_conn *conn, uint8_t *buf, size_t rxbytes);

/**
 * Used by server to send data to the client.
 *
 * @param conn  Pointer to Authentication connection struct.
 * @param data  Data to send.
 * @param len   Byte length of data.
 *
 * @return Number of bytes sent, negative number on error.
 */
int auth_server_tx(struct authenticate_conn *conn, const unsigned char *data, size_t len);

/**
 * Used by server to receive data.
 *
 * @param conn  Pointer to Authentication connection struct.
 * @param buf   Buffer to copy received bytes into.
 * @param len   Number of bytes requested.
 *
 * @return Number of bytes copied (received) into the buffer. On error, negative error number.
 */
int auth_sever_rx(struct authenticate_conn *conn, uint8_t *buf, size_t len);


void auth_ringbuf_init(struct auth_ringbuf *ringbuf);


void auth_ringbuf_put_byte(struct auth_ringbuf *ringbuf, uint8_t one_byte);

bool auth_ringbuf_get_byte(struct auth_ringbuf *ringbuf, uint8_t *one_byte);

bool auth_ringbuf_overflow(struct auth_ringbuf *ringbuf);

void auth_ringbuf_reset(struct auth_ringbuf *ringbuf);



#endif   /* ZEPHYR_INCLUDE_AUTH_INTERNAL_H_ */