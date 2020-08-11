/**
 * @file auth_internal.h
 *
 * @brief  BLE Authentication Service functions internal to the Authentication
 *         service.  Not intended for external use.
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

/**
 *  Used by peripheral code to get the service attributes.
 *
 * @param auth_conn  Pointer to Authentication connection struct.
 *
 * @return  0 on success else one of AUTH_ERROR_* values.
 */
int auth_svc_get_peripheral_attributes(struct authenticate_conn *auth_conn);


/**
 * Starts the authentication thread.
 *
 * @param auth_conn Pointer to Authentication connection struct.
 *
 * @return  0 on success else negative error number.
 */
int auth_svc_start_thread(struct authenticate_conn *auth_conn);


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
 *  Used by the Central to send data bytes to the Peripheral.
 *  If necessary, will break up data into several sends depending
 *  on the MTU size.
 *
 * @param auth_conn   Pointer to Authentication connection struct.
 * @param buf         Buffer to send.
 * @param len         Buffer size.
 *
 * @return  Number of bytes sent or negative error value.
 */
int auth_svc_central_tx(struct authenticate_conn *auth_conn, const unsigned char *buf, size_t len);

/**
 * Used by the Central to read data from the receive buffer.  Will not
 * block, if no bytes are available from the Peripheral returns 0.
 *
 * @param auth_conn  Pointer to Authentication connection struct.
 * @param buf        Buffer to copy byes into.
 * @param len        Buffer length.
 *
 * @return  Number of bytes returned, 0 if no bytes returned, or negative if
 *          an error occurred.
 */
int auth_svc_central_recv(struct authenticate_conn *auth_conn, unsigned char *buf, size_t len);

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
int auth_svc_central_recv_timeout(struct authenticate_conn *auth_conn, unsigned char *buf, size_t len, uint32_t timeout);

/**
 * Used by the Peripheral to send data to the Central. Will break up buffer to max MTU
 * sizes if necessary and send multiple PDUs.  Uses Write Indications to get acknowledgement
 * from the Central before sending additional packet.
 *
 * @param auth_conn Pointer to Authentication connection struct.
 * @param buf       Data to send
 * @param len       Data length.
 *
 * @return  Number of bytes send, or negative if an error occurred.
 */
int auth_svc_peripheral_tx(struct authenticate_conn *auth_conn, const unsigned char *buf, size_t len);

/**
 * Used by the Peripheral to read data from the receive buffer. Non-blocking.
 *
 * @param auth_conn Context, pointer to Authentication connection struct.
 * @param buf       Buffer to copy bytes into.
 * @param len       Number of bytes requested.
 *
 * @return Number of bytes returned, 0 if no bytes, of negative if an error occurred.
 */
int auth_svc_peripheral_recv(struct authenticate_conn *auth_conn, unsigned char *buf, size_t len);

/**
 * Used by the Peripheral to read data from the receive buffer.  Blocking call.
 *
 * @param auth_conn  Context, pointer to Authentication connection struct.
 * @param buf        Buffer to copy bytes into.
 * @param len        Number of bytes requested.
 * @param timeout    Wait time in msecs for data, K_FOREVER or K_NO_WAIT.
 *
 * @return  Number of bytes returned, or -EAGAIN if timed out.
 */
int auth_svc_peripheral_recv_timeout(struct authenticate_conn *auth_conn, unsigned char *buf, size_t len, uint32_t timeout);


/**
 * Routines to read/write over L2CAP
 */

/**
 * Send data over L2CAP channel.   * Also used as MbedTLS BIO function.
 *
 * @param ctx  Context, pointer to Authentication connection struct.
 * @param buf  Buffer to copy bytes into.
 * @param len  Number of bytes requested.
 *
 * @return Number of bytes sent, 0 if no bytes, of negative if an error occurred.
 */
int auth_svc_tx_l2cap(void *ctx, const unsigned char *buf, size_t len);

/**
 * Receive data from L2CAP channel.
 * Also used as MbedTLS BIO function.
 *
 * @param ctx  Context, pointer to Authentication connection struct.
 * @param buf  Buffer to copy bytes into.
 * @param len  Number of bytes requested.
 *
 * @return Number of bytes returned, 0 if no bytes, of negative if an error occurred.
 */
int auth_svc_recv_l2cap(void *ctx, unsigned char *buf, size_t len);

/**
 * Receive data from L2CAP channel with timeout, blocking call.
 * Also used as MbedTLS BIO function.
 *
 * @param ctx  Context, pointer to Authentication connection struct.
 * @param buf  Buffer to copy bytes into.
 * @param len  Number of bytes requested.
 * @param timeout  Wait time in msecs for data, K_FOREVER or K_NO_WAIT.
 *
 * @return  Number of bytes returned, or -EAGAIN if timed out.
 */
int auth_svc_recv_over_l2cap_timeout(void *ctx, unsigned char *buf,
                                     size_t len, uint32_t timeout);

/**
 * Used by the Central to send data to Peripheral.  Uses either GATT or L2CAP
 * interface depending on the configuration.
 *
 * @param conn  Pointer to Authentication connection struct.
 * @param data  Data to send.
 * @param len   Byte length of data.
 *
 * @return Number of bytes sent, negative number on error.
 */
int auth_central_tx(struct authenticate_conn *conn, const unsigned char *data, size_t len);

/**
 * Used by the Central to receive data to Peripheral.  Uses either GATT or L2CAP
 * interface depending on the configuration.
 *
 * @param conn     Pointer to Authentication connection struct.
 * @param buf      Buffer to copy received bytes into.
 * @param rxbytes  Number of bytes requested.
 *
 * @return Number of bytes copied into the buffer. On error, negative error number.
 */
int auth_central_rx(struct authenticate_conn *conn, uint8_t *buf, size_t rxbytes);

/**
 * Used by Peripheral to send data to the Central. Uses either GATT or L2CAP
 * interface depending on the configuration.
 *
 * @param conn  Pointer to Authentication connection struct.
 * @param data  Data to send.
 * @param len   Byte length of data.
 *
 * @return Number of bytes sent, negative number on error.
 */
int auth_periph_tx(struct authenticate_conn *conn, const unsigned char *data, size_t len);

/**
 * Used by Peripheral to receive data. Uses either GATT or L2CAP
 * interface depending on the configuration.
 *
 * @param conn  Pointer to Authentication connection struct.
 * @param buf   Buffer to copy received bytes into.
 * @param len   Number of bytes requested.
 *
 * @return Number of bytes copied (received) into the buffer. On error, negative error number.
 */
int auth_periph_rx(struct authenticate_conn *conn, uint8_t *buf, size_t len);



/**
 * @brief IO buffer routines used to manage the circular receive buffer for
 *        the Central and Peripheral.
 */

/**
 * Initializes a IO buffer.
 *
 * @param iobuf   Pointer to IO buffer struct.
 *
 * @return   0 on success, negative on error.
 */
int auth_svc_buffer_init(struct auth_io_buffer *iobuf);

/**
 *  Puts data into the buffer.
 *
 * @param iobuf        Pointer to IO buffer struct.
 * @param in_buf       Bytes to put.
 * @param num_bytes    Number of bytes to put.
 *
 * @return  Number of bytes put into the buffer, can be less than request.
 *          On error, negative number.
 */
int auth_svc_buffer_put(struct auth_io_buffer *iobuf, const uint8_t *in_buf,  int num_bytes);

/**
 *  Gets bytes from the buffer, Non-Blocking
 *
 * @param iobuf       Pointer to IO buffer struct.
 * @param out_buf     Buffer to copy bytes into.
 * @param num_bytes   Number of bytes requested.
 *
 * @return  Number of bytes copied, can be less than requested.
 *          Negative number on error.
 */
int auth_svc_buffer_get(struct auth_io_buffer *iobuf, uint8_t *out_buf, int num_bytes);

/**
 * Gets number of bytes from the buffer, optionally waiting.
 *
 * @param iobuf      Pointer to IO buffer struct.
 * @param out_buf    Buffer to copy bytes into.
 * @param num_bytes  Number of bytes requested.
 * @param waitmsec   Wait time in msecs for data, K_FOREVER or K_NO_WAIT.
 *
 * @return Number of bytes copied. -EAGAIN if timed out.
 */
int auth_svc_buffer_get_wait(struct auth_io_buffer *iobuf, uint8_t *out_buf, int num_bytes, int waitmsec);

/**
 * Return the number of bytes in the buffer.
 *
 * @param iobuf  Pointer to IO buffer struct.
 *
 * @return  Number of bytes or error.
 */
int auth_svc_buffer_bytecount(struct auth_io_buffer *iobuf);

/**
 * Get number of bytes in buffer, wait number of msecs if no bytes are available.
 *
 * @param iobuf      Pointer to IO buffer struct.
 * @param waitmsec   Number of milliseconds to wait until bytes arrive in buffer.
 *
 * @return  Number of bytes, timeout, or error
 */
int auth_svc_buffer_bytecount_wait(struct auth_io_buffer *iobuf, uint32_t waitmsec);


/**
 * Return the number of available bytes to write into buffer.
 *
 * @param iobuf   Pointer to IO buffer struct.
 *
 * @return       Number of bytes avail to use.
 */
int auth_svc_buffer_avail_bytes(struct auth_io_buffer *iobuf);

/**
 * Determines if the buffer is full;
 *
 * @param iobuf  Pointer to IO buffer struct.
 *
 * @return  true if full, else fals.
 */
bool auth_svc_buffer_isfull(struct auth_io_buffer *iobuf);

/**
 * Clears the buffer contents.
 *
 * @param iobuf  Pointer to IO buffer struct.
 *
 * @return   0 on success, else negative on error.
 */
int auth_svc_buffer_clear(struct auth_io_buffer *iobuf);



#endif   /* ZEPHYR_INCLUDE_AUTH_INTERNAL_H_ */