/**
 * @file auth_internal.h
 *
 * @brief  BLE Authentication Service functions internal to the Authentication
 *         service.  Not intended for external use.
 */

#ifndef ZEPHYR_INCLUDE_AUTH_INTERNAL_H_
#define ZEPHYR_INCLUDE_AUTH_INTERNAL_H_


/**
 *  Used by peripheral code to get the service attributes.
 *
 * @param auth_con  Pointer to Authentication connection struct.
 *
 * @return  0 on success else one of AUTH_ERROR_* values.
 */
int auth_svc_get_peripheral_attributes(struct authenticate_conn *auth_con);


/**
 * Routines to read/write from Authentication service attributes
 */

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


/**
 *  Used by the Central to send data bytes to the Peripheral.  Also used as MbedTLS
 *  BIO function.  If necessary, will break up data into several sends depending
 *  on the MTU size.
 *
 * @param ctx   Context, pointer to Authentication connection struct.
 * @param buf   Buffer to send.
 * @param len   Buffer size.
 *
 * @return  Number of bytes sent or negative error value.
 */
int auth_svc_central_tx(void *ctx, const unsigned char *buf, size_t len);

/**
 * Used by the Central to read data from the receive buffer.  Will not
 * block, if no bytes are available from the Peripheral returns 0.
 * Also used as MbedTLS BIO function.
 *
 * @param ctx  Context, pointer to Authentication connection struct.
 * @param buf  Buffer to copy byes into.
 * @param len  Buffer length.
 *
 * @return  Number of bytes returned, 0 if no bytes returned, or negative if
 *          an error occurred.
 */
int auth_svc_central_recv(void *ctx, unsigned char *buf, size_t len);

/**
 * Used by the Central to receive data from the Peripheral.  Will block until data is
 * received or a timeout has occurred.  Also used as MbedTLS BIO function.
 *
 * @param ctx      Context, pointer to Authentication connection struct.
 * @param buf      Buffer to copy byes into.
 * @param len      Buffer length.
 * @param timeout  Wait time in msecs for data, K_FOREVER or K_NO_WAIT.
 *
 * @return  Number of bytes returned, 0 if no bytes returned, or negative if
 *          an error occurred.
 */
int auth_svc_central_recv_timeout(void *ctx, unsigned char *buf, size_t len, uint32_t timeout);

/**
 * Used by the Peripheral to send data to the Central. Will break up buffer to max MTU
 * sizes if necessary and send multiple PDUs.  Uses Write Indications to get acknowledgement
 * from the Central before sending additional packet.
 * Also used as MbedTLS BIO function.
 *
 * @param ctx   Context, pointer to Authentication connection struct.
 * @param buf   Data to send
 * @param len   Data length.
 *
 * @return  Number of bytes send, or negative if an error occurred.
 */
int auth_svc_peripheral_tx(void *ctx, const unsigned char *buf, size_t len);

/**
 * Used by the Peripheral to read data from the receive buffer. Non-blocking.
 * Also used as MbedTLS BIO function.
 *
 * @param ctx Context, pointer to Authentication connection struct.
 * @param buf  Buffer to copy bytes into.
 * @param len  Number of bytes requested.
 *
 * @return Number of bytes returned, 0 if no bytes, of negative if an error occurred.
 */
int auth_svc_peripheral_recv(void *ctx,unsigned char *buf, size_t len);

/**
 * Used by the Peripheral to read data from the receive buffer.  Blocking call.
 * Also used as MbedTLS BIO function.
 *
 * @param ctx      Context, pointer to Authentication connection struct.
 * @param buf      Buffer to copy bytes into.
 * @param len      Number of bytes requested.
 * @param timeout  Wait time in msecs for data, K_FOREVER or K_NO_WAIT.
 *
 * @return  Number of bytes returned, or -EAGAIN if timed out.
 */
int auth_svc_peripheral_recv_timeout(void *ctx, unsigned char *buf, size_t len, uint32_t timeout);


/**
 * Routines to read/write over L2CAP
 */
int auth_svc_tx_l2cap(void *ctx, const unsigned char *buf, size_t len);
int auth_svc_recv_l2cap(void *ctx, unsigned char *buf, size_t len);
int auth_svc_recv_over_l2cap_timeout(void *ctx, unsigned char *buf,
                                     size_t len, uint32_t timeout);


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
int auth_svc_buffer_get(struct auth_io_buffer *iobuf, uint8_t *out_buf,  int num_bytes);

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
 * @return  Number of bytes.
 */
int auth_svc_buffer_bytecount(struct auth_io_buffer *iobuf);

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