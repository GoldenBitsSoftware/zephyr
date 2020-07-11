/**
 *  @file  auth_loopback.c
 *
 *  @brief  Code to loopback test messages between a BLE Peripheral and Central.
 *          Intended for dev testing.   Maybe make this a sample?
 */

#include <zephyr/types.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <zephyr.h>
#include <init.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/conn.h>
#include <bluetooth/uuid.h>
#include <bluetooth/gatt.h>
#include <bluetooth/l2cap.h>

#define LOG_LEVEL CONFIG_BT_GATT_AUTHS_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_DECLARE(auth_svc, CONFIG_BT_GATT_AUTHS_LOG_LEVEL);

#include <bluetooth/services/auth_svc.h>

#include "auth_internal.h"



#ifdef CONFIG_LOOPBACK_TEST



#define  TEST_DATA_LEN          (200u)

/**
 * For testing
 * @param arg1
 * @param arg2
 * @param arg3
 */
void auth_looback_thread(void *arg1, void *arg2, void *arg3)
{
    int numbytes;
    uint8_t test_data[TEST_DATA_LEN];
    uint8_t recv_test_data[TEST_DATA_LEN];
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)arg1;

    /* init some test pattern */
    memset(test_data, 0x41, sizeof(test_data));

#if defined(CONFIG_BT_GATT_CLIENT)

    uint32_t test_len = TEST_DATA_LEN;
    if(auth_conn->is_central) {

        numbytes = auth_central_tx(auth_conn, test_data, test_len);
        if(numbytes < 0) {
            LOG_ERR("Central: failed initial send to peripheral, err: %d.\n", numbytes);
        } else {
            LOG_DBG("Central: wrote %d bytes.\n", numbytes);
        }
    }
#endif

    while(true) {

#if defined(CONFIG_BT_GATT_CLIENT)

         int rx_byte_count;
         if(auth_conn->is_central) {

             memset(recv_test_data, 0, sizeof(recv_test_data));
             rx_byte_count = 0;
             numbytes = 0;

             while(rx_byte_count < test_len) {

                 /* wait for echo back from peripheral */
                 numbytes = auth_central_rx(auth_conn, recv_test_data + rx_byte_count, test_len);

                 if(numbytes == -EAGAIN) {
                    LOG_ERR("Central: Timed out, trying read again.\n");
                    continue;
                 }

                 if(numbytes < 0) {
                    LOG_DBG("Central: failed receive from peripheral, err: %d.\n", numbytes);
                    break;
                 }

                 rx_byte_count += numbytes;

                 /* If zero bytes read, yield */
                 if(numbytes == 0) {
                     k_yield();
                 }
             }

             if(numbytes < 0) {
                 continue;
             }

             if(rx_byte_count == 0) {
                 /* Didn't read any bytes */
                 LOG_INF("Central: Read zero bytes from peripheral.\n");
                 continue;
             }

             LOG_DBG("Central: Read %d bytes from peripheral.\n", rx_byte_count);

             /* verify test pattern */
             if(memcmp(test_data, recv_test_data, test_len)) {
                 printk("Central: Failed data check.\n");
             }


             // send packet again
             numbytes = auth_central_tx(auth_conn, test_data, test_len);
             if(numbytes < 0) {
                 LOG_ERR("Central: failed to send, err: %d\n", numbytes);
             } else {
                 LOG_DBG("Central: wrote %d bytes.\n", numbytes);
             }
         }
#else
         /* peripehral */
         if(!auth_conn->is_central) {
             /* wait for test data from central */
            numbytes = auth_periph_rx(auth_conn, recv_test_data, sizeof(recv_test_data));

            if(numbytes < 0 && numbytes != -EAGAIN) {
                LOG_INF("Periph: Failed to recieve data, err: %d\n", numbytes);
            }

            if(numbytes == -EAGAIN) {
                /* just timed out, try again */
                LOG_INF("Periph: Timed out, trying to read again.\n");
                continue;
            }

            LOG_DBG("Periph: bytes read: %d\n", numbytes);

            if(numbytes == 0) {
                continue;
            }

             /* echo back */
             numbytes = auth_periph_tx(auth_conn, recv_test_data, numbytes);
            if(numbytes < 0) {
                LOG_ERR("Periph: Failed to send data, err: %d\n", numbytes);
            }
        }

#endif  /*  CONFIG_BT_GATT_CLIENT  */
    }

}

#endif


