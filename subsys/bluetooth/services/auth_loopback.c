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

#define LOG_LEVEL CONFIG_BT_GATT_AUTHS_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_DECLARE(AUTH_SERVICE_LOG_MODULE);

#include <bluetooth/services/auth_svc.h>



#ifdef CONFIG_LOOPBACK_TEST


static int auth_central_tx(struct authenticate_conn *conn, uint8_t *data, size_t len)
{
    int err = 0;

    if(conn->use_gatt_attributes) {
        err = auth_svc_central_tx(conn, data, len);
    } else {
        /* use L2CAP layer */
        err = auth_svc_tx_l2cap(conn, data, len);
    }

    return err;
}

static int auth_central_rx(struct authenticate_conn *conn, uint8_t *buf, size_t rxbytes)
{
    int err;
    if(conn->use_gatt_attributes) {
        err = auth_svc_central_recv(conn, buf, rxbytes);
        //auth_svc_central_recv_timeout(void *ctx, unsigned char *buf, size_t len, uint32_t timeout);
    } else {
        err =  auth_svc_recv_l2cap(conn, buf, rxbytes);
        // int auth_svc_recv_over_l2cap_timeout(void *ctx, unsigned char *buf,
        //                                     size_t len, uint32_t timeout);
    }

    return err;
}

static int auth_periph_tx(struct authenticate_conn *conn, uint8_t *data, size_t len)
{
    int err;
    if(conn->use_gatt_attributes) {
        err = auth_svc_peripheral_tx(conn, data, len);
    } else {
        err = auth_svc_tx_l2cap(conn, data, len);
    }

    return err;
}

static int auth_periph_rx(struct authenticate_conn *conn, uint8_t *buf, size_t len)
{
    int err;

    if(conn->use_gatt_attributes) {
        err = auth_svc_peripheral_recv(conn, buf, len);
        // int auth_svc_peripheral_recv_timeout(void *ctx, unsigned char *buf, size_t len, uint32_t timeout)
    } else {
         err =  auth_svc_recv_l2cap(conn, buf, len);
        // int auth_svc_recv_over_l2cap_timeout(void *ctx, unsigned char *buf,
        //                                     size_t len, uint32_t timeout);

    }

    return err;
}



#define  TEST_DATA_LEN          (200u)

/**
 * For testing
 * @param arg1
 * @param arg2
 * @param arg3
 */
void auth_looback_thread(void *arg1, void *arg2, void *arg3)
{
    int err;
    uint32_t test_len = 10;
    uint8_t test_data[TEST_DATA_LEN];
    uint8_t recv_test_data[TEST_DATA_LEN];
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)arg1;

    /* init some test pattern */
    memset(test_data, 0x41, sizeof(test_data));

    if(auth_conn->is_central) {

        err = auth_central_tx(auth_conn, test_data, test_len);
        if(err) {
            printk("Central: failed initial send to peripheral, err: %d.\n", err);
        }
    }

    while(true) {


         if(auth_conn->is_central) {

             // wait for echo back from peripheral
             err = auth_central_rx(auth_conn, recv_test_data, test_len);
             if(err) {
                printk("Central: failed receive from peripheral, err: %d.\n", err);
             }


             // verify test pattern
             if(memcmp(test_data, recv_test_data, test_len)) {
                 // Failed!!
                 printk("Central: Failed data check.\n");
             }


            // vary the data length
            //test_len += 10;
            //if(test_len > TEST_DATA_LEN) {
            //     test_len = 10;
            //}

             // send packet again
             err = auth_central_tx(auth_conn, test_data, test_len);
             if(err) {
                 printk("Central: failed to send, err: %d\n", err);
             }


         } else {

             // peripehral

             // wait for test data from central
             /* TODO: how to know when received enough? */
            err = auth_periph_rx(auth_conn, recv_test_data, sizeof(recv_test_data));
            if(err) {
                printk("Periph: Failed to recieve data, err: %d\n", err);
            }

             // echo back
             err = auth_periph_tx(auth_conn, recv_test_data, sizeof(recv_test_data));
            if(err) {
                printk("Periph: Failed to send data, err: %d\n", err);
            }

         }

    }

}

#endif


