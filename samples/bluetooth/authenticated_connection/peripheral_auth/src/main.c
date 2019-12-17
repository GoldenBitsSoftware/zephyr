
/* main.c - Application main entry point */

/*
 * SPDX-License-Identifier: Apache-2.0
 */


#include <zephyr/types.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <sys/printk.h>
#include <sys/byteorder.h>
#include <zephyr.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/conn.h>
#include <bluetooth/uuid.h>
#include <bluetooth/gatt.h>

#include <bluetooth/services/auth_svc.h>



#if 0
-- Misc notes....
* Authenticate via L2CAP or Attribute?
* Can authenticate via L2CAP, but still use attributes.
* OR use dedicated characteristic for authentication.
* Will need authentiation state machine.

* Add an authentication service to Zephyr, similar to hrs.c (heart rate service)?
#endif

struct bt_conn *default_conn;

static bool is_connected = false;

static struct authenticate_conn auth_conn;

/**
 * Set up the advertising data
 */
static const struct bt_data ad[] = {
        BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
        BT_DATA_BYTES(BT_DATA_UUID16_ALL, 0x10, 0x30 ),  //BT_UUID_AUTH_SVC
        // "Auth Svc"
        BT_DATA_BYTES(BT_DATA_NAME_SHORTENED, 0x41, 0x75, 0x74, 0x68, 0x20, 0x53, 0x76, 0x63),
};

/**
 *
 * @param conn
 * @param err
 */
static void connected(struct bt_conn *conn, u8_t err)
{
    if (err) {
        printk("Connection failed (err 0x%02x)\n", err);
    } else {
        default_conn = bt_conn_ref(conn);
        printk("Connected\n");

        auth_conn.conn = default_conn;

        bt_conn_set_context(conn, &auth_conn);

        /* After connecting, get the perpiheral GATT attributes */
        auth_svc_get_peripheral_attributes(&auth_conn);

        is_connected = true;


        // Start authentication??

        // is the service enumeration done by now?


    }
}

static void disconnected(struct bt_conn *conn, u8_t reason)
{
    printk("Disconnected (reason 0x%02x)\n", reason);

    is_connected = false;

    if (default_conn) {
        bt_conn_unref(default_conn);
        default_conn = NULL;
    }
}

/**
 * Connect callbacks
 */
static struct bt_conn_cb conn_callbacks = {
        .connected = connected,
        .disconnected = disconnected,
};

/**
 * If the paring security (pincode, etc..) failed.
 * @param conn
 */
static void auth_cancel(struct bt_conn *conn)
{
    char addr[BT_ADDR_LE_STR_LEN];

    bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

    printk("Pairing cancelled: %s\n", addr);
}

static struct bt_conn_auth_cb auth_cb_display = {
        .cancel = auth_cancel,
};

/**
 * Called after the BT module has initialized or not (error occurred).
 *
 * @param err
 */
static void bt_ready(int err)
{
    if (err) {
        printk("Bluetooth init failed (err %d)\n", err);
        return;
    }

    printk("Bluetooth initialized\n");

    /* Start advertising after BT module has initialized OK */
    err = bt_le_adv_start(BT_LE_ADV_CONN_NAME, ad, ARRAY_SIZE(ad), NULL, 0);
    if (err) {
        printk("Advertising failed to start (err %d)\n", err);
        return;
    }

    printk("Advertising successfully started\n");
}


static void auth_status(struct authenticate_conn *auth_conn, auth_status_t status, void *context)
{
    //
    printk("Authentication process status: %d\n", status);
}


void main(void)
{
    int err;
    uint8_t test_data[5] = {0xB, 0xE, 0xE, 0xF, 0x41};

    struct auth_connection_params con_params = {0};

    auth_error_t auth_err;
    auth_err = auth_svc_init(&auth_conn, &con_params, auth_status, NULL, (AUTH_CONN_PERIPHERAL|AUTH_CONN_DTLS_AUTH_METHOD));

    if(auth_err != AUTH_SUCCESS)
    {
        printk("Failed to init authentication service.\n");
        return;
    }

    err = bt_enable(bt_ready);
    if (err) {
        printk("Bluetooth init failed (err %d)\n", err);
        return;
    }

    bt_conn_cb_register(&conn_callbacks);
    bt_conn_auth_cb_register(&auth_cb_display);


    printk("Peripheral Auth started\n");

    while(true)
    {
        k_sleep(MSEC_PER_SEC * 5);

        // loop forever
        if(is_connected) {
            printk("Sending test data.\n");
            auth_svc_peripheral_tx(&auth_conn, test_data, sizeof(test_data));
        }
    }
}
