
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
#include <device.h>
#include <drivers/gpio.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/conn.h>
#include <bluetooth/uuid.h>
#include <bluetooth/gatt.h>
#include <sys/byteorder.h>

#include <bluetooth/services/auth_svc.h>

#define PORT	DT_ALIAS_SW0_GPIOS_CONTROLLER

/* change this to use another GPIO pin */
#ifdef DT_ALIAS_SW0_GPIOS_PIN
#define PIN     DT_ALIAS_SW0_GPIOS_PIN
#else
#error DT_ALIAS_SW0_GPIOS_PIN needs to be set in board.h
#endif

/* change to use another GPIO pin interrupt config */
#ifdef DT_ALIAS_SW0_GPIOS_FLAGS
#define EDGE    (DT_ALIAS_SW0_GPIOS_FLAGS | GPIO_INT_EDGE)
#else
/*
 * If DT_ALIAS_SW0_GPIOS_FLAGS not defined used default EDGE value.
 * Change this to use a different interrupt trigger
 */
#define EDGE    (GPIO_INT_EDGE | GPIO_INT_ACTIVE_LOW)
#endif
#define PULL_UP DT_ALIAS_SW0_GPIOS_FLAGS

/**
 * Handy macro to spin forever
 */
#define SPIN_FOREVER        while(1) {};

static struct bt_conn *default_conn;
static struct bt_uuid_16 uuid = BT_UUID_INIT_16(0);
static struct bt_gatt_discover_params discover_params;
static struct bt_gatt_subscribe_params subscribe_params;

/**
 * Button callback struct
 */
static struct gpio_callback gpio_cb;

/**
 * Authentication connect struct
 */
static struct authenticate_conn auth_conn;

/**
 *
 * @param conn
 * @param params
 * @param data
 * @param length
 * @return
 */
static u8_t notify_func(struct bt_conn *conn,
                        struct bt_gatt_subscribe_params *params,
                        const void *data, u16_t length)
{
    if (!data) {
        printk("[UNSUBSCRIBED]\n");
        params->value_handle = 0U;
        return BT_GATT_ITER_STOP;
    }

    printk("[NOTIFICATION] data %p length %u\n", data, length);

    return BT_GATT_ITER_CONTINUE;
}

/**
 * Characteristic discovery function
 *
 * @param conn
 * @param attr
 * @param params
 * @return
 */
static u8_t discover_func(struct bt_conn *conn,
                          const struct bt_gatt_attr *attr,
                          struct bt_gatt_discover_params *params)
{
    int err;

    if (!attr) {
        printk("Discover complete\n");
        (void)memset(params, 0, sizeof(*params));

        /**
        * TODO:  If authenticating via L2CAP directly, then
        * create a channel here.
        * #if defined(CONFIG_BT_AUTH_L2CAP)
        * #endif
        */

        //  Put all of the BLE attribute info into the struct authenticate_con
        //auth_srv_set_bleinfo(struct authenticate_conn *auth_con, server_attr, client_attr);
        //auth_error_t auth_svc_start(struct authenticate_conn *auth_con, attributes, conn);

        return BT_GATT_ITER_STOP;
    }

    printk("[ATTRIBUTE] handle %u\n", attr->handle);

    if (!bt_uuid_cmp(discover_params.uuid, BT_UUID_HRS)) {
        memcpy(&uuid, BT_UUID_HRS_MEASUREMENT, sizeof(uuid));
        discover_params.uuid = &uuid.uuid;
        discover_params.start_handle = attr->handle + 1;
        discover_params.type = BT_GATT_DISCOVER_CHARACTERISTIC;

        err = bt_gatt_discover(conn, &discover_params);
        if (err) {
            printk("Discover failed (err %d)\n", err);
        }
    } else if (!bt_uuid_cmp(discover_params.uuid,
                            BT_UUID_HRS_MEASUREMENT)) {
        memcpy(&uuid, BT_UUID_GATT_CCC, sizeof(uuid));
        discover_params.uuid = &uuid.uuid;
        discover_params.start_handle = attr->handle + 2;
        discover_params.type = BT_GATT_DISCOVER_DESCRIPTOR;
        subscribe_params.value_handle = bt_gatt_attr_value_handle(attr);

        err = bt_gatt_discover(conn, &discover_params);
        if (err) {
            printk("Discover failed (err %d)\n", err);
        }
    } else {
        subscribe_params.notify = notify_func;
        subscribe_params.value = BT_GATT_CCC_NOTIFY;
        subscribe_params.ccc_handle = attr->handle;

        err = bt_gatt_subscribe(conn, &subscribe_params);
        if (err && err != -EALREADY) {
            printk("Subscribe failed (err %d)\n", err);
        } else {
            printk("[SUBSCRIBED]\n");
        }

        return BT_GATT_ITER_STOP;
    }

    return BT_GATT_ITER_STOP;
}

/**
 * Connected to the peripheral device
 *
 * @param conn
 * @param conn_err
 */
static void connected(struct bt_conn *conn, u8_t conn_err)
{
    char addr[BT_ADDR_LE_STR_LEN];
    int err;

    bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

    if (conn_err) {
        printk("Failed to connect to %s (%u)\n", addr, conn_err);
        return;
    }

    printk("Connected: %s\n", addr);

    if (conn == default_conn) {
        memcpy(&uuid, BT_UUID_HRS, sizeof(uuid));
        discover_params.uuid = &uuid.uuid;
        discover_params.func = discover_func;
        discover_params.start_handle = 0x0001;
        discover_params.end_handle = 0xffff;
        discover_params.type = BT_GATT_DISCOVER_PRIMARY;

        /**
         * Discover characteristics for the service
         */
        err = bt_gatt_discover(default_conn, &discover_params);
        if (err) {
            printk("Discover failed(err %d)\n", err);
            return;
        }
    }
}

/**
 * Parse through the BLE adv data, looking for our service
 *
 * @param data
 * @param user_data
 * @return
 */
static bool bt_adv_data_found(struct bt_data *data, void *user_data)
{
    bt_addr_le_t *addr = user_data;
    int i;

    printk("[AD]: %u data_len %u\n", data->type, data->data_len);

    switch (data->type) {
        case BT_DATA_UUID16_SOME:
        case BT_DATA_UUID16_ALL:
            if (data->data_len % sizeof(u16_t) != 0U) {
                printk("AD malformed\n");
                return true;
            }

            for (i = 0; i < data->data_len; i += sizeof(u16_t)) {
                struct bt_uuid *uuid;
                u16_t u16;
                int err;

                memcpy(&u16, &data->data[i], sizeof(u16));
                uuid = BT_UUID_DECLARE_16(sys_le16_to_cpu(u16));

                /**
                 * Is this the service we're looking for? If not continue
                 * else stop the scan and connect to the device.
                 */
                if (bt_uuid_cmp(uuid, BT_UUID_AUTH_SVC)) {
                    continue;
                }

                /* stop scanning, we've found the service */
                err = bt_le_scan_stop();
                if (err) {
                    printk("Stop LE scan failed (err %d)\n", err);
                    continue;
                }

                /**
                 * @brief  Connect to the device, NOTE
                 */
                default_conn = bt_conn_create_le(addr,
                                                 BT_LE_CONN_PARAM_DEFAULT);


                return false;
            }
    }

    return true;
}

/**
 * Found a device when scanning
 *
 * @param addr
 * @param rssi
 * @param type
 * @param ad
 */
static void device_found(const bt_addr_le_t *addr, s8_t rssi, u8_t type,
                         struct net_buf_simple *ad)
{
    char dev[BT_ADDR_LE_STR_LEN];

    bt_addr_le_to_str(addr, dev, sizeof(dev));
    printk("[DEVICE]: %s, AD evt type %u, AD data len %u, RSSI %i\n",
           dev, type, ad->len, rssi);

    /* We're only interested in connectable events */
    if (type == BT_LE_ADV_IND || type == BT_LE_ADV_DIRECT_IND) {
        bt_data_parse(ad, bt_adv_data_found, (void *)addr);
    }
}

static void disconnected(struct bt_conn *conn, u8_t reason)
{
    char addr[BT_ADDR_LE_STR_LEN];
    int err;

    bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

    printk("Disconnected: %s (reason 0x%02x)\n", addr, reason);

    if (default_conn != conn) {
        return;
    }

    bt_conn_unref(default_conn);
    default_conn = NULL;

    /* This demo doesn't require active scan */
    err = bt_le_scan_start(BT_LE_SCAN_PASSIVE, device_found);
    if (err) {
        printk("Scanning failed to start (err %d)\n", err);
    }
}

/**
 * Connection callbacks
 */
static struct bt_conn_cb conn_callbacks = {
        .connected = connected,
        .disconnected = disconnected,
};

static struct k_work ble_start_scan_work;

/**
 *
 */
static void ble_scan_work_func(struct k_work *work)
{
    printk("Starting BLE scanning\n");

    /* start scanning */
    int err = bt_le_scan_start(BT_LE_SCAN_ACTIVE, device_found);

    if (err) {
        printk("Scanning failed to start (err %d)\n", err);
    }

}

/**
 * Called when button is pressed, note called in interrupt context
 *
 * @param gpiob
 * @param cb
 * @param pins
 */
static void button_pressed(struct device *gpiob, struct gpio_callback *cb,
                           u32_t pins)
{
    printk("Button pressed\n");

    /* Since this function is called directly by the interrupt, start
     * the BLE in a reguar thread context.  Create a work item which
     * will start the BLE scanning
     */
    k_work_init(&ble_start_scan_work, ble_scan_work_func);

    k_work_submit(&ble_start_scan_work);
}

/**
 *
 * @return
 */
static int init_button(void)
{
    struct device *gpiob;

    gpiob = device_get_binding(PORT);
    if (!gpiob) {
        printk("Failed to get GPIO port: %s\n", PORT);
        return -1;
    }

    gpio_pin_configure(gpiob, PIN,
                       GPIO_DIR_IN | GPIO_INT |  PULL_UP | EDGE);

    gpio_init_callback(&gpio_cb, button_pressed, BIT(PIN));

    gpio_add_callback(gpiob, &gpio_cb);
    gpio_pin_enable_callback(gpiob, PIN);

    return 0;
}

static int tls_credential_add()
{
    /*
     * TODO
    int err = tls_credential_add(SERVER_CERTIFICATE_TAG,
                                 TLS_CREDENTIAL_SERVER_CERTIFICATE,
                                 server_certificate,
                                 sizeof(server_certificate));

    */

    return -1;
}


static void auth_status(auth_status_t status, void *context);
{
    //
    printk("Authentication process status: %d\n", status);
}

void main(void)
{
    struct auth_connection_params conn_params;

    // TBD, not used just yet
    memset(&conn_params, 0, sizeof(conn_params))

    printk("Central Auth started\n");

    /**
     * Add certificates to tls_credentls store
     */
    tls_credential_add();

    auth_error_t auth_err;
    err = auth_svc_init(auth_conn, &conn_params, auth_status, NULL, (AUTH_CONN_CENTRAL|AUTH_CONN_DTLS_AUTH_METHOD));

    if(err != AUTH_SUCCESS)
    {
        printk("Failed to init authentication service.\n");
        return;
    }

    /**
     * @brief Enable the Bluetooth module.  Passing NULL to bt_enable
     * will block while the BLE stack is initialized.
     * nable bluetooth module
     */
    int err;
    err = bt_enable(NULL);

    if (err) {
        printk("Failed to enable the bluetooth module, err: %d\n", err);
        SPIN_FOREVER;
    }

    /* Register connect/disconnect callbacks */
    bt_conn_cb_register(&conn_callbacks);

    /* Init button 1 to start scanning process */
    init_button();

    /* just spin while the BT modules handle the connection and authentiation */
    SPIN_FOREVER;

}
