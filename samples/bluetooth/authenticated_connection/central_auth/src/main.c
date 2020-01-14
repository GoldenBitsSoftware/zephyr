
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
#include <bluetooth/l2cap.h>
#include <logging/log.h>
#include <logging/log_ctrl.h>

#include <bluetooth/services/auth_svc.h>


LOG_MODULE_REGISTER(central_auth, CONFIG_BT_GATT_AUTHS_LOG_LEVEL);


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
#define SPIN_FOREVER        while(1) { };

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
static struct authenticate_conn central_auth_conn;
//struct auth_connection_params conn_params;


/* Auth service, client descriptor, server descriptor */
#define AUTH_SVC_GATT_COUNT             (4u)

#define AUTH_SVC_INDEX                  (0u)
#define AUTH_SVC_CLIENT_CHAR_INDEX      (1u)
#define AUTH_SVC_CLIENT_CCC_INDEX       (2u)  /* for enable/disable of notification */
#define AUTH_SVC_SERVER_CHAR_INDEX      (3u)

/**
 * Used to store Authentication GATT service and characteristics.
 */
typedef struct {
    const struct bt_uuid *uuid;
    const struct bt_gatt_attr *attr;
    uint16_t handle;
    uint16_t value_handle;
    uint8_t permissions;  /* Bitfields from: BT_GATT_PERM_NONE, BT_GATT_PERM_READ, .. in gatt.h */
    const uint32_t gatt_disc_type;
} auth_svc_gatt_t;


static uint32_t auth_desc_index;


/* Table content should match indexes above */
static auth_svc_gatt_t auth_svc_gatt_tbl[AUTH_SVC_GATT_COUNT] = {
        { BT_UUID_AUTH_SVC,             NULL, 0, 0, BT_GATT_PERM_NONE, BT_GATT_DISCOVER_PRIMARY },       //!< AUTH_SVC_INDEX
        { BT_UUID_AUTH_SVC_CLIENT_CHAR, NULL, 0, 0, BT_GATT_PERM_NONE, BT_GATT_DISCOVER_CHARACTERISTIC}, //!< AUTH_SVC_CLIENT_CHAR_INDEX
        { BT_UUID_GATT_CCC,             NULL, 0, 0, BT_GATT_PERM_NONE, BT_GATT_DISCOVER_DESCRIPTOR},     //!< AUTH_SVC_CLIENT_CCC_INDEX CCC for Client char */
        { BT_UUID_AUTH_SVC_SERVER_CHAR, NULL, 0, 0, BT_GATT_PERM_NONE, BT_GATT_DISCOVER_CHARACTERISTIC}   //!< AUTH_SVC_SERVER_CHAR_INDEX
 };

/**
 * Params used to change the connection MTU lenght.
 */
struct bt_gatt_exchange_params mtu_parms;

void mtu_change_cb(struct bt_conn *conn, u8_t err, struct bt_gatt_exchange_params *params)
{
    if(err) {
        LOG_ERR("Failed to set MTU, err: %d", err);
    } else {
        struct authenticate_conn *auth_conn = (struct authenticate_conn *)bt_con_get_context(conn);

        auth_conn->payload_size = bt_gatt_get_mtu(conn) - BLE_LINK_HEADER_BYTES;

        LOG_DBG("Successfuly set MTU to: %d", bt_gatt_get_mtu(conn));
        LOG_DBG("Payload size is: %d", auth_conn->payload_size );
    }
}


/**
 * Characteristic discovery function
 *
 *
 * @param conn
 * @param attr      Discovered attribute.  NOTE: This pointer will go out fo scope
 *                  do not save pointer for future use.
 * @param params
 * @return
 */
static u8_t discover_func(struct bt_conn *conn,
                          const struct bt_gatt_attr *attr,
                          struct bt_gatt_discover_params *params)
{
    int err;

    if (!attr) {
        LOG_INF("Discover complete, NULL attribute.");
        (void)memset(params, 0, sizeof(*params));
        return BT_GATT_ITER_STOP;
    }


    // debug output
    LOG_DBG("====auth_desc_index is: %d=====", auth_desc_index);
    LOG_DBG("[ATTRIBUTE] handle 0x%x", attr->handle);
    LOG_DBG("[ATTRIBUTE] value handle 0x%x", bt_gatt_attr_value_handle(attr));

    /* let's get string */
    char uuid_str[50];
    bt_uuid_to_str(attr->uuid, uuid_str, sizeof(uuid_str));
    LOG_DBG("Attribute UUID: %s", log_strdup(uuid_str));

    // print attribute UUID
    bt_uuid_to_str(discover_params.uuid, uuid_str, sizeof(uuid_str));
    LOG_DBG("Discovery UUID: %s", log_strdup(uuid_str));


    /**
     * Verify the correct UUID was found
     */
    if (bt_uuid_cmp(discover_params.uuid, auth_svc_gatt_tbl[auth_desc_index].uuid)) {

        /* Failed, not the UUID we're expecting */
        LOG_ERR("Error Unknown UUID.");
        return BT_GATT_ITER_STOP;
    }

    /* save off GATT info */
    auth_svc_gatt_tbl[auth_desc_index].attr = NULL;  /* NOTE: attr var not used for the Central */
    auth_svc_gatt_tbl[auth_desc_index].handle = attr->handle;
    auth_svc_gatt_tbl[auth_desc_index].value_handle = bt_gatt_attr_value_handle(attr);
    auth_svc_gatt_tbl[auth_desc_index].permissions = attr->perm;

    auth_desc_index++;

    /* Are all of the characteristics discovered? */
    if(auth_desc_index >= AUTH_SVC_GATT_COUNT) {

        /* we're done */
        LOG_INF("Discover complete");

        /* save off the server attribute handle */
        struct authenticate_conn *auth_conn = (struct authenticate_conn*)bt_con_get_context(conn);

        if(auth_conn != NULL) {
            auth_conn->server_char_handle = auth_svc_gatt_tbl[AUTH_SVC_SERVER_CHAR_INDEX].value_handle;
        } else {
            LOG_ERR("Failed to get connection context.");
        }

        /* setup the subscribe params
          Value handle for the Client characteristic for indication of
          peripheral data. */
        subscribe_params.notify = auth_svc_gatt_central_notify;
        subscribe_params.value = BT_GATT_CCC_NOTIFY;
        subscribe_params.value_handle = auth_svc_gatt_tbl[AUTH_SVC_CLIENT_CHAR_INDEX].value_handle;

        /* Handle for the CCC descriptor itself */
        subscribe_params.ccc_handle = auth_svc_gatt_tbl[AUTH_SVC_CLIENT_CCC_INDEX].handle;

        err = bt_gatt_subscribe(conn, &subscribe_params);
        if (err && err != -EALREADY) {
            LOG_ERR("Subscribe failed (err %d)", err);
        }

        /* Start auth process */
        err = auth_svc_start(auth_conn);
        if(err) {
            LOG_ERR("Failed to start auth service, err: %d", err);
        } else {
            LOG_INF("Started auth service.");
        }

        return BT_GATT_ITER_STOP;
    }

    /* set up the next discovery params */
    memcpy(&uuid, auth_svc_gatt_tbl[auth_desc_index ].uuid, sizeof(uuid));
    discover_params.uuid = &uuid.uuid;
    discover_params.start_handle = attr->handle + 1;
    discover_params.type = auth_svc_gatt_tbl[auth_desc_index].gatt_disc_type;


    /* Start discovery */
    err = bt_gatt_discover(conn, &discover_params);
    if (err) {
        LOG_ERR("Discover failed (err %d)", err);
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
        LOG_ERR("Failed to connect to %s (%u)", log_strdup(addr), conn_err);
        return;
    }

    LOG_INF("Connected: %s", log_strdup(addr));

    if (conn == default_conn) {

        /* Save off the bt connection, also set the auth context
         * into the bt connection for later use */
        central_auth_conn.conn = conn;
        bt_conn_set_context(conn, &central_auth_conn);


        /* If connecting via L2CAP, no need to discover attibutes
        * just connect via L2CAP layer */
        if(!central_auth_conn.use_gatt_attributes) {

            // start authentication service
            err = auth_svc_start(&central_auth_conn);

            if(err) {
                LOG_ERR("Failed to start L2CAP authentication, error: %d", err);
            }

            return;
        }

        /* set the max MTU, only for GATT interface */
        mtu_parms.func = mtu_change_cb;
        bt_gatt_exchange_mtu(conn, &mtu_parms);

        /* reset gatt discovery index */
        auth_desc_index = 0;

        // Else not using L2CAP, discover attributes
        memcpy(&uuid, auth_svc_gatt_tbl[auth_desc_index].uuid, sizeof(uuid));
        discover_params.uuid = &uuid.uuid;
        discover_params.func = discover_func;
        discover_params.start_handle = 0x0001;
        discover_params.end_handle = 0xffff;
        discover_params.type = auth_svc_gatt_tbl[auth_desc_index].gatt_disc_type;

        /**
         * Discover characteristics for the service
         */
        err = bt_gatt_discover(default_conn, &discover_params);
        if (err) {
            LOG_ERR("Discover failed(err %d)", err);
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

    LOG_DBG("[AD]: %u data_len %u", data->type, data->data_len);

    switch (data->type) {
        case BT_DATA_UUID16_SOME:
        case BT_DATA_UUID16_ALL:
            if (data->data_len % sizeof(u16_t) != 0U) {
                LOG_WRN("AD malformed");
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
                    LOG_ERR("Stop LE scan failed (err %d)", err);
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
    LOG_DBG("[DEVICE]: %s, AD evt type %u, AD data len %u, RSSI %i",
           log_strdup(dev), type, ad->len, rssi);

    /* We're only interested in connectable events */
    if (type == BT_LE_ADV_IND || type == BT_LE_ADV_DIRECT_IND) {
        bt_data_parse(ad, bt_adv_data_found, (void *)addr);
    }
}

static void disconnected(struct bt_conn *conn, u8_t reason)
{
    char addr[BT_ADDR_LE_STR_LEN];
    //int err;

    bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

    LOG_INF("Disconnected: %s (reason 0x%02x)", log_strdup(addr), reason);

    if (default_conn != conn) {
        return;
    }

    bt_conn_unref(default_conn);
    default_conn = NULL;
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
    LOG_INF("Starting BLE scanning");

    /* start scanning */
    int err = bt_le_scan_start(BT_LE_SCAN_ACTIVE, device_found);

    if (err) {
        LOG_ERR("Scanning failed to start (err %d)", err);
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
    LOG_DBG("Button pressed");

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
        LOG_ERR("Failed to get GPIO port: %s", PORT);
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


static void auth_status(struct authenticate_conn *auth_conn, auth_status_t status, void *context)
{
    /* display status */
    printk("Authentication process status: %s\n", auth_svc_getstatus_str(status));
}

static void process_log_msgs(void)
{
    while(log_process(false)) {
        ;  /* intentionally empty statement */
    }
}

void main(void)
{
    log_init();

    LOG_INF("Central Auth started.");

    /**
     * Add certificates to tls_credentls store
     */
    tls_credential_add();

    uint32_t flags = AUTH_CONN_CENTRAL|AUTH_CONN_DTLS_AUTH_METHOD;
    flags |= AUTH_CONN_USE_L2CAP;
    int err = auth_svc_init(&central_auth_conn, auth_status, NULL, flags);


    if(err) {
        LOG_ERR("Failed to init authentication service, err: %d.", err);
        return;
    }

    /**
     * @brief Enable the Bluetooth module.  Passing NULL to bt_enable
     * will block while the BLE stack is initialized.
     * nable bluetooth module
     */
    err = bt_enable(NULL);
    if (err) {
        LOG_ERR("Failed to enable the bluetooth module, err: %d", err);
        SPIN_FOREVER;
    }

    /* Register connect/disconnect callbacks */
    bt_conn_cb_register(&conn_callbacks);

    /* Init button 1 to start scanning process */
    init_button();


    /* just spin while the BT modules handle the connection and authentiation */
    while(true) {

        process_log_msgs();

        /* Let the handshake thread run */
        k_yield();
    }

}
