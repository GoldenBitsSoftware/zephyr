
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

#include <net/tls_credentials.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/conn.h>
#include <bluetooth/uuid.h>
#include <bluetooth/gatt.h>

#include <auth/auth_lib.h>
#include <logging/log.h>
#include <logging/log_ctrl.h>



#if defined(CONFIG_DTLS_AUTH_METHOD)
#include "../cert_chain/ble_auth_all_certs/bleauth_ca_chain.h"
#include "../cert_chain/ble_auth_all_certs/bleauth_central_cert.h"
#include "../cert_chain/ble_auth_all_certs/bleauth_peripheral_key.h"
#include "../cert_chain/ble_auth_all_certs/bleauth_central_key.h"
#endif


LOG_MODULE_REGISTER(central_auth, CONFIG_AUTH_LOG_LEVEL);


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

#if defined(CONFIG_DTLS_AUTH_METHOD)
/* The Root and Intermediate Certs, in a single chain, PEM format.*/
static struct auth_tls_certs ca_cert_chain = {
    .cert_type = AUTH_CERT_CA_CHAIN,
    .cert_data = bleauth_root_ca_chain_pem,
    .cert_len = sizeof(bleauth_root_ca_chain_pem),
    .private_key = NULL,            /* not used for CA certs */
    .key_len = 0u
};

static struct auth_tls_certs device_cert = {
    .cert_type = AUTH_CERT_END_DEVICE,
    .cert_data = bleauth_central_cert_pem,
    .cert_len = sizeof(bleauth_central_cert_pem),
    .private_key = bleauth_central_key_pem,
    .key_len = sizeof(bleauth_central_key_pem)
};

/**
 * @brief Struct containing all of the certs for this Central device.
 */
static struct auth_cert_container certs = {
        .num_ca_certs = 1,            ///<  1 if passing a chain of CA certs.
        .ca_certs = &ca_cert_chain,   ///<  Cert chain, contians Root and Intermediate
        .device_cert = &device_cert   ///<  End device cert.
};
#endif


/**
 * Params used to change the connection MTU lenght.
 */
struct bt_gatt_exchange_params mtu_parms;

void mtu_change_cb(struct bt_conn *conn, u8_t err, struct bt_gatt_exchange_params *params)
{
    if(err) {
        LOG_ERR("Failed to set MTU, err: %d", err);
    } else {
        //auth_conn->payload_size = bt_gatt_get_mtu(conn) - BLE_LINK_HEADER_BYTES;

        LOG_DBG("Successfuly set MTU to: %d", bt_gatt_get_mtu(conn));
        //LOG_DBG("Payload size is: %d", auth_conn->payload_size );
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


        /* setup the subscribe params
          Value handle for the Client characteristic for indication of
          peripheral data. */
        subscribe_params.notify = auth_xp_bt_central_notify;
        subscribe_params.value = BT_GATT_CCC_NOTIFY;
        subscribe_params.value_handle = auth_svc_gatt_tbl[AUTH_SVC_CLIENT_CHAR_INDEX].value_handle;

        /* Handle for the CCC descriptor itself */
        subscribe_params.ccc_handle = auth_svc_gatt_tbl[AUTH_SVC_CLIENT_CCC_INDEX].handle;

        err = bt_gatt_subscribe(conn, &subscribe_params);
        if (err && err != -EALREADY) {
            LOG_ERR("Subscribe failed (err %d)", err);
        }

        /* Get the server BT characteristic, the central sends data to this characteristic */
        uint16_t server_char_handle = auth_svc_gatt_tbl[AUTH_SVC_SERVER_CHAR_INDEX].value_handle;

        /* setup the BT transport params */
        struct auth_xp_bt_params xport_params = {.conn = conn, .is_central = true,
                                                 .server_char_hdl = server_char_handle };

        err = auth_xport_init(&central_auth_conn.xport_hdl, 0, &xport_params);

        if(err) {
            LOG_ERR("Failed to initialize Bluetooth transport, err: %d", err);
            return BT_GATT_ITER_STOP;
        }

        /* Start auth process */
        err = auth_lib_start(&central_auth_conn);
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

        /* Save off the bt connection */
        central_auth_conn.conn = conn;

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
                default_conn = bt_conn_create_le(addr, BT_LE_CONN_PARAM_DEFAULT);
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

    bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

    LOG_INF("Disconnected: %s (reason 0x%02x)", log_strdup(addr), reason);

    if (default_conn != conn) {
        return;
    }

    /* de init transport */
    /* Send disconnect event to BT transport. */
    struct auth_xport_evt conn_evt = {.event = XP_EVT_DISCONNECT };
    auth_xport_event(central_auth_conn.xport_hdl, &conn_evt);

    /* Deinit lower transport */
    auth_xport_deinit(central_auth_conn.xport_hdl);
    central_auth_conn.xport_hdl = NULL;

    bt_conn_unref(default_conn);
    default_conn = NULL;
    central_auth_conn.conn = NULL;
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


static void auth_status(struct authenticate_conn *auth_conn, enum auth_status status, void *context)
{
    /* display status */
    printk("Authentication process status: %s\n", auth_lib_getstatus_str(status));
}

static void process_log_msgs(void)
{
    while(log_process(false)) {
        ;  /* intentionally empty statement */
    }
}

static void idle_process(void)
{
    /* Just spin while the BT modules handle the connection and authentication. */
    while(true) {

        process_log_msgs();

        /* Let the handshake thread run */
        k_yield();
    }
}


void main(void)
{
    int err = 0;

    log_init();

    LOG_INF("Client Auth started.");


    uint32_t flags = AUTH_CONN_CLIENT;

#if defined(CONFIG_AUTH_DTLS) && defined(CONFIG_AUTH_CHALLENGE_RESPONSE)
#error Invalid authenticaiton config, either DTLS or Challenge-Response, not both.
#endif

#if defined(CONFIG_AUTH_DTLS)
     flags |= AUTH_CONN_DTLS_AUTH_METHOD;
#endif

#if defined(CONFIG_AUTH_CHALLENGE_RESPONSE)
     flags |= AUTH_CONN_CHALLENGE_AUTH_METHOD;
#endif


#if defined(CONFIG_AUTH_DTLS)
    /**
    * Add certificates to authentication instance.
    */
    auth_svc_set_tls_certs(&central_auth_conn, &certs);
#endif

    err = auth_lib_init(&central_auth_conn, auth_status, NULL, flags);

    if(err) {
        LOG_ERR("Failed to init authentication service, err: %d.", err);
        idle_process();  /* does not return */
    }

    /**
     * @brief Enable the Bluetooth module.  Passing NULL to bt_enable
     * will block while the BLE stack is initialized.
     * Enable bluetooth module
     */
    err = bt_enable(NULL);
    if (err) {
        LOG_ERR("Failed to enable the bluetooth module, err: %d", err);
        idle_process();  /* does not return */
    }

    /* Register connect/disconnect callbacks */
    bt_conn_cb_register(&conn_callbacks);

    /* Init button 1 to start scanning process */
    init_button();

    /* does not return */
    idle_process();

    /* should not reach here */

}
