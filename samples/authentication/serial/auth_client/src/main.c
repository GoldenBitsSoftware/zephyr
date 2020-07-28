
/* main.c - Application main entry point
 *          Sample authenticating over a UART link */

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
#include <drivers/uart.h>


#include <auth/auth_lib.h>
#include <logging/log.h>
#include <logging/log_ctrl.h>


LOG_MODULE_REGISTER(auth_serial_client, CONFIG_AUTH_LOG_LEVEL);


static struct device *uart_dev;

static struct uart_config uart_cfg = {
    .baudrate = 115200,
    .parity = UART_CFG_PARITY_NONE,
    .stop_bits = UART_CFG_STOP_BITS_1,
    .data_bits = UART_CFG_DATA_BITS_8,
    .flow_ctrl = UART_CFG_FLOW_CTRL_NONE,
};


/* Authentication connection info */
static struct authenticate_conn auth_conn_serial;


void auth_status_callback(struct authenticate_conn *auth_conn, enum auth_status status, void *context)
{
    LOG_INF("Authentiction status: %s", auth_lib_getstatus_str(status));

    if((status == AUTH_STATUS_FAILED) || (status == AUTH_STATUS_AUTHENTICATION_FAILED) ||
       (status == AUTH_STATUS_SUCCESSFUL))
    {
        /* Authentication has finished */
        auth_lib_deinit(auth_conn);

    }
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

static int config_uart(void)
{
    struct auth_xp_serial_params xp_params;

    uart_dev = device_get_binding(DT_ALIAS_UART_0_LABEL);

    int err = uart_configure(uart_dev, &uart_cfg);

    if(err) {
        LOG_ERR("Failed to configure UART, err: %d", err);
        return err;
    }

    /* If successful,then init lower transport layer. */
    xp_params.serial_dev = uart_dev;
    //xp_params.payload_size = 2048;

    err = auth_xport_init(&auth_conn_serial.xport_hdl,  0, &xp_params);

    if(err) {
        LOG_ERR("Failed to initialize authentication transport, error: %d", err);
    }

    return err;
}


void main(void)
{
    log_init();

    /* init authentication library */
    int err = auth_lib_init(&auth_conn_serial, auth_status_callback, NULL,
                                  AUTH_CONN_CLIENT|AUTH_CONN_CHALLENGE_AUTH_METHOD);

    /* If successful, then configure the UAR and start the
     * authentication process */
    if(!err) {

        /* configure the UART and init the lower serial transport */
        err = config_uart();

        /* start authentication */
        if(!err) {
            err = auth_lib_start(&auth_conn_serial);

            if(err) {
                LOG_ERR("Failed to start authentication, err: %d", err);
            }
        }

    }

    /* does not return */
    idle_process();

    /* should not reach here */
}
