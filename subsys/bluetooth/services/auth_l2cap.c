/**
 *  @file  auth_l2cap.c
 *
 *  @brief  Handles L2CAP layer interface for the Central and Peripheral
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

#include <bluetooth/services/auth_svc.h>

#define LOG_LEVEL CONFIG_BT_GATT_AUTHS_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_DECLARE(AUTH_SERVICE_LOG_MODULE);




/* ==================== L2CAP I/O funcs ====================== */

/**
 * Question:  If we're using L2CAP, can we drop the use of authentication attributes?
 */
int auth_svc_tx_l2cap(void *ctx, const unsigned char *buf, size_t len)
{
    int ret = 0;
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)ctx;

    (void)auth_conn; // fix compiler warning

    return ret -1;
}


int auth_svc_recv_l2cap(void *ctx,
                        unsigned char *buf,
                        size_t len )
{
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)ctx;

    (void)auth_conn; // fix compiler warning

    return -1;
}


int auth_svc_recv_over_l2cap_timeout(void *ctx,
                                     unsigned char *buf,
                                     size_t len,
                                     uint32_t timeout )
{
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)ctx;

    (void)auth_conn; // fix compiler warning

    return -1;
}
