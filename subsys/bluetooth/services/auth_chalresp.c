/**
 *  @file  auth_chalresp.c
 *
 *  @brief  Challenge-Response method for authenticating a BLE connection.
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
#include <random/rand32.h>

#include <mbedtls/error.h>
#include <mbedtls/sha256.h>


#define LOG_LEVEL CONFIG_BT_GATT_AUTHS_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_DECLARE(auth_svc, CONFIG_BT_GATT_AUTHS_LOG_LEVEL);

#define AUTH_SHA256_HASH                    (32u)
#define AUTH_SHARED_KEY_LEN                 (32u)
#define AUTH_CHALLENGE_LEN                  (32u)
#define AUTH_CHAL_RESPONSE_LEN              AUTH_SHA256_HASH


#define CHALLENGE_RESP_SOH                  0x65A2    /* magic number to help identify and parse messages */

/* Message IDs */
#define AUTH_CENTRAL_CHAL_MSG_ID            0x01
#define AUTH_PERIPH_CHALRESP_MSG_ID         0x02
#define AUTH_CENTRAL_CHALRESP_MSG_ID        0x03
#define AUTH_CHALRESP_RESULT_MSG_ID         0x04

/* Timeout for receive */
#define AUTH_RX_TIMEOUT_MSEC                (3000u)


/* ensure structs are byte aligned */
#pragma pack(push, 1)

struct chalresp_header {
    uint16_t soh;          /* start of header */
    uint8_t msg_id;
};

struct central_challenge  {
    struct chalresp_header hdr;
    uint8_t central_challenge[AUTH_CHALLENGE_LEN];
};

struct periph_chal_response {
    struct chalresp_header hdr;
    uint8_t periph_response[AUTH_CHAL_RESPONSE_LEN];
    uint8_t periph_challenge[AUTH_CHALLENGE_LEN];
};

struct central_chal_resp {
    struct chalresp_header hdr;
    uint8_t central_response[AUTH_CHAL_RESPONSE_LEN];
};

/* From Central or Peripheral indicating result of challenge-response */
struct auth_chalresp_result {
    struct chalresp_header hdr;
    uint8_t result;    /* 0 == success, 1 == failure */
};

#pragma pack(pop)

#ifdef CONFIG_CHALLENGE_RESP_AUTH_METHOD

/**
 * Shared key.
 * @brief  In a production system, the shared key should be stored in a
 * secure hardware store such as an ECC608A or TrustZone.
 */
static uint8_t shared_key[AUTH_SHARED_KEY_LEN] = {
    0xBD, 0x84, 0xDC, 0x6E, 0x5C, 0x77, 0x41, 0x58, 0xE8, 0xFB, 0x1D, 0xB9, 0x95, 0x39, 0x20, 0xE4,
    0xC5, 0x03, 0x69, 0x9D, 0xBC, 0x53, 0x08, 0x20, 0x1E, 0xF4, 0x72, 0x8E, 0x90, 0x56, 0x49, 0xA8 };


static void auth_chalresp_status(struct authenticate_conn *auth_conn, auth_status_t status)
{
     if(auth_conn->status_cb_func != NULL) {
         auth_conn->status_cb_func(auth_conn, status, auth_conn->callback_context);
     }
}

/**
 * Utility function to create the has of the random challenge and the shared key.
 */
static int auth_chalresp_hash(const uint8_t *random_chal, uint8_t *hash)
{
    int err = 0;
    mbedtls_sha256_context ctx;

    mbedtls_sha256_init(&ctx);

    err = mbedtls_sha256_starts_ret(&ctx, false);

    if(err) {
        return err;
    }

    /* Update the hash with the random challenge followed by the shared key. */
    if((err = mbedtls_sha256_update_ret(&ctx, random_chal, AUTH_CHALLENGE_LEN)) != 0 ||
       (err = mbedtls_sha256_update_ret(&ctx, shared_key, AUTH_SHARED_KEY_LEN)) != 0) {
        return err;
    }

    /* calc the final hash */
    err = mbedtls_sha256_finish_ret(&ctx, hash);

    return err;
}

static bool auth_check_msg(struct chalresp_header *hdr, const uint8_t msg_id)
{
    if((hdr->soh != CHALLENGE_RESP_SOH) || (hdr->msg_id != msg_id)) {
        return false;
    }

    return true;
}

#if defined(CONFIG_BT_GATT_CLIENT)

static bool auth_central_send_challenge(struct authenticate_conn *auth_conn, const uint8_t *random_chal)
{
    int numbytes;
    struct central_challenge chal;

     /* build and send challenge message to Peripheral */
    memset(&chal, 0, sizeof(chal));
    chal.hdr.soh = CHALLENGE_RESP_SOH;
    chal.hdr.msg_id = AUTH_CENTRAL_CHAL_MSG_ID;

    memcpy(&chal.central_challenge, random_chal, sizeof(chal.central_challenge));

    /* send to peripheral */
    numbytes = auth_svc_central_tx(auth_conn, (const unsigned char*)&chal, sizeof(chal));

    if((numbytes <= 0) || (numbytes != sizeof(chal))) {
        /* error */
        LOG_ERR("Error sending challenge to peripherl, err: %d", numbytes);
        return false;
    }

    return true;
}

static bool auth_central_recv_chal_resp(struct authenticate_conn *auth_conn, const uint8_t *random_chal, auth_status_t *status)
{
    uint8_t hash[AUTH_CHAL_RESPONSE_LEN];
    int numbytes;
    int err;
    struct periph_chal_response perph_resp;
    struct central_chal_resp central_resp;
    struct auth_chalresp_result chal_result;
    uint8_t *buf = (uint8_t*)&perph_resp;
    int len = sizeof(perph_resp);

    while(len > 0) {

        numbytes = auth_svc_central_recv_timeout(auth_conn, buf, len, AUTH_RX_TIMEOUT_MSEC);

        if(numbytes <= 0) {
            LOG_ERR("Failed to read peripheral challenge response, err: %d", numbytes);
            *status = AUTH_STATUS_FAILED;
            return false;
        }

        buf += numbytes;
        len -= numbytes;
    }

    /* check message */
    if(!auth_check_msg(&perph_resp.hdr, AUTH_PERIPH_CHALRESP_MSG_ID)) {
        LOG_ERR("Invalid message recieved from the peripheral.");
        *status = AUTH_STATUS_FAILED;
        return false;
    }


    /* now verify response, is the response correct?  Hash the random challenge
     * with the shared key */
    err = auth_chalresp_hash(random_chal, hash);

    if(err) {
        LOG_ERR("Failed to calc hash, err: %d", err);
        *status = AUTH_STATUS_FAILED;
        return false;
    }

    /* Does the response match what is expected? */
    if(memcmp(hash, perph_resp.periph_response, sizeof(hash))) {
        /* authententication failed */
        LOG_ERR("Peripherial authentication failed.");
        *status = AUTH_STATUS_AUTHENTICATION_FAILED;

        /* send failed message to the Peripheral */
        memset(&chal_result, 0, sizeof(chal_result));
        chal_result.hdr.soh = CHALLENGE_RESP_SOH;
        chal_result.hdr.msg_id = AUTH_CHALRESP_RESULT_MSG_ID;
        chal_result.result = 1;

        numbytes = auth_svc_central_tx(auth_conn, (const unsigned char*)&chal_result, sizeof(chal_result));

        if((numbytes <= 0) || (numbytes != sizeof(chal_result))) {
            LOG_ERR("Failed to send authentication error result to peripheral.");
        }

        return false;
    }

    /* init Central response message */
    memset(&central_resp, 0, sizeof(central_resp));
    central_resp.hdr.soh = CHALLENGE_RESP_SOH;
    central_resp.hdr.msg_id = AUTH_CENTRAL_CHALRESP_MSG_ID;

    /* Create response to the peripheral's random challeng */
     err = auth_chalresp_hash(perph_resp.periph_challenge, central_resp.central_response);

     if(err) {
         LOG_ERR("Failed to create peripheral response to challenge, err: %d", err);
        *status = AUTH_STATUS_FAILED;
        return false;
     }

     /* send Central's response to the Peripheral's random challenge */
     numbytes = auth_svc_central_tx(auth_conn, (const unsigned char*)&central_resp, sizeof(central_resp));

    if((numbytes <= 0) || (numbytes != sizeof(central_resp))) {
        LOG_ERR("Failed to send Central response.");
        *status = AUTH_STATUS_FAILED;
        return false;
    }

    /* so far so good, need to wait for Peripheral response */
    *status = AUTH_STATUS_IN_PROCESS;
    return true;
}

#else

static bool auth_periph_recv_msg(struct authenticate_conn *auth_conn, uint8_t *msgbuf, size_t msglen)
{
    int numbytes;

    while((int)msglen > 0) {
        numbytes = auth_svc_peripheral_recv_timeout(auth_conn, msgbuf, msglen, AUTH_RX_TIMEOUT_MSEC);

        if(numbytes <= 0) {
            return false;
        }

        msgbuf += numbytes;
        msglen -= numbytes;
    }

    return true;
}

static bool auth_periph_recv_challenge(struct authenticate_conn *auth_conn, uint8_t *random_chal)
{
    struct central_challenge chal;
    struct periph_chal_response periph_resp;
    int numbytes;

    if(!auth_periph_recv_msg(auth_conn, (uint8_t*)&chal, sizeof(chal))) {
        LOG_ERR("Failed to recieve challenge message from Central");
        return false;
    }

    if(!auth_check_msg(&chal.hdr, AUTH_CENTRAL_CHAL_MSG_ID)) {
        LOG_ERR("Invalid message.");
        return false;
    }

    /* create response and send back to the Central */
    periph_resp.hdr.soh = CHALLENGE_RESP_SOH;
    periph_resp.hdr.msg_id = AUTH_PERIPH_CHALRESP_MSG_ID;

    /* copy the Peripheral's challenge for the Central */
    memcpy(periph_resp.periph_challenge, random_chal, sizeof(periph_resp.periph_challenge));

    /* Now create the response for the Central */
    auth_chalresp_hash(chal.central_challenge, periph_resp.periph_response);

    /* Send response */
    numbytes = auth_svc_peripheral_tx(auth_conn, (const unsigned char *)&chal, sizeof(chal));

    if((numbytes <= 0) || (numbytes != sizeof(chal))) {
        LOG_ERR("Failed to send challenge response to Central.");
        return false;
    }

    return true;
}


static bool auth_periph_recv_chalresp(struct authenticate_conn *auth_conn, uint8_t *random_chal, auth_status_t *status)
{
    struct central_chal_resp central_resp;
    struct auth_chalresp_result result_resp;
    uint8_t hash[AUTH_SHA256_HASH];
    int err, numbytes;

    /* read just the header */
    if(!auth_periph_recv_msg(auth_conn, (uint8_t*)&central_resp, sizeof(central_resp.hdr))) {
        LOG_ERR("Failed to recieve challenge response  from Central");
        *status = AUTH_STATUS_FAILED;
        return false;
    }

    /* This is a result message, means the Central failed to authenticate the Periphaerl*/
    if(central_resp.hdr.msg_id == AUTH_CHALRESP_RESULT_MSG_ID) {

        /* read the remainder of the message */
        auth_periph_recv_msg(auth_conn, (uint8_t*)&result_resp.result, sizeof(result_resp.result));

        /* Result should be non-zero, meaning an authentication failure. */
        if(result_resp.result != 0) {
            LOG_ERR("Unexpected result value: %d", result_resp.result);
        }

        LOG_ERR("Central authentication failed.");
        *status = AUTH_STATUS_AUTHENTICATION_FAILED;
        return false;
    }

    /* The Central authenticated the Peripheral (this code) response. Now verify the Central's
     * response to the Peripheral challenge. */
    if(!auth_periph_recv_msg(auth_conn, (uint8_t*)&central_resp.hdr + sizeof(central_resp.hdr),
                             sizeof(central_resp.hdr) - sizeof(central_resp.hdr))) {
        LOG_ERR("Failed to read Central response.");
        *status = AUTH_STATUS_FAILED;
        return false;
    }

    err = auth_chalresp_hash(random_chal, hash);
    if(err) {
        LOG_ERR("Failed to create hash.");
        *status = AUTH_STATUS_FAILED;
        return false;
    }

    /* init result response message */
    memset(&result_resp, 0, sizeof(result_resp));
    result_resp.hdr.soh = CHALLENGE_RESP_SOH;
    result_resp.hdr.msg_id = AUTH_CHALRESP_RESULT_MSG_ID;

    /* verify Central's response */
    if(memcmp(hash, central_resp.central_response, sizeof(hash))) {
        /* authenatication failed, the Central did not sent the correct response */
        result_resp.result = 1;
    }

    /* send result back to the Central */
    numbytes = auth_svc_peripheral_tx(auth_conn, (const unsigned char *)&result_resp, sizeof(result_resp));

    if((numbytes <= 0) || (numbytes != sizeof(result_resp))) {
        LOG_ERR("Failed to send Central authentication result.");
        *status = AUTH_STATUS_FAILED;
        return false;
    }

    *status = (result_resp.result == 0) ? AUTH_STATUS_SUCCESSFUL : AUTH_STATUS_AUTHENTICATION_FAILED;

    return true;
}


#endif /* CONFIG_BT_GATT_CLIENT */


/**
 * @brief  Use hash (SHA-256) with shared key to authenticate each side.
 */
void auth_chalresp_thread(void *arg1, void *arg2, void *arg3)
{
    auth_status_t status;
    uint8_t random_chal[AUTH_CHALLENGE_LEN];
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)arg1;

    auth_chalresp_status(auth_conn, AUTH_STATUS_STARTED);

    /* generate random number as challenge */
    sys_rand_get(random_chal, sizeof(random_chal));

#if defined(CONFIG_BT_GATT_CLIENT)

    int numbytes;
    struct auth_chalresp_result periph_result;

    /* if central, generate random num and send challenge */
    if(!auth_conn->is_central) {
        LOG_ERR("Incorrect configuration, should be Central.");
        auth_chalresp_status(auth_conn, AUTH_STATUS_FAILED);
        return;  /* exit thread */
    }

    if(!auth_central_send_challenge(auth_conn, random_chal)) {
        auth_chalresp_status(auth_conn, AUTH_STATUS_FAILED);
        return;
    }

    /* read response from peripheral */
    if(!auth_central_recv_chal_resp(auth_conn, random_chal, &status)) {
        auth_chalresp_status(auth_conn, status);
        return;
    }

    /* Wait for the final response from the Peripheral indicating success or failure
     * of the Centrals response. */
    numbytes = auth_svc_central_recv_timeout(auth_conn, (unsigned char*)&periph_result, sizeof(periph_result), AUTH_RX_TIMEOUT_MSEC);

    if((numbytes <= 0) || (numbytes != sizeof(periph_result))) {
        LOG_ERR("Failed to receive peripheral authentication result.");
        auth_chalresp_status(auth_conn, AUTH_STATUS_AUTHENTICATION_FAILED);
        return;
    }

    /* check message */
    if(!auth_check_msg(&periph_result.hdr, AUTH_CHALRESP_RESULT_MSG_ID)) {
        LOG_ERR("Peripheral rejected Central response, authentication failed.");
        auth_chalresp_status(auth_conn, AUTH_STATUS_AUTHENTICATION_FAILED);
        return;
    }

    /* check the Peripheral result */
    if(periph_result.result != 0) {
        LOG_ERR("Authentication with peripherl failed.");
        auth_chalresp_status(auth_conn, AUTH_STATUS_AUTHENTICATION_FAILED);
    } else {
        LOG_INF("Authentication with peripherl successful.");
        auth_chalresp_status(auth_conn, AUTH_STATUS_SUCCESSFUL);
    }

    /* exit thread */

#else

    /* Check code is configured to run as a Peripheral */
    if(auth_conn->is_central) {
        LOG_ERR("Incorrect configuration, should be Peripheral.");
        auth_chalresp_status(auth_conn, AUTH_STATUS_FAILED);
        return;
    }

    /* Wait for challenge from the Central */
    if(!auth_periph_recv_challenge(auth_conn, random_chal)) {
        auth_chalresp_status(auth_conn, AUTH_STATUS_FAILED);
        return;
    }

    /* Wait for challenge response from the Central */
    auth_periph_recv_chalresp(auth_conn, random_chal, &status);

    if(status == AUTH_STATUS_SUCCESSFUL) {
        LOG_INF("Authentication with Central successful.");
    } else {
        LOG_INF("Authentication with Central failed.");
    }

    auth_chalresp_status(auth_conn, status);

#endif /* CONFIG_BT_GATT_CLIENT */

    /* End of Challenge-Response authentication thread */
    LOG_DBG("Challenge-Response thread complete.");
}


#endif  /* CONFIG_CHALLENGE_RESP_AUTH_METHOD */

