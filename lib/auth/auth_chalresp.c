/**
 *  @file  auth_chalresp.c
 *
 *  @brief  Challenge-Response method for authenticating connection.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/types.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <zephyr.h>
#include <init.h>

#include <auth/auth_lib.h>
#include <random/rand32.h>

#include <tinycrypt/constants.h>
#include <tinycrypt/sha256.h>



#define LOG_LEVEL CONFIG_AUTH_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_DECLARE(auth_lib, CONFIG_AUTH_LOG_LEVEL);

#include "auth_internal.h"

#define AUTH_SHA256_HASH                    (TC_SHA256_DIGEST_SIZE)
#define AUTH_SHARED_KEY_LEN                 (32u)
#define AUTH_CHALLENGE_LEN                  (32u)
#define AUTH_CHAL_RESPONSE_LEN              AUTH_SHA256_HASH


#define CHALLENGE_RESP_SOH                  0x65A2    /* magic number to help identify and parse messages */

/* Message IDs */
#define AUTH_CLIENT_CHAL_MSG_ID             0x01
#define AUTH_SERVER_CHALRESP_MSG_ID         0x02
#define AUTH_CLIENT_CHALRESP_MSG_ID         0x03
#define AUTH_CHALRESP_RESULT_MSG_ID         0x04

/* Timeout for receive */
#define AUTH_RX_TIMEOUT_MSEC                (3000u)


/* ensure structs are byte aligned */
#pragma pack(push, 1)

struct chalresp_header {
    uint16_t soh;          /* start of header */
    uint8_t msg_id;
};

struct client_challenge  {
    struct chalresp_header hdr;
    uint8_t client_challenge[AUTH_CHALLENGE_LEN];
};

struct server_chal_response {
    struct chalresp_header hdr;
    uint8_t server_response[AUTH_CHAL_RESPONSE_LEN];
    uint8_t server_challenge[AUTH_CHALLENGE_LEN];
};

struct client_chal_resp {
    struct chalresp_header hdr;
    uint8_t client_response[AUTH_CHAL_RESPONSE_LEN];
};

/* From Central or Peripheral indicating result of challenge-response */
struct auth_chalresp_result {
    struct chalresp_header hdr;
    uint8_t result;    /* 0 == success, 1 == failure */
};

#pragma pack(pop)


/**
 * Shared key.
 * @brief  In a production system, the shared key should be stored in a
 * secure hardware store such as an ECC608A or TrustZone.
 */
static uint8_t shared_key[AUTH_SHARED_KEY_LEN] = {
    0xBD, 0x84, 0xDC, 0x6E, 0x5C, 0x77, 0x41, 0x58, 0xE8, 0xFB, 0x1D, 0xB9, 0x95, 0x39, 0x20, 0xE4,
    0xC5, 0x03, 0x69, 0x9D, 0xBC, 0x53, 0x08, 0x20, 0x1E, 0xF4, 0x72, 0x8E, 0x90, 0x56, 0x49, 0xA8 };


/**
 * Utility function to create the has of the random challenge and the shared key.
 */
static int auth_chalresp_hash(const uint8_t *random_chal, uint8_t *hash)
{
    int err = 0;
    struct tc_sha256_state_struct hash_state;

    tc_sha256_init(&hash_state);


    /* Update the hash with the random challenge followed by the shared key. */
    if((err = tc_sha256_update(&hash_state, random_chal, AUTH_CHALLENGE_LEN)) != TC_CRYPTO_SUCCESS ||
       (err = tc_sha256_update(&hash_state, shared_key, AUTH_SHARED_KEY_LEN)) != TC_CRYPTO_SUCCESS) {
        return AUTH_CRYPTO_ERROR;
    }

    /* calc the final hash */
    err = tc_sha256_final(hash, &hash_state) == TC_CRYPTO_SUCCESS ?
                      AUTH_SUCCESS : AUTH_CRYPTO_ERROR;

    return err;
}

static bool auth_check_msg(struct chalresp_header *hdr, const uint8_t msg_id)
{
    if((hdr->soh != CHALLENGE_RESP_SOH) || (hdr->msg_id != msg_id)) {
        return false;
    }

    return true;
}

#if defined(CONFIG_AUTH_CLIENT)

static bool auth_client_send_challenge(struct authenticate_conn *auth_conn, const uint8_t *random_chal)
{
    int numbytes;
    struct client_challenge chal;

     /* build and send challenge message to Peripheral */
    memset(&chal, 0, sizeof(chal));
    chal.hdr.soh = CHALLENGE_RESP_SOH;
    chal.hdr.msg_id = AUTH_CLIENT_CHAL_MSG_ID;

    memcpy(&chal.client_challenge, random_chal, sizeof(chal.client_challenge));

    /* send to peripheral */
    numbytes = auth_xport_send(auth_conn->xport_hdl, (uint8_t*)&chal, sizeof(chal));

    if((numbytes <= 0) || (numbytes != sizeof(chal))) {
        /* error */
        LOG_ERR("Error sending challenge to peripherl, err: %d", numbytes);
        return false;
    }

    return true;
}

static bool auth_client_recv_chal_resp(struct authenticate_conn *auth_conn, const uint8_t *random_chal,
                                       enum auth_status *status)
{
    uint8_t hash[AUTH_CHAL_RESPONSE_LEN];
    int numbytes;
    int err;
    struct server_chal_response server_resp;
    struct client_chal_resp client_resp;
    struct auth_chalresp_result chal_result;
    uint8_t *buf = (uint8_t*)&server_resp;
    int len = sizeof(server_resp);

    while(len > 0) {

        numbytes = auth_xport_recv(auth_conn->xport_hdl, buf, len, 3000);

        if(numbytes <= 0) {
            LOG_ERR("Failed to read client challenge response, err: %d", numbytes);
            *status = AUTH_STATUS_FAILED;
            return false;
        }

        buf += numbytes;
        len -= numbytes;
    }

    /* check message */
    if(!auth_check_msg(&server_resp.hdr, AUTH_SERVER_CHALRESP_MSG_ID)) {
        LOG_ERR("Invalid message recieved from the server.");
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
    if(memcmp(hash, server_resp.server_response, sizeof(hash))) {
        /* authententication failed */
        LOG_ERR("Server authentication failed.");
        *status = AUTH_STATUS_AUTHENTICATION_FAILED;

        /* send failed message to the Peripheral */
        memset(&chal_result, 0, sizeof(chal_result));
        chal_result.hdr.soh = CHALLENGE_RESP_SOH;
        chal_result.hdr.msg_id = AUTH_CHALRESP_RESULT_MSG_ID;
        chal_result.result = 1;

        numbytes = auth_xport_send(auth_conn->xport_hdl, (uint8_t*)&chal_result, sizeof(chal_result));

        if((numbytes <= 0) || (numbytes != sizeof(chal_result))) {
            LOG_ERR("Failed to send authentication error result to server.");
        }

        return false;
    }

    /* init Client response message */
    memset(&client_resp, 0, sizeof(client_resp));
    client_resp.hdr.soh = CHALLENGE_RESP_SOH;
    client_resp.hdr.msg_id = AUTH_CLIENT_CHALRESP_MSG_ID;

    /* Create response to the server's random challeng */
     err = auth_chalresp_hash(server_resp.server_challenge, client_resp.client_response);

     if(err) {
         LOG_ERR("Failed to create server response to challenge, err: %d", err);
        *status = AUTH_STATUS_FAILED;
        return false;
     }
     
     /* send Client's response to the Server's random challenge */
     numbytes = auth_xport_send(auth_conn->xport_hdl, (uint8_t*)&client_resp, sizeof(client_resp));

    if((numbytes <= 0) || (numbytes != sizeof(client_resp))) {
        LOG_ERR("Failed to send Client response.");
        *status = AUTH_STATUS_FAILED;
        return false;
    }

    /* so far so good, need to wait for Server response */
    *status = AUTH_STATUS_IN_PROCESS;
    return true;
}

#else

static bool auth_server_recv_msg(struct authenticate_conn *auth_conn, uint8_t *msgbuf, size_t msglen)
{
    int numbytes;

    while((int)msglen > 0) {

        // TODO: Add receive timeout function
        // TODO:  Add retry? Add ability to cancel when waiting for data
       numbytes = auth_xport_recv(auth_conn->xport_hdl, msgbuf, msglen, 30000);

        if(numbytes <= 0) {
            return false;
        }

        msgbuf += numbytes;
        msglen -= numbytes;
    }

    return true;
}

static bool auth_server_recv_challenge(struct authenticate_conn *auth_conn, uint8_t *random_chal)
{
    struct client_challenge chal;
    struct server_chal_response server_resp;
    int numbytes;

    if(!auth_server_recv_msg(auth_conn, (uint8_t*)&chal, sizeof(chal))) {
        LOG_ERR("Failed to recieve challenge message from Client.");
        return false;
    }

    if(!auth_check_msg(&chal.hdr, AUTH_CLIENT_CHAL_MSG_ID)) {
        LOG_ERR("Invalid message.");
        return false;
    }

    /* create response and send back to the Client */
    server_resp.hdr.soh = CHALLENGE_RESP_SOH;
    server_resp.hdr.msg_id = AUTH_SERVER_CHALRESP_MSG_ID;

    /* copy the Server's challenge for the Central */
    memcpy(server_resp.server_challenge, random_chal, sizeof(server_resp.server_challenge));

    /* Now create the response for the Client */
    auth_chalresp_hash(chal.client_challenge, server_resp.server_response);

    /* Send response */
    numbytes = auth_xport_send(auth_conn->xport_hdl, (uint8_t *)&server_resp, sizeof(server_resp));

    if((numbytes <= 0) || (numbytes != sizeof(server_resp))) {
        LOG_ERR("Failed to send challenge response to the Client.");
        return false;
    }

    return true;
}


static bool auth_server_recv_chalresp(struct authenticate_conn *auth_conn, uint8_t *random_chal, enum auth_status *status)
{
    struct client_chal_resp client_resp;
    struct auth_chalresp_result result_resp;
    uint8_t hash[AUTH_SHA256_HASH];
    int err, numbytes;

    memset(&client_resp, 0, sizeof(client_resp));

    /* read just the header */
    if(!auth_server_recv_msg(auth_conn, (uint8_t*)&client_resp, sizeof(client_resp.hdr))) {
        LOG_ERR("Failed to recieve challenge response from the Client");
        *status = AUTH_STATUS_FAILED;
        return false;
    }

    /* This is a result message, means the Client failed to authenticate the Server. */
    if(client_resp.hdr.msg_id == AUTH_CHALRESP_RESULT_MSG_ID) {

        /* read the remainder of the message */
        auth_server_recv_msg(auth_conn, (uint8_t*)&result_resp.result, sizeof(result_resp.result));

        /* Result should be non-zero, meaning an authentication failure. */
        if(result_resp.result != 0) {
            LOG_ERR("Unexpected result value: %d", result_resp.result);
        }

        LOG_ERR("Client authentication failed.");
        *status = AUTH_STATUS_AUTHENTICATION_FAILED;
        return false;
    }

    /* The Client authenticated the Server (this code) response. Now verify the Client's
     * response to the Server challenge. */
    if(!auth_server_recv_msg(auth_conn, (uint8_t*)&client_resp.hdr + sizeof(client_resp.hdr),
                             sizeof(client_resp) - sizeof(client_resp.hdr))) {
        LOG_ERR("Failed to read Client response.");
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
    if(memcmp(hash, client_resp.client_response, sizeof(hash))) {
        /* authenatication failed, the Client did not sent the correct response */
        result_resp.result = 1;
    }

    /* send result back to the Client */
    numbytes = auth_xport_send(auth_conn->xport_hdl, (uint8_t*)&result_resp, sizeof(result_resp));

    if((numbytes <= 0) || (numbytes != sizeof(result_resp))) {
        LOG_ERR("Failed to send Client authentication result.");
        *status = AUTH_STATUS_FAILED;
        return false;
    }

    *status = (result_resp.result == 0) ? AUTH_STATUS_SUCCESSFUL : AUTH_STATUS_AUTHENTICATION_FAILED;

    return true;
}


#endif /* CONFIG_AUTH_CLIENT */


/**
 * @brief  Use hash (SHA-256) with shared key to authenticate each side.
 */
void auth_chalresp_thread(void *arg1, void *arg2, void *arg3)
{
    enum auth_status status;
    uint8_t random_chal[AUTH_CHALLENGE_LEN];
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)arg1;

    auth_lib_set_status(auth_conn, AUTH_STATUS_STARTED);

    /* generate random number as challenge */
    sys_rand_get(random_chal, sizeof(random_chal));


#if defined(CONFIG_AUTH_CLIENT)
    int numbytes;
    struct auth_chalresp_result server_result;

    /* if client role, generate random num and send challenge */
    if(!auth_conn->is_client) {
        LOG_ERR("Incorrect configuration, should be client role.");
        auth_lib_set_status(auth_conn, AUTH_STATUS_FAILED);
        return;  /* exit thread */
    }

    if(!auth_client_send_challenge(auth_conn, random_chal)) {
        auth_lib_set_status(auth_conn, AUTH_STATUS_FAILED);
        return;
    }

    /* read response from the sever */
    if(!auth_client_recv_chal_resp(auth_conn, random_chal, &status)) {
        auth_lib_set_status(auth_conn, status);
        return;
    }

    /* Wait for the final response from the Server indicating success or failure
     * of the Client's response. */

    numbytes = auth_xport_recv(auth_conn->xport_hdl, (uint8_t*)&server_result,
                                        sizeof(server_result), AUTH_RX_TIMEOUT_MSEC);

    if((numbytes <= 0) || (numbytes != sizeof(server_result))) {
        LOG_ERR("Failed to receive server authentication result.");
        auth_lib_set_status(auth_conn, AUTH_STATUS_AUTHENTICATION_FAILED);
        return;
    }

    /* check message */
    if(!auth_check_msg(&server_result.hdr, AUTH_CHALRESP_RESULT_MSG_ID)) {
        LOG_ERR("Server rejected Client response, authentication failed.");
        auth_lib_set_status(auth_conn, AUTH_STATUS_AUTHENTICATION_FAILED);
        return;
    }

    /* check the SErver result */
    if(server_result.result != 0) {
        LOG_ERR("Authentication with server failed.");
        auth_lib_set_status(auth_conn, AUTH_STATUS_AUTHENTICATION_FAILED);
    } else {
        LOG_INF("Authentication with server successful.");
        auth_lib_set_status(auth_conn, AUTH_STATUS_SUCCESSFUL);
    }

    /* exit thread */
#else

    /* Check code is configured to run as a Peripheral */
    if(auth_conn->is_client) {
        LOG_ERR("Incorrect configuration, should be server.");
        auth_lib_set_status(auth_conn, AUTH_STATUS_FAILED);
        return;
    }

    /* Wait for challenge from the Central */
    if(!auth_server_recv_challenge(auth_conn, random_chal)) {
        auth_lib_set_status(auth_conn, AUTH_STATUS_FAILED);
        return;
    }

    /* Wait for challenge response from the Client */
    auth_server_recv_chalresp(auth_conn, random_chal, &status);

    if(status == AUTH_STATUS_SUCCESSFUL) {
        LOG_INF("Authentication with Client successful.");
    } else {
        LOG_INF("Authentication with Client failed.");
    }

    auth_lib_set_status(auth_conn, status);

#endif /* CONFIG_AUTH_CLIENT */

    /* End of Challenge-Response authentication thread */
    LOG_DBG("Challenge-Response thread complete.");
}

