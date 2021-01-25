/**
 *  Copyright (c) 2021 Golden Bits Software, Inc.
 *
 *  @file  auth_lib.c
 *
 *  @brief  Authentication Library functions used to authenticate a
 *          connection between a client and server.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/types.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <zephyr.h>
#include <init.h>
#include <stdint.h>


#include <logging/log_ctrl.h>
#include <logging/log.h>
LOG_MODULE_REGISTER(auth_lib, CONFIG_AUTH_LOG_LEVEL);

#include <auth/auth_lib.h>
#include "auth_internal.h"


#define AUTH_THRD_STACK_SIZE       (4096u)
#define AUTH_THRD_PRIORITY         CONFIG_AUTH_THREAD_PRIORITY



#if defined(AUTH_INSTANCE_1)
K_SEM_DEFINE(thrd_sem_1, 0, 1);
#endif

#if defined(AUTH_INSTANCE_2)
K_SEM_DEFINE(thrd_sem_2, 0, 1);
#endif

static void auth_thrd_entry(void *, void *, void *);

static struct auth_thread_params thrd_params[CONFIG_NUM_AUTH_INSTANCES] = {
#if defined(AUTH_INSTANCE_1)
	{ .thrd_sem = &thrd_sem_1 },
#endif

#if defined(AUTH_INSTANCE_2)
	{ .thrd_sem = &thrd_sem_2 },
#endif
};

#if defined(AUTH_INSTANCE_1)
K_THREAD_DEFINE(auth_tid_1, AUTH_THRD_STACK_SIZE,
		auth_thrd_entry, &thrd_params[AUTH_INST_1_ID], NULL, NULL,
		AUTH_THRD_PRIORITY, 0, 0);
#endif


#if defined(AUTH_INSTANCE_2)
K_THREAD_DEFINE(auth_tid_2, AUTH_THRD_STACK_SIZE,
		auth_thrd_entry, &thrd_params[AUTH_INST_2_ID], NULL, NULL,
		AUTH_THRD_PRIORITY, 0, 0);
#endif



/* ========================== local functions ========================= */

/**
 * Check auth flags consistency.
 *
 * @param flags Flags to check.
 *
 * @return  true if flags are correct, else false.
 */
static bool auth_lib_checkflags(uint32_t flags)
{
	/* Check for invalid flag combinations */

	/* server and client roles are mutually exclusive */
	if ((flags & (AUTH_CONN_SERVER | AUTH_CONN_CLIENT)) ==
	    (AUTH_CONN_SERVER | AUTH_CONN_CLIENT)) {
		return false;
	}

	/* can only define one auth method */
	if ((flags & (AUTH_CONN_DTLS_AUTH_METHOD | AUTH_CONN_CHALLENGE_AUTH_METHOD))
	    == (AUTH_CONN_DTLS_AUTH_METHOD | AUTH_CONN_CHALLENGE_AUTH_METHOD)) {
		return false;
	}

	return true;
}


/**
 * Invokes the status callback from the system work queue
 *
 * @param work Pointer to work item.
 */
static void auth_lib_status_work(struct k_work *work)
{
	struct authenticate_conn *auth_conn =
		CONTAINER_OF(work, struct authenticate_conn, auth_status_work);

	if (!auth_conn) {
		LOG_ERR("Failed to get auth conn struct.");
		return;
	}

	/* invoke callback */
	auth_conn->status_cb(auth_conn, auth_conn->instance, auth_conn->curr_status,
			     auth_conn->callback_context);
}


/**
 * Auth thread starts during boot and waits on semaphore.
 *
 * @param arg1  Pointer to struct auth_thread_params.
 * @param arg2  Unused
 * @param arg3  Unused
 */
static void auth_thrd_entry(void *arg1, void *arg2, void *arg3)
{
	int ret;
	struct auth_thread_params *thrd_params = (struct auth_thread_params *)arg1;

	while (true) {

		ret = k_sem_take(thrd_params->thrd_sem, K_FOREVER);

		if (ret) {
			LOG_ERR("Failed to get semaphore for auth thread, err: %d", ret);
			LOG_ERR("Auth thread terminating, instance id: %d.",
				thrd_params->auth_conn->instance);
			return;
		}

		/* call auth thread function */
		thrd_params->auth_conn->auth_func(thrd_params->auth_conn);
	}
}



/* ========================= external API ============================ */


/**
 * @see auth_lib.h
 */
int auth_lib_init(struct authenticate_conn *auth_conn, enum auth_instance_id instance,
		  auth_status_cb_t status_func, void *context,
		  struct auth_optional_param *opt_params, enum auth_flags auth_flags)
{
	int err;

	/* check input params */
	if (status_func == NULL) {
		LOG_ERR("Error, status function is NULL.");
		return AUTH_ERROR_INVALID_PARAM;
	}

	/* check auth flags */
	if (!auth_lib_checkflags(auth_flags)) {
		LOG_ERR("Invalid auth flags.");
		return AUTH_ERROR_INVALID_PARAM;
	}

	/* init the struct to zero */
	memset(auth_conn, 0, sizeof(struct authenticate_conn));

	/* setup the status callback */
	auth_conn->status_cb = status_func;
	auth_conn->callback_context = context;

	auth_conn->cancel_auth = false;
	auth_conn->instance = instance;
	auth_conn->authflags = auth_flags;

	/* init the work item used to post authentication status */
	k_work_init(&auth_conn->auth_status_work, auth_lib_status_work);

	auth_conn->is_client = (auth_flags & AUTH_CONN_CLIENT) ? true : false;

	err = AUTH_ERROR_FAILED;

#if defined(CONFIG_AUTH_DTLS)
	if (auth_flags & AUTH_CONN_DTLS_AUTH_METHOD) {
		err = auth_init_dtls_method(auth_conn, opt_params);
	}
#endif

#if defined(CONFIG_AUTH_CHALLENGE_RESPONSE)
	if (auth_flags & AUTH_CONN_CHALLENGE_AUTH_METHOD) {
		err = auth_init_chalresp_method(auth_conn, opt_params);
	}
#endif

	/* check if auth method was initialized correctly. */
	if (err) {
		LOG_ERR("Failed to initialize authentication method.");
		return err;
	}

	/*
	 * Set auth connect into thread param instance.
	 *
	 * @note:  k_sem_give() is called to start the thread, which provides
	 * a compile_barrier() and for SMP systems should handle any
	 * necessary memory barriers and/or cache syncing.
	 * The important point is the auth_conn pointer is set into
	 * a structure used by another thread (auth_thrd_entry)
	 */
	thrd_params[instance].auth_conn = auth_conn;

	return AUTH_SUCCESS;
}

/**
 * @see auth_lib.h
 */
int auth_lib_deinit(struct authenticate_conn *auth_conn)
{
	int ret = AUTH_ERROR_INTERNAL;

#if defined(CONFIG_AUTH_DTLS)
	/* Free any resources for the auth method used */
	if (auth_conn->authflags & AUTH_CONN_DTLS_AUTH_METHOD) {
		ret = auth_deinit_dtls(auth_conn);
	}
#endif

#if defined(CONFIG_AUTH_CHALLENGE_RESPONSE)
	if (auth_conn->authflags & AUTH_CONN_CHALLENGE_AUTH_METHOD) {
		ret = auth_deinit_chalresp(auth_conn);
	}
#endif

	return ret;
}

/**
 * @see auth_lib.h
 */
int auth_lib_start(struct authenticate_conn *auth_conn)
{
	/* Start the authentication thread */
	k_sem_give(thrd_params[auth_conn->instance].thrd_sem);

	return AUTH_SUCCESS;
}

/**
 * @see auth_lib.h
 */
int auth_lib_cancel(struct authenticate_conn *auth_conn)
{
	auth_conn->cancel_auth = true;

	auth_lib_set_status(auth_conn, AUTH_STATUS_CANCELED);

	return AUTH_SUCCESS;
}

// DAG DEBUG BEG

/**
 * @see auth_lib.h
 */
int auth_lib_dtls_send(struct authenticate_conn *auth_conn, void *data, size_t len)
{
	int bytes_sent = AUTH_ERROR_NOT_IMPLEMENTED;

#if defined(CONFIG_AUTH_DTLS)
	/* Check auth type, only able to send when DTLS is used.  Future
	 * versions may enable sending over an encrypted link after authentication.
	 */
	if((auth_conn->authflags & AUTH_CONN_DTLS_AUTH_METHOD) != AUTH_CONN_DTLS_AUTH_METHOD) {
		LOG_ERR("Connection not using DTLS");
		return AUTH_ERROR_INVALID_PARAM;
	}

	/* Can only send if authentication is complete. */
	if(auth_conn->curr_status != AUTH_STATUS_SUCCESSFUL) {
		LOG_ERR("Unable to send, authentication not successful.");
		return AUTH_ERROR_XPORT_SEND;
	}

	bytes_sent = auth_dtls_send(auth_conn, data, len);
#endif
	return bytes_sent;
}


/**
 * @see auth_lib.h
 */
int auth_lib_dtls_recv(struct authenticate_conn *auth_conn, void *data, size_t len)
{
	int bytes_recv = AUTH_ERROR_NOT_IMPLEMENTED;

#if defined(CONFIG_AUTH_DTLS)
	/* Check auth type, only able to send when DTLS is used.  Future
	 * versions may enable sending over an encrypted link after authentication.
	 */
	if((auth_conn->authflags & AUTH_CONN_DTLS_AUTH_METHOD) != AUTH_CONN_DTLS_AUTH_METHOD) {
		LOG_ERR("Connection not using DTLS");
		return AUTH_ERROR_INVALID_PARAM;
	}

	/* Can only send if authentication is complete. */
	if(auth_conn->curr_status != AUTH_STATUS_SUCCESSFUL) {
		LOG_ERR("Unable to send, authentication not successful.");
		return AUTH_ERROR_XPORT_SEND;
	}

	bytes_recv = auth_dtls_recv(auth_conn, data, len);
#endif
	return bytes_recv;
}

/**
 * @see auth_lib.h
 */
bool auth_lib_is_finished(struct authenticate_conn *auth_conn, enum auth_status *status)
{
	bool is_finished = false;

	switch(auth_conn->curr_status) {

	case AUTH_STATUS_STARTED:
	case AUTH_STATUS_IN_PROCESS:
		break;

	case AUTH_STATUS_CANCELED:
	case AUTH_STATUS_FAILED:
	case AUTH_STATUS_AUTHENTICATION_FAILED:
	case AUTH_STATUS_SUCCESSFUL:
		is_finished = true;
		break;

	}

	if(status != NULL) {
		*status = auth_conn->curr_status;
	}

	return is_finished;
}
// DAG DEBUG END

/**
 * @see auth_lib.h
 */
const char *auth_lib_getstatus_str(enum auth_status status)
{
	switch (status) {
	case AUTH_STATUS_STARTED:
		return "Authentication started";
		break;

	case AUTH_STATUS_IN_PROCESS:
		return "In process";
		break;

	case AUTH_STATUS_CANCELED:
		return "Canceled";
		break;

	case AUTH_STATUS_FAILED:
		return "Failure";
		break;

	case AUTH_STATUS_AUTHENTICATION_FAILED:
		return "Authentication Failed";
		break;

	case AUTH_STATUS_SUCCESSFUL:
		return "Authentication Successful";
		break;

	default:
		break;
	}

	return "unknown";
}

/**
 * @see auth_lib.h
 */
enum auth_status auth_lib_get_status(struct authenticate_conn *auth_conn)
{
	return auth_conn->curr_status;
}

/**
 * @see auth_lib.h
 */
void auth_lib_set_status(struct authenticate_conn *auth_conn, enum auth_status status)
{
	auth_conn->curr_status = status;

	if (auth_conn->status_cb) {

		/* submit work item */
		k_work_submit(&auth_conn->auth_status_work);
	}
}
