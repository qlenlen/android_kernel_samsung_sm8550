/*
 * TEE Driver
 *
 * Copyright (C) 2021 Samsung Electronics, Inc.
 * An Seongjin, <seongjin.an@samsung.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/firmware.h>
#include <linux/mz.h>
#include <soc/samsung/exynos-pmu-if.h>
#include <tzdev/tee_client_api.h>

int target_count;

/////////////////////////////////////////// TA message struct
#define MAX_SHMEM_LEN_BYTES 1024
typedef uint32_t tciCommandId_t;
typedef uint32_t tciResponseId_t;
typedef uint32_t tciReturnCode_t;

/**
 * TCI command header.
 */
typedef struct _tciCommandHeader_t {
	tciCommandId_t commandId; /**< Command ID */
} tciCommandHeader_t;

/**
 * TCI response header.
 */
typedef struct _tciResponseHeader_t {
	tciResponseId_t     responseId; /**< Response ID (must be command ID | RSP_ID_MASK )*/
	tciReturnCode_t     returnCode; /**< Return code of command */
} tciResponseHeader_t;


typedef struct _cmdTest_t {
	tciCommandHeader_t  header; /**< Command header */
	uint32_t            number; /**< Length of data to process */
} cmdTest_t;

/**
 * Response structure Trustlet -> Trustlet Connector.
 */
typedef struct _rspTest_t {
	tciResponseHeader_t header; /**< Response header */
	int32_t status;
	uint32_t value;
} rspTest_t;

typedef struct _msgData_t {
	uint32_t buffer[MAX_SHMEM_LEN_BYTES];
	uint32_t bufferSize;
} msgData_t;

/**
 * TCI message data.
 */
typedef struct _tciMessage_t {
	cmdTest_t command;
	rspTest_t response;
	msgData_t msgData;
} tciMessage_t;
/////////////////////////////////////////// TA message struct

#define AES_BLOCK_SIZE_FOR_TZ 1024
#define CMD_MZ_WB_ENCRYPT 0x900
#define CMD_REMOVEKEY 2
#define MZ_PATH_MAX 4096

#define MAX_SESS_NUM        1 // tlc sessions nums

static TEEC_UUID uuid = {
	0x00000000, 0x0000, 0x0000, {0x00, 0x00, 0x4d, 0x65, 0x6d, 0x5a, 0x72, 0x67}
};

typedef struct tlc_struct {
	TEEC_Context        context;
	TEEC_Session        session;
	TEEC_Operation      operation;
	TEEC_SharedMemory   shmem;
	TEEC_UUID           uuid;
	uint8_t             *shmem_buff;
} tlc_struct_t;

typedef struct tlc_struct_th {
	tlc_struct_t        tlc_struct_arr[MAX_SESS_NUM]; // thread unsafe struct
} tlc_struct_th_t;

static tlc_struct_th_t  tlc_struct_safe;
static uint8_t          is_initialized; // to be checked

/*!
 * \brief   returns pointer to first unfilled tlc_sttuct item in massive
 * \return  pointer to empty tlc_sttuct
 */
static tlc_struct_t *get_empty(void)
{
	return &tlc_struct_safe.tlc_struct_arr[0];
}

/*!
 * \brief   returns pointer to tlc_struct owned by current thread
 * \return  pointer to empty tlc_sttuct
 */
static tlc_struct_t *mz_get_current(void)
{
	return &tlc_struct_safe.tlc_struct_arr[0];
}

/*!
 * \brief   Performs useful things only at once at zrtp_create
 * \        where could be several processes single thread each
 * \return  operation result, 0 if OK
 */
static int tlc_init(void)
{
	if (is_initialized)
		return 0;

	memset(&tlc_struct_safe, 0x00, sizeof(tlc_struct_safe));

	is_initialized = 1;
	return 0;
}

struct tci_msg {
	uint32_t cmd;
	uint32_t pid;
	uint8_t encrypt[8];
	uint8_t iv[16];
} __packed;

struct tee_msg {
	struct completion *comp;
	uint16_t cmd;
	uint32_t tgid;
	void *encrypt;
	void *iv;
	uint16_t rc;
	struct list_head queue;
};

bool is_TA_session_opened;

static int send_cmd(uint16_t cmd, uint32_t tgid,
		void *encrypt,
		void *iv);

static DEFINE_SPINLOCK(tee_msg_lock);
static LIST_HEAD(tee_msg_queue);
struct task_struct *mz_tee_msg_task;


static int tee_msg_thread(void *arg)
{
	for (;;) {
		set_current_state(TASK_INTERRUPTIBLE);
		if (kthread_should_stop()) {
			set_current_state(TASK_RUNNING);
			break;
		}
		if (list_empty(&tee_msg_queue))
			schedule();
		set_current_state(TASK_RUNNING);

		spin_lock(&tee_msg_lock);
		while (!list_empty(&tee_msg_queue)) {
			struct tee_msg *send_cmd_args;
			int rc;

			send_cmd_args = list_entry(tee_msg_queue.next,
					    struct tee_msg, queue);
			list_del_init(&send_cmd_args->queue);
			spin_unlock(&tee_msg_lock);

			rc = send_cmd(send_cmd_args->cmd,
					send_cmd_args->tgid,
					send_cmd_args->encrypt,
					send_cmd_args->iv);
			send_cmd_args->rc = rc;
			// when processing tee_iovec comp is not NULL
			// only for last cmd in array
			if (send_cmd_args->comp)
				complete(send_cmd_args->comp);
			spin_lock(&tee_msg_lock);
		}
		spin_unlock(&tee_msg_lock);
	}

	return 0;
}

static int send_cmd(uint16_t cmd,
		uint32_t tgid,
		void *encrypt,
		void *iv)
{
	tciMessage_t *tci;
	uint32_t      retVal = 0;
	struct tci_msg *mzbuffer;
	int res = MZ_SUCCESS;
	TEEC_Result     result;
	tlc_struct_t    *tlc_struct = 0;

	if (!is_TA_session_opened) {
		pr_err("MZ %s TA session not opened\n", __func__);
		return -1;
	}

	tlc_struct = mz_get_current();
	tci = (tciMessage_t *)tlc_struct->shmem_buff;

	memset(tci, 0x00, sizeof(tciMessage_t));

	tci->command.header.commandId = cmd;
	tci->msgData.bufferSize = sizeof(struct tci_msg);

	mzbuffer = kmalloc(sizeof(struct tci_msg), GFP_KERNEL);
	if (!mzbuffer)
		return -1;

	mzbuffer->cmd = cmd;
	mzbuffer->pid = tgid;
	if (encrypt != NULL) {
		memcpy(mzbuffer->encrypt, encrypt, 8);
		memcpy(mzbuffer->iv, iv, 16);
	}

	memcpy(tci->msgData.buffer, mzbuffer, sizeof(struct tci_msg));

	result = TEEC_InvokeCommand(&tlc_struct->session, cmd, &tlc_struct->operation, NULL);
	if (result == TEEC_ERROR_TARGET_DEAD) {
		pr_err("MZ %d, %08x\n", __LINE__, result);
		res = -1;
		goto exit_error;
	}

	if (result != TEEC_SUCCESS) {
		pr_err("MZ SendMess: TEEC_InvokeCommand failed with error: %08x\n", result);
		res = -1;
		goto exit_error;
	}

	// Check the Trustlet return code
	if (tci->response.header.returnCode != 0) {
		pr_err("MZ %s ta return error %d\n", __func__, tci->response.header.returnCode);
		return -1;
	}

	// Read result from TCI buffer
	retVal = tci->response.status;
	if (retVal != 1) {
		pr_err("MZ %s ta return status error %d\n", __func__, retVal);
		goto exit_error;
	}

	if (tci->msgData.bufferSize > MAX_SHMEM_LEN_BYTES) {
		pr_err("MZ %s ta return buffer size error\n", __func__);
		goto exit_error;
	}

	memcpy(mzbuffer, tci->msgData.buffer, sizeof(struct tci_msg));

	if (encrypt != NULL)
		memcpy(encrypt, mzbuffer->encrypt, 8);

	kfree(mzbuffer);

	return 1;

exit_error:
	memset(tci, 0x00, sizeof(tciMessage_t));

	return retVal;
}

static int send_cmd_kthread(uint16_t cmd, uint32_t tgid, u8 *encrypt, uint8_t *iv)
{
	struct completion cmd_sent;
	struct tee_msg cmd_msg;

	init_completion(&cmd_sent);

	cmd_msg.comp = &cmd_sent;
	cmd_msg.cmd = cmd;
	cmd_msg.tgid = tgid;
	cmd_msg.encrypt = encrypt;
	cmd_msg.iv = iv;
	cmd_msg.rc = -EBADMSG;

	spin_lock(&tee_msg_lock);
	list_add_tail(&cmd_msg.queue, &tee_msg_queue);
	spin_unlock(&tee_msg_lock);
	wake_up_process(mz_tee_msg_task);
	wait_for_completion(&cmd_sent);
	return cmd_msg.rc;
}

MzResult encrypt_impl(uint8_t *pt, uint8_t *ct, uint8_t *iv)
{
	MzResult mzret = MZ_SUCCESS;
	int taret;

	taret = send_cmd_kthread(CMD_MZ_WB_ENCRYPT, 0, pt, iv);
	if (taret != MZ_TA_SUCCESS) {
		pr_err("MZ %s ta return error %d\n", __func__, taret);
		mzret = MZ_TA_FAIL;
	}
	memcpy(ct, pt, 8);
	return mzret;
}

MzResult load_trusted_app_teegris(void)
{
	MzResult mzret = MZ_SUCCESS;
	TEEC_Result   result = 0;
	tlc_struct_t *tlc_struct = 0;

	pr_info("MZ %s target_count %d\n", __func__, target_count);
	if (target_count != 0) {
		target_count++;
		return mzret;
	}

	if (tlc_init() != 0)
		return mzret;

	// Initialize Contex
	tlc_struct = get_empty();

	tlc_struct->uuid = uuid;

	// Initialize TEEC_Context
	result = TEEC_InitializeContext(NULL, &tlc_struct->context);
	if (result != TEEC_SUCCESS) {
		pr_err("MZ TEEC_InitializeContext failed with error: %08x\n", result);
		goto exit;
	}
	pr_debug("MZ TEEC_InitializeContext - OK\n");

	// register shared memory
	tlc_struct->shmem_buff = kmalloc(sizeof(tciMessage_t), GFP_KERNEL);
	if (!tlc_struct->shmem_buff) {
		result = TEEC_ERROR_OUT_OF_MEMORY;
		pr_err("MZ %s shmem kmalloc fail %08x\n", __func__, result);
		goto exit;
	}

	tlc_struct->shmem.buffer = tlc_struct->shmem_buff;
	tlc_struct->shmem.size = sizeof(tciMessage_t);
	tlc_struct->shmem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

	result = TEEC_RegisterSharedMemory(&tlc_struct->context, &tlc_struct->shmem);
	if (result != TEEC_SUCCESS) {
		pr_err("MZ TEEC_RegisterSharedMemory failed with error: %08x\n", result);
		goto close_session;
	}
	pr_debug("MZ TEEC_RegisterSharedMemory - OK\n");

	// Step 3: Open session
	result = TEEC_OpenSession(&tlc_struct->context, &tlc_struct->session, &tlc_struct->uuid,
								TEEC_LOGIN_USER,
								NULL, // No connection data needed for TEEC_LOGIN_USER.
								NULL, // dont use operation
								NULL);
	if (result != TEEC_SUCCESS) {
		pr_err("MZ  TEEC_OpenSession failed with error: %08x\n", result);
		goto close_context;
	}
	pr_debug("MZ TEEC_OpenSession - OK\n");

	tlc_struct->operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	tlc_struct->operation.params[0].memref.parent = &tlc_struct->shmem;
	tlc_struct->operation.params[0].memref.size = tlc_struct->shmem.size;
	tlc_struct->operation.params[0].memref.offset = 0;

	goto exit;

close_session:
	TEEC_CloseSession(&tlc_struct->session);

close_context:
	TEEC_FinalizeContext(&tlc_struct->context);
	kfree(tlc_struct->shmem_buff);

exit:
	if (result == TEEC_SUCCESS) {
		mzret = MZ_SUCCESS;
		is_TA_session_opened = true;
		target_count++;
	} else
		mzret = MZ_TA_FAIL;

	return mzret;
}

static int register_tee_driver(void)
{
	struct mz_tee_driver_fns fn = {
		.encrypt = encrypt_impl,
	};

	return register_mz_tee_crypto_driver(&fn);
}

static void unregister_tee_driver(void)
{
	unregister_mz_tee_crypto_driver();
}

void unload_trusted_app_teegris(void)
{
	tlc_struct_t *tlc_struct = 0;

	tlc_struct = mz_get_current();

	pr_info("MZ %s target_count %d\n", __func__, target_count);
	if (target_count > 1) {
		target_count--;
		return;
	}
	if (target_count != 1)
		return;

	pr_debug("MZ TA session is getting closed\n");

	// TEEC_ReleaseSharedMemory -> void function
	TEEC_ReleaseSharedMemory(&tlc_struct->shmem);
	kfree(tlc_struct->shmem_buff);

	// TEEC_CloseSession -> void function
	TEEC_CloseSession(&tlc_struct->session);

	// TEEC_FinalizeContext -> void function
	TEEC_FinalizeContext(&tlc_struct->context);

	memset(tlc_struct, 0x00, sizeof(tlc_struct_t));
	is_TA_session_opened = false;
	target_count--;
	pr_info("MZ ta unload\n");
}

static int __init tee_driver_init(void)
{
	int rc = 0;

	is_initialized = 0;
	is_TA_session_opened = false;
	target_count = 0;

	mz_tee_msg_task = kthread_run(tee_msg_thread, NULL, "mz_tee_msg_thread");
	if (IS_ERR(mz_tee_msg_task)) {
		rc = PTR_ERR(mz_tee_msg_task);
		pr_err("MZ Can't create mz_tee_msg_task: %d\n", rc);
		goto out;
	}
	rc = register_tee_driver();
	if (rc != MZ_SUCCESS) {
		pr_err("MZ Can't register tee_driver\n");
		goto out;
	}

	load_trusted_app = load_trusted_app_teegris;
	unload_trusted_app = unload_trusted_app_teegris;

out:
	return rc;
}

static void __exit tee_driver_exit(void)
{
	unregister_tee_driver();
	kthread_stop(mz_tee_msg_task);
}

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Samsung MZ tee Driver");
MODULE_VERSION("1.00");

module_init(tee_driver_init);
module_exit(tee_driver_exit);
