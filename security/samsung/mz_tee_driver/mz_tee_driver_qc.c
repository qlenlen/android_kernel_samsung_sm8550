/*
 * TEE Driver
 *
 * Copyright (C) 2019 Samsung Electronics, Inc.
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

#include "qseecom_kernel.h"

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
#define QSEE_DEVICE_APP_DIR "/vendor/firmware_mnt/image/"
#define QSEE_APP_NAME "mz"
#define MZ_PATH_MAX 4096

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

static int send_cmd(uint16_t cmd, uint32_t tgid,
		void *encrypt,
		void *iv);

static DEFINE_SPINLOCK(tee_msg_lock);
static LIST_HEAD(tee_msg_queue);
struct task_struct *mz_tee_msg_task;
static struct qseecom_handle *session;

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

	int           iResult = 0;
	tciMessage_t *tci;
	tciMessage_t *rsptci;
	uint32_t      retVal = 0;
	struct tci_msg *mzbuffer;

	if (session == NULL) {
		pr_err("MZ %s ta session is null\n", __func__);
		return -1;
	}

	if ((tciMessage_t *)(session)->sbuf == NULL) {
		pr_err("MZ %s sbuf is null\n", __func__);
		return -1;
	}

	tci = (tciMessage_t *)((session)->sbuf);
	rsptci = (tciMessage_t *)((session)->sbuf + sizeof(tciMessage_t));

	memset(tci, 0x00, sizeof(tciMessage_t));
	memset(rsptci, 0x00, sizeof(tciMessage_t));


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

	iResult = qseecom_set_bandwidth(session, true);
	if (iResult != 0) {
		pr_err("MZ %s qseecom_set_bandwidth fail\n", __func__);
		return -1;
	}

	// send command
	iResult = qseecom_send_command(session,
		(char *)tci,
		sizeof(tciMessage_t),
		(char *)rsptci,
		sizeof(tciMessage_t));
	if (iResult != 0) {
		iResult = qseecom_set_bandwidth(session, false);
		if (iResult != 0) {
			pr_err("MZ %s qseecom_set_bandwidth fail 2\n", __func__);
			return -1;
		}
		pr_err("MZ %s qseecom_send_command fail\n", __func__);
		return -1;
	}

	iResult = qseecom_set_bandwidth(session, false);
	if (iResult != 0) {
		pr_err("MZ %s qseecom_set_bandwidth fail 3\n", __func__);
		return -1;
	}

	// Check the Trustlet return code
	if (rsptci->response.header.returnCode != 0) {
		pr_err("MZ %s ta return error %d\n", __func__, rsptci->response.header.returnCode);
		return -1;
	}

	// Read result from TCI buffer
	retVal = rsptci->response.status;
	if (retVal != 1) {
		pr_err("MZ %s ta return status error %d\n", __func__, retVal);
		goto exit_error;
	}

	if (rsptci->msgData.bufferSize > MAX_SHMEM_LEN_BYTES) {
		pr_err("MZ %s ta return buffer size error\n", __func__);
		goto exit_error;
	}

	memcpy(mzbuffer, rsptci->msgData.buffer, sizeof(struct tci_msg));

	if (encrypt != NULL)
		memcpy(encrypt, mzbuffer->encrypt, 8);

	kfree(mzbuffer);

	return 1;

exit_error:
	memset(tci, 0x00, sizeof(tciMessage_t));
	memset(rsptci, 0x00, sizeof(tciMessage_t));

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

MzResult load_trusted_app(void)
{
	int qsee_res = 0;
	int tci_size = 0;
	MzResult mzret = MZ_SUCCESS;

	pr_info("MZ %s target_count %d\n", __func__, target_count);

	if (target_count != 0 && session != NULL) {
		target_count++;
		return mzret;
	}

	if (session != NULL) {
		pr_err("MZ %s ta session is not null\n", __func__);
		return MZ_TA_FAIL;
	}

	session = NULL;

	// Open the QSEE device
	tci_size = QSEECOM_ALIGN(2 * sizeof(tciMessage_t));
	qsee_res = qseecom_start_app(&session, QSEE_APP_NAME, tci_size);
	if (qsee_res != 0) {
		pr_err("MZ %s qseecom_start_app fail %d\n", __func__, qsee_res);
		mzret = MZ_TA_FAIL;
	} else {
		target_count++;
		pr_info("MZ ta load\n");
	}

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

void unload_trusted_app(void)
{
	int iResult = 0;

	pr_info("MZ %s target_count %d\n", __func__, target_count); //TODO remove
	if (target_count > 1 && session != NULL)
		target_count--;
		return;

	if (session == NULL) {
		pr_err("MZ %s ta session is null\n", __func__);
		return;
	}

	iResult = qseecom_shutdown_app(&session);
	session = NULL;
	target_count--;
	pr_info("MZ ta unload\n");
}

static int __init tee_driver_init(void)
{
	int rc = 0;

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
