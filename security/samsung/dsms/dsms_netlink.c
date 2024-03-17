/*
 * Copyright (c) 2020-2021 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <linux/delay.h>
#include <linux/dsms.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/version.h>
#include <net/genetlink.h>
#include "dsms_kernel_api.h"
#include "dsms_netlink.h"
#include "dsms_netlink_protocol.h"
#include "dsms_preboot_buffer.h"
#include "dsms_test.h"

__visible_for_testing int dsms_daemon_callback(struct sk_buff *skb,
					       struct genl_info *info);
__visible_for_testing atomic_t daemon_ready = ATOMIC_INIT(0);

static struct nla_policy dsms_netlink_policy[DSMS_ATTR_COUNT + 1] = {
	[DSMS_VALUE] = { .type = NLA_U64 },
	[DSMS_FEATURE_CODE] = { .type = NLA_STRING, .len = FEATURE_CODE_LENGTH + 1},
	[DSMS_DETAIL] = { .type = NLA_STRING, .len = MAX_ALLOWED_DETAIL_LENGTH + 1},
	[DSMS_DAEMON_READY] = { .type = NLA_U32 },
};

static const struct genl_ops dsms_kernel_ops[] = {
	{
		.cmd = DSMS_MSG_CMD,
		.doit = dsms_daemon_callback,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
		.policy = dsms_netlink_policy,
#endif
	},
};

struct genl_multicast_group dsms_group[] = {
	{
		.name = DSMS_GROUP,
	},
};

static struct genl_family dsms_family = {
	.name = DSMS_FAMILY,
	.version = 1,
	.maxattr = DSMS_ATTR_MAX,
	.module = THIS_MODULE,
	.ops = dsms_kernel_ops,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
	.policy = dsms_netlink_policy,
#endif
	.mcgrps = dsms_group,
	.n_mcgrps = ARRAY_SIZE(dsms_group),
	.n_ops = ARRAY_SIZE(dsms_kernel_ops),
};

int __kunit_init dsms_netlink_init(void)
{
	int ret;

	ret = genl_register_family(&dsms_family);
	if (ret != 0)
		DSMS_LOG_ERROR("Netlink register failed: %d.", ret);

	return ret;
}

void __kunit_exit dsms_netlink_exit(void)
{
	int ret;

	ret = genl_unregister_family(&dsms_family);
	if (ret != 0)
		DSMS_LOG_ERROR("Netlink unregister failed: %d.", ret);
}

__visible_for_testing int dsms_daemon_callback(struct sk_buff *skb,
					       struct genl_info *info)
{
	if (atomic_add_unless(&daemon_ready, 1, 1)) {
		DSMS_LOG_DEBUG("Netlink daemon ready.");
		wakeup_preboot_sender();
	}

	return 0;
}

int dsms_daemon_ready(void)
{
	return atomic_read(&daemon_ready);
}

int dsms_send_netlink_message(const char *feature_code,
			      const char *detail,
			      int64_t value)
{
	int ret;
	void *msg_head;
	size_t detail_len;
	struct sk_buff *skb;

	DSMS_LOG_DEBUG("Sending netlink message.");

	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
	if (skb == NULL) {
		DSMS_LOG_ERROR("genlmsg_new error.");
		return -ENOMEM;
	}

	msg_head = genlmsg_put(skb, 0, 0,
			       &dsms_family, 0, DSMS_MSG_CMD);
	if (msg_head == NULL) {
		DSMS_LOG_ERROR("genlmsg_put error.");
		nlmsg_free(skb);
		return -ENOMEM;
	}

	ret = nla_put(skb, DSMS_VALUE, sizeof(value), &value);
	if (ret) {
		DSMS_LOG_ERROR("nla_put value error.");
		nlmsg_free(skb);
		return ret;
	}

	ret = nla_put(skb, DSMS_FEATURE_CODE,
		      FEATURE_CODE_LENGTH + 1, feature_code);
	if (ret) {
		DSMS_LOG_ERROR("nla_put feature error.");
		nlmsg_free(skb);
		return ret;
	}

	detail_len = strnlen(detail, MAX_ALLOWED_DETAIL_LENGTH);
	ret = nla_put(skb, DSMS_DETAIL, detail_len + 1, detail);
	if (ret) {
		DSMS_LOG_ERROR("nla_put detail error.");
		nlmsg_free(skb);
		return ret;
	}

	genlmsg_end(skb, msg_head);
	ret = genlmsg_multicast(&dsms_family, skb, 0, 0, GFP_ATOMIC);
	if (ret) {
		DSMS_LOG_ERROR("genlmsg_multicast error.");
		return ret;
	}

	return DSMS_SUCCESS;
}
