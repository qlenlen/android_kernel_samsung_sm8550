// SPDX-License-Identifier: GPL-2.0
/*
 *  drivers/usb/core/usb_host_certify.c
 *
 * Copyright (C) 2020-2020 Samsung, Inc.
 * Author: Youngmin Park <ym.bak@samsung.com>
 *
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/usb.h>
#include <linux/string.h>
#include <linux/ratelimit.h>

void send_usb_host_certi_uevent(struct device *dev, int usb_certi)
{
	char *envp[3];
	char *state = {"STATE=ADD"};
	char *words;
	int index = 0;
	static DEFINE_RATELIMIT_STATE(rs_warm_reset, 5 * HZ, 1);

	envp[index++] = state;

	switch (usb_certi) {
	case USB_HOST_CERTI_UNSUPPORT_ACCESSORY:
		words = "WARNING=unsupport_accessory";
		break;
	case USB_HOST_CERTI_NO_RESPONSE:
		words = "WARNING=no_response";
		break;
	case USB_HOST_CERTI_HUB_DEPTH_EXCEED:
		words = "WARNING=hub_depth_exceed";
		break;
	case USB_HOST_CERTI_HUB_POWER_EXCEED:
		words = "WARNING=hub_power_exceed";
		break;
	case USB_HOST_CERTI_HOST_RESOURCE_EXCEED:
		words = "WARNING=host_resource_exceed";
		break;
	case USB_HOST_CERTI_WARM_RESET:
		if (!__ratelimit(&rs_warm_reset))
			goto err;
		words = "WARNING=no_response";
		break;
	default:
		pr_err("%s invalid input\n", __func__);
		goto err;
	}

	envp[index++] = words;

	envp[index++] = NULL;

	kobject_uevent_env(&dev->kobj, KOBJ_CHANGE, envp);
	pr_info("%s: %s\n", __func__, words);
err:
	return;
}
EXPORT_SYMBOL_GPL(send_usb_host_certi_uevent);

