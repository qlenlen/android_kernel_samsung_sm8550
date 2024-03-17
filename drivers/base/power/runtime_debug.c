/*
 * This file is temporarily added for pm runtime debugging.
 * case# 06517725.
 */
#include <linux/device.h>
#include <linux/of_address.h>

void print_runtime_debug_log_rpmflags(struct device *dev, int rpmflags)
{
	struct device_node *np;
	struct device_node *p_np;

	if (of_device_is_compatible(dev->of_node, "qcom,sde-kms")) {
		np = dev->of_node;
		p_np = of_find_node_by_name(np, "Q5_S6E3XA2_AMF756BQ03");
	}

	if (of_device_is_compatible(dev->of_node, "qcom,sde-kms") && (atomic_read(&dev->power.usage_count) <= 1))
		pr_err("%s:rpmflags%d: Usage count : %d Caller : %pS\n", __func__,rpmflags, atomic_read(&dev->power.usage_count), __builtin_return_address(1));


	return;
}

void print_runtime_debug_log(struct device *dev)
{
	struct device_node *np;
	struct device_node *p_np;

	if (of_device_is_compatible(dev->of_node, "qcom,sde-kms")) {
		np = dev->of_node;
		p_np = of_find_node_by_name(np, "Q5_S6E3XA2_AMF756BQ03");
	}

	if (of_device_is_compatible(dev->of_node, "qcom,sde-kms") && (atomic_read(&dev->power.usage_count) <= 1))
		pr_err("%s:%d Usage count : %d Caller : %pS\n", __func__, __LINE__, atomic_read(&dev->power.usage_count), __builtin_return_address(1));

	return;
}
