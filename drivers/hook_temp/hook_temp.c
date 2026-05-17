#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/notifier.h>

// 定义kprobe结构体
static struct kprobe kp;

// 后处理函数
static void handler_post(struct kprobe *p, struct pt_regs *regs,
			 unsigned long flags)
{
	int i;
	for (i = 0; i < 31; i++) {
		if (regs->regs[i] >= 200 && regs->regs[i] <= 420) {
			pr_info("sec_bat_get_temperature: regs[%d]: from %lld to %lld\n",
				i, regs->regs[i], 261);
			regs->regs[i] = 261;
		} else if (regs->regs[i] >= 420 && regs->regs[i] <= 470) {
			pr_info("sec_bat_get_temperature: regs[%d]: from %lld to %lld\n",
				i, regs->regs[i], 361);
			regs->regs[i] = 361;
		}
	}
}

// 模块加载通知回调函数
static int module_notify(struct notifier_block *nb, unsigned long action,
			 void *data)
{
	struct module *mod = data;

	switch (action) {
	case MODULE_STATE_COMING:
		if (strcmp(mod->name, "sec_battery") == 0) {
			int ret;

			// 设置要钩住的函数地址
			kp.symbol_name = "sec_bat_get_temperature";
			kp.post_handler = handler_post;

			// 注册kprobe
			ret = register_kprobe(&kp);
			if (ret < 0) {
				pr_err("register_kprobe failed, returned %d\n",
				       ret);
				return NOTIFY_BAD;
			}
			pr_info("kprobe registered for sec_bat_get_temperature\n");
		}
		break;
	default:
		break;
	}
	return NOTIFY_OK;
}

// 定义notifier_block
static struct notifier_block nb = {
	.notifier_call = module_notify,
};

// 模块初始化
static int __init hook_temp_init(void)
{
	int ret;

	// 设置要钩住的函数地址
	kp.symbol_name = "sec_bat_get_temperature";
	kp.post_handler = handler_post;

	// 注册kprobe
	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_err("register_kprobe failed, returned %d\n", ret);
		register_module_notifier(&nb);
	}
	pr_info("kprobe registered for sec_bat_get_temperature\n");
	return 0;
}

// 模块退出
static void __exit hook_temp_exit(void)
{
	unregister_kprobe(&kp);
	unregister_module_notifier(&nb);
	pr_info("hook_temp module unloaded\n");
}

module_init(hook_temp_init);
module_exit(hook_temp_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Q");
MODULE_DESCRIPTION("Hook Temperature Module");