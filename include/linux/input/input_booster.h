#ifndef _INPUT_BOOSTER_CORE_H_
#define _INPUT_BOOSTER_CORE_H_

#include <linux/kernel.h>
#include <linux/workqueue.h>
#include <linux/input.h>

#define MAX_IB_COUNT	100
#define MAX_EVENT_COUNT	1024
#define IB_EVENT_TOUCH_BOOSTER 1

struct ib_event_data {
	struct input_value *vals;
	int evt_cnt;
};

struct ib_event_work {
	struct input_value vals[MAX_EVENT_COUNT];
	int evt_cnt;
	struct work_struct evdev_work;
};

#endif // _INPUT_BOOSTER_CORE_H_
