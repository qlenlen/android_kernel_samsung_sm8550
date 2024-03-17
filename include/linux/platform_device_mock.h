/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Fake platform device API for unit testing platform drivers.
 *
 * Copyright (C) 2018, Google LLC.
 * Author: Brendan Higgins <brendanhiggins@google.com>
 */

#include <linux/platform_device.h>
#include <kunit/mock.h>

static inline struct platform_driver *platform_driver_find(const char *name)
{
	struct device_driver *driver;

	driver = driver_find(name, &platform_bus_type);
	if (!driver)
		return NULL;

	return to_platform_driver(driver);
}

/**
 * of_fake_node()
 * @test: the test to associate node with
 * @name: name of the node
 *
 * The &struct device_node returned is allocated as a root node with the given
 * name and otherwise behaves as a real &struct device_node.
 *
 * Returns: the faked &struct device_node
 */
struct device_node *of_fake_node(struct kunit *test, const char *name);

/**
 * of_fake_probe_platform()
 * @test: the test to associate the fake platform device with
 * @driver: driver to probe
 * @node_name: name of the device node created
 *
 * Creates a &struct platform_device and an associated &struct device_node,
 * probes the provided &struct platform_driver with the &struct platform_device.
 *
 * Returns: the &struct platform_device that was created
 */
struct platform_device *
of_fake_probe_platform(struct kunit *test,
		       struct platform_driver *driver,
		       const char *node_name);

/**
 * of_fake_probe_platform_by_name()
 * @test: the test to associate the fake platform device with
 * @driver_name: name of the driver to probe
 * @node_name: name of the device node created
 *
 * Same as of_fake_probe_platform() but looks up the &struct platform_driver by
 * the provided name.
 *
 * Returns: the &struct platform_device that was created
 */
struct platform_device *of_fake_probe_platform_by_name(struct kunit *test,
						       const char *driver_name,
						       const char *node_name);
