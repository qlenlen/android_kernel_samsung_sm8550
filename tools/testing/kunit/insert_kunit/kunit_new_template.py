# SPDX-License-Identifier: GPL-2.0

import os
import string

TEMPLATE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_TEMPLATE_PATH = os.path.join(TEMPLATE_DIR, 'test_template.c')
KCONFIG_TEMPLATE_PATH = os.path.join(TEMPLATE_DIR, 'test_template.Kconfig')
MAKEFILE_TEMPLATE_PATH = os.path.join(TEMPLATE_DIR, 'test_template.Makefile')

def create_skeleton_from_template(template_path, test_prefix, test_object_file):
	with open(template_path, 'r') as f:
		return string.Template(f.read()).safe_substitute(
				test_prefix=test_prefix,
				caps_test_prefix=test_prefix.upper(),
				test_object_file=test_object_file)

def create_kconfig_from_template(template_path, file_name, test_prefix):
	with open(template_path, 'r') as f:
		return string.Template(f.read()).safe_substitute(
				file_name=file_name,
				test_prefix=test_prefix,
				caps_test_prefix=test_prefix.upper())

class Skeletons(object):
	"""
	Represents the KUnit skeletons for a test, Kconfig entry, and Makefile
	entry.
	"""
	def __init__(self, test_skeleton, kconfig_skeleton, makefile_skeleton):
		self.test_skeleton = test_skeleton
		self.kconfig_skeleton = kconfig_skeleton
		self.makefile_skeleton = makefile_skeleton


def create_skeletons(file_name, namespace_prefix, test_object_file):
	test_prefix = namespace_prefix + '_test'
	return Skeletons(
			test_skeleton=create_skeleton_from_template(
					TEST_TEMPLATE_PATH,
					test_prefix,
					test_object_file),
			kconfig_skeleton=create_kconfig_from_template(
					KCONFIG_TEMPLATE_PATH,
					file_name,
					test_prefix),
			makefile_skeleton=create_skeleton_from_template(
					MAKEFILE_TEMPLATE_PATH,
					test_prefix,
					test_object_file)
	)

def namespace_prefix_from_path(path):
	file_name = os.path.basename(path)
	return os.path.splitext(file_name)

def create_skeletons_from_path(path, namespace_prefix=None, print_test_only=False):
	dir_name, file_name = os.path.split(path)
	file_prefix, _ = os.path.splitext(file_name)
	test_path = os.path.join(dir_name, file_prefix + '-test.c')
	test_object_file = file_prefix + '-test.o'
	if not namespace_prefix:
		namespace_prefix = file_prefix.replace('-', '_')
	skeletons = create_skeletons(file_name, namespace_prefix, test_object_file)
	print('### In ' + test_path)
	print(skeletons.test_skeleton)
	if print_test_only:
		return
	print('### In Kconfig')
	print(skeletons.kconfig_skeleton)
	print('### In Makefile')
	print(skeletons.makefile_skeleton)

