#! /usr/bin/env python3
'''
Unit Test for insert_kunit.py
'''

__author__ = 'Ji-Hun Kim'
__version__ = '0.1.0'
__maintainer__ = 'Ji-Hun Kim'
__email__ = 'ji_hun.kim@samsung.com'

import unittest
import shutil
import os
from insert_kunit import *

script_path, _ = os.path.split(os.path.realpath(__file__))

test_list = [
        'test_data/bsp_kernel/drivers/fingerprint',
        'test_data/bsp_kernel/drivers/muic'
]

def generate_test_data(path_name):
    test_orig=os.path.join(script_path, path_name)
    test_target = os.path.join(script_path, 'temp', path_name)

    try:
        shutil.copytree(test_orig, test_target)
    except FileExistsError as e:
        print(e)
        shutil.rmtree(test_target)
        shutil.copytree(test_orig, test_target)

    test_path = os.path.join(test_target, 'qbt2000_common.c')

    return test_path, test_target

def remove_temp_test_data():
    try:
        generated_path = os.path.join(script_path, 'temp')
        shutil.rmtree(generated_path)
    except Exception as e:
        print(e)

def is_contain(string, fpath):
    with open(fpath, 'r') as fp:
        if string in fp.read():
            return True
        else:
            return False

def how_many_contains(string, fpath):
    cnt = 0
    with open(fpath, 'r') as fp:
        for line in fp.readlines():
            if string in line:
                cnt = cnt + 1
    return cnt

class TestAdditionalInsertionSameDirectory(unittest.TestCase):
    '''
    If inserting test template to the same directory where is another templete
    has been generated previously.
    '''
    def setUp(self):
        self.test_path, self.test_tgt = generate_test_data(test_list[0])

        # 1. generate first test template for 'fingerprint/qbt2000_common.c'
        self.tgt_driver = os.path.join(self.test_tgt, 'qbt2000_common.c')
        self.af = TestConstructor(self.tgt_driver)
        self.af.append_makefile()
        self.af.append_kconfig()
        self.af.write_test_makefile()
        self.af.write_test_driver()

        # 2. generate second test template for 'fingerprint/fingerprint_sysfs.c'
        self.tgt_driver = os.path.join(self.test_tgt, 'fingerprint_sysfs.c')
        self.af2 = TestConstructor(self.tgt_driver)
        self.af2.append_makefile()
        self.af2.append_kconfig()
        self.af2.write_test_makefile()
        self.af2.write_test_driver()

        # these are target for check
        self.mkfile = os.path.join(self.test_tgt, 'Makefile')
        self.kconf = os.path.join(self.test_tgt, 'Kconfig')
        self.test = os.path.join(self.test_tgt, 'kunit_test')
        self.test_mkfile = os.path.join(self.test, 'Makefile')
        self.test_driver = os.path.join(self.test, 'qbt2000_common_test.c')
        self.test_driver2 = os.path.join(self.test, 'fingerprint_sysfs_test.c')

    def tearDown(self):
        remove_temp_test_data()

    # 1. Test cases for 'fingerprint/qbt2000_common.c'
    def test_append_makefile_qbt2000_common(self):
        self.assertTrue(os.path.exists(self.mkfile))
        self.assertTrue(is_contain('obj-$(CONFIG_SEC_KUNIT)', self.mkfile))
        self.assertTrue(is_contain('kunit_test/', self.mkfile))
        self.assertTrue(is_contain('GCOV_PROFILE_qbt2000_common', self.mkfile))

    def test_append_kconfig_qbt2000_common(self):
        self.assertTrue(os.path.exists(self.kconf))
        self.assertTrue(is_contain('config QBT2000_COMMON_TEST', self.kconf))

    def test_mkdir_test(self):
        self.assertTrue(os.path.exists(self.test))

    def test_gen_test_makefile_qbt2000_common(self):
        self.assertTrue(os.path.exists(self.test_mkfile))
        self.assertTrue(is_contain('CONFIG_SENSORS_QBT2000', self.test_mkfile))
        # CONFIG_SENSORS_QBT2000 should be in Makefile as well
        self.assertTrue(is_contain('CONFIG_SENSORS_QBT2000', self.mkfile))
        self.assertTrue(is_contain('CONFIG_QBT2000_COMMON_TEST', self.test_mkfile))
        self.assertTrue(is_contain('qbt2000_common_test.o', self.test_mkfile))

    def test_gen_test_driver_qbt2000_common(self):
        self.assertTrue(os.path.exists(self.test_driver))
        self.assertTrue(is_contain('module_test(qbt2000_common_test_module)', self.test_driver))

    # 2. Test cases for additional inserted 'fingerprint/fingerprint_sysfs.c'
    def test_append_makefile_fingerprint_sysfs(self):
        check_str = 'GCOV_PROFILE_fingerprint_sysfs'
        check_str_test = '+= kunit_test/'
        self.assertTrue(os.path.exists(self.mkfile))
        self.assertTrue(is_contain(check_str, self.mkfile))
        # Must have only one '+= kunit_test/' in Makefile
        self.assertEqual(how_many_contains(check_str, self.mkfile), 1)
        self.assertEqual(how_many_contains(check_str_test, self.mkfile), 1)

    def test_append_kconfig_fingerprint_sysfs(self):
        self.assertTrue(is_contain('config FINGERPRINT_SYSFS_TEST', self.kconf))

    def test_gen_test_makefile_fingerprint_sysfs(self):
        self.assertTrue(is_contain('CONFIG_FINGERPRINT_SYSFS_TEST', self.test_mkfile))
        self.assertTrue(is_contain('fingerprint_sysfs_test.o', self.test_mkfile))

    def test_gen_test_driver_fingerprint_sysfs(self):
        self.assertTrue(os.path.exists(self.test_driver2))
        self.assertTrue(is_contain('module_test(fingerprint_sysfs_test_module)', self.test_driver2))


class TestConstruntionTemplate(unittest.TestCase):
    def setUp(self):
        self.test_path, self.test_tgt = generate_test_data(test_list[0])
        self.tgt_driver = os.path.join(self.test_tgt, 'qbt2000_common.c')
        self.mkfile = os.path.join(self.test_tgt, 'Makefile')
        self.kconf = os.path.join(self.test_tgt, 'Kconfig')
        self.test = os.path.join(self.test_tgt, 'kunit_test')
        self.test_mkfile = os.path.join(self.test, 'Makefile')
        self.test_driver = os.path.join(self.test, 'qbt2000_common_test.c')
        self.af = TestConstructor(self.tgt_driver)

    def tearDown(self):
        remove_temp_test_data()

    def test_append_makefile(self):
        self.af.append_makefile()
        self.assertTrue(os.path.exists(self.mkfile))
        self.assertTrue(is_contain('obj-$(CONFIG_SEC_KUNIT)', self.mkfile))
        self.assertTrue(is_contain('kunit_test/', self.mkfile))
        self.assertTrue(is_contain('GCOV_PROFILE_qbt2000_common', self.mkfile))

    def test_append_kconfig(self):
        self.af.append_kconfig()
        self.assertTrue(os.path.exists(self.kconf))
        self.assertTrue(is_contain('config QBT2000_COMMON_TEST', self.kconf))
        self.assertTrue(is_contain('depends on SEC_KUNIT', self.kconf))

    def test_mkdir_test(self):
        self.assertTrue(os.path.exists(self.test))

    def test_gen_test_makefile(self):
        self.af.write_test_makefile()
        self.assertTrue(os.path.exists(self.test_mkfile))
        self.assertTrue(is_contain('CONFIG_SENSORS_QBT2000', self.test_mkfile))
        # CONFIG_SENSORS_QBT2000 should be in Makefile as well
        self.assertTrue(is_contain('CONFIG_SENSORS_QBT2000', self.mkfile))
        self.assertTrue(is_contain('CONFIG_QBT2000_COMMON_TEST', self.test_mkfile))
        self.assertTrue(is_contain('qbt2000_common_test.o', self.test_mkfile))

    def test_gen_test_driver(self):
        self.af.write_test_driver()
        self.assertTrue(os.path.exists(self.test_driver))
        self.assertTrue(is_contain('module_test(qbt2000_common_test_module)', self.test_driver))
        self.assertTrue(is_contain('include <kunit/test.h>', self.test_driver))

class TestConfigExtractor(unittest.TestCase):
    def setUp(self):
        self.test_path, self.test_tgt = generate_test_data(test_list[0])
        self.tgt_driver1 = os.path.join(self.test_tgt, 'qbt2000_common.c')
        self.tgt_driver2 = os.path.join(self.test_tgt, 'fingerprint_sysfs.c')

    def tearDown(self):
        remove_temp_test_data()

    def test_gen_tmplt(self):
        tmplt = TemplateGenerator(self.test_path)
        #print(tmplt.get_testfile())
        #print(tmplt.get_kconfig())
        #print(tmplt.get_makefile())

    def test_get_config(self):
        c = ConfigNameExtractor(self.tgt_driver1)
        self.assertEqual('CONFIG_SENSORS_QBT2000', c.result)

    def test_get_config2(self):
        c = ConfigNameExtractor(self.tgt_driver2)
        self.assertEqual('CONFIG_SENSORS_FINGERPRINT', c.result)


if __name__ == '__main__':
    unittest.main()
