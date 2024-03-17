#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module Utils contains Utils class with general purpose helper functions.
"""

import struct
import os
from itertools import chain

__author__ = "Vadym Stupakov"
__copyright__ = "Copyright (c) 2017 Samsung Electronics"
__credits__ = ["Vadym Stupakov"]
__version__ = "1.0"
__maintainer__ = "Vadym Stupakov"
__email__ = "v.stupakov@samsung.com"
__status__ = "Production"


class Utils:
    """
    Utils class with general purpose helper functions.
    """
    @staticmethod
    def flatten(alist):
        """
        Make list from sub lists
        :param alist: any list: [[item1, item2], [item3, item4], ..., [itemN, itemN+1]]
        :return: [item1, item2, item3, item4, ..., itemN, itemN+1]
        """
        if alist is []:
            return []
        elif type(alist) is not list:
            return [alist]
        else:
            return [el for el in chain.from_iterable(alist)]

    @staticmethod
    def pairwise(iterable):
        """
        Iter over two elements: [s0, s1, s2, s3, ..., sN] -> (s0, s1), (s2, s3), ..., (sN, sN+1)
        :param iterable:
        :return: (s0, s1), (s2, s3), ..., (sN, sN+1)
        """
        a = iter(iterable)
        return zip(a, a)

    @staticmethod
    def paths_exists(path_list):
        """
        Check if path exist, otherwise raise FileNotFoundError exception
        :param path_list: list of paths
        """
        for path in path_list:
            if not os.path.exists(path):
                raise FileNotFoundError("File: \"" + path + "\" doesn't exist!\n")

    @staticmethod
    def to_int(value, base=16):
        """
        Converts string to int
        :param value: string or int
        :param base: string base int
        :return: integer value
        """
        if isinstance(value, int):
            return value
        elif isinstance(value, str):
            return int(value.strip(), base)

    def to_bytearray(self, value):
        """
        Converts list to bytearray with block size 8 byte
        :param value: list of integers or bytearray or int
        :return: bytes
        """
        if isinstance(value, bytearray) or isinstance(value, bytes):
            return value
        elif isinstance(value, list):
            value = self.flatten(value)
            return struct.pack("%sQ" % len(value), *value)
        elif isinstance(value, int):
            return struct.pack("Q", value)

    @staticmethod
    def human_size(nbytes):
        """
        Print in human readable
        :param nbytes: number of bytes
        :return: human readable string. For instance: 0x26a5d (154.6 K)
        """
        raw = nbytes
        suffixes = ("B", "K", "M")
        i = 0
        while nbytes >= 1024 and i < len(suffixes) - 1:
            nbytes /= 1024.
            i += 1
        f = "{:.1f}".format(nbytes).rstrip("0").rstrip(".")
        return "{} ({} {})".format(hex(raw), f, suffixes[i])

    def byte_int_to_hex_str(self, value):
        str_hex = "{:#x}".format(self.to_int(value))
        if len(str_hex) == 3:
            return "0x0" + str_hex[-1]
        return str_hex

    def byte_int_to_hex_str2(self, value):
        str_hex = "{:x}".format(self.to_int(value))
        if len(str_hex) == 1:
            return "0" + str_hex[-1]
        return str_hex

    def dump_to_int(self, dump_mem):
        str_dump = ""
        for l_count in range(0, 8):
            str_dump += self.byte_int_to_hex_str(dump_mem[7 - l_count])[2:]
        return self.to_int(str_dump)
