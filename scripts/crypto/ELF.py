#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module ELF contains ELF, Symbol, Section classes for manipulation over ELF files.
It can parse, and change ELF file. This version works only with vmlinux and doesn't properly work with ELF that contains
UND symbols
"""

import subprocess
import re
import os
import sys
import struct
from collections import OrderedDict
from binascii import unhexlify
from Utils import Utils
from math import ceil

__author__ = "Vadym Stupakov"
__copyright__ = "Copyright (c) 2017 Samsung Electronics"
__credits__ = ["Vadym Stupakov"]
__version__ = "1.0"
__maintainer__ = "Vadym Stupakov"
__email__ = "v.stupakov@samsung.com"
__status__ = "Production"

DEFAULT_NAME_JUMP_TABLE_START_SYM = "__start___jump_table"
DEFAULT_NAME_JUMP_TABLE_END_SYM = "__stop___jump_table"
DEFAULT_ARM_INST_WIDTH = 4

class Sec_Jumptable_Data:
    target_sec_idx = -1
    target_offset = -1
    code = -1
    key = -1

class Symbol:
    def __init__(self, name=str(), sym_type=str(), bind=str(), visibility=str(), addr=int(), size=int(), ndx=str()):
        self.utils = Utils()
        self.name = str(name)
        self.type = str(sym_type)
        self.bind = str(bind)
        self.ndx = str(ndx)
        self.visibility = str(visibility)
        self.addr = self.utils.to_int(addr)
        self.size = self.utils.to_int(size)

    def __str__(self):
        return "name: '{}', type: '{}', bind: '{}', ndx: '{}', visibility: '{}', address: '{}', size: '{}'".format(
            self.name, self.type, self.bind, self.ndx, self.visibility, hex(self.addr), hex(self.size)
        )


class Section:
    def __init__(self, name=str(), sec_type=str(), addr=int(), offset=int(), size=int()):
        self.utils = Utils()
        self.name = str(name)
        self.type = str(sec_type)
        self.addr = self.utils.to_int(addr)
        self.offset = self.utils.to_int(offset)
        self.size = self.utils.to_int(size)

    def __str__(self):
        return "name: '{}', type: '{}', address: '{}', offset: '{}', size: '{}'".format(
            self.name, self.type, hex(self.addr), hex(self.offset), hex(self.size)
        )


class ELF:
    """
    Utils for manipulating over ELF
    """
    def __init__(self, elf_file, first_obj_file):
        self.__elf_file = elf_file
        self.utils = Utils()
        self.__readelf_path = None
        self.__obj_parser_tool = None
        self.__parsers_elf_list = ["llvm-readelf", "readelf"]
        self.__parsers_obj_list = ["llvm-nm", "nm"]
        self.__sections = OrderedDict()
        self.__symbols = OrderedDict()
        self.__symbols_list_text = None
        self.__symbols_list_rodata = None
        self.__symbols_list_init_data = None
        self.__relocs_text = None
        self.__relocs_rodata = None
        self.__re_hexadecimal = "\s*[0-9A-Fa-f]+\s*"
        self.__re_sec_name = "\s*[._a-zA-Z]+\s*"
        self.__re_type = "\s*[A-Z]+\s*"
        self.__altinstr_text = None
        self.__altinstr_rodata = None
        self.__readelf_path, self.__obj_parser_tool = self.select_parser_tools(elf_file, first_obj_file)
        self.jumptable_struct_format = '<iiQ'
        self.__jt_rec = []

    def get_raw_by_tool(self, tool_name, options):
        """
        Execute tool_name with options and print raw output
        :param tool_name: name of applied tool
        :param options: options of applied tool: ["opt1", "opt2", "opt3", ..., "optN"]
        :returns raw output
        """
        ret = subprocess.Popen(args=[tool_name] + options,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        stdout, stderr = ret.communicate()
        err_msg = stderr.decode("utf-8").strip()
        if ret.returncode != 0 and ("error" in err_msg or "Error" in err_msg):
            raise ChildProcessError(stderr.decode("utf-8"))
        return stdout.decode("utf-8")

    def check_tool_on_error(self, tool_name, options):
        """
        Execute tool_name with options and print raw output
        :param tool_name: name of applied tool
        :param options: options of applied tool: ["opt1", "opt2", "opt3", ..., "optN"]
        :returns raw output
        """
        ret = subprocess.Popen(args=[tool_name] + options,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        ret.communicate()
        if ret.returncode != 0:
            return False
        return True

    def check_is_parser(self, parser):
        try:
            ret = subprocess.Popen(args=[parser] + ["--help"],
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
            ret.communicate()
        except FileNotFoundError:
            return False
        return True

    def get_elf_file(self):
        return os.path.abspath(self.__elf_file)

    def get_sections(self):
        """"
        Execute -> parse -> transform to dict() readelf output
        :returns dict: {sec_addr : Section()}
        """
        if len(self.__sections) == 0:
            sec_header = self.get_raw_by_tool(self.__readelf_path, ["-SW",  self.__elf_file]).strip()
            secs = re.compile("^.*\[.*\](" + self.__re_sec_name + self.__re_type + self.__re_hexadecimal +
                              self.__re_hexadecimal + self.__re_hexadecimal + ")", re.MULTILINE)
            found = secs.findall(sec_header)
            for line in found:
                line = line.split()
                if len(line) == 5:
                    self.__sections[int(line[2], 16)] = Section(name=line[0], sec_type=line[1], addr=int(line[2], 16),
                                                                offset=int(line[3], 16), size=int(line[4], 16))
            self.__sections = OrderedDict(sorted(self.__sections.items()))
        return self.__sections

    def find_str_in_text(self, req_str, text):
        for line in text.splitlines():
            if req_str in line:
                return True
        return False

    def select_parser_tools(self, elf_file, first_obj_file):
        """
        Select parser tool for output ELF file
        If ELF file has section "relr.dyn" than "llvm-readelf" parser will be to employed
        otherwise "readelf"
        "llvm-nm" is used to parse object files
        :param elf_file: name of output ELF file
        :return "output ELF parser", "object files parser"
        """
        ret_tool_readelf = None
        ret_tool_nm = None
        for parser in self.__parsers_elf_list:
            if self.check_is_parser(parser):
                raw_sections = self.get_raw_by_tool(parser, ["-SW", elf_file]).strip()
                if self.find_str_in_text(" .relr.dyn ", raw_sections) and parser == "llvm-readelf":
                    ret_tool_readelf = parser
                    break
                if not self.find_str_in_text(" .relr.dyn ", raw_sections) and parser == "readelf":
                    ret_tool_readelf = parser
                    break

        for parser in self.__parsers_obj_list:
            if self.check_is_parser(parser):
                abs_path_file = os.path.abspath(first_obj_file)
                if self.check_tool_on_error(parser, ["--defined-only", abs_path_file]):
                    ret_tool_nm = parser
                    break

        if ret_tool_readelf is None:
            print("\nERROR: Neither required ELF parsers {} is found\n".format(", ".join(self.__parsers_elf_list)))
        if ret_tool_nm is None:
            print("\nERROR: Neither required OBJs parsers {} is found\n".format(", ".join(self.__parsers_obj_list)))
        if ret_tool_readelf is None or ret_tool_nm is None:
            sys.exit(-1)

        print("Used parsers are: ", ret_tool_readelf, ret_tool_nm)
        return ret_tool_readelf, ret_tool_nm

    def get_rodata_text_scope(self):
        raw_sections = self.get_raw_by_tool(self.__readelf_path, ["-SW",  self.__elf_file]).strip()
        section_rodata = list()
        section_text = list()

        for line in raw_sections.splitlines():
            line_list = list(line.split())
            i = 0
            len_list = len(line_list)
            while i < len_list:
                if "." not in line_list[i]:
                    del line_list[i]
                    len_list = len(line_list)
                else:
                    break
            if len(line_list) >= 6:
                if line_list[0].strip().startswith('.rodata'):
                    if int(line_list[4].strip(), 16) != 0:
                        section_rodata.append([line_list[2].strip(), line_list[4].strip()])
                elif line_list[0].strip().startswith('.text') or line_list[0].strip() == ".init.text":
                    section_text.append([line_list[2].strip(), line_list[4].strip()])
        return section_text, section_rodata

    def get_list_symbols_from_file(self, path_to_files, file_name):
        """
        Extract from object file the symbols from section .text and all .data sections
        :param path_to_files: path to object files
        :param file_name: name of parsing object file
        :return: symbols_text, symbols_rodata
        """
        not_allowed_syms = ["__UNIQUE_ID_", "__kstrtab_", "__ksym_marker_", "__ksymtab_", "__exitcall_", "__initcall_", "$x", "$d"]
        abs_path_file = os.path.abspath(os.path.join(path_to_files, file_name))
        raw_syms_output = self.get_raw_by_tool(self.__obj_parser_tool,["--defined-only", abs_path_file])
        symbols_text = list()
        symbols_rodata = list()

        for line in raw_syms_output.splitlines():
            line_split = line.split()
            if len(line_split) == 3:
                skip_symbol = False
                if line_split[1] in ("D", "d", "T", "t", "R", "r"):
                    for l_sort in not_allowed_syms:
                        if line_split[2].startswith(str(l_sort)):
                            skip_symbol = True
                            break
                    if not skip_symbol:
                        if line_split[1] in ("T", "t"):
                            symbols_text.append([line_split[1], line_split[2]])
                        elif line_split[1] in ("D", "d", "R", "r"):
                            symbols_rodata.append([line_split[1], line_split[2]])

        return symbols_text, symbols_rodata

    def get_symbols_from_obj_files(self, path_to_files, list_files):
        """
        Forming list with candidates to canister
        """
        text_obj_symbols = list()
        rodata_obj_symbols = list()

        for l_file in list_files:
            if os.path.isfile(str(path_to_files + "/" + l_file)):
                file_obj_text, file_obj_data = self.get_list_symbols_from_file(path_to_files, l_file)
                text_obj_symbols.extend(file_obj_text)
                rodata_obj_symbols.extend(file_obj_data)
            else:
                print("\nSKC file ", l_file, "is not found")
        return text_obj_symbols, rodata_obj_symbols

    def filtered_addr_by_section(self, addr, section_gap):
        for l_addr in section_gap:
            start_addr = self.utils.to_int(l_addr[0])
            end_addr = start_addr + self.utils.to_int(l_addr[1])
            if self.utils.to_int(addr) >= start_addr and self.utils.to_int(addr) < end_addr:
                return True
        return False

    def get_single_symbol_raw(self, name: str) -> Symbol:
        sym_tab = self.get_raw_by_tool(self.__readelf_path, ["-sW",  self.__elf_file])
        syms = re.compile(r"^.*\d+:\s(.*$)", re.MULTILINE)
        found = syms.findall(sym_tab.strip())
        for line in found:
            line = line.split()
            if len(line) == 7:
                size = line[1]
                # This needs, because readelf prints sizes in hex if size is large
                if size[:2].upper() == "0X":
                    size = int(size, 16)
                else:
                    size = int(size, 10)

                one_symbol = Symbol(addr=int(line[0], 16), size=size, sym_type=line[2],
                                    bind=line[3], visibility=line[4], ndx=line[5],
                                    name=line[6])
                if one_symbol.name == name:
                    return one_symbol
        return None

    def get_elf_symbols_list(self):
        """"
        Execute -> parse -> transform readelf symbols output into lists [symbols in .text, .init.text]
        and [symbols in .rodata]
        :returns lists: [symbols in .text, .init.text], [symbols in .rodata], [symbols in .init.data]
        """
        if self.__symbols_list_text is None or self.__symbols_list_rodata is None:
            self.__symbols_list_text = list()
            self.__symbols_list_rodata = list()
            self.__symbols_list_init_data = list()
            section_text, section_rodata = self.get_rodata_text_scope()
            section_obj_init_data = self.get_section_by_name(".init.data")
            sym_tab = self.get_raw_by_tool(self.__readelf_path, ["-sW",  self.__elf_file])
            syms = re.compile(r"^.*\d+:\s(.*$)", re.MULTILINE)
            found = syms.findall(sym_tab.strip())
            for line in found:
                line = line.split()
                if len(line) == 7:
                    size = line[1]
                    # This needs, because readelf prints sizes in hex if size is large
                    if size[:2].upper() == "0X":
                        size = int(size, 16)
                    else:
                        size = int(size, 10)

                    addr_symbol=self.utils.to_int(line[0])
                    one_symbol = Symbol(addr=int(line[0], 16), size=size, sym_type=line[2],
                                        bind=line[3], visibility=line[4], ndx=line[5],
                                        name=line[6])
                    if not line[6].startswith('$') and (size != 0) and ".cfi_jt" not in line[6]:
                        if self.filtered_addr_by_section(addr_symbol, section_text):
                            self.__symbols_list_text.append(one_symbol)
                        elif self.filtered_addr_by_section(addr_symbol, section_rodata):
                            self.__symbols_list_rodata.append(one_symbol)
                    else:
                        if section_obj_init_data is not None:
                            if self.filtered_addr_by_section(addr_symbol, \
                                [[section_obj_init_data.addr, section_obj_init_data.size]]):
                                self.__symbols_list_init_data.append(one_symbol)

        return self.__symbols_list_text, self.__symbols_list_rodata, self.__symbols_list_init_data

    def get_text_symbols(self):
        list_text, _, _ = self.get_elf_symbols_list()
        return list_text

    def get_rodata_symbols(self):
        _, list_rodata, _ = self.get_elf_symbols_list()
        return list_rodata

    def get_init_data_symbols(self):
        _, _, list_init_data = self.get_elf_symbols_list()
        return list_init_data

    def get_symbols(self):
        """"
        Execute -> parse -> transform the to dict() readelf output
        :returns dict: {sym_addr : Symbol()}
        """
        if len(self.__symbols) == 0:
            list_text, list_rodata, _ = self.get_elf_symbols_list()

            for l_symbol in list_text:
                self.__symbols[l_symbol.addr] = l_symbol

            for l_symbol in list_rodata:
                self.__symbols[l_symbol.addr] = l_symbol

            self.__symbols = OrderedDict(sorted(self.__symbols.items()))
        return self.__symbols

    def get_relocs_text_rodata(self):
        """
        returns list: [reloc_text1, reloc_text2, ..., reloc_textN], [reloc_rodata1, reloc_rodata2, ..., reloc_rodataN]
        """
        if self.__relocs_text is None or self.__relocs_rodata is None:
            self.__relocs_text = list()
            self.__relocs_rodata = list()
            relocs = self.get_raw_by_tool(self.__readelf_path, ["-rW",  self.__elf_file])
            rel = re.compile(r"^(" + self.__re_hexadecimal + ")\s*", re.MULTILINE)
            section_text, section_rodata = self.get_rodata_text_scope()
            for el in rel.findall(relocs.strip()):
                rel_addr = self.utils.to_int(el)
                if self.filtered_addr_by_section(rel_addr, section_rodata):
                    self.__relocs_rodata.append(rel_addr)
                elif self.filtered_addr_by_section(rel_addr, section_text):
                    self.__relocs_text.append(rel_addr)
            self.__relocs_text.sort()
            self.__relocs_rodata.sort()
        return self.__relocs_text, self.__relocs_rodata

    def get_relocs_for_symbol(self, relocs_list, start_addr=None, end_addr=None):
        """"
        :param relocs_list: input relocation list
        :param start_addr: start address :int
        :param end_addr: end address: int
        :returns list: [reloc1, reloc2, reloc3, ..., relocN]
        """
        ranged_rela = list()
        if start_addr and end_addr is not None:
            for el in relocs_list:
                if self.utils.to_int(end_addr) <= self.utils.to_int(el):
                    break
                if self.utils.to_int(start_addr) <= self.utils.to_int(el):
                    ranged_rela.append(el)
        return ranged_rela

    def get_text_rodata_altinstructions_lists(self):
        """
        :returns list: [[text_alt_inst1_addr, length1], [text_alt_inst2_addr, length2], ...], [[rodata_alt_inst1_addr, length1], [rodata_alt_inst2_addr, length2], ...]

        .altinstructions section contains an array of struct alt_instr.
        As instance, for kernel 4.14 from /arch/arm64/include/asm/alternative.h
        struct alt_instr {
            s32 orig_offset;    /* offset to original instruction */
            s32 alt_offset;     /* offset to replacement instruction */
            u16 cpufeature;     /* cpufeature bit set for replacement */
            u8  orig_len;       /* size of original instruction(s) */
            u8  alt_len;        /* size of new instruction(s), <= orig_len */
        };

        Later, address of original instruction can be calculated as
        at runtime     : &(alt_instr->orig_offset) + alt_instr->orig_offset + kernel offset
        ELF processing : address of .altinstruction section + in section offset of alt_instr structure + value of alt_instr.orig_offset
        details in /arch/arm64/kernel/alternative.c, void __apply_alternatives(void *, bool)
        """

        # The struct_format should reflect <struct alt_instr> content
        struct_format = '<iiHBB'
        pattern_altinst_section_content = "^ *0x[0-9A-Fa-f]{16} (.*) .*.{16}$"
        pattern_altinstr_section_addr = "^ *(0x[0-9A-Fa-f]{16}).*.*.{16}$"

        if self.__altinstr_text is not None:
            return self.__altinstr_text, self.__altinstr_rodata

        self.__altinstr_text = list()
        self.__altinstr_rodata = list()

        __hex_dump = self.get_raw_by_tool(self.__readelf_path, ["--hex-dump=.altinstructions", self.__elf_file])
        if len(__hex_dump) == 0:
            return self.__altinstr_text, self.__altinstr_rodata

        # .altinstruction section start addr in ELF
        __altinstr_section_addr = int(re.findall(pattern_altinstr_section_addr, __hex_dump, re.MULTILINE)[0], 16)

        # To provide .altinstruction section content using host readelf only
        # some magic with string parcing is needed
        hex_dump_list = re.findall(pattern_altinst_section_content, __hex_dump, re.MULTILINE)
        __hex_dump_str = ''.join(hex_dump_list).replace(" ", "")
        __altinstr_section_bin = unhexlify(__hex_dump_str)
        __struct_size = struct.calcsize(struct_format)

        if (len(__altinstr_section_bin) % __struct_size) != 0:
            return self.__altinstr_text, self.__altinstr_rodata

        section_text, section_rodata = self.get_rodata_text_scope()
        if len(section_text) !=0 or len(section_rodata) !=0:
            __i = 0
            while __i < (len(__altinstr_section_bin) - __struct_size):
                __struct_byte = __altinstr_section_bin[__i: __i + __struct_size]
                __struct_value = list(struct.unpack(struct_format, __struct_byte))

                # original instruction addr (going to be replaced) considered as "gap"
                __original_instruction_addr = __struct_value[0] + __altinstr_section_addr + __i

                # derive the target ARM instruction(s) length.
                __target_instruction_len = __struct_value[4]

                if self.filtered_addr_by_section( __original_instruction_addr, section_text):
                    self.__altinstr_text.append([__original_instruction_addr, __target_instruction_len])
                elif self.filtered_addr_by_section(__original_instruction_addr, section_rodata):
                    self.__altinstr_rodata.append([__original_instruction_addr, __target_instruction_len])
                __i = __i + __struct_size
            self.__altinstr_text.sort()
            self.__altinstr_rodata.sort()
        return self.__altinstr_text, self.__altinstr_rodata

    def add_addrs_space_to_list(self, addr_list, addr_start, addr_end):
        for addr in range(addr_start, addr_end):
            addr_list.append(addr)

    def get_altinstructions(self, alt_instr_list, start_addr=None, end_addr=None):
        """
        :param start_addr: start address :int
        :param end_addr: end address: int
        :param alt_instr_list: list alternative instractions
        :returns list: [[alt_inst1_addr, length1], [alt_inst2_addr, length2], ...]
        """
        ranged_altinst = list()
        if len(alt_instr_list) == 0:
            return ranged_altinst
        if start_addr is not None and end_addr is not None:
            start_addr_int = self.utils.to_int(start_addr)
            end_addr_int = self.utils.to_int(end_addr)
            for l_instr in alt_instr_list:
                l_instr_addr_end = l_instr[0] + l_instr[1]
                if end_addr_int <= l_instr[0]:
                    break
                if start_addr_int <= l_instr[0] < end_addr_int and l_instr_addr_end < end_addr_int:
                    self.add_addrs_space_to_list(ranged_altinst, l_instr[0], l_instr_addr_end)
                elif start_addr_int <= l_instr[0] < end_addr_int and l_instr_addr_end >= end_addr_int:
                    self.add_addrs_space_to_list(ranged_altinst, l_instr[0], end_addr_int)
                elif start_addr_int > l_instr[0] and l_instr_addr_end < end_addr_int:
                    self.add_addrs_space_to_list(ranged_altinst, start_addr_int, l_instr_addr_end)
                elif start_addr_int > l_instr[0] and l_instr_addr_end > end_addr_int:
                    self.add_addrs_space_to_list(ranged_altinst, start_addr_int, end_addr_int)
        return ranged_altinst

    def get_jump_table_list(self) -> list:
        """
        :param start_addr: seek start address :int
        :param end_addr: seek end address: int
        :param alt_instr_list: list of instruction addrs modified in frame of jump_lables patch
        :returns list: [[inst1_addr, length1], [inst2_addr, length2], ...]
        """

        jump_table_start_sym = self.get_single_symbol_raw(DEFAULT_NAME_JUMP_TABLE_START_SYM)
        jump_table_end_sym = self.get_single_symbol_raw(DEFAULT_NAME_JUMP_TABLE_END_SYM)
        if jump_table_start_sym == None or jump_table_end_sym == None:
            return []

        __jumptable_struct_size = struct.calcsize(self.jumptable_struct_format)
        jump_table_content = self.get_data_by_vaddr(jump_table_start_sym.addr,
                                               jump_table_end_sym.addr - jump_table_start_sym.addr)

        for i in range(ceil((jump_table_end_sym.addr - jump_table_start_sym.addr)/__jumptable_struct_size)):
            __jtr = Sec_Jumptable_Data()
            __begin = i * __jumptable_struct_size
            __end = __begin + __jumptable_struct_size

            [ __jtr.code,
            __jtr.target_offset,
            __jtr.key ] = list(struct.unpack(self.jumptable_struct_format,
                                    jump_table_content[__begin: __end]))

            __jtr.code = __jtr.code + jump_table_start_sym.addr + i * __jumptable_struct_size
            __jtr.target_offset = __jtr.target_offset + jump_table_start_sym.addr + i * __jumptable_struct_size
            self.__jt_rec.append(__jtr)

        return self.__jt_rec

    def get_jump_table_module(self, start_addr: int, end_addr: int, jump_table: list) -> list:
        """
        Return JT related gaps are in range of our module
        :param start_addr: int
        :param end_addr: int
        :param jump_table: list   full list (over whole kernel) of JT items
        :returns list of addrs to be excluded [exclude_addr1, exclude_addr2, ...]
        """
        result_jt_gaps = list()
        for jt_item in jump_table:
            if start_addr <= jt_item.code and end_addr > jt_item.code:
                for __addr in range(jt_item.code, jt_item.code + DEFAULT_ARM_INST_WIDTH):
                    result_jt_gaps.append(__addr)
        return result_jt_gaps

    def get_symbol_by_name_text(self, sym_name: str) -> Symbol:
        """
        Get symbol by_name in section .rodata
        :param sym_name: name of symbol
        :return: Symbol()
        """
        for symbol_obj in self.get_text_symbols():
            if symbol_obj.name == sym_name:
                return symbol_obj
        return None

    def get_symbol_by_name_rodata(self, sym_name: str):
        """
        Get symbol by_name in section .rodata
        :param sym_name: name of symbol
        :return: Symbol()
        """
        for symbol_obj in self.get_rodata_symbols():
            if symbol_obj.name == sym_name:
                return symbol_obj
        return None

    def get_symbol_by_name_init_data(self, sym_name: str):
        """
        Get symbol by_name in section .init.data
        :param sym_name: name of symbol
        :return: Symbol()
        """
        for symbol_obj in self.get_init_data_symbols():
            if symbol_obj.name == sym_name:
                return symbol_obj
        return None

    def get_symbol_by_vaddr(self, vaddrs=None):
        """
        Get symbol by virtual address
        :param vaddrs: vaddr : int or list
        :return: Symbol() or [Symbol()]
        """
        if isinstance(vaddrs, int):
            if vaddrs in self.get_symbols():
                return self.get_symbols()[vaddrs]
            for addr, symbol_obj in self.get_symbols().items():
                if (addr + symbol_obj.size) >= vaddrs >= addr:
                    return symbol_obj
        elif isinstance(vaddrs, list):
            symbol = [self.get_symbol_by_vaddr(vaddr) for vaddr in vaddrs]
            return symbol
        else:
            raise ValueError
        return None

    def get_section_by_name(self, sec_names=None):
        """
        Get section by_name
        :param sec_names: "sec_name" : str or list
        :return: Section() or [Section()]
        """
        if isinstance(sec_names, str):
            for _, section_obj in self.get_sections().items():
                if section_obj.name == sec_names:
                    return section_obj
        elif isinstance(sec_names, list):
            sections = [self.get_section_by_name(sec_name) for sec_name in sec_names]
            return sections
        else:
            raise ValueError
        return None

    def get_section_by_vaddr(self, vaddrs=None):
        """
        Get section by virtual address
        :param vaddrs: vaddr : int  or list
        :return: Section() or [Section()]
        """
        if isinstance(vaddrs, int):
            if vaddrs in self.get_sections():
                return self.get_sections()[vaddrs]
            for addr, section_obj in self.get_sections().items():
                if (addr + section_obj.size) >= vaddrs >= addr:
                    return section_obj
        elif isinstance(vaddrs, list):
            sections = [self.get_symbol_by_vaddr(vaddr) for vaddr in vaddrs]
            return sections
        else:
            raise ValueError
        return None

    def vaddr_to_file_offset(self, vaddrs):
        """
        Transform virtual address to file offset
        :param vaddrs: addr string or int or list
        :returns file offset or list
        """
        if isinstance(vaddrs, str) or isinstance(vaddrs, int):
            section = self.get_section_by_vaddr(vaddrs)
            return self.utils.to_int(vaddrs, 16) - section.addr + section.offset
        elif isinstance(vaddrs, list):
            return [self.vaddr_to_file_offset(vaddr) for vaddr in vaddrs]
        else:
            raise ValueError

    def read_data_from_vaddr(self, vaddr, size, out_file):
        with open(self.__elf_file, "rb") as elf_fp:
            elf_fp.seek(self.vaddr_to_file_offset(vaddr))
            with open(out_file, "wb") as out_fp:
                out_fp.write(elf_fp.read(size))

    def get_data_by_vaddr(self, vaddr, size) -> bytearray:
        with open(self.__elf_file, "rb") as elf_fp:
            elf_fp.seek(self.vaddr_to_file_offset(vaddr))
            outbuff = elf_fp.read(size)
        return outbuff
