#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module IntegrityRoutine Contains IntegrityRoutine class helps with FIPS 140-2 build time integrity routine.
This module is needed to calculate HMAC and embed other needed stuff.
"""

import hmac
import hashlib
import binascii
from itertools import groupby
from ELF import ELF

__author__ = "Vadym Stupakov"
__copyright__ = "Copyright (c) 2017 Samsung Electronics"
__credits__ = ["Vadym Stupakov"]
__version__ = "1.0"
__maintainer__ = "Vadym Stupakov"
__email__ = "v.stupakov@samsung.com"
__status__ = "Production"


class IntegrityRoutine(ELF):
    """
    Utils for fips-integrity process
    """
    def __init__(self, elf_file, first_obj_file):
        ELF.__init__(self, elf_file, first_obj_file)

    @staticmethod
    def __remove_all_dublicates(lst):
        """
        Removes all occurrences of the same value. For instance: transforms [1, 2, 4, 3, 1] -> [2, 3, 4]
        :param lst: input list
        :return: sorted lst w/o duplicates
        """
        if len(lst) < 2:
            return lst
        lst.sort()
        return [k for k, v in groupby(lst) if len(list(v)) < 2]

    def get_reloc_gaps(self, relocs_list, start_addr, end_addr):
        """
        :param start_addr: start address :int
        :param end_addr: end address: int
        :returns list of exclude addr like [exclude_addr1, exclude_addr2, ...]
        """
        relocs_gaps = list()
        all_relocs = self.get_relocs_for_symbol(relocs_list, start_addr, end_addr)
        for addr in all_relocs:
            relocs_gaps.extend(range(addr, addr + 8))
        return relocs_gaps

    def get_altinstruction_gaps(self, start_addr, end_addr, alt_instr_text):
        """
        :param start_addr: start address :int
        :param end_addr: end address: int
        :returns list of exclude addr like [exclude_alt_addr1, exclude_alt_addr2, ...]
        """
        return self.get_altinstructions(alt_instr_text, start_addr, end_addr)

    def get_jump_table_gaps(self, start_addr: int, end_addr: int, jump_table: list) -> list:
        """
        Return JT related gaps are in range of our module
        :param start_addr: int
        :param end_addr: int
        :param jump_table: list   full list (over whole kernel) of JT items
        :returns list of addrs to be excluded [exclude_addr1, exclude_addr2, ...]
        """
        return self.get_jump_table_module(start_addr, end_addr, jump_table)

    def get_gaps(self, exclude_addrs):
        gaps = list()
        for addr in exclude_addrs:
            gaps.append(addr)
            gaps.append(addr+1)
        gaps_removed_equal = self.__remove_all_dublicates(gaps)
        return [[addr1, addr2] for addr1, addr2 in self.utils.pairwise(gaps_removed_equal)]

    def get_addrs_for_hmac(self, sec_sym_sequence, exclude_addrs):
        """
        Generate addresses for calculating HMAC
        :param sec_sym_sequence: [[text_symbol1, ..., text_symbolN]],[rodata_symbol1, ..., rodata_symbolN]]
        :param exclude_addrs: [exclude_addr1, exclude_addr2, ..., exclude_addr3]
        :return: addresses for calculating HMAC: [[addr_start, addr_end], [addr_start, addr_end], ...]
        """
        symbol_scope = list()
        hmac_scope = list()
        for symbol in sec_sym_sequence[0]:
            for addr_one in range(symbol.addr, symbol.addr + symbol.size):
                symbol_scope.append(addr_one)
        for symbol in sec_sym_sequence[1]:
            for addr_one in range(symbol.addr, symbol.addr + symbol.size):
                symbol_scope.append(addr_one)
        symbol_scope.sort()
        symbol_scope_final = [el for el, _ in groupby(symbol_scope)]

        """ Exclude addresses from HMAC """
        i_exclude = 0
        for sym_addr in symbol_scope_final:
            while i_exclude < len(exclude_addrs):
                if sym_addr < exclude_addrs[i_exclude]:
                    hmac_scope.append(sym_addr)
                    hmac_scope.append(sym_addr + 1)
                    break
                if sym_addr == exclude_addrs[i_exclude]:
                    break
                i_exclude += 1
            if i_exclude >= len(exclude_addrs):
                hmac_scope.append(sym_addr)
                hmac_scope.append(sym_addr + 1)
        hmac_removed_equal = self.__remove_all_dublicates(hmac_scope)
        return [[item1, item2] for item1, item2 in self.utils.pairwise(hmac_removed_equal) if item1 != item2]

    def embed_bytes(self, vaddr, in_bytes):
        """
        Write bytes to ELF file
        :param vaddr: virtual address in ELF
        :param in_bytes: byte array to write
        """
        offset = self.vaddr_to_file_offset(vaddr)
        with open(self.get_elf_file(), "rb+") as elf_file:
            elf_file.seek(offset)
            elf_file.write(in_bytes)

    def __update_hmac(self, hmac_obj, file_obj, file_offset_start, file_offset_end):
        """
        Update hmac from addrstart tp addr_end
        FIXMI: it needs to implement this function via fixed block size
        :param file_offset_start: could be string or int
        :param file_offset_end:   could be string or int
        """
        file_offset_start = self.utils.to_int(file_offset_start)
        file_offset_end = self.utils.to_int(file_offset_end)
        file_obj.seek(self.vaddr_to_file_offset(file_offset_start))
        block_size = file_offset_end - file_offset_start
        msg = file_obj.read(block_size)
        hmac_obj.update(msg)

    def get_hmac(self, offset_sequence, key, output_type="byte"):
        """
        Calculate HMAC
        :param offset_sequence: start and end addresses sequence [addr_start, addr_end], [addr_start, addr_end], ...]
        :param key HMAC key: string value
        :param output_type string value. Could be "hex" or "byte"
        :return: bytearray or hex string
        """
        digest = hmac.new(bytearray(key.encode("utf-8")), digestmod=hashlib.sha256)
        with open(self.get_elf_file(), "rb") as file:
            for addr_start, addr_end in offset_sequence:
                self.__update_hmac(digest, file, addr_start, addr_end)
        if output_type == "byte":
            return digest.digest()
        if output_type == "hex":
            return digest.hexdigest()

    def get_canister_symbols(self, list_object_symbols, list_elf_symbols):
        """
        Getting result canister symbols list
        """
        canister_symbols = list()
        for obj_one in list_object_symbols:
            for elf_one in list_elf_symbols:
                if obj_one[1] == elf_one.name or elf_one.name.startswith(str(obj_one[1] + ".")):
                    canister_symbols.append(elf_one)
        return canister_symbols

    def get_filtered_canister_symbols(self, list_object_files, debug=False):
        """
        Getting final list of canister symbols for sections .text, init.text and .rodata
        """
        text_object_symbols = list()
        rodata_object_symbols = list()
        for path_to_files in list_object_files:
            s_text_object_symbols, s_rodata_object_symbols = self.get_symbols_from_obj_files(path_to_files[0], path_to_files[1])
            text_object_symbols.extend(s_text_object_symbols)
            rodata_object_symbols.extend(s_rodata_object_symbols)

        if debug:
            print("\nNumber defined symbols in .text and .init.text of SKC object files: ", len(text_object_symbols))
            print("Number defined symbols in .rodata of SKC object files: ", len(rodata_object_symbols))

        elf_symbols_text, elf_symbols_rodata, _ = self.get_elf_symbols_list()

        if debug:
            print("\nNumber symbols from output ELF in .text and .init.text: ", len(elf_symbols_text))
            print("Number symbols from output ELF in .rodata: ", len(elf_symbols_rodata))

        canister_symbols_text = self.get_canister_symbols(text_object_symbols, elf_symbols_text)
        canister_symbols_rodata = self.get_canister_symbols(rodata_object_symbols, elf_symbols_rodata)
        canister_symbols_text.sort(key=lambda class_symbol: class_symbol.addr)
        canister_symbols_rodata.sort(key=lambda class_symbol: class_symbol.addr)

        if debug:
            print("\nNumber symbols included to canister from .text and .init.text: ", len(canister_symbols_text))
            print("Number symbols included to canister from .rodata", len(canister_symbols_rodata))

        canister_symbols_text_no_matches = [el for el, _ in groupby(canister_symbols_text)]
        canister_symbols_rodata_no_matches = [el for el, _ in groupby(canister_symbols_rodata)]

        if debug:
            print("\nSize canister after removing unnecessary identical symbols in .text and .init.text: ", len(canister_symbols_text_no_matches))
            print("Size canister after removing unnecessary identical symbols in .rodata: ", len(canister_symbols_rodata_no_matches))

        return [canister_symbols_text_no_matches, canister_symbols_rodata_no_matches]

    def unite_borders(self, fields_scope):
        if len(fields_scope) < 2:
            return fields_scope
        united_list = list()
        united_list.extend(fields_scope[0])
        for i in range(1, len(fields_scope)):
            united_list.extend(fields_scope[i])
            if united_list[-2] == united_list[-3]:
                united_list.pop(-2)
                united_list.pop(-2)

        return [[item1, item2] for item1, item2 in self.utils.pairwise(united_list) if item1 != item2]

    def print_covered_symbols_info(self, sec_sym, addrs_for_hmac, gaps_cover):
        str_out = "{:<4}| {:<72} {:<25} {:<10} {:<12} size: {:<10}"
        print("\nSymbols for integrity in .text:\n")
        for i in range(0, len(sec_sym[0])):
            symbol_one = sec_sym[0][i]
            print(str_out.format(i + 1, symbol_one.name, hex(symbol_one.addr),
                  symbol_one.type, symbol_one.bind, hex(symbol_one.size)))

        print("\nSymbols for integrity in .rodata:\n")
        for i in range(0, len(sec_sym[1])):
            symbol_one = sec_sym[1][i]
            print(str_out.format(i + 1, symbol_one.name, hex(symbol_one.addr),
                  symbol_one.type, symbol_one.bind, hex(symbol_one.size)))

        str_out = "{:4}| [{}, {}]"
        print("\nHMAC integrity area cover:\n")
        hmac_cover = 0
        for i in range(0, len(addrs_for_hmac)):
            l_one_hmac = addrs_for_hmac[i]
            hmac_cover += (l_one_hmac[1] - l_one_hmac[0])
            print(str_out.format(i + 1, hex(l_one_hmac[0]), hex(l_one_hmac[1])))

        percent_cover = ((100*hmac_cover) / (hmac_cover + gaps_cover))
        print("\nModule covered bytes len : {}  ".format(self.utils.human_size(hmac_cover + gaps_cover)))
        print("HMAC covered bytes len   : {}  ".format(self.utils.human_size(hmac_cover)))
        print("Skipped bytes len        : {}  ".format(self.utils.human_size(gaps_cover)))
        print("HMAC % covered           : {:.4}% ".format(percent_cover))

    def print_relocation_gaps_info(self, gaps, print_reloc_gaps):
        gaps_cover = 0
        if not print_reloc_gaps:
            for i in range(0, len(gaps)):
                l_one_gap = gaps[i]
                gaps_cover += (l_one_gap[1] - l_one_gap[0])
            return gaps_cover
        str_out = "{:4}| [{}, {}]"
        print("\nRelocation gaps:\n")
        for i in range(0, len(gaps)):
            l_one_gap = gaps[i]
            gaps_cover += (l_one_gap[1] - l_one_gap[0])
            print(str_out.format(i + 1, hex(l_one_gap[0]), hex(l_one_gap[1])))
        return gaps_cover

    def dump_covered_bytes(self, vaddr_seq, out_file_bin, out_file_txt):
        """
        Dumps covered bytes
        :param vaddr_seq: [[start1, end1], [start2, end2]] start - end sequence of covered bytes
        :param out_file_bin: file where will be stored binary dumped bytes
        :param out_file_txt: file where will be stored string dumped bytes
        """
        with open(self.get_elf_file(), "rb") as elf_fp:
            with open(out_file_bin, "wb") as out_fp:
                with open(out_file_txt, mode="w", encoding='utf-8') as out_ft:
                    i = 0
                    for vaddr_start, vaddr_end, in vaddr_seq:
                        elf_fp.seek(self.vaddr_to_file_offset(vaddr_start))
                        block_size = vaddr_end - vaddr_start
                        dump_mem = elf_fp.read(block_size)
                        out_fp.write(dump_mem)
                        out_ft.write("\nArea cover {} [{}, {}], size = {}:\n".format(i, hex(vaddr_start), hex(vaddr_end), hex(block_size)))
                        str_dump = ''
                        for l_count in range(0, block_size):
                            str_dump = str_dump + self.utils.byte_int_to_hex_str2(dump_mem[l_count]) + " "
                            if (l_count + 1) % 16 == 0:
                                str_dump = str_dump + "\n"
                        str_dump = str_dump + "\n"
                        out_ft.write(str_dump)
                        i += 1

    def print_dump_covered_area(self, vaddr_start, vaddr_end):
        """
        Dumps covered bytes in [vaddr_start - vaddr_end]
        :param vaddr_start: start address for print area
        :param vaddr_end: end address for print area
        """
        with open(self.get_elf_file(), "rb") as elf_fp:
            elf_fp.seek(self.vaddr_to_file_offset(vaddr_start))
            block_size = vaddr_end - vaddr_start
            dump_mem = elf_fp.read(block_size)
            print("\nArea cover [{}, {}], size = {}:\n".format(hex(vaddr_start), hex(vaddr_end), hex(block_size)))
            str_dump = ''
            for l_count in range(0, block_size):
                str_dump = str_dump + self.utils.byte_int_to_hex_str(dump_mem[l_count]) + " "
                if (l_count + 1) % 16 == 0:
                    str_dump = str_dump + "\n"
            str_dump = str_dump + "\n"
            print(str_dump)

    def print_address_field(self, addr_start, size, base):
        with open(self.get_elf_file(), "rb") as elf_fp:
            elf_fp.seek(self.vaddr_to_file_offset(addr_start))
            dump_mem = elf_fp.read(size)
            str_dump = ''
            for l_count in range(0, size):
                str_dump = str_dump + self.utils.byte_int_to_hex_str(dump_mem[l_count]) + " "
                if (l_count + 1) % base == 0:
                    str_dump = str_dump + "\n"
            print("From addr_start ", hex(addr_start), ":")
            print(str_dump)

    def print_numeric_list(self, str_descr, input_list):
        if input_list is not None:
            if len(input_list) != 0:
                print(str_descr, "\n")
                i = 1
                str_out = "{:4}| {}"
                for l in input_list:
                    print(str_out.format(i, hex(l)))
                    i += 1
                print("\n")

    def get_relocations_for_init_data(self, addr_start, addr_end):
        """
        Getting relocation table from output ELF file
        """
        ftrace_tbl = list()
        rela_sect_obj = self.get_section_by_name(".rela.dyn")
        if rela_sect_obj is None:
            return ftrace_tbl
        with open(self.get_elf_file(), "rb") as elf_fp:
            elf_fp.seek(self.vaddr_to_file_offset(rela_sect_obj.addr))
            i = 0
            while i < rela_sect_obj.size:
                dump_mem = elf_fp.read(8)
                r_offset = self.utils.dump_to_int(dump_mem)
                dump_mem = elf_fp.read(8)
                r_info = self.utils.dump_to_int(dump_mem) # pylint: disable=unused-variable
                dump_mem = elf_fp.read(8)
                r_addend = self.utils.dump_to_int(dump_mem)
                if addr_start <= r_offset < addr_end:
                    ftrace_tbl.append(r_addend)
                i += 24
        ftrace_tbl.sort()
        return ftrace_tbl

    def get_exclude_ftrace_addr(self, sec_sym, ftrace_tbl):
        """
        Getting excluded addresses from ftrace table
        """
        ftrace_addr_change = list()
        if len(ftrace_tbl) == 0:
            return ftrace_addr_change
        i_ftrace = 0
        for symbol in sec_sym:
            addr_start = symbol.addr
            addr_end = symbol.addr + symbol.size
            while i_ftrace < len(ftrace_tbl):
                if ftrace_tbl[i_ftrace] >= addr_start and ftrace_tbl[i_ftrace] < addr_end:
                    for skip_addr in range(ftrace_tbl[i_ftrace], ftrace_tbl[i_ftrace] + 4):
                        ftrace_addr_change.append(skip_addr)
                elif ftrace_tbl[i_ftrace] >= addr_end:
                    break
                i_ftrace += 1
        return ftrace_addr_change

    def get_ftrace_gaps(self, sec_sym):
        ftrace_tbl = list()
        start_mcount_loc = self.get_symbol_by_name_init_data("__start_mcount_loc")
        stop_mcount_loc = self.get_symbol_by_name_init_data("__stop_mcount_loc")
        if start_mcount_loc is not None and stop_mcount_loc is not None:
            print("\nFind ftrace table:")
            print("\"__start_mcount_loc\", address = ", hex(start_mcount_loc.addr))
            print("\"__stop_mcount_loc.addr\", address = ", hex(stop_mcount_loc.addr))
            ftrace_tbl = self.get_relocations_for_init_data(start_mcount_loc.addr, stop_mcount_loc.addr)
            print("Number addresses in ftrace table", len(ftrace_tbl))
        return self.get_exclude_ftrace_addr(sec_sym, ftrace_tbl)

    def make_integrity(self, sec_sym, module_name, debug=False, print_reloc_gaps=False):
        """
        Calculate HMAC and embed needed info
        :param sec_sym: {sec_name: [addr1, addr2, ..., addrN]}
        :param module_name: module name that you want to make integrity. See Makefile targets
        :param debug: If True prints debug information
        :param print_reloc_addrs: If True, print relocation addresses that are skipped
        :param sort_by: sort method
        :param reverse: sort order

        Checks: .rodata     section for relocations
                .text       section for alternated instructions
                .init.text  section for alternated instructions
                .init.data  section for ftrace table
        """
        relocs_text, relocs_rodata = self.get_relocs_text_rodata()
        alt_instr_text, alt_instr_rodata = self.get_text_rodata_altinstructions_lists()
        jump_table = self.get_jump_table_list()

        if debug:
            print("\nSize relocations instruction in text sections:", len(relocs_text))
            print("Size relocations instruction in .rodata:", len(relocs_rodata))
            print("\nSize alternative instruction in text sections:", len(alt_instr_text))
            print("Size alternative instruction in .rodata:", len(alt_instr_rodata))

        if len(alt_instr_rodata) != 0:
            print("\nAttention: size alternative instruction in .rodata != 0:", len(alt_instr_rodata))

        ftrace_exclude_addrs = self.get_ftrace_gaps(sec_sym[0])

        exclude_addrs = list()

        if len(ftrace_exclude_addrs) != 0:
            exclude_addrs.extend(ftrace_exclude_addrs)
            print("Number exclude ftrace addresses from canister", len(ftrace_exclude_addrs))

        if len(relocs_rodata) != 0:
            for symbol_rodata in sec_sym[1]:
                exclude_addrs.extend(self.get_reloc_gaps(relocs_rodata, symbol_rodata.addr, symbol_rodata.addr + symbol_rodata.size))

        if len(relocs_text) != 0:
            for symbol_text in sec_sym[0]:
                exclude_addrs.extend(self.get_reloc_gaps(relocs_text, symbol_text.addr, symbol_text.addr + symbol_text.size))

        if len(alt_instr_text) != 0:
            for symbol_text in sec_sym[0]:
                exclude_addrs.extend(self.get_altinstruction_gaps(symbol_text.addr, symbol_text.addr + symbol_text.size, alt_instr_text))

        if len(jump_table) != 0:
            for symbol_text in sec_sym[0]:
                exclude_addrs.extend(self.get_jump_table_gaps(symbol_text.addr, symbol_text.addr + symbol_text.size, jump_table))

        exclude_addrs.sort()
        exclude_addrs_no_matches = [ex for ex, _ in groupby(exclude_addrs)]
        gaps_cover = self.print_relocation_gaps_info(self.get_gaps(exclude_addrs_no_matches), print_reloc_gaps)
        print("\nGAPs covered bytes len   : {}  \n".format(self.utils.human_size(gaps_cover)))

        hmac_fields = self.get_addrs_for_hmac(sec_sym, exclude_addrs_no_matches)
        addrs_for_hmac = self.unite_borders(hmac_fields)

        if len(addrs_for_hmac) < 4096:
            digest = self.get_hmac(addrs_for_hmac, "The quick brown fox jumps over the lazy dog")

            self.embed_bytes(self.get_symbol_by_name_rodata("buildtime_" + module_name + "_hmac").addr,
                             self.utils.to_bytearray(digest))

            buildtime_integrity_crypto_addrs = self.get_symbol_by_name_rodata("integrity_" + module_name + "_addrs")
            buildtime_crypto_buildtime_address = self.get_symbol_by_name_rodata(module_name + "_buildtime_address")

            self.embed_bytes(self.get_symbol_by_name_rodata("integrity_" + module_name + "_addrs").addr,
                             self.utils.to_bytearray(addrs_for_hmac))

            self.embed_bytes(self.get_symbol_by_name_rodata(module_name + "_buildtime_address").addr,
                             self.utils.to_bytearray(self.get_symbol_by_name_rodata(module_name + "_buildtime_address").addr))

            if debug:
                self.print_numeric_list("\nFtrace excluded addresses:", ftrace_exclude_addrs)
                self.print_covered_symbols_info(sec_sym, addrs_for_hmac, gaps_cover)
                self.dump_covered_bytes(addrs_for_hmac, "covered_dump_for_" + module_name + ".bin",
                                        "covered_dump_for_" + module_name + ".txt")

                print("\nCovered area for " + "integrity_" + module_name + "_addrs:")
                self.print_dump_covered_area(buildtime_integrity_crypto_addrs.addr,
                     buildtime_integrity_crypto_addrs.addr + len(addrs_for_hmac)*2*8 + 2*8)

            print("integrity_crypto_addrs: ", buildtime_integrity_crypto_addrs)
            print("crypto_buildtime_address: ", buildtime_crypto_buildtime_address)
            print("HMAC for \"{}\" module is: {}".format(module_name, binascii.hexlify(digest)))
            print("FIPS integrity procedure has been finished for {}".format(module_name))
        else:
            print("ERROR: size of address HMAC gaps exceeds allocated memory in kernel " + module_name + "module: ",
                  len(addrs_for_hmac))
