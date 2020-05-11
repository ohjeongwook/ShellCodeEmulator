#!/usr/bin/env python
# pylint: disable=unused-wildcard-import

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import struct
import traceback
import logging
import capstone

from unicorn import *
from unicorn.x86_const import *

import shellcode_emulator.utils

class Tool:
    def __init__(self, emulator):
        self.emulator = emulator
        self.uc = emulator.uc
        self.last_code_address = 0
        self.last_code_size = 0
        self.start = 0
        self.end = 0

    def set_code_range(self, start, end):
        self.start = start
        self.end = end

    def disassemble(self, code, address):
        if self.emulator.arch == 'x86':
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        elif self.emulator.arch == 'AMD64':
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        return md.disasm(code, address)

    def dump_disassembly(self, address, size, find_symbol = False, dump_instruction_count = 1):
        code = self.uc.mem_read(address, size)

        try:            
            disasm_list = self.disassemble(code, address)
        except:
            traceback.print_exc(file = sys.stdout)
            return

        i = 0
        offset = 0
        for instruction in disasm_list:
            symbol_str = ''
            if self.emulator.debugger:
                try:
                    symbol_str = self.emulator.debugger.find_symbol(instruction.address) + ':\t'
                except:
                    pass
                    

            code_offset = 0
            if self.start <= instruction.address and instruction.address <= self.end:
                code_offset = instruction.address - self.start
                
            if code_offset>0:
                address_str = '+%.8X: ' % (code_offset)
            else:
                address_str = ' %.8X: ' % (instruction.address)

            print('%s%s%s\t%s\t%s' % (symbol_str, address_str, shellcode_emulator.utils.Tool.dump_hex(code[offset:offset+instruction.size]), instruction.mnemonic, instruction.op_str))

            offset += instruction.size
            i += 1

            if i >= dump_instruction_count:
                break

    def dump_context(self, dump_registers = True, dump_previous_eip = False):
        self.dump_disassembly(self.uc.reg_read(self.emulator.get_register_by_name("eip")), 10)

        if dump_registers:
            self.emulator.register.print_registers()

        if dump_previous_eip and self.last_code_address>0:
            print('> Last EIP before this instruction:')
            self.dump_disassembly(self.last_code_address, self.last_code_size)
