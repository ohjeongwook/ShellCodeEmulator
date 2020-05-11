#!/usr/bin/env python
# pylint: disable=unused-wildcard-import

import os
import sys

import struct
import traceback
import logging

from unicorn import *
from unicorn.x86_const import *

import capstone
import pykd

import windbgtool.debugger
import windbgtool.util

try:
    import idatool.list
except:
    pass

import shellcode_emulator.pe
import shellcode_emulator.memory
import shellcode_emulator.instruction
import shellcode_emulator.register
import shellcode_emulator.api

logger = logging.getLogger(__name__)

class Emulator:
    def __init__(self, dump_filename, arch = 'AMD64'):
        self.arch = arch
        if arch == 'x86':
            self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        elif arch == 'AMD64':
            self.uc = Uc(UC_ARCH_X86, UC_MODE_64)

        self.instruction = shellcode_emulator.instruction.Tool(self)
        self.memory = shellcode_emulator.memory.Tool(self)
        self.register = shellcode_emulator.register.Tool(self)
        self.debugger = windbgtool.debugger.DbgEngine()
        self.debugger.load_dump(dump_filename)

    def get_register_by_name(self, register_name):
        if register_name == "esp":
            if self.arch == 'x86':
                return UC_X86_REG_ESP
            elif self.arch == 'AMD64':
                return UC_X86_REG_RSP
        elif register_name == "ebp":
            if self.arch == 'x86':
                return UC_X86_REG_EBP
            elif self.arch == 'AMD64':
                return UC_X86_REG_RBP
        elif register_name == "eip":
            if self.arch == 'x86':
                return UC_X86_REG_EIP
            elif self.arch == 'AMD64':
                return UC_X86_REG_RIP
        elif register_name == "eax":
            if self.arch == 'x86':
                return UC_X86_REG_EAX
            elif self.arch == 'AMD64':
                return UC_X86_REG_RAX

    def add_unicorn_hook(self, hook_type, callback, arg = None, start = 0, end = 0):
        self.uc.hook_add(hook_type, callback, arg, start, end)

    def start(self, start, end):
        self.uc.emu_start(start, end)

class ShellEmu:
    def __init__(self, shellcode_filename, shellcode_bytes = '', dump_filename = '', exhaustive_loop_dump_frequency = 0x10000):
        self.shellcode_filename = shellcode_filename
        self.shellcode_bytes = shellcode_bytes
        self.exhaustive_loop_dump_frequency = exhaustive_loop_dump_frequency
        self.address_hit_map = {}            
        self.last_code_address = 0
        self.last_code_size = 0

        self.emulator = Emulator(dump_filename = dump_filename)

    def instruction_callback(self, uc, address, size, user_data):
        self.emulator.instruction.dump_context()

        if not address in self.address_hit_map:
            self.address_hit_map[address] = 1
        else:
            self.address_hit_map[address] += 1
            
            if self.address_hit_map[address] % self.exhaustive_loop_dump_frequency == 0:
                print('Exhaustive Loop found: %x' % (self.address_hit_map[address]))
                self.emulator.instruction.dump_context()
                print('')
                pass

        self.last_code_address = address
        self.last_code_size = size

    def run(self, trace_self_modification = False, print_first_instructions = False):
        process_memory = shellcode_emulator.pe.ProcessMemory(self.emulator)
        process_memory.load_process_memory()

        if self.shellcode_bytes:
            shellcode_bytes = self.shellcode_bytes
        else:
            with open(self.shellcode_filename, 'rb') as fd:
                shellcode_bytes = fd.read()

        if shellcode_bytes:
            self.code_length = len(shellcode_bytes)
            self.code_start = self.emulator.debugger.get_entry_point_address()
            logger.info("Writing shellcode to %x (len=%x)", self.code_start, self.code_length)
            self.emulator.memory.write_memory(self.code_start, shellcode_bytes, debug = 0)            

        if trace_self_modification:
            self.emulator.memory.hook_memory_write(self.code_start, self.code_start+self.code_length)

        if print_first_instructions:
            self.emulator.add_unicorn_hook(UC_HOOK_CODE, self.instruction_callback, None, self.code_start, self.code_start+1)

        self.emulator.memory.hook_unmapped_memory_access()
        api_hook = shellcode_emulator.api.Hook(self.emulator)
        api_hook.start()

        self.emulator.instruction.set_code_range(self.code_start, self.code_start+self.code_length)
        try:
            self.emulator.start(self.code_start, self.code_start+self.code_length)
        except:
            traceback.print_exc(file = sys.stdout)
            self.emulator.instruction.dump_context()

if __name__ == '__main__':
    from optparse import OptionParser, Option

    logging.basicConfig(level = logging.INFO)
    root = logging.getLogger()  
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    formatter = logging.Formatter('%(message)s')
    ch.setFormatter(formatter)
    root.addHandler(ch)

    parser = OptionParser(usage = "usage: %prog [options] args")
    parser.add_option("-b", "--image_base", dest = "image_base", type = "string", default = "", metavar = "IMAGE_BASE", 
                        help = "Image base to load the shellcode inside process memory")
    parser.add_option("-d", "--dump_filename", dest = "dump_filename", 
                        type = "string", default = "", metavar = "DUMP_FILENAME", 
                        help = "A process dump file from normal Windows process")
    parser.add_option("-l", "--list_filename", dest = "list_filename", 
                        type = "string", default = "", metavar = "LIST_FILENAME", 
                        help = "A list filename generated by IDA (this can be used instead of shellcode filename)")
    
    (options, args) = parser.parse_args(sys.argv)

    shellcode_filename = ''
    if len(args) > 1:
        shellcode_filename = args[1]

    shellcode_bytes = ''
    if options.list_filename:
        list_parser = idatool.list.Parser(options.list_filename)
        list_parser.parse()
        shellcode_bytes = ''
        for name in list_parser.get_names():
            shellcode_bytes += list_parser.get_bytes(name)

    if not shellcode_filename and not shellcode_bytes:
        parser.print_help()
        sys.exit(0)

    shell_emu = ShellEmu(shellcode_filename, shellcode_bytes = shellcode_bytes, dump_filename = options.dump_filename)
    shell_emu.run(trace_self_modification = True, print_first_instructions = True)
