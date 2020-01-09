#!/usr/bin/env python
# pylint: unused-wildcard-import

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
        self.Arch = arch
        if arch == 'x86':
            self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        elif arch == 'AMD64':
            self.uc = Uc(UC_ARCH_X86, UC_MODE_64)

        self.Instruction = instruction.Tool(self)
        self.Memory = memory.Tool(self)
        self.Register = register.Tool(self)
        self.Debugger = windbgtool.debugger.DbgEngine()
        self.Debugger.LoadDump(dump_filename)

    def get_register_by_name(self, register_name):
        if register_name == "esp":
            if self.Arch == 'x86':
                return UC_X86_REG_ESP
            elif self.Arch == 'AMD64':
                return UC_X86_REG_RSP
        elif register_name == "ebp":
            if self.Arch == 'x86':
                return UC_X86_REG_EBP
            elif self.Arch == 'AMD64':
                return UC_X86_REG_RBP
        elif register_name == "eip":
            if self.Arch == 'x86':
                return UC_X86_REG_EIP
            elif self.Arch == 'AMD64':
                return UC_X86_REG_RIP
        elif register_name == "eax":
            if self.Arch == 'x86':
                return UC_X86_REG_EAX
            elif self.Arch == 'AMD64':
                return UC_X86_REG_RAX

    def add_unicorn_hook(self, hook_type, callback, arg = None, start = 0, end = 0):
        self.uc.hook_add(hook_type, callback, arg, start, end)

    def start(self, start, end):
        self.uc.emu_start(start, end)

class ShellEmu:
    def __init__(self, shellcode_filename, shellcode_bytes = '', dump_filename = ''):
        self.ShellcodeFilename = shellcode_filename
        self.ShellcodeBytes = shellcode_bytes
        self.DumpFilename = dump_filename
        self.ExhaustiveLoopDumpFrequency = 0x10000
        self.HitMap = {}            
        self.LastCodeAddress = 0
        self.LastCodeSize = 0

        self.Emulator = Emulator(dump_filename = dump_filename)

    def instruction_callback(self, uc, address, size, user_data):
        self.Emulator.Instruction.dump_context()

        if not address in self.HitMap:
            self.HitMap[address] = 1
        else:
            self.HitMap[address] += 1
            
            if self.HitMap[address] % self.ExhaustiveLoopDumpFrequency == 0:
                print('Exhaustive Loop found: %x' % (self.HitMap[address]))
                self.Emulator.Instruction.dump_context()
                print('')
                pass

        self.LastCodeAddress = address
        self.LastCodeSize = size

    def run(self, trace_self_modification = False, print_first_instructions = False):
        process_memory = pe.ProcessMemory(self.Emulator)
        process_memory.load_process_memory()

        if self.ShellcodeBytes:
            shellcode_bytes = self.ShellcodeBytes
        else:
            with open(self.ShellcodeFilename, 'rb') as fd:
                shellcode_bytes = fd.read()

        if shellcode_bytes:
            self.CodeLen = len(shellcode_bytes)
            self.CodeStart = self.Emulator.Debugger.GetEntryPoint()
            logger.info("Writing shellcode to %x (len=%x)", self.CodeStart, self.CodeLen)
            self.Emulator.Memory.write_memory(self.CodeStart, shellcode_bytes, debug = 0)            

        if trace_self_modification:
            self.Emulator.Memory.hook_memory_write(self.CodeStart, self.CodeStart+self.CodeLen)

        if print_first_instructions:
            self.Emulator.add_unicorn_hook(UC_HOOK_CODE, self.instruction_callback, None, self.CodeStart, self.CodeStart+1)

        self.Emulator.Memory.hook_unmapped_memory_access()
        api_hook = shellcode_emulator.api.Hook(self.Emulator)
        api_hook.start()

        self.Emulator.Instruction.set_code_range(self.CodeStart, self.CodeStart+self.CodeLen)
        try:
            self.Emulator.start(self.CodeStart, self.CodeStart+self.CodeLen)
        except:
            traceback.print_exc(file = sys.stdout)
            self.Emulator.Instruction.dump_context()

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
        list_parser.Parse()
        shellcode_bytes = ''
        for name in list_parser.GetNames():
            shellcode_bytes += list_parser.GetBytes(name)

    if not shellcode_filename and not shellcode_bytes:
        parser.print_help()
        sys.exit(0)

    shell_emu = ShellEmu(shellcode_filename, shellcode_bytes = shellcode_bytes, dump_filename = options.dump_filename)
    shell_emu.run(trace_self_modification = True, print_first_instructions = True)
