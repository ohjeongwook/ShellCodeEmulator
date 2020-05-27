#!/usr/bin/env python
# pylint: disable=unused-wildcard-import

import os
import sys

import struct
import traceback
import logging
import capstone

from unicorn import *
from unicorn.x86_const import *

class Tool:
    registers = {
        'ax': [UC_X86_REG_EAX, UC_X86_REG_RAX],
        'bx': [UC_X86_REG_EBX, UC_X86_REG_RBX],
        'cx': [UC_X86_REG_ECX, UC_X86_REG_RCX],
        'dx': [UC_X86_REG_EDX, UC_X86_REG_RDX],
        'di': [UC_X86_REG_EDI, UC_X86_REG_RDI],
        'si': [UC_X86_REG_ESI, UC_X86_REG_RSI],
        'bp': [UC_X86_REG_EBP, UC_X86_REG_RBP],
        'sp': [UC_X86_REG_ESP, UC_X86_REG_RSP],
        'ip': [UC_X86_REG_EIP, UC_X86_REG_RIP],
    }
    
    def __init__(self, emulator, arch):
        self.arch = arch
        self.emulator = emulator
        self.uc = emulator.uc

    def get_by_name(self, name):
        if self.arch == 'x86':
            index = 0
        elif self.arch == 'AMD64':
            index = 1
        else:
            return None

        if name in self.registers:
            return self.registers[name][index]

    def write(self, register_name, value):
        self.uc.reg_write(self.emulator.register.get_by_name(register_name), value)

    def write_register(self, register, value):
        self.uc.reg_write(register, value)

    def print_registers(self):
        if self.emulator.arch == 'x86':
            print('eax: %.8X ebx: %.8X ecx: %.8X edx: %.8X' % (
                                self.uc.reg_read(UC_X86_REG_EAX), 
                                self.uc.reg_read(UC_X86_REG_EBX), 
                                self.uc.reg_read(UC_X86_REG_ECX), 
                                self.uc.reg_read(UC_X86_REG_EDX)
                            )
                        )
                            
            print('esp: %.8X ebp: %.8X esi: %.8X edi: %.8X' % (
                                self.uc.reg_read(UC_X86_REG_ESP), 
                                self.uc.reg_read(UC_X86_REG_EBP), 
                                self.uc.reg_read(UC_X86_REG_ESI), 
                                self.uc.reg_read(UC_X86_REG_EDI)
                            )
                        )
                            
            print('eip: %.8X' % (
                                self.uc.reg_read(UC_X86_REG_EIP)
                            )
                        )
        elif self.emulator.arch == 'AMD64':
            print('rax: %.8X ebx: %.8X ecx: %.8X edx: %.8X' % (
                                self.uc.reg_read(UC_X86_REG_RAX), 
                                self.uc.reg_read(UC_X86_REG_RBX), 
                                self.uc.reg_read(UC_X86_REG_RCX), 
                                self.uc.reg_read(UC_X86_REG_RDX)
                            )
                        )
                            
            print('rsp: %.8X rbp: %.8X rsi: %.8X rdi: %.8X' % (
                                self.uc.reg_read(UC_X86_REG_RSP), 
                                self.uc.reg_read(UC_X86_REG_RBP), 
                                self.uc.reg_read(UC_X86_REG_RSI), 
                                self.uc.reg_read(UC_X86_REG_RDI)
                            )
                        )
                            
            print('rip: %.8X' % (
                                self.uc.reg_read(UC_X86_REG_RIP)
                            )
                        )

        print(' fs: %.8X gs: %.8X cs: %.8X  ds: %.8X  es: %.8X' % (
                            self.uc.reg_read(UC_X86_REG_FS), 
                            self.uc.reg_read(UC_X86_REG_GS), 
                            self.uc.reg_read(UC_X86_REG_CS), 
                            self.uc.reg_read(UC_X86_REG_DS), 
                            self.uc.reg_read(UC_X86_REG_ES)
                        )
                    )
