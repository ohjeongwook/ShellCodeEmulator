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
    def __init__(self, emulator):
        self.emulator = emulator
        self.uc = emulator.uc

    def write(self, register_name, value):
        self.uc.reg_write(self.emulator.get_register_by_name(register_name), value)

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
