import os
import sys

import struct
import traceback
import logging
import capstone

from unicorn import *
from unicorn.x86_const import *

import utils

class Tool:
    def __init__(self, emulator):
        self.Emulator = emulator
        self.uc = emulator.uc

    def SetCodeRange(self, start, end):
        self.Start = start
        self.End = end

    def Disassemble(self, code, address):
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        return md.disasm(code, address)

    def DumpDisasm(self, address, size, resolve_symbol = False, dump_instruction_count = 1):
        code = self.uc.mem_read(address, size)

        try:            
            disasm_list = self.Disassemble(code, address)
        except:
            traceback.print_exc(file = sys.stdout)
            return

        i = 0
        offset = 0
        for instruction in disasm_list:
            symbol_str = ''
            if self.Emulator.Debugger:
                try:
                    symbol_str = self.Emulator.Debugger.ResolveSymbol(instruction.address) + ':\t'
                except:
                    pass
                    

            code_offset = 0
            if self.Start <= instruction.address and instruction.address <= self.End:
                code_offset = instruction.address - self.Start
                
            if code_offset>0:
                address_str = '+%.8X: ' % (code_offset)
            else:
                address_str = ' %.8X: ' % (instruction.address)

            print('%s%s%s\t%s\t%s' % (symbol_str, address_str, utils.Tool.DumpHex(code[offset:offset+instruction.size]), instruction.mnemonic, instruction.op_str))

            offset += instruction.size
            i += 1

            if i >= dump_instruction_count:
                break

    def DumpRegisters(self):
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

        print(' fs: %.8X gs: %.8X cs: %.8X  ds: %.8X  es: %.8X' % (
                            self.uc.reg_read(UC_X86_REG_FS), 
                            self.uc.reg_read(UC_X86_REG_GS), 
                            self.uc.reg_read(UC_X86_REG_CS), 
                            self.uc.reg_read(UC_X86_REG_DS), 
                            self.uc.reg_read(UC_X86_REG_ES)
                        )
                    )

    def DumpContext(self, dump_registers = True, dump_previous_eip = False):
        self.DumpDisasm(self.uc.reg_read(UC_X86_REG_EIP), 10)

        if dump_registers:
            self.DumpRegisters()

        if dump_previous_eip and self.LastCodeAddress>0:
            print('> Last EIP before this instruction:')
            self.DumpDisasm(self.LastCodeAddress, self.LastCodeSize)
