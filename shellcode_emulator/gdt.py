#!/usr/bin/env python
# pylint: disable=unused-wildcard-import

from unicorn import *
from unicorn.x86_const import *
from struct import pack

F_GRANULARITY = 0x8
F_PROT_32 = 0x4
F_LONG = 0x2
F_AVAILABLE = 0x1 

A_PRESENT = 0x80

A_PRIV_3 = 0x60
A_PRIV_2 = 0x40
A_PRIV_1 = 0x20
A_PRIV_0 = 0x0

A_CODE = 0x10
A_DATA = 0x10
A_TSS = 0x0
A_GATE = 0x0

A_EXEC = 0x8
A_DATA_WRITABLE = 0x2
A_CODE_READABLE = 0x2

A_DIR_CON_BIT = 0x4

S_GDT = 0x0
S_LDT = 0x4
S_PRIV_3 = 0x3
S_PRIV_2 = 0x2
S_PRIV_1 = 0x1
S_PRIV_0 = 0x0

CODE_ADDR = 0x40000
CODE_SIZE = 0x1000

class Layout:
    def __init__(self, uc):
        self.uc = uc

    def create_gdt_entry(self, base, limit, access, flags):
        to_ret = limit & 0xffff
        to_ret |= (base & 0xffffff) << 16
        to_ret |= (access & 0xff) << 40
        to_ret |= ((limit >> 16) & 0xf) << 48
        to_ret |= (flags & 0xff) << 52
        to_ret |= ((base >> 24) & 0xff) << 56
        return pack('<Q',to_ret)

    def create_selector(self, idx, flags):
        to_ret = flags
        to_ret |= idx << 3
        return to_ret

    def setup(self, 
                gdt_addr = 0x80043000, 
                gdt_limit = 0x1000, 
                gdt_entry_size = 0x8, 
                fs_base = None, 
                fs_limit = None, 
                gs_base = None, 
                gs_limit = None, 
                segment_limit = 0xffffffff
        ):
        self.uc.Memory.map(gdt_addr, gdt_limit)
        gdt = [self.create_gdt_entry(0,0,0,0) for i in range(0x34)]
        
        if fs_base != None and fs_limit != None:
            gdt[0x0e] = self.create_gdt_entry(fs_base, fs_limit , A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_0 | A_DIR_CON_BIT, F_PROT_32)
        else:
            gdt[0x0e] = self.create_gdt_entry(0, segment_limit, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3 | A_DIR_CON_BIT, F_PROT_32)

        if gs_base != None and gs_limit != None:
            gdt[0x0f] = self.create_gdt_entry(gs_base, gs_limit, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3 | A_DIR_CON_BIT, F_PROT_32)
        else:
            gdt[0x0f] = self.create_gdt_entry(0, segment_limit, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3 | A_DIR_CON_BIT, F_PROT_32)

        gdt[0x10] = self.create_gdt_entry(0, segment_limit, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3 | A_DIR_CON_BIT, F_PROT_32)  # Data Segment
        gdt[0x11] = self.create_gdt_entry(0, segment_limit, A_PRESENT | A_CODE | A_CODE_READABLE | A_PRIV_3 | A_EXEC | A_DIR_CON_BIT, F_PROT_32)  # Code Segment
        gdt[0x12] = self.create_gdt_entry(0, segment_limit, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_0 | A_DIR_CON_BIT, F_PROT_32)  # Stack Segment
        gdt[0x6] = self.create_gdt_entry(0, segment_limit, A_PRESENT | A_CODE | A_CODE_READABLE | A_PRIV_3 | A_EXEC | A_DIR_CON_BIT, F_PROT_32)  # Code Segment

        for idx, value in enumerate(gdt):
            offset = idx * gdt_entry_size
            self.uc.Memory.write_memory(gdt_addr + offset, value)
        
        self.uc.Register.write_register(UC_X86_REG_GDTR, (0, gdt_addr, len(gdt) * gdt_entry_size-1, 0x0))
        self.uc.Register.write_register(UC_X86_REG_FS, self.create_selector(0x0e, S_GDT | S_PRIV_0))
        self.uc.Register.write_register(UC_X86_REG_GS, self.create_selector(0x0f, S_GDT | S_PRIV_3))
        self.uc.Register.write_register(UC_X86_REG_DS, self.create_selector(0x10, S_GDT | S_PRIV_3))
        self.uc.Register.write_register(UC_X86_REG_CS, self.create_selector(0x11, S_GDT | S_PRIV_3))
        self.uc.Register.write_register(UC_X86_REG_SS, self.create_selector(0x12, S_GDT | S_PRIV_0))
