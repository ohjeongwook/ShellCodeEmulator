#!/usr/bin/env python
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
        self.UC = uc

    def CreateGDTEntry(self, base, limit, access, flags):
        to_ret = limit & 0xffff;
        to_ret |= (base & 0xffffff) << 16;
        to_ret |= (access & 0xff) << 40;
        to_ret |= ((limit >> 16) & 0xf) << 48;
        to_ret |= (flags & 0xff) << 52;
        to_ret |= ((base >> 24) & 0xff) << 56;
        return pack('<Q',to_ret)

    def CreateSelector(self, idx, flags):
        to_ret = flags
        to_ret |= idx << 3
        return to_ret

    def Setup(self, gdt_addr = 0x80043000, gdt_limit = 0x1000, gdt_entry_size = 0x8, fs_base = 0x0f4c000, fs_limit = 0x00001000):
        self.UC.Memory.Map(gdt_addr, gdt_limit)
        gdt = [self.CreateGDTEntry(0,0,0,0) for i in range(0x34)]
        gdt[0x0e] = self.CreateGDTEntry(fs_base, fs_limit , A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_0 | A_DIR_CON_BIT, F_PROT_32)
        gdt[0x0f] = self.CreateGDTEntry(0, 0xffffffff, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3 | A_DIR_CON_BIT, F_PROT_32)
        gdt[0x10] = self.CreateGDTEntry(0, 0xffffffff, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3 | A_DIR_CON_BIT, F_PROT_32)  # Data Segment
        gdt[0x11] = self.CreateGDTEntry(0, 0xffffffff, A_PRESENT | A_CODE | A_CODE_READABLE | A_PRIV_3 | A_EXEC | A_DIR_CON_BIT, F_PROT_32)  # Code Segment
        gdt[0x12] = self.CreateGDTEntry(0, 0xffffffff, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_0 | A_DIR_CON_BIT, F_PROT_32)  # Stack Segment
        gdt[0x6] = self.CreateGDTEntry(0, 0xffffffff, A_PRESENT | A_CODE | A_CODE_READABLE | A_PRIV_3 | A_EXEC | A_DIR_CON_BIT, F_PROT_32)  # Code Segment

        for idx, value in enumerate(gdt):
            offset = idx * gdt_entry_size
            self.UC.Memory.WriteMem(gdt_addr + offset, value)
        
        self.UC.Register.WriteReg(UC_X86_REG_GDTR, (0, gdt_addr, len(gdt) * gdt_entry_size-1, 0x0))

        selector = self.CreateSelector(0x0e, S_GDT | S_PRIV_0)
        self.UC.Register.WriteReg(UC_X86_REG_FS, selector)

        selector = self.CreateSelector(0x0f, S_GDT | S_PRIV_3)
        self.UC.Register.WriteReg(UC_X86_REG_GS, selector)

        selector = self.CreateSelector(0x10, S_GDT | S_PRIV_3)
        self.UC.Register.WriteReg(UC_X86_REG_DS, selector)

        selector = self.CreateSelector(0x11, S_GDT | S_PRIV_3)
        self.UC.Register.WriteReg(UC_X86_REG_CS, selector)

        selector = self.CreateSelector(0x12, S_GDT | S_PRIV_0)
        self.UC.Register.WriteReg(UC_X86_REG_SS, selector)
