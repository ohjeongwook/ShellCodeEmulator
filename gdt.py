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

GDT_ADDR = 0x3000
GDT_LIMIT = 0x1000
GDT_ENTRY_SIZE = 0x8

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

    def WriteGDT(self, gdt, mem):
        for idx, value in enumerate(gdt):
            offset = idx * GDT_ENTRY_SIZE
            self.UC.mem_write(mem + offset, value)

    def CreateSelector(self, idx, flags):
        to_ret = flags
        to_ret |= idx << 3
        return to_ret

    def HookUnMappedMemRead(self, uc, type, addr,*args):
        print(hex(addr))
        return False
    
    def Setup(self):
        self.UC.hook_add(UC_HOOK_MEM_READ_UNMAPPED, self.HookUnMappedMemRead)

        self.UC.mem_map(GDT_ADDR, GDT_LIMIT)
        gdt = [self.CreateGDTEntry(0,0,0,0) for i in range(31)]

        self.UC.mem_map(0x1000000, 0x1000)
        gdt[14] = self.CreateGDTEntry(0x1000000, 0x1000 , A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_0 | A_DIR_CON_BIT, F_PROT_32)  

        self.UC.mem_map(0x2000000, 0x1000)
        gdt[15] = self.CreateGDTEntry(0x2000000, 0x1000, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3 | A_DIR_CON_BIT, F_PROT_32)

        self.UC.mem_map(0x3000000, 0x1000000)
        gdt[16] = self.CreateGDTEntry(0x3000000, 0x1000000 , A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3 | A_DIR_CON_BIT, F_PROT_32)  # Data Segment

        self.UC.mem_map(0x4000000, 0x1000000)
        gdt[17] = self.CreateGDTEntry(0x4000000, 0x1000000 , A_PRESENT | A_CODE | A_CODE_READABLE | A_PRIV_3 | A_EXEC | A_DIR_CON_BIT, F_PROT_32)  # Code Segment

        self.UC.mem_map(0x5000000, 0x1000000)
        gdt[18] = self.CreateGDTEntry(0x5000000, 0x1000000 , A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_0 | A_DIR_CON_BIT, F_PROT_32)  # Stack Segment

        self.WriteGDT(gdt, GDT_ADDR)
        self.UC.reg_write(UC_X86_REG_GDTR, (0, GDT_ADDR, len(gdt) * GDT_ENTRY_SIZE-1, 0x0))

        selector = self.CreateSelector(14, S_GDT | S_PRIV_0)
        self.UC.reg_write(UC_X86_REG_FS, selector)

        selector = self.CreateSelector(15, S_GDT | S_PRIV_3)
        self.UC.reg_write(UC_X86_REG_GS, selector)

        selector = self.CreateSelector(16, S_GDT | S_PRIV_3)
        self.UC.reg_write(UC_X86_REG_DS, selector)

        selector = self.CreateSelector(17, S_GDT | S_PRIV_3)
        self.UC.reg_write(UC_X86_REG_CS, selector)

        selector = self.CreateSelector(18, S_GDT | S_PRIV_0)
        self.UC.reg_write(UC_X86_REG_SS, selector)
