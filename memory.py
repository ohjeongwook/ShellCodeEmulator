import sys
import struct
import traceback
import logging

from unicorn import *
from unicorn.x86_const import *

logger = logging.getLogger(__name__)

class Tool:
    def __init__(self, emulator):
        self.Emulator = emulator
        self.uc = emulator.uc

    def ReadString(self, address): 
        null_found = False
        ret = ''
        offset = 0
        chunk_len = 0x100
        while 1:
            for ch in self.uc.mem_read(address+offset, chunk_len):
                if ch == 0x00:
                    null_found = True
                    break
                ret += chr(ch)

            if null_found:
                break
                
            offset += chunk_len
            
        return ret

    def GetStack(self, arg_count):
        esp = self.uc.reg_read(self.Emulator.GetReg("esp"))
        ret = struct.unpack("<"+"L"*(arg_count+1), self.uc.mem_read(esp, 4*(1+arg_count)))    
        return ret

    def ReadUnicodeString(self, address):
        (length, maximum_length, buffer) = struct.unpack("<HHL", self.uc.mem_read(address, 8))
        pwstr = self.uc.mem_read(buffer, length)
        
        ret = ''
        for i in range(0, len(pwstr), 2):
            ret += chr(pwstr[i])
        return ret

    def WriteUintMem(self, ptr, data):
        return self.WriteMem(ptr, struct.pack("<L", data))
        
    def WriteMem(self, address, data, debug = 1):
        try:
            self.uc.mem_write(address, data)
        except:
            logger.error('* Error in writing memory: %.8x (size: %.8x)' % (address, len(data)))
            traceback.print_exc(file = sys.stdout)

    def Map(self, base, size):        
        while base<0x100000000:
            try:
                self.uc.mem_map(base, size)
                break
            except:
                pass
            base += 0x1000
            
        return base

    def ReadMemoryFile(self, filename, base, size = 0, fixed_allocation = False):
        with open(filename, 'rb') as fd:
            if size>0:
                data = fd.read(size)
            else:
                data = fd.read()
                size = len(data)

        logger.debug('* ReadMemoryFile: %.8x (size: %.8x)' % (base, len(data)))
        logger.debug(' > self.uc.mem_map(base = %.8x, size = %.8x)' % (base, size))

        if fixed_allocation:
            try:
                self.uc.mem_map(base, size)
            except:
                logger.error('* Error in memory mapping: %.8x (size: %.8x)' % (base, len(data)))
                traceback.print_exc(file = sys.stdout)
        else:
            base = self.Map(base, size)

        logger.debug(' > WriteMem(base = %.8x, size = %.8x)' % (base, len(data)))
        self.WriteMem(base, data, debug = 0)
        return (base, size)

    def MemoryWriteCallback(self, uc, access, address, size, value, user_data):
        if access == UC_MEM_WRITE:
            eip = uc.reg_read(self.Emulator.GetReg("eip"))
            logger.debug("* %.8x: Memory Write 0x%.8x (Size:%.8u) <-- 0x%.8x" %(eip - self.CodeStart, address, size, value))
            self.Emulator.Instruction.DumpContext()

    def HookMemoryWrite(self, start, end):
        self.Emulator.AddHook(
                    UC_HOOK_MEM_WRITE, 
                    self.MemoryWriteCallback, 
                    None, 
                    start, 
                    end
                )

    def MemoryAccessCallback(self, uc, access, address, size, value, user_data):
        eip = uc.reg_read(self.Emulator.GetReg("eip"))
        if access == UC_MEM_WRITE:
            logger.info("* %.8x: Memory Write 0x%.8x (Size:%.8u) <-- 0x%.8x" %
                            (
                                eip-self.CodeStart, 
                                address, 
                                size, 
                                value
                            )
                        )

        elif access == UC_MEM_READ:
            bytes = uc.mem_read(address, size)
            
            if size == 4:
                (value, ) = struct.unpack("<L", bytes)

            logger.info("* %.8x (%.8x + %.8x): Memory Read  0x%.8x (Size:%.8u) --> 0x%.8x" %
                            (
                                eip,
                                self.CodeStart,
                                eip-self.CodeStart, 
                                address, 
                                size, 
                                value
                            )
                        )
            self.Emulator.Instruction.DumpContext()

    def HookMemoryAccess(self, start, end):
        self.Emulator.AddHook(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self.MemoryAccessCallback, start, end)                

    def UnmappedMemoryAccessCallback(self, uc, access, address, size, value, user_data):
        if access == UC_MEM_WRITE_UNMAPPED:
            logger.info("* Memory Write Fail: 0x%.8x (Size:%u) --> 0x%.8x " % (value, size, address))
        elif access == UC_MEM_READ_UNMAPPED:
            logger.info("* Memory Read Fail: @0x%x (Size:%u)" % (address, size))
        elif access == UC_MEM_FETCH_UNMAPPED:
            logger.info("* Memory Fetch Fail: @0x%x (Size:%u)" % (address, size))

        self.Emulator.Instruction.DumpContext()
        print(hex(self.uc.reg_read(self.Emulator.GetReg("eip"))))
        return False
        
    def HookUnmappedMemoryAccess(self):
        self.uc.hook_add(
                    UC_HOOK_MEM_READ_UNMAPPED |
                    UC_HOOK_MEM_WRITE_UNMAPPED | 
                    UC_HOOK_MEM_FETCH_UNMAPPED, 
                    self.UnmappedMemoryAccessCallback
                )
