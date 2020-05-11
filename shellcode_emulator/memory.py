#!/usr/bin/env python
# pylint: disable=unused-wildcard-import

import sys
import struct
import traceback
import logging

from unicorn import *
from unicorn.x86_const import *

logger = logging.getLogger(__name__)

class Tool:
    def __init__(self, emulator):
        self.emulator = emulator
        self.uc = emulator.uc

    def read_string(self, address): 
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

    def get_stack(self, arg_count):
        esp = self.uc.reg_read(self.emulator.get_register_by_name("esp"))
        ret = struct.unpack("<"+"L"*(arg_count+1), self.uc.mem_read(esp, 4*(1+arg_count)))    
        return ret

    def read_unicode_string(self, address):
        (length, maximum_length, buffer) = struct.unpack("<HHL", self.uc.mem_read(address, 8))
        pwstr = self.uc.mem_read(buffer, length)
        
        ret = ''
        for i in range(0, len(pwstr), 2):
            ret += chr(pwstr[i])
        return ret

    def write_uint_value(self, ptr, data):
        return self.write_memory(ptr, struct.pack("<L", data))
        
    def write_memory(self, address, data, debug = 1):
        try:
            self.uc.mem_write(address, data)
        except:
            logger.error('* Error in writing memory: %.8x (size: %.8x)' % (address, len(data)))
            traceback.print_exc(file = sys.stdout)

    def map(self, base, size):        
        while base<0x100000000:
            try:
                self.uc.mem_map(base, size)
                break
            except:
                pass
            base += 0x1000
            
        return base

    def import_memory_from_file(self, filename, base, size = 0, fixed_allocation = False):
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
            base = self.map(base, size)

        logger.debug(' > write_memory(base = %.8x, size = %.8x)' % (base, len(data)))
        self.write_memory(base, data, debug = 0)
        return (base, size)

    def memory_write_callback(self, uc, access, address, size, value, user_data):
        if access == UC_MEM_WRITE:
            eip = uc.reg_read(self.emulator.get_register_by_name("eip"))
            logger.debug("* %.8x: Memory Write 0x%.8x (Size:%.8u) <-- 0x%.8x" %(eip - self.code_start, address, size, value))
            self.emulator.instruction.dump_context()

    def hook_memory_write(self, start, end):
        self.emulator.add_unicorn_hook(
                    UC_HOOK_MEM_WRITE, 
                    self.memory_write_callback, 
                    None, 
                    start, 
                    end
                )

    def memory_access_callback(self, uc, access, address, size, value, user_data):
        eip = uc.reg_read(self.emulator.get_register_by_name("eip"))
        if access == UC_MEM_WRITE:
            logger.info("* %.8x: Memory Write 0x%.8x (Size:%.8u) <-- 0x%.8x" %
                            (
                                eip-self.code_start, 
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
                                self.code_start,
                                eip-self.code_start, 
                                address, 
                                size, 
                                value
                            )
                        )
            self.emulator.instruction.dump_context()

    def hook_memory_access(self, start, end):
        self.emulator.add_unicorn_hook(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self.memory_access_callback, start, end)                

    def unmapped_memory_access_callback(self, uc, access, address, size, value, user_data):
        if access == UC_MEM_WRITE_UNMAPPED:
            logger.info("* Memory Write Fail: 0x%.8x (Size:%u) --> 0x%.8x " % (value, size, address))
        elif access == UC_MEM_READ_UNMAPPED:
            logger.info("* Memory Read Fail: @0x%x (Size:%u)" % (address, size))
        elif access == UC_MEM_FETCH_UNMAPPED:
            logger.info("* Memory Fetch Fail: @0x%x (Size:%u)" % (address, size))

        self.emulator.instruction.dump_context()
        print(hex(self.uc.reg_read(self.emulator.get_register_by_name("eip"))))
        return False
        
    def hook_unmapped_memory_access(self):
        self.uc.hook_add(
                    UC_HOOK_MEM_READ_UNMAPPED |
                    UC_HOOK_MEM_WRITE_UNMAPPED | 
                    UC_HOOK_MEM_FETCH_UNMAPPED, 
                    self.unmapped_memory_access_callback
                )
