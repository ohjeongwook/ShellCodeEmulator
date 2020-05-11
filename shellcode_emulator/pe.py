#!/usr/bin/env python
# pylint: disable=unused-wildcard-import

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import struct
import logging
import traceback

import shellcode_emulator.gdt

upack32 = lambda x: struct.unpack('I', x)[0]
pack32 = lambda x: struct.pack('I', x)

logger = logging.getLogger(__name__)

class ProcessMemory:
    def __init__(self, emulator, tib_bytes = None, stack_base = 0, stack_limit = 0, fs = 0, teb_addr = 0, peb_addr = 0):
        self.emulator = emulator
        self.stack_base_address = stack_base
        self.stack_limit = stack_limit
        self.fs = fs
        self.teb_address = teb_addr
        self.peb_address = peb_addr

        if tib_bytes:
            self.parse_teb(tib_bytes)
        
    def parse_teb(self, tib_bytes):
        unpacked_entries = struct.unpack('I'*13, tib_bytes[0:4*13])
        self.stack_base_address = unpacked_entries[1]
        self.stack_limit = unpacked_entries[2]
        self.teb_address = unpacked_entries[11]
        self.peb_address = unpacked_entries[12]

    def load_process_memory(self):
        self.emulator.debugger.set_symbol_path()
        self.emulator.debugger.enumerate_modules()
        
        teb_list = []
        teb_bytes = []
        for address in self.emulator.debugger.get_address_list():
            if address['State'] in ('MEM_FREE', 'MEM_RESERVE') or address['Usage'] == 'Free':
                continue

            logger.info("Mapping %.8x ~ %.8x (size: %.8x) - [%s] %s" % (
                                                                address['BaseAddr'], 
                                                                address['BaseAddr']+address['RgnSize'], 
                                                                address['RgnSize'], 
                                                                address['Usage'], 
                                                                address['Comment']
                                                            )
                                                        )

            if address['Usage'] == 'TEB':
                teb_list.append(address)

            if address['Usage'].startswith('Stack'):
                self.stack_limit = address['BaseAddr']
                self.StackSize = address['RgnSize']
                self.stack_base_address = address['BaseAddr']+address['RgnSize']
                
                logger.debug('\tStack: 0x%.8x ~ 0x%.8x (0x%.8x)' % (self.stack_limit, self.stack_base_address, self.StackSize))

                self.emulator.register.write("esp", address['BaseAddr']+address['RgnSize']-0x1000)
                self.emulator.register.write("ebp", address['BaseAddr']+address['RgnSize']-0x1000)

            if self.emulator.debugger:
                tmp_dmp_filename = 'tmp.dmp'
                try:
                    self.emulator.debugger.run_command(".writemem %s %x L?%x" % (tmp_dmp_filename, address['BaseAddr'], address['RgnSize']))
                except:
                    logger.debug("* Writemem failed")
                    traceback.print_exc(file = sys.stdout)

                self.emulator.memory.import_memory_from_file(tmp_dmp_filename, address['BaseAddr'], size = address['RgnSize'], fixed_allocation = True)
                if address['Usage'] == 'TEB':
                    with open (tmp_dmp_filename, 'rb') as fd:
                        teb_bytes.append(fd.read())
            else:
                self.emulator.memory.map(address['BaseAddr'], address['RgnSize'])

                try:
                    bytes_list = self.emulator.debugger.get_bytes(address['BaseAddr'], address['RgnSize'])
                except:
                    logger.debug("* loadBytes failed")
                    traceback.print_exc(file = sys.stdout)
                    continue

                bytes = ''
                for n in bytes_list:
                    bytes += chr(n)

                self.emulator.memory.write_memory(address['BaseAddr'], bytes)

        if len(teb_list) > 0:
            gdt_layout = shellcode_emulator.gdt.Layout(self.emulator)
            if self.emulator.arch == 'x86':
                segment_limit = 0xffffffff
                logger.info("* Setting up fs: %x (len=%x)" % (teb_list[0]['BaseAddr'], teb_list[0]['RgnSize']))
                gdt_layout.setup(fs_base = teb_list[0]['BaseAddr'], fs_limit = teb_list[0]['RgnSize'], segment_limit = segment_limit)
            elif self.emulator.arch == 'AMD64':
                segment_limit = 0xffffffffffffffff
                logger.info("* Setting up gs: %x (len=%x)" % (teb_list[0]['BaseAddr'], teb_list[0]['RgnSize']))
                gdt_layout.setup(gs_base = teb_list[0]['BaseAddr'], gs_limit = teb_list[0]['RgnSize'], segment_limit = segment_limit)
                self.emulator.memory.map(0, len(teb_bytes[0]))
                self.emulator.memory.write_memory(0, teb_bytes[0]) #64bit hack to map TEB to 0 ~ 
