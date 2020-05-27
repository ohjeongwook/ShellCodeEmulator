#!/usr/bin/env python
# pylint: disable=unused-wildcard-import

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import logging
import traceback

from unicorn import *
from unicorn.x86_const import *

import shellcode_emulator.utils

logger = logging.getLogger(__name__)

class Hook:
    amd64_argument_regs = (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9)
    def __init__(self, emulator, arch):
        self.emulator = emulator
        self.arch = arch
        self.uc = emulator.uc
        self.trace_target_modules = ['ntdll', 'kernel32', 'kernelbase']
        self.last_code_information = {}

    def return_function(self, uc, return_address, arg_count, return_value):
        print('Return Address: %x' % (return_address))
        uc.reg_write(self.emulator.register.get_by_name("ip"), return_address)

        esp = uc.reg_read(self.emulator.register.get_by_name("sp"))
        print('New ESP: %x' % (esp+4*(arg_count+1)))
        uc.reg_write(self.emulator.register.get_by_name("sp"), esp+4*(arg_count+1))        
        uc.reg_write(self.emulator.register.get_by_name("ax"), return_value)

    def get_arguments(self, count):
        arguments = []

        stack_argument_count = count
        if self.arch == 'AMD64':
            reg_argument_count = min(count, len(self.amd64_argument_regs))
            stack_argument_count -= reg_argument_count
            for i in range(0, reg_argument_count, 1):
                arguments.append(self.uc.reg_read(self.amd64_argument_regs[i]))

        if stack_argument_count > 0:
            arguments += self.emulator.memory.get_stack(stack_argument_count)

        return arguments        

    def callback(self, uc, address, size, user_data):
        code = uc.mem_read(address, size)
        try:
            name = self.emulator.debugger.find_symbol(address)
        except:
            name = ''
            self.emulator.instruction.dump_disassembly(address, size, find_symbol = True)

        sp = self.uc.reg_read(self.emulator.register.get_by_name("sp"))
        print('%x: %s (%x)' % (sp, name, address))
        if name == 'kernel32!WinExec':
            arguments = self.get_arguments(2)
            command = self.emulator.memory.read_string(arguments[0])
            print('command: %s' % command)

        elif name == 'ntdll!LdrLoadDll':
            try:
                (return_address, path_to_file, flags, module_filename_addr, module_handle_out_ptr) = self.emulator.memory.get_stack(4)
                if self.Debug>0:
                    logger.debug('PathToFile: %.8x Flags: %.8x ModuleFilename: %.8x ModuleHandle: %.8x' % 
                                    (
                                        path_to_file, 
                                        flags, 
                                        module_filename_addr, 
                                        module_handle_out_ptr
                                    )
                                )

                module_filename = self.emulator.memory.read_unicode_string(uc, module_filename_addr)
                logger.debug('Module Filename: ' + module_filename)

                module_base = self.emulator.debugger.get_module_base(module_filename)
                
                if not module_base:
                    module_base = self.emulator.debugger.get_module_base(module_filename.split('.')[0])
                    
                if module_base:                        
                    logger.debug('Write Module Base: %.8x --> %.8x' % 
                                    (
                                        module_base, 
                                        module_handle_out_ptr
                                    )
                                )
                    self.emulator.memory.write_uint_value(uc, module_handle_out_ptr, module_base)
                    self.return_function(uc, return_address, 4, 1)
            except:
                traceback.print_exc(file = sys.stdout)

        elif name == 'kernel32!GetProcAddress':
            (return_address, module_handle, proc_name_ptr) = self.emulator.memory.get_stack(uc, 2)
            logger.debug("\tReturnAddress: %.8x, ModuleHandle: %.8x, ProcName: %.8x" % 
                            (
                                return_address, 
                                module_handle, 
                                proc_name_ptr
                            )
                        )
            
            module_name = self.emulator.debugger.get_module_name_from_base(module_handle)
            proc_name = self.emulator.memory.read_string(uc, proc_name_ptr)
            symbol = "%s!%s" % (module_name, proc_name)
            
            logger.debug('\tSymbol: %s' % symbol)
            # TODO: address = self.GetSymbolAddress(symbol)
            logger.debug('\tAddress: %x' % (address))
            uc.reg_write(self.emulator.register.get_by_name("ax"), address)
            self.return_function(uc, return_address, 2, address)
            
        elif name == 'kernel32!LoadLibraryA':
            (return_address, filename_ptr) = self.emulator.memory.get_stack(uc, 1)
            filename = self.emulator.memory.read_string(uc, filename_ptr)
            logger.debug('\tLoadLibraryA Filename:%s' % filename)

        elif name == 'kernel32!VirtualAlloc' or name == 'KERNELBASE!VirtualAlloc':
            (return_address, lp_address, dw_size, fl_allocation_type, fl_protect) = self.emulator.memory.get_stack(uc, 4)
        
            logger.debug('> ReturnAddress: %.8x, lpAddress: %.8x, dwSize: %.8x, flAllocationType: %.8x, flProtect: %.8x' % 
                            (
                                return_address, 
                                lp_address, 
                                dw_size, 
                                fl_allocation_type, 
                                fl_protect
                            )
                        )
            
            if lp_address == 0:
                start_address = 0x70000
                
                base = start_address
                
                while 1:
                    try:
                        logger.debug('Allocating at %.8x' % base)
                        dw_size += (4096-dw_size%4096)
                        self.emulator.memory.map(base, int(dw_size))
                        break
                    except:
                        traceback.print_exc(file = sys.stdout)
                    base += 0x10000

                self.return_function(uc, return_address, 4, base)
                
        elif name == 'ntdll!RtlDecompressBuffer':
            (return_address, compression_format, uncompressed_buffer, uncompressed_buffer_size, compressed_buffer, compressed_buffer_size, final_uncompressed_size) = self.emulator.memory.get_stack(6)
            
            logger.debug('> ReturnAddress: %.8x, CompressionFormat: %.8x, UncompressedBuffer: %.8x, UncompressedBufferSize: %.8x, CompressedBuffer: %.8x, CompressedBufferSize: %.8x, FinalUncompressedSize: %.8x' % 
                            (
                                return_address, 
                                compression_format, 
                                uncompressed_buffer, 
                                uncompressed_buffer_size, 
                                compressed_buffer, 
                                compressed_buffer_size, 
                                final_uncompressed_size
                            )
                        )

            """
            bytes = uc.mem_read(compressed_buffer, compressed_buffer_size)
            fd = open('compressed.bin', 'wb')
            fd.write(bytes)
            fd.close()
            """

            #self.uc.add_unicorn_hook(UC_HOOK_CODE, self.dump_memory_callback, None, return_address, return_address+1)

        elif name == 'kernel32!GetFileSize':
            (return_address, hfile, lp_file_size_high) = self.emulator.memory.get_stack(uc, 2)
            
            logger.debug('> hFile: %.8x, lpFileSizeHigh: %.8x' % 
                            (
                                hfile, 
                                lp_file_size_high
                            )
                        )
            
            #uc.hook_add(UC_HOOK_CODE, self.dump_memory_callback, None, return_address, return_address+1)
            self.return_function(uc, return_address, 2, 0x7bafe)

        #kernel32!CreateFileMappingA
        #kernel32!MapViewOfFile
        if code == '\x0f\x34': #sysenter
            asm = self.uc.Instruction.disassemble(code, address)

            offset = 0
            for a in asm:
                logger.debug('%.8X: %s\t%s\t%s' % 
                                (
                                    a.address, 
                                    shellcode_emulator.utils.Tool.dump_hex(code[offset:offset+a.size]), 
                                    a.mnemonic, a.op_str
                                )
                            )
                offset += a.size
            
        self.last_code_information = user_data

    def start(self):
        self.emulator.debugger.load_symbols(self.trace_target_modules)

        for trace_module in self.trace_target_modules:
            for (symbol, address) in self.emulator.debugger.symbol_to_address.items():
                logger.debug("api.Hook.start: %s - %s (%x)", trace_module, symbol, address)
                self.emulator.add_unicorn_hook(UC_HOOK_CODE, self.callback, trace_module, address, address)

