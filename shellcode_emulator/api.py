import sys
import logging
import traceback

from unicorn import *
from unicorn.x86_const import *

import shellcode_emulator.utils

logger = logging.getLogger(__name__)

class Hook:
    def __init__(self, emulator):
        self.Emulator = emulator
        self.UC = emulator.uc
        self.TraceModules = ['ntdll', 'kernel32', 'kernelbase']
        self.LastCodeInfo = {}

    def ReturnFunction(self, uc, return_address, arg_count, return_value):
        print('Return Address: %x' % (return_address))
        uc.reg_write(self.Emulator.GetReg("eip"), return_address)

        esp = uc.reg_read(self.Emulator.GetReg("esp"))
        print('New ESP: %x' % (esp+4*(arg_count+1)))
        uc.reg_write(self.Emulator.GetReg("esp"), esp+4*(arg_count+1))        
        uc.reg_write(self.Emulator.GetReg("eax"), return_value)

    def Callback(self, uc, address, size, user_data):
        self.Emulator.Instruction.DumpDisasm(address, size, resolve_symbol = True)

        code = uc.mem_read(address, size)
        try:
            name = self.Emulator.Debugger.ResolveSymbol(instruction.address)
        except:
            name = ''

        if name == 'ntdll!LdrLoadDll':
            try:
                (return_address, path_to_file, flags, module_filename_addr, module_handle_out_ptr) = self.UC.Memory.GetStack(4)
                if self.Debug>0:
                    logger.debug('PathToFile: %.8x Flags: %.8x ModuleFilename: %.8x ModuleHandle: %.8x' % 
                                    (
                                        path_to_file, 
                                        flags, 
                                        module_filename_addr, 
                                        module_handle_out_ptr
                                    )
                                )

                module_filename = self.UC.Memory.ReadUnicodeString(uc, module_filename_addr)
                logger.debug('Module Filename: ' + module_filename)

                module_base = self.Emulator.Debugger.GetModuleBase(module_filename)
                
                if not module_base:
                    module_base = self.Emulator.Debugger.GetModuleBase(module_filename.split('.')[0])
                    
                if module_base:                        
                    logger.debug('Write Module Base: %.8x --> %.8x' % 
                                    (
                                        module_base, 
                                        module_handle_out_ptr
                                    )
                                )
                    self.UC.Memory.WriteUintMem(uc, module_handle_out_ptr, module_base)
                    self.ReturnFunction(uc, return_address, 4, 1)
            except:
                traceback.print_exc(file = sys.stdout)

        elif name == 'kernel32!GetProcAddress':
            (return_address, module_handle, proc_name_ptr) = self.UC.Memory.GetStack(uc, 2)
            logger.debug("\tReturnAddress: %.8x, ModuleHandle: %.8x, ProcName: %.8x" % 
                            (
                                return_address, 
                                module_handle, 
                                proc_name_ptr
                            )
                        )
            
            module_name = self.Emulator.Debugger.GetModuleNameFromBase(module_handle)
            proc_name = self.UC.Memory.ReadString(uc, proc_name_ptr)
            symbol = "%s!%s" % (module_name, proc_name)
            
            logger.debug('\tSymbol: %s' % symbol)
            #TODO: address = self.GetSymbolAddress(symbol)
            logger.debug('\tAddress: %x' % (address))
            uc.reg_write(self.Emulator.GetReg("eax"), address)
            self.ReturnFunction(uc, return_address, 2, address)
            
        elif name == 'kernel32!LoadLibraryA':
            (return_address, filename_ptr) = self.UC.Memory.GetStack(uc, 1)
            filename = self.UC.Memory.ReadString(uc, filename_ptr)
            logger.debug('\tLoadLibraryA Filename:%s' % filename)

        elif name == 'kernel32!VirtualAlloc' or name == 'KERNELBASE!VirtualAlloc':
            (return_address, lp_address, dw_size, fl_allocation_type, fl_protect) = self.UC.Memory.GetStack(uc, 4)
        
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
                        self.UC.Memory.Map(base, int(dw_size))
                        break
                    except:
                        traceback.print_exc(file = sys.stdout)
                    base += 0x10000

                self.ReturnFunction(uc, return_address, 4, base)
                
        elif name == 'ntdll!RtlDecompressBuffer':
            (return_address, compression_format, uncompressed_buffer, uncompressed_buffer_size, compressed_buffer, compressed_buffer_size, final_uncompressed_size) = self.UC.Memory.GetStack(6)
            
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

            self.UC.AddHook(UC_HOOK_CODE, self.CodeHookForDump, None, return_address, return_address+1)

        elif name == 'kernel32!GetFileSize':
            (return_address, hfile, lp_file_size_high) = self.UC.Memory.GetStack(uc, 2)
            
            logger.debug('> hFile: %.8x, lpFileSizeHigh: %.8x' % 
                            (
                                hfile, 
                                lp_file_size_high
                            )
                        )
            
            #uc.hook_add(UC_HOOK_CODE, self.CodeHookForDump, None, return_address, return_address+1)
            self.ReturnFunction(uc, return_address, 2, 0x7bafe)

        #kernel32!CreateFileMappingA
        #kernel32!MapViewOfFile
        if code == '\x0f\x34': #sysenter
            asm = self.UC.Instruction.Disassemble(code, address)

            offset = 0
            for a in asm:
                logger.debug('%.8X: %s\t%s\t%s' % 
                                (
                                    a.address, 
                                    utils.Tool.DumpHex(code[offset:offset+a.size]), 
                                    a.mnemonic, a.op_str
                                )
                            )
                offset += a.size
            
        self.LastCodeInfo = user_data

    def Start(self):
        self.Emulator.Debugger.LoadSymbols(self.TraceModules)

        for trace_module in self.TraceModules:
            for (symbol, address) in self.Emulator.Debugger.SymbolToAddress.items():
                logger.debug("api.Hook.Start: %s - %s (%x)", trace_module, symbol, address)
                self.Emulator.AddHook(UC_HOOK_CODE, self.Callback, trace_module, address, address)

