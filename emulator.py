import os
import sys

import struct
import traceback
import logging
import sqlite3

from unicorn import *
from unicorn.x86_const import *

import capstone
import pykd

import windbgtool.debugger
import util.common

try:
    import idatool.list
except:
    pass

import gdt

upck32 = lambda x: struct.unpack('I', x)[0]
pck32 = lambda x: struct.pack('I', x)

class PEStructure:
    def __init__(self, tib_bytes = None, stack_base = 0, stack_limit = 0, fs = 0, teb_addr = 0, peb_addr = 0):
        self.logger = logging.getLogger(__name__)
        self.StackBase = stack_base
        self.StackLimit = stack_limit
        self.FS = fs
        self.TebAddr = teb_addr
        self.PebAddr = peb_addr

        if tib_bytes:
            self._ReadTIB(tib_bytes)
        
    def _ReadTIB(self, tib_bytes):
        unpacked_entries = struct.unpack('I'*13, tib_bytes[0:4*13])
        self.StackBase = unpacked_entries[1]
        self.StackLimit = unpacked_entries[2]
        self.TebAddr = unpacked_entries[11]
        self.PebAddr = unpacked_entries[12]

    def InitLDR(seft, FLoad, Bload, FMem, BMem, FInit, BInit, DllBase, EntryPoint, DllName, addrofnamedll):
        # InOrder
        ldr = ''
        ldr += pck32(FLoad)  # flink
        ldr += pck32(Bload)  # blink
        # Inmem
        ldr += pck32(FMem)  # flink
        ldr += pck32(BMem)  # blink
        # InInit
        ldr += pck32(FInit)  # flink 0x10
        ldr += pck32(BInit)  # blink 0x14

        ldr += pck32(DllBase)  # baseOfdll 0x18
        ldr += pck32(EntryPoint)  # entryPoint 0x1c
        ldr += pck32(0x0)  # sizeOfImage 0x20
        ldr += pck32(0x0) * 2  # Fullname 0x28
        # basename
        ldr += pck32(0x0)  # 0x2c
        ldr += pck32(addrofnamedll)  # 0x30
        return ldr

    def init_teb(seft):
        teb = ''
        teb += pck32(0x0) * 7
        teb += pck32(0x0)  # EnvironmentPointer
        teb += pck32(0x0)  # ClientId
        teb += pck32(0x0)  # ThreadLocalStoragePointer
        teb += pck32(PEB_ADD)  # ProcessEnvironmentBlock
        teb += pck32(0x0)  # LastErrorValue
        return teb

    def init_peb(seft):
        peb = ''
        peb += pck32(0x0) * 2  # InheritedAddressSpace
        peb += pck32(pe_struct['imageBase'])  # imageBaseAddress
        peb += pck32(PEB_LDR_ADD)  # Ldr
        peb += pck32(0x0)  # process parameter
        return peb

    def init_peb_ldr_data(self):
        peb_ldr_data = ''
        peb_ldr_data += pck32(0x0) * 3  # 0x8
        peb_ldr_data += pck32(LDR_ADD1)  # 0x0c
        peb_ldr_data += pck32(LDR_ADD1 + 0x4)
        peb_ldr_data += pck32(LDR_ADD1 + 0x8)  # 0x14
        peb_ldr_data += pck32(LDR_ADD1 + 0xc)
        peb_ldr_data += pck32(LDR_ADD1 + 0x10)  # 0x1C
        peb_ldr_data += pck32(LDR_ADD1 + 0x14)
        return peb_ldr_data

    def InitFS(self):
        fs_data = ''
        fs_data += pck32(0x0)  # 0x0
        fs_data += pck32(self.StackBase)  # 0x4
        fs_data += pck32(self.StackLimit)  # 0x8
        fs_data += pck32(0x0) * 3  # 0x14
        fs_data += pck32(self.FS)
        fs_data += pck32(0x0) * 4
        fs_data += pck32(self.TebAddr)
        fs_data += pck32(self.PebAddr)
        fs_data += pck32(0x0)
        return fs_data

class ShellEmu:
    def __init__(self, shellcode_filename, shellcode_bytes = '', dump_filename = ''):
        self.ShellcodeFilename = shellcode_filename
        self.ShellcodeBytes = shellcode_bytes
        self.DumpFilename = dump_filename
        self.TraceModules = ['ntdll', 'kernel32', 'kernelbase']

        self.logger = logging.getLogger(__name__)

        self.ExhaustiveLoopDumpFrequency = 0x10000
        self.HitMap = {}            
        self.LastCodeAddress = 0
        self.LastCodeSize = 0

        #self.Conn = sqlite3.connect("Emulator.db", check_same_thread = False)
        #self.Cursor = self.Conn.cursor()
        #self.Cursor.execute('''CREATE TABLE CodeExecution (address int)''')
        
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
            try:
                symbol_str = self.Debugger.ResolveSymbol(instruction.address) + ':\t'
            except:
                symbol_str = ''

            code_offset = 0
            if self.CodeStart <= instruction.address and instruction.address <= self.CodeStart + self.CodeLen:
                code_offset = instruction.address - self.CodeStart
                
            if code_offset>0:
                address_str = '+%.8X: ' % (code_offset)
            else:
                address_str = ' %.8X: ' % (instruction.address)

            print('%s%s%s\t%s\t%s' % (symbol_str, address_str, self.DumpHex(code[offset:offset+instruction.size]), instruction.mnemonic, instruction.op_str))

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

    def DumpHex(self, bytes):
        line = ''
        count = 0
        for ch in bytes:
            if isinstance(ch, str):
                ch = ord(ch)
            line += '%.2x ' % ch
            if count % 0x10 == 0xf:
                line += '\n'
            count += 1
            
        return line
    
    def DumpContext(self, dump_registers = True, dump_previous_eip = False):
        self.DumpDisasm(self.uc.reg_read(UC_X86_REG_EIP), 10)

        if dump_registers:
            self.DumpRegisters()

        if dump_previous_eip and self.LastCodeAddress>0:
            print('> Last EIP before this instruction:')
            self.DumpDisasm(self.LastCodeAddress, self.LastCodeSize)

    def CodeHookForDump(self, uc, address, size, user_data):
        self.DumpContext()
        print('')
        
    def HookKernel32Code(self, uc, address, size, user_data):
        print('Calling %x' % (address))
            
    def MemoryWriteHook(self, uc, access, address, size, value, user_data):
        if access == UC_MEM_WRITE:
            eip = self.uc.reg_read(UC_X86_REG_EIP)
            logger.debug("* %.8x: Memory Write 0x%.8x (Size:%.8u) <-- 0x%.8x" %(eip-self.CodeStart, address, size, value))
            self.DumpContext()

    def HookMemoryWrite(self, start, end):
        self.uc.hook_add(
                    UC_HOOK_MEM_WRITE, 
                    self.MemoryWriteHook, 
                    None, 
                    start, 
                    end
                )

    def HookMemoryRead(self, uc, access, address, size, value, user_data):
        #print('Read:', user_data)
        pass

    def CodeExecutionHook(self, uc, address, size, user_data):
        if self.Debug>0:            
            self.logger.debug("CodeExecutionHook: 0x%.8x" % address)
            self.DumpContext()
            self.logger.debug("")

        #self.Cursor.execute("INSERT INTO CodeExecution VALUES (%d)" % address)
        #self.Conn.commit()

        if not self.HitMap.has_key(address):
            self.HitMap[address] = 1
        else:
            self.HitMap[address] += 1
            
            if self.HitMap[address]%self.ExhaustiveLoopDumpFrequency == 0:
                print('Exhaustive Loop found: %x' % (self.HitMap[address]))
                self.DumpContext()
                print('')
                pass

        self.LastCodeAddress = address
        self.LastCodeSize = size
        
    def ReadUnicodeString(self, uc, address):
        (length, maximum_length, buffer) = struct.unpack("<HHL", self.uc.mem_read(address, 8))
        if self.Debug>0:
            print('UNICODE_STRING: %.4x %.4x %.8x' % (length, maximum_length, buffer))
        pwstr = self.uc.mem_read(buffer, length)
        
        ret = ''
        for i in range(0, len(pwstr), 2):
            ret += chr(pwstr[i])
        return ret

    def ReadString(self, uc, address): 
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

    def GetStack(self, uc, arg_count):
        esp = self.uc.reg_read(UC_X86_REG_ESP)
        ret = struct.unpack("<"+"L"*(arg_count+1), self.uc.mem_read(esp, 4*(1+arg_count)))    
        return ret

    def ReturnFunction(self, uc, return_address, arg_count, return_value):
        print('Return Address: %x' % (return_address))
        self.uc.reg_write(UC_X86_REG_EIP, return_address)

        esp = self.uc.reg_read(UC_X86_REG_ESP)
        print('New ESP: %x' % (esp+4*(arg_count+1)))
        self.uc.reg_write(UC_X86_REG_ESP, esp+4*(arg_count+1))        
        self.uc.reg_write(UC_X86_REG_EAX, return_value)

    def WriteCurrentCode(self, filename):
        fd = open(filename, 'wb')            
        bytes = self.uc.mem_read(self.CodeStart, self.CodeLen)
        fd.write(bytes)
        fd.close()

    def WriteUintMem(self, uc, ptr, data):
        return self.WriteMem(ptr, struct.pack("<L", data))
        
    def WriteMem(self, address, data, debug = 1):
        try:
            self.uc.mem_write(address, data)
        except:
            self.logger.error('* Error in writing memory: %.8x (size: %.8x)' % (address, len(data)))
            traceback.print_exc(file = sys.stdout)

    def AllocateMemory(self, base, size):        
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

        self.logger.debug('* ReadMemoryFile: %.8x (size: %.8x)' % (base, len(data)))
        
        self.logger.debug(' > self.uc.mem_map(base = %.8x, size = %.8x)' % (base, size))
        if fixed_allocation:
            try:
                self.uc.mem_map(base, size)
            except:
                self.logger.error('* Error in memory mapping: %.8x (size: %.8x)' % (base, len(data)))
                traceback.print_exc(file = sys.stdout)
        else:
            base = self.AllocateMemory(base, size)

        self.logger.debug(' > WriteMem(base = %.8x, size = %.8x)' % (base, len(data)))
        self.WriteMem(base, data, debug = 0)
        return (base, size)

    def LoadProcessMemory(self):
        self.Debugger = windbgtool.debugger.DbgEngine()
        self.Debugger.LoadDump(self.DumpFilename)
        self.Debugger.SetSymbolPath()
        self.Debugger.EnumerateModules()
        self.Debugger.LoadSymbols(self.TraceModules)
        
        for address in self.Debugger.GetAddressList():
            if address['State'] in ('MEM_FREE', 'MEM_RESERVE') or address['Usage'] == 'Free':
                continue

            self.logger.debug("Mapping %.8x ~ %.8x (size: %.8x) - %s %s" % (
                                                                address['BaseAddr'], 
                                                                address['BaseAddr']+address['RgnSize'], 
                                                                address['RgnSize'], 
                                                                address['Usage'], 
                                                                address['Comment']
                                                            )
                                                        )
            
            if address['Usage'].startswith('Stack'):
                self.StackLimit = address['BaseAddr']
                self.StackSize = address['RgnSize']
                self.StackBase = address['BaseAddr']+address['RgnSize']
                
                self.logger.debug('\tStack: 0x%.8x ~ 0x%.8x (0x%.8x)' % (self.StackLimit, self.StackBase, self.StackSize))

                self.uc.reg_write(UC_X86_REG_ESP, address['BaseAddr']+address['RgnSize']-0x100)
                self.uc.reg_write(UC_X86_REG_EBP, address['BaseAddr']+address['RgnSize']-0x100)
        
            if self.DumpFilename:
                tmp_dmp_filename = 'tmp.dmp'
                try:
                    pykd.dbgCommand(".writemem %s %x L?%x" % (tmp_dmp_filename, address['BaseAddr'], address['RgnSize']))
                except:
                    self.logger.debug("* Writemem failed")
                    traceback.print_exc(file = sys.stdout)
                self.ReadMemoryFile(tmp_dmp_filename, address['BaseAddr'], size = address['RgnSize'], fixed_allocation = True)
            else:
                self.uc.mem_map(address['BaseAddr'], address['RgnSize'])

                try:
                    bytes_list = pykd.loadBytes(address['BaseAddr'], address['RgnSize'])
                except:
                    self.logger.debug("* loadBytes failed")
                    traceback.print_exc(file = sys.stdout)
                    continue

                bytes = ''
                for n in bytes_list:
                    bytes += chr(n)

                self.WriteMem(address['BaseAddr'], bytes, debug = debug)
                
            self.LastCodeInfo = {}

    def APIExecutionHook(self, uc, address, size, user_data):
        self.DumpDisasm(address, size, resolve_symbol = True)

        code = self.uc.mem_read(address, size)
        try:
            name = self.Debugger.ResolveSymbol(instruction.address)
        except:
            name = ''

        if name == 'ntdll!LdrLoadDll':
            try:
                (return_address, path_to_file, flags, module_filename_addr, module_handle_out_ptr) = self.GetStack(self.uc, 4)
                if self.Debug>0:
                    self.logger.debug('PathToFile: %.8x Flags: %.8x ModuleFilename: %.8x ModuleHandle: %.8x' % 
                                    (
                                        path_to_file, 
                                        flags, 
                                        module_filename_addr, 
                                        module_handle_out_ptr
                                    )
                                )

                module_filename = self.ReadUnicodeString(self.uc, module_filename_addr)
                self.logger.debug('Module Filename: ' + module_filename)

                module_base = self.Debugger.GetModuleBase(module_filename)
                
                if not module_base:
                    module_base = self.Debugger.GetModuleBase(module_filename.split('.')[0])
                    
                if module_base:                        
                    self.logger.debug('Write Module Base: %.8x --> %.8x' % 
                                    (
                                        module_base, 
                                        module_handle_out_ptr
                                    )
                                )
                    self.WriteUintMem(self.uc, module_handle_out_ptr, module_base)
                    self.ReturnFunction(self.uc, return_address, 4, 1)
            except:
                traceback.print_exc(file = sys.stdout)

        elif name == 'kernel32!GetProcAddress':
            (return_address, module_handle, proc_name_ptr) = self.GetStack(self.uc, 2)
            self.logger.debug("\tReturnAddress: %.8x, ModuleHandle: %.8x, ProcName: %.8x" % 
                            (
                                return_address, 
                                module_handle, 
                                proc_name_ptr
                            )
                        )
            
            module_name = self.Debugger.GetModuleNameFromBase(module_handle)
            proc_name = self.ReadString(self.uc, proc_name_ptr)
            symbol = "%s!%s" % (module_name, proc_name)
            
            self.logger.debug('\tSymbol: %s' % symbol)
            address = self.GetSymbolAddress(symbol)
            self.logger.debug('\tAddress: %x' % (address))
            self.uc.reg_write(UC_X86_REG_EAX, address)
            self.ReturnFunction(self.uc, return_address, 2, address)
            
        elif name == 'kernel32!LoadLibraryA':
            (return_address, filename_ptr) = self.GetStack(self.uc, 1)
            filename = self.ReadString(self.uc, filename_ptr)
            self.logger.debug('\tLoadLibraryA Filename:%s' % filename)

        elif name == 'kernel32!VirtualAlloc' or name == 'KERNELBASE!VirtualAlloc':
            (return_address, lp_address, dw_size, fl_allocation_type, fl_protect) = self.GetStack(self.uc, 4)
        
            self.logger.debug('> ReturnAddress: %.8x, lpAddress: %.8x, dwSize: %.8x, flAllocationType: %.8x, flProtect: %.8x' % 
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
                        self.logger.debug('Allocating at %.8x' % base)
                        dw_size += (4096-dw_size%4096)
                        self.uc.mem_map(base, int(dw_size))
                        break
                    except:
                        traceback.print_exc(file = sys.stdout)
                    base += 0x10000

                self.ReturnFunction(self.uc, return_address, 4, base)
                
        elif name == 'ntdll!RtlDecompressBuffer':
            (return_address, compression_format, uncompressed_buffer, uncompressed_buffer_size, compressed_buffer, compressed_buffer_size, final_uncompressed_size) = self.GetStack(self.uc, 6)
            
            self.logger.debug('> ReturnAddress: %.8x, CompressionFormat: %.8x, UncompressedBuffer: %.8x, UncompressedBufferSize: %.8x, CompressedBuffer: %.8x, CompressedBufferSize: %.8x, FinalUncompressedSize: %.8x' % 
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
            bytes = self.uc.mem_read(compressed_buffer, compressed_buffer_size)
            fd = open('compressed.bin', 'wb')
            fd.write(bytes)
            fd.close()
            """
            self.uc.hook_add(UC_HOOK_CODE, self.CodeHookForDump, None, return_address, return_address+1)

        elif name == 'kernel32!GetFileSize':
            (return_address, hfile, lp_file_size_high) = self.GetStack(self.uc, 2)
            
            self.logger.debug('> hFile: %.8x, lpFileSizeHigh: %.8x' % 
                            (
                                hfile, 
                                lp_file_size_high
                            )
                        )
            
            #self.uc.hook_add(UC_HOOK_CODE, self.CodeHookForDump, None, return_address, return_address+1)
            self.ReturnFunction(self.uc, return_address, 2, 0x7bafe)

        #kernel32!CreateFileMappingA
        #kernel32!MapViewOfFile
        if code == '\x0f\x34': #sysenter
            asm = self.Disassemble(code, address)

            offset = 0
            for a in asm:
                self.logger.debug('%.8X: %s\t%s\t%s' % 
                                (
                                    a.address, 
                                    self.DumpHex(code[offset:offset+a.size]), 
                                    a.mnemonic, a.op_str
                                )
                            )
                offset += a.size
            
        self.LastCodeInfo = user_data

    def HookAPIExecution(self):
        for trace_module in self.TraceModules:
            (start, end) = self.Debugger.GetModuleRange(trace_module)
            self.logger.info("* HookAPIExecution %s (%x~%x)", trace_module, start, end)
            self.uc.hook_add(UC_HOOK_CODE, self.APIExecutionHook, trace_module, begin = start, end = end)

    def MemoryAccessCallback(self, uc, access, address, size, value, user_data):
        eip = self.uc.reg_read(UC_X86_REG_EIP)
        if access == UC_MEM_WRITE:
            self.logger.info("* %.8x: Memory Write 0x%.8x (Size:%.8u) <-- 0x%.8x" %
                            (
                                eip-self.CodeStart, 
                                address, 
                                size, 
                                value
                            )
                        )

        elif access == UC_MEM_READ:
            bytes = self.uc.mem_read(address, size)
            
            if size == 4:
                (value, ) = struct.unpack("<L", bytes)

            self.logger.info("* %.8x (%.8x + %.8x): Memory Read  0x%.8x (Size:%.8u) --> 0x%.8x" %
                            (
                                eip,
                                self.CodeStart,
                                eip-self.CodeStart, 
                                address, 
                                size, 
                                value
                            )
                        )
            self.DumpContext()

    def HookMemoryAccess(self, start, end):
            self.uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self.MemoryAccessCallback, start, end)

    def UnmappedMemoryAccessCallback(self, uc, access, address, size, value, user_data):
        ret = False
        if access == UC_MEM_WRITE_UNMAPPED:
            self.logger.debug("* Memory Write Fail: 0x%.8x (Size:%u) --> 0x%.8x " % (value, size, address))
        elif access == UC_MEM_READ_UNMAPPED or access == UC_MEM_FETCH_UNMAPPED:
            self.logger.debug("* Memory Read Fail: @0x%x (Size:%u)" % (address, size))
        return ret
        
    def HookUnmappedMemoryAccess(self):
        self.uc.hook_add(
                    UC_HOOK_MEM_READ_UNMAPPED |
                    UC_HOOK_MEM_WRITE_UNMAPPED | 
                    UC_HOOK_MEM_FETCH_UNMAPPED, 
                    self.UnmappedMemoryAccessCallback
                )

    def SetupStack(self):
        self.StackSize = 0x1000
        self.StackLimit = self.AllocateMemory(0x1000, self.StackSize)
        self.StackBase = self.StackLimit+self.StackSize
        self.logger.debug("* Setup stack at 0x%.8x ~ 0x%.8x" % (self.StackLimit, self.StackBase))

        self.uc.reg_write(UC_X86_REG_ESP, self.StackBase-0x100)
        self.uc.reg_write(UC_X86_REG_EBP, self.StackBase-0x100)

    def SetupTIB(self, tib_filename = 'tib.bin', fs_base = 0x0f4c000):
        if self.DumpFilename and not tib_filename:
            tib_filename = 'tib.dmp'
            pykd.dbgCommand(".writemem %s fs:0 L?0x1000" % tib_filename)

        if tib_filename:
            with open(tib_filename, 'rb') as fd:
                tib_bytes = fd.read()
                pe_structure = PEStructure(tib_bytes)
                self.WriteMem(fs_base, tib_bytes, debug = 0)
                self.logger.info("Writing TIB to 0x%.8x" % fs_base)
        else:
            self.TebAddr = 0
            self.PebAddr = 0
            pe_structure = PEStructure()
            tib_bytes = pe_structure.InitFS()
            fs_base = self.AllocateMemory(fs_base, len(fs_data))
            self.WriteMem(fs_base, tib_bytes, debug = 0)

    def OverwriteShellcodeOverEntry(self, shellcode):
        self.CodeLen = len(shellcode)
        self.CodeStart = self.Debugger.GetEntryPoint()
        self.logger.info("Writing shellcode to %x (len=%x)", self.CodeStart, self.CodeLen)
        self.WriteMem(self.CodeStart, shellcode, debug = 0)

    def TraceExecution(self, uc, address, size, user_data):
        self.DumpContext(dump_registers = True)

    def Run(self, trace_self_modification = False, fs_base = 0x0f4c000):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        gdt_layout = gdt.Layout(self.uc)
        gdt_layout.Setup(fs_base = fs_base)
        self.LoadProcessMemory()
        self.SetupStack()
        # self.SetupTIB(fs_base = fs_base)

        if self.ShellcodeBytes:
            shellcode_bytes = self.ShellcodeBytes
        else:
            with open(self.ShellcodeFilename, 'rb') as fd:
                shellcode_bytes = fd.read()

        if shellcode_bytes:
            self.OverwriteShellcodeOverEntry(shellcode_bytes)

        self.HookAPIExecution()
        """
        self.HookUnmappedMemoryAccess()

        self.SetupResolveAPIHook()
        self.HookMemoryAccess(self.CodeStart, self.CodeStart+self.CodeLen)
        if trace_self_modification:
            self.HookMemoryWrite(self.CodeStart, self.CodeStart+self.CodeLen)

        self.uc.hook_add(UC_HOOK_CODE, self.TraceExecution, None, self.CodeStart, self.CodeStart+self.CodeLen)
        """

        try:
            self.uc.emu_start(self.CodeStart, self.CodeStart+self.CodeLen)
        except:
            traceback.print_exc(file = sys.stdout)
            self.DumpContext()

    def DumpAL(self, uc, address, size, user_data):
        ch = self.uc.reg_read(UC_X86_REG_EAX) & 0xff
        if ch != 0x00:
            self.APIName += chr(ch)

    def DumpEBX(self, uc, address, size, user_data):
        self.logger.debug('%s\t%.8X' % (self.APIName, self.uc.reg_read(UC_X86_REG_EBX)))
        self.APIName = ''

    def SetupResolveAPIHook(self):
        self.APIName = ''
        start = self.CodeStart+0x001F1504-0x001F146D
        self.uc.hook_add(UC_HOOK_CODE, self.DumpAL, None, start, start+1)
        
        start = self.CodeStart+0x001F1516-0x001F146D
        self.uc.hook_add(UC_HOOK_CODE, self.DumpEBX, None, start, start+2)

if __name__ == '__main__':
    import logging
    from optparse import OptionParser, Option

    logging.basicConfig(level = logging.INFO)
    root = logging.getLogger()
    
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)

    formatter = logging.Formatter('%(message)s')
    ch.setFormatter(formatter)
    root.addHandler(ch)

    parser = OptionParser(usage = "usage: %prog [options] args")
    parser.add_option("-b", "--image_base", dest = "image_base", type = "string", default = "", metavar = "IMAGE_BASE", help = "Image base")
    parser.add_option("-d", "--dump_filename", dest = "dump_filename", type = "string", default = "", metavar = "DUMP_FILENAME", help = "")
    parser.add_option("-l", "--list_filename", dest = "list_filename", type = "string", default = "", metavar = "LIST_FILENAME", help = "")
    
    (options, args) = parser.parse_args(sys.argv)

    shellcode_filename = args[1]

    shellcode_bytes = ''
    if options.list_filename:
        parser = idatool.list.Parser(options.list_filename)
        parser.Parse()
        shellcode_bytes = ''
        for name in parser.GetNames():
            shellcode_bytes += parser.GetBytes(name)

    shell_emu = ShellEmu(shellcode_filename, shellcode_bytes = shellcode_bytes, dump_filename = options.dump_filename)
    shell_emu.Run(False)
