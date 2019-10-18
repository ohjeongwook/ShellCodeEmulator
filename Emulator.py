import os
import sys

import struct
import traceback
import logging
import sqlite3

from unicorn import *
from unicorn.x86_const import *
from capstone import *
from pykd import *
import pykd

import windbgtool.debugger
import util.common
import idatool.list

upck32 = lambda x: struct.unpack('I', x)[0]
pck32 = lambda x: struct.pack('I', x)

class PE:
    def init_ldr(seft, FLoad, Bload, FMem, BMem, FInit, BInit, DllBase, EntryPoint, DllName, addrofnamedll):
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
        
    def DumpFS(self,data):
        unpacked_entries=struct.unpack('I'*13, data[0:4*13])
        
        entry={
            'StackBase': unpacked_entries[1],
            'StackLimit': unpacked_entries[2],
            'TEB': unpacked_entries[11],
            'PEB': unpacked_entries[12]            
        }
        
        return entry

class ShellEmu:
    Debug=1
    TraceModules=['ntdll', 'kernel32', 'kernelbase']
    #TraceModules=['ntdll']
    TraceSelfModification=False

    def __init__(self):
        self.logger=logging.getLogger(__name__)

        self.DmpFilename=''
        self.ExhaustiveLoopDumpFrequency=0x10000
        self.HitMap={}            
        self.LastCodeAddress=0
        self.LastCodeSize=0
        self.Conn = sqlite3.connect("Emulator.db", check_same_thread=False)
        self.Cursor = self.Conn.cursor()
        #self.Cursor.execute('''CREATE TABLE CodeExecution (address int)''')
        
    def Disassemble(self,code,address):
        md=Cs(CS_ARCH_X86,CS_MODE_32)
        assem=md.disasm(str(code),address)
        return assem
        
    def DumpDisasm(self,address,size):
        try:
            code=self.uc.mem_read(address,size)
            asm=self.Disassemble(code,address)
            
            offset=0
            for a in asm:
                code_offset=0
                if self.CodeStart<=a.address and a.address<=self.CodeStart+self.CodeLen:
                    code_offset=a.address-self.CodeStart
                    
                if code_offset>0:
                    address_str='+%.8X: ' % (code_offset)
                else:
                    address_str=' %.8X: ' % (a.address)
                self.logger.debug('%s%s\t%s\t%s' % (address_str, self.DumpHex(code[offset:offset+a.size]), a.mnemonic, a.op_str))

                offset+=a.size
                break            
        except:
            traceback.print_exc(file=sys.stdout)
        
    def DumpRegisters(self):
        self.logger.debug('eax: %.8X ebx: %.8X ecx: %.8X edx: %.8X' % (
                            self.uc.reg_read(UC_X86_REG_EAX),
                            self.uc.reg_read(UC_X86_REG_EBX),
                            self.uc.reg_read(UC_X86_REG_ECX),
                            self.uc.reg_read(UC_X86_REG_EDX)
                        )
                    )
                        
        self.logger.debug('esp: %.8X ebp: %.8X esi: %.8X edi: %.8X' % (
                            self.uc.reg_read(UC_X86_REG_ESP),
                            self.uc.reg_read(UC_X86_REG_EBP),
                            self.uc.reg_read(UC_X86_REG_ESI),
                            self.uc.reg_read(UC_X86_REG_EDI)
                        )
                    )
                        
        self.logger.debug('eip: %.8X' % (
                            self.uc.reg_read(UC_X86_REG_EIP)
                        )
                    )

        self.logger.debug(' fs: %.8X  cs: %.8X  ds: %.8X  es: %.8X' % (
                            self.uc.reg_read(UC_X86_REG_FS),
                            self.uc.reg_read(UC_X86_REG_CS),
                            self.uc.reg_read(UC_X86_REG_DS),
                            self.uc.reg_read(UC_X86_REG_ES)
                        )
                    )

    def DumpHex(self,bytes):
        line=''
        count=0
        for ch in bytes:
            if isinstance(ch, basestring):
                ch=ord(ch)
            line+='%.2x ' % ch
            if count%0x10==0xf:
                line+='\n'
            count+=1
            
        return line
    
    def DumpCurrentStatus(self):
        self.DumpDisasm(self.uc.reg_read(UC_X86_REG_EIP),10)
        self.DumpRegisters()
        
        if self.LastCodeAddress>0 and self.Debug>2:
            self.logger.debug('> Last EIP before this:')
            self.DumpDisasm(self.LastCodeAddress, self.LastCodeSize)

    def CodeHookForDump(self, uc, address, size, user_data):
        self.DumpCurrentStatus(self.uc)
        print('')
        
    def HookKernel32Code(self, uc, address, size, user_data):
        print('Calling %x' % (address))
            
    def MemoryWriteHook(self, uc, access, address, size, value, user_data):
        if access==UC_MEM_WRITE:
            eip=self.uc.reg_read(UC_X86_REG_EIP)
            logger.debug("* %.8x: Memory Write 0x%.8x (Size:%.8u) <-- 0x%.8x" %(eip-self.CodeStart, address, size, value))
            self.DumpCurrentStatus()

    def HookMemoryWrite(self,start,end):
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
            self.DumpCurrentStatus()
            self.logger.debug("")

        #self.Cursor.execute("INSERT INTO CodeExecution VALUES (%d)" % address)
        #self.Conn.commit()

        if not self.HitMap.has_key(address):
            self.HitMap[address]=1
        else:
            self.HitMap[address]+=1
            
            if self.HitMap[address]%self.ExhaustiveLoopDumpFrequency==0:
                print('Exhaustive Loop found: %x' % (self.HitMap[address]))
                self.DumpCurrentStatus()
                print('')
                pass

        self.LastCodeAddress=address
        self.LastCodeSize=size

    def HookCodeExecution(self,start,end,hook_func,args=None):
        self.uc.hook_add(
                    UC_HOOK_CODE, 
                    hook_func,
                    args,
                    start, 
                    end
                )
        
    def ReadUnicodeString(self,uc,address):
        (length,maximum_length,buffer)=struct.unpack("<HHL", self.uc.mem_read(address,8))
        if self.Debug>0:
            print('UNICODE_STRING: %.4x %.4x %.8x' % (length,maximum_length,buffer))
        pwstr=self.uc.mem_read(buffer,length)
        
        ret=''
        for i in range(0,len(pwstr),2):
            ret+=chr(pwstr[i])
        return ret

    def ReadString(self,uc,address): 
        null_found=False
        ret=''
        offset=0
        chunk_len=0x100
        while 1:
            for ch in self.uc.mem_read(address+offset,chunk_len):
                if ch==0x00:
                    null_found=True
                    break
                ret+=chr(ch)

            if null_found:
                break
                
            offset+=chunk_len
            
        return ret

    def GetStack(self,uc,arg_count):
        esp=self.uc.reg_read(UC_X86_REG_ESP)
        ret=struct.unpack("<"+"L"*(arg_count+1), self.uc.mem_read(esp,4*(1+arg_count)))    
        return ret

    def ReturnFunction(self,uc,return_address,arg_count,return_value):
        print('Return Address: %x' % (return_address))
        self.uc.reg_write(UC_X86_REG_EIP, return_address)

        esp=self.uc.reg_read(UC_X86_REG_ESP)
        print('New ESP: %x' % (esp+4*(arg_count+1)))
        self.uc.reg_write(UC_X86_REG_ESP, esp+4*(arg_count+1))        
        self.uc.reg_write(UC_X86_REG_EAX, return_value)

    def WriteCurrentCode(self,filename):
        fd=open(filename,'wb')            
        bytes=self.uc.mem_read(self.CodeStart,self.CodeLen)
        fd.write(bytes)
        fd.close()

    def WriteUintMem(self,uc,ptr,data):
        return self.WriteMem(ptr,struct.pack("<L", data))
        
    def WriteMem(self,ptr,data, debug=1):
        if self.Debug>0 and debug>0:
            hex_dump=self.DumpHex(data)
            
            if len(hex_dump)>0x10*3:
                logger.debug('* WriteMem: %x - \n%s' % (ptr, self.DumpHex(data)))
            else:
                logger.debug('* WriteMem: %x - %s' % (ptr, self.DumpHex(data)))

        self.uc.mem_write(ptr,data)
        
    def AllocateMemory(self,base,size):        
        while base<0x100000000:
            try:
                self.uc.mem_map(base, size)
                break
            except:
                pass
            base+=0x1000
            
        return base

    def ReadMemoryFile(self,filename,base,size=0,fixed_allocation=False):
        fd=open(filename,'rb')
        if size>0:
            data=fd.read(size)
        else:
            data=fd.read()
            size=len(data)
        fd.close()

        if self.Debug>2:
            self.logger.debug('* ReadMemoryFile: %.8x (size: %.8x)' % (base, len(data)))
        
        try:
            if self.Debug>2:
                self.logger.debug(' > self.uc.mem_map(base=%.8x, size=%.8x)' % (base, size))

            if fixed_allocation:
                self.uc.mem_map(base, size)
            else:            
                base=self.AllocateMemory(base,size)
            
            if self.Debug>2:
                self.logger.debug(' > WriteMem(base=%.8x, size=%.8x)' % (base, len(data)))
            self.WriteMem(base, data, debug=0)
        except:
            self.logger.debug('* Error in memory mapping: %.8x (size: %.8x)' % (base, len(data)))
            traceback.print_exc(file=sys.stdout)
            return (base,size)

        return (base,size)

    def LoadProcessMemory(self):
        for address in self.Debugger.GetAddressList():
            if address['State'] in ('MEM_FREE','MEM_RESERVE') or address['Usage']=='Free':
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
                self.StackLimit=address['BaseAddr']
                self.StackSize=address['RgnSize']
                self.StackBase=address['BaseAddr']+address['RgnSize']
                
                self.logger.debug('\tStack: 0x%.8x ~ 0x%.8x (0x%.8x)' % (self.StackLimit, self.StackBase, self.StackSize))

                self.uc.reg_write(UC_X86_REG_ESP, address['BaseAddr']+address['RgnSize']-0x100)
                self.uc.reg_write(UC_X86_REG_EBP, address['BaseAddr']+address['RgnSize']-0x100)
        
            if self.DmpFilename:
                tmp_dmp_filename='tmp.dmp'
                try:
                    dbgCommand(".writemem %s %x L?%x" % (tmp_dmp_filename, address['BaseAddr'], address['RgnSize']))
                except:
                    self.logger.debug("* Writemem failed")
                    traceback.print_exc(file=sys.stdout)

                try:
                    (addr,size)=self.ReadMemoryFile(tmp_dmp_filename, address['BaseAddr'], size=address['RgnSize'], fixed_allocation=True)
                except:
                    self.logger.debug("* ReadMemoryFile failed")
                    traceback.print_exc(file=sys.stdout)
            else:
                self.uc.mem_map(address['BaseAddr'], address['RgnSize'])

                try:
                    bytes_list=loadBytes(address['BaseAddr'], address['RgnSize'])
                except:
                    self.logger.debug("* loadBytes failed")
                    traceback.print_exc(file=sys.stdout)
                    continue
                
                bytes=''
                for n in bytes_list:
                    bytes+=chr(n)
                self.WriteMem(address['BaseAddr'], bytes, debug=debug)
                
            if debug>2:
                self.uc.hook_add(
                                UC_HOOK_MEM_READ, 
                                self.HookMemoryRead, 
                                address['Comment'], 
                                address['BaseAddr'], 
                                address['BaseAddr']+address['RgnSize']
                            )

            self.LastCodeInfo={}

    def APIExecutionHook(self, uc, address, size, user_data):
        code=self.uc.mem_read(address,size)
        name=self.PyKD.ResolveSymbol(address)        

        name_str=''
        if name:
            name_str=' (%s)' % name

        self.logger.debug('APIExecutionHook: %.8x%s' % (address, name_str))
        self.DumpDisasm(address,size)
        return

        if name=='ntdll!LdrLoadDll':
            try:
                (return_address, path_to_file, flags, module_filename_addr, module_handle_out_ptr)=self.GetStack(self.uc, 4)
                if self.Debug>0:
                    self.logger.debug('PathToFile: %.8x Flags: %.8x ModuleFilename: %.8x ModuleHandle: %.8x' % 
                                    (
                                        path_to_file,
                                        flags,
                                        module_filename_addr,
                                        module_handle_out_ptr
                                    )
                                )

                module_filename=self.ReadUnicodeString(self.uc,module_filename_addr)
                self.logger.debug('Module Filename:', module_filename)

                module_base=self.Debugger.GetModuleBase(module_filename)
                
                if not module_base:
                    module_base=self.Debugger.GetModuleBase(module_filename.split('.')[0])
                    
                if module_base:                        
                    self.logger.debug('Write Module Base: %.8x --> %.8x' % 
                                    (
                                        module_base,
                                        module_handle_out_ptr
                                    )
                                )
                    self.WriteUintMem(self.uc,module_handle_out_ptr,module_base)
                    self.ReturnFunction(self.uc,return_address,4,1)
            except:
                traceback.print_exc(file=sys.stdout)

        elif name=='kernel32!GetProcAddress':
            (return_address, module_handle, proc_name_ptr)=self.GetStack(self.uc, 2)
            self.logger.debug("\tReturnAddress: %.8x, ModuleHandle: %.8x, ProcName: %.8x" % 
                            (
                                return_address, 
                                module_handle, 
                                proc_name_ptr
                            )
                        )
            
            module_name=self.Debugger.GetModuleNameFromBase(module_handle)
            proc_name=self.ReadString(self.uc,proc_name_ptr)
            symbol="%s!%s" % (module_name,proc_name)
            
            self.logger.debug('\tSymbol: %s' % symbol)
            address=self.GetSymbolAddress(symbol)
            self.logger.debug('\tAddress: %x' % (address))
            self.uc.reg_write(UC_X86_REG_EAX, address)
            self.ReturnFunction(self.uc,return_address,2,address)
            
        elif name=='kernel32!LoadLibraryA':
            (return_address, filename_ptr)=self.GetStack(self.uc, 1)
            filename=self.ReadString(self.uc,filename_ptr)
            self.logger.debug('\tLoadLibraryA Filename:%s' % filename)

        elif name=='kernel32!VirtualAlloc' or name=='KERNELBASE!VirtualAlloc':
            (return_address, lp_address, dw_size, fl_allocation_type, fl_protect)=self.GetStack(self.uc, 4)
        
            self.logger.debug('> ReturnAddress: %.8x, lpAddress: %.8x, dwSize: %.8x, flAllocationType: %.8x, flProtect: %.8x' % 
                            (
                                return_address, 
                                lp_address, 
                                dw_size, 
                                fl_allocation_type, 
                                fl_protect
                            )
                        )
            
            if lp_address==0:
                start_address=0x70000
                
                base=start_address
                
                while 1:
                    try:
                        self.logger.debug('Allocating at %.8x' % base)
                        dw_size+=(4096-dw_size%4096)
                        self.uc.mem_map(base, int(dw_size))
                        break
                    except:
                        traceback.print_exc(file=sys.stdout)
                    base+=0x10000

                self.ReturnFunction(self.uc,return_address,4,base)
                
        elif name=='ntdll!RtlDecompressBuffer':
            (return_address, compression_format, uncompressed_buffer, uncompressed_buffer_size, compressed_buffer, compressed_buffer_size, final_uncompressed_size)=self.GetStack(self.uc, 6)
            
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
            bytes=self.uc.mem_read(compressed_buffer, compressed_buffer_size)
            fd=open('compressed.bin','wb')
            fd.write(bytes)
            fd.close()
            """
            self.uc.hook_add(UC_HOOK_CODE, self.CodeHookForDump, None, return_address, return_address+1)

        elif name=='kernel32!GetFileSize':
            (return_address, hfile, lp_file_size_high)=self.GetStack(self.uc, 2)
            
            self.logger.debug('> hFile: %.8x, lpFileSizeHigh: %.8x' % 
                            (
                                hfile, 
                                lp_file_size_high
                            )
                        )
            
            #self.uc.hook_add(UC_HOOK_CODE, self.CodeHookForDump, None, return_address, return_address+1)
            self.ReturnFunction(self.uc,return_address,2,0x7bafe)

        #kernel32!CreateFileMappingA
        #kernel32!MapViewOfFile
        if code=='\x0f\x34': #sysenter
            asm=self.Disassemble(code,address)

            offset=0
            for a in asm:
                self.logger.debug('%.8X: %s\t%s\t%s' % 
                                (
                                    a.address, 
                                    self.DumpHex(code[offset:offset+a.size]), 
                                    a.mnemonic, a.op_str
                                )
                            )
                offset+=a.size
            
        self.LastCodeInfo=user_data

    def HookAPIExecution(self):
        for trace_module in self.TraceModules:
            (start,end)=self.Debugger.GetModuleRange(trace_module)
            self.logger.debug("* HookAPIExecution %s (%x~%x)", trace_module, start, end)
            self.uc.hook_add(
                            UC_HOOK_CODE, 
                            self.APIExecutionHook, 
                            trace_module, 
                            start, 
                            end
                        )

    def MemoryAccessHook(self, uc, access, address, size, value, user_data):
        eip=self.uc.reg_read(UC_X86_REG_EIP)
        if access==UC_MEM_WRITE:
            self.logger.debug("* %.8x: Memory Write 0x%.8x (Size:%.8u) <-- 0x%.8x" %
                            (
                                eip-self.CodeStart, 
                                address, 
                                size, 
                                value
                            )
                        )

        elif access==UC_MEM_READ:
            bytes=self.uc.mem_read(address,size)
            
            if size==4:
                (value,)=struct.unpack("<L", bytes)

            self.logger.debug("* %.8x: Memory Read  0x%.8x (Size:%.8u) --> 0x%.8x" %
                            (
                                eip-self.CodeStart, 
                                address, 
                                size, 
                                value
                            )
                        )

    def HookMemoryAccess(self,start,end):
            self.uc.hook_add(
                        UC_HOOK_MEM_READ | 
                        UC_HOOK_MEM_WRITE, 
                        self.MemoryAccessHook,
                        start,
                        end
                    )

    def UnmappedMemoryAccessHook(self, uc, access, address, size, value, user_data):
        ret=False
        if access == UC_MEM_WRITE_UNMAPPED:
            self.logger.debug("* Memory Write Fail: 0x%.8x (Size:%u) --> 0x%.8x " %
                            (
                                value,
                                size,
                                address
                            )
                        )

        elif access == UC_MEM_READ_UNMAPPED or access==UC_MEM_FETCH_UNMAPPED:
            self.logger.debug("* Memory Read Fail: @0x%x (Size:%u)" %
                            (
                                address,
                                size
                            )
                        )

        self.DumpCurrentStatus()
        return ret
        
    def HookUnmappedMemoryAccess(self):
        self.uc.hook_add(
                    UC_HOOK_MEM_READ_UNMAPPED |
                    UC_HOOK_MEM_WRITE_UNMAPPED | 
                    UC_HOOK_MEM_FETCH_UNMAPPED, 
                    self.UnmappedMemoryAccessHook
                )

    def SetupStack(self):
        self.StackSize=0x1000
        self.StackLimit=self.AllocateMemory(0x1000,self.StackSize)
        self.StackBase=self.StackLimit+self.StackSize
        self.logger.debug("* Setup stack at 0x%.8x ~ 0x%.8x" % (self.StackLimit, self.StackBase))

        self.uc.reg_write(UC_X86_REG_ESP,self.StackBase-0x100)
        self.uc.reg_write(UC_X86_REG_EBP,self.StackBase-0x100)

    def SetupTIB(self):
        if self.DmpFilename:
            tmp_dmp_filename='tib.dmp'
            dbgCommand(".writemem %s fs:0 L?0x1000" % tmp_dmp_filename)
            
            fd=open(tmp_dmp_filename,'rb')
            data=fd.read()
            fd.close()

            pe=PE()
            fs_entries=pe.DumpFS(data)
            self.logger.debug("FS: %.8x - %.8x" % (fs_entries['StackLimit'], fs_entries['StackBase']))
            
            (self.FS,size)=self.ReadMemoryFile(tmp_dmp_filename, 0)
            self.logger.debug("Writing TIB to 0x%.8x" % self.FS)
        else:
            self.TebAddr=0
            self.PebAddr=0
            pe=PE()
            fs_data=pe.InitFS()
            self.FS=self.AllocateMemory(0,len(fs_data))
            self.WriteMem(self.FS, fs_data, debug=0)

        self.uc.reg_write(UC_X86_REG_FS, self.FS)

    def OverwriteShellcodeOverEntryWithFile(self,filename):
        self.logger.debug("Writing shellcode to %x", self.CodeStart)

        fd=open(filename,'rb')
        shellcode=fd.read()
        fd.close()
        
        self.OverwriteShellcodeOverEntry(shellcode)

    def OverwriteShellcodeOverEntry(self,shellcode):
        self.CodeLen=len(shellcode)
        self.CodeStart=self.Debugger.GetEntryPoint()
        self.WriteMem(self.CodeStart, shellcode, debug=0)

    def Run(self,filename,dmp_filename='',debug=0):
        self.DmpFilename=dmp_filename
        
        if self.DmpFilename:
            self.Debugger=windbgtool.debugger.Debugger(dump_file=self.DmpFilename)
            self.Debugger.SetSymbolPath()
            self.Debugger.EnumerateModules()
            self.Debugger.LoadSymbols(self.TraceModules)

        self.uc=Uc(UC_ARCH_X86, UC_MODE_32)

        self.LoadProcessMemory()
        self.SetupStack()
        self.SetupTIB()

        if filename.lower().endswith('.txt'):
            parser=idatool.list.Parser(filename)
            parser.Parse()
            bytes=''
            for name in parser.GetNames():
                bytes+=parser.GetBytes(name)

            self.logger.debug(util.common.DumpHex(bytes))
            self.OverwriteShellcodeOverEntry(bytes)
        else:
            self.OverwriteShellcodeOverEntryWithFile(filename)

        self.HookAPIExecution()
        self.HookUnmappedMemoryAccess()
        #self.SetupResolveAPIHook()
        #self.HookMemoryAccess(self.CodeStart, self.CodeStart+self.CodeLen)
        #if self.TraceSelfModification:
        #    self.HookMemoryWrite(self.CodeStart, self.CodeStart+self.CodeLen)       
        #self.HookCodeExecution(self.CodeStart,self.CodeStart+self.CodeLen)

        self.uc.emu_start(self.CodeStart, self.CodeStart+self.CodeLen)

    def DumpAL(self, uc, address, size, user_data):
        ch=self.uc.reg_read(UC_X86_REG_EAX) & 0xff
        if ch!=0x00:
            self.APIName+=chr(ch)

    def DumpEBX(self, uc, address, size, user_data):
        self.logger.debug('%s\t%.8X' % (self.APIName, self.uc.reg_read(UC_X86_REG_EBX)))
        self.APIName=''

    def SetupResolveAPIHook(self):
        self.APIName=''
        start=self.CodeStart+0x001F1504-0x001F146D
        self.HookCodeExecution(start,start+1,self.DumpAL)
        
        start=self.CodeStart+0x001F1516-0x001F146D
        self.HookCodeExecution(start,start+2,self.DumpEBX)

if __name__=='__main__':
    import logging
    from optparse import OptionParser, Option

    logging.basicConfig(level=logging.DEBUG)
    root = logging.getLogger()
    
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)

    formatter = logging.Formatter('%(message)s')
    ch.setFormatter(formatter)
    root.addHandler(ch)

    parser=OptionParser(usage="usage: %prog [options] args")
    parser.add_option("-b","--image_base",dest="image_base",type="string",default="",metavar="IMAGE_BASE",help="Image base")
    parser.add_option("-d","--dmp_filename",dest="dmp_filename",type="string",default="",metavar="DMP_FILENAME",help="")
    
    (options,args)=parser.parse_args(sys.argv)

    shellcode_filename=args[1]

    shell_emu=ShellEmu()
    shell_emu.TraceSelfModification=False
    shell_emu.Run(shellcode_filename,options.dmp_filename)
