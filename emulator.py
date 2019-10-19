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
import pe
import memory
import instruction
import register
import api

logger = logging.getLogger(__name__)

class Emulator:
    def __init__(self):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        self.Instruction = instruction.Tool(self)
        self.Memory = memory.Tool(self)
        self.Register = register.Tool(self)

    def AddHook(self, hook_type, callback, arg, start, end):
        self.uc.hook_add(hook_type, callback, arg, start, end)

    def Start(self, start, end):
        self.uc.emu_start(start, end)

class ShellEmu:
    def __init__(self, shellcode_filename, shellcode_bytes = '', dump_filename = ''):
        self.ShellcodeFilename = shellcode_filename
        self.ShellcodeBytes = shellcode_bytes
        self.DumpFilename = dump_filename
        self.ExhaustiveLoopDumpFrequency = 0x10000
        self.HitMap = {}            
        self.LastCodeAddress = 0
        self.LastCodeSize = 0

        self.Emulator = Emulator()
        
        #self.Conn = sqlite3.connect("Emulator.db", check_same_thread = False)
        #self.Cursor = self.Conn.cursor()
        #self.Cursor.execute('''CREATE TABLE CodeExecution (address int)''') 

    def InstructionCallback(self, uc, address, size, user_data):
        self.Emulator.Instruction.DumpContext()
        #self.Cursor.execute("INSERT INTO CodeExecution VALUES (%d)" % address)
        #self.Conn.commit()

        if not address in self.HitMap:
            self.HitMap[address] = 1
        else:
            self.HitMap[address] += 1
            
            if self.HitMap[address]%self.ExhaustiveLoopDumpFrequency == 0:
                print('Exhaustive Loop found: %x' % (self.HitMap[address]))
                self.Emulator.Instruction.DumpContext()
                print('')
                pass

        self.LastCodeAddress = address
        self.LastCodeSize = size

    def LoadProcessMemory(self):
        self.Debugger = windbgtool.debugger.DbgEngine()
        self.Debugger.LoadDump(self.DumpFilename)
        self.Debugger.SetSymbolPath()
        self.Debugger.EnumerateModules()
        self.Emulator.Instruction.SetDebugger(self.Debugger)
        
        for address in self.Debugger.GetAddressList():
            if address['State'] in ('MEM_FREE', 'MEM_RESERVE') or address['Usage'] == 'Free':
                continue

            logger.debug("Mapping %.8x ~ %.8x (size: %.8x) - %s %s" % (
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
                
                logger.debug('\tStack: 0x%.8x ~ 0x%.8x (0x%.8x)' % (self.StackLimit, self.StackBase, self.StackSize))

                self.Emulator.Register.Write("esp", address['BaseAddr']+address['RgnSize']-0x100)
                self.Emulator.Register.Write("ebp", address['BaseAddr']+address['RgnSize']-0x100)        
            if self.DumpFilename:
                tmp_dmp_filename = 'tmp.dmp'
                try:
                    pykd.dbgCommand(".writemem %s %x L?%x" % (tmp_dmp_filename, address['BaseAddr'], address['RgnSize']))
                except:
                    logger.debug("* Writemem failed")
                    traceback.print_exc(file = sys.stdout)
                self.Emulator.Memory.ReadMemoryFile(tmp_dmp_filename, address['BaseAddr'], size = address['RgnSize'], fixed_allocation = True)
            else:
                self.Emulator.Memory.Map(address['BaseAddr'], address['RgnSize'])

                try:
                    bytes_list = pykd.loadBytes(address['BaseAddr'], address['RgnSize'])
                except:
                    logger.debug("* loadBytes failed")
                    traceback.print_exc(file = sys.stdout)
                    continue

                bytes = ''
                for n in bytes_list:
                    bytes += chr(n)

                self.Emulator.Memory.WriteMem(address['BaseAddr'], bytes, debug = debug)
                
            self.LastCodeInfo = {}

    def UnmappedMemoryAccessCallback(self, uc, access, address, size, value, user_data):
        ret = False
        if access == UC_MEM_WRITE_UNMAPPED:
            logger.debug("* Memory Write Fail: 0x%.8x (Size:%u) --> 0x%.8x " % (value, size, address))
        elif access == UC_MEM_READ_UNMAPPED or access == UC_MEM_FETCH_UNMAPPED:
            logger.debug("* Memory Read Fail: @0x%x (Size:%u)" % (address, size))
        return ret
        
    def HookUnmappedMemoryAccess(self):
        self.Emulator.AddHook(
                    UC_HOOK_MEM_READ_UNMAPPED |
                    UC_HOOK_MEM_WRITE_UNMAPPED | 
                    UC_HOOK_MEM_FETCH_UNMAPPED, 
                    self.UnmappedMemoryAccessCallback
                )

    def SetupStack(self):
        self.StackSize = 0x1000
        self.StackLimit = self.Emulator.Memory.Map(0x1000, self.StackSize)
        self.StackBase = self.StackLimit+self.StackSize
        logger.debug("* Setup stack at 0x%.8x ~ 0x%.8x" % (self.StackLimit, self.StackBase))

        self.Emulator.Register.Write("esp", self.StackBase-0x100)
        self.Emulator.Register.Write("esp", self.StackBase-0x100)

    def LoadTib(self, tib_filename = 'tib.bin', fs_base = 0x0f4c000):
        if self.DumpFilename and not tib_filename:
            tib_filename = 'tib.dmp'
            pykd.dbgCommand(".writemem %s fs:0 L?0x1000" % tib_filename)

        if tib_filename:
            with open(tib_filename, 'rb') as fd:
                tib_bytes = fd.read()
                self.TIB = pe.PEStructure(tib_bytes)
                self.Emulator.Memory.WriteMem(fs_base, tib_bytes, debug = 0)
                logger.info("Writing TIB to 0x%.8x" % fs_base)
        else:
            self.TebAddr = 0
            self.PebAddr = 0
            self.TIB = pe.PEStructure()
            tib_bytes = self.TIB.InitFS()
            fs_base = self.Emulator.Memory.Map(fs_base, len(fs_data))
            self.Emulator.Memory.WriteMem(fs_base, tib_bytes, debug = 0)

    def Run(self, trace_self_modification = False, fs_base = 0x0f4c000, print_first_instructions = False):
        gdt_layout = gdt.Layout(self.Emulator)
        gdt_layout.Setup(fs_base = fs_base)
        self.LoadProcessMemory()

        if self.ShellcodeBytes:
            shellcode_bytes = self.ShellcodeBytes
        else:
            with open(self.ShellcodeFilename, 'rb') as fd:
                shellcode_bytes = fd.read()

        if shellcode_bytes:
            self.CodeLen = len(shellcode_bytes)
            self.CodeStart = self.Debugger.GetEntryPoint()
            logger.info("Writing shellcode to %x (len=%x)", self.CodeStart, self.CodeLen)
            self.Emulator.Memory.WriteMem(self.CodeStart, shellcode_bytes, debug = 0)            

        if trace_self_modification:
            self.Emulator.Memory.HookMemoryWrite(self.CodeStart, self.CodeStart+self.CodeLen)

        if print_first_instructions:
            self.Emulator.AddHook(UC_HOOK_CODE, self.InstructionCallback, None, self.CodeStart, self.CodeStart+5)

        api_hook = api.Hook(self.Emulator, self.Debugger)
        api_hook.Start()

        self.Emulator.Instruction.SetCodeRange(self.CodeStart, self.CodeStart+self.CodeLen)
        try:
            self.Emulator.Start(self.CodeStart, self.CodeStart+self.CodeLen)
        except:
            traceback.print_exc(file = sys.stdout)
            self.Emulator.Instruction.DumpContext()

if __name__ == '__main__':
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
    shell_emu.Run(trace_self_modification = True, print_first_instructions = True)
