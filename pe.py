import sys
import struct
import logging
import traceback

import gdt

upack32 = lambda x: struct.unpack('I', x)[0]
pack32 = lambda x: struct.pack('I', x)

logger = logging.getLogger(__name__)

class ProcessMemory:
    def __init__(self, emulator, tib_bytes = None, stack_base = 0, stack_limit = 0, fs = 0, teb_addr = 0, peb_addr = 0):
        self.Emulator = emulator
        self.StackBase = stack_base
        self.StackLimit = stack_limit
        self.FS = fs
        self.TebAddr = teb_addr
        self.PebAddr = peb_addr

        if tib_bytes:
            self.ParseTEB(tib_bytes)
        
    def ParseTEB(self, tib_bytes):
        unpacked_entries = struct.unpack('I'*13, tib_bytes[0:4*13])
        self.StackBase = unpacked_entries[1]
        self.StackLimit = unpacked_entries[2]
        self.TebAddr = unpacked_entries[11]
        self.PebAddr = unpacked_entries[12]

    def InitLDR(self, FLoad, Bload, FMem, BMem, FInit, BInit, DllBase, EntryPoint, DllName, addrofnamedll):
        # InOrder
        ldr = ''
        ldr += pack32(FLoad)  # flink
        ldr += pack32(Bload)  # blink
        # Inmem
        ldr += pack32(FMem)  # flink
        ldr += pack32(BMem)  # blink
        # InInit
        ldr += pack32(FInit)  # flink 0x10
        ldr += pack32(BInit)  # blink 0x14

        ldr += pack32(DllBase)  # baseOfdll 0x18
        ldr += pack32(EntryPoint)  # entryPoint 0x1c
        ldr += pack32(0x0)  # sizeOfImage 0x20
        ldr += pack32(0x0) * 2  # Fullname 0x28
        # basename
        ldr += pack32(0x0)  # 0x2c
        ldr += pack32(addrofnamedll)  # 0x30
        return ldr

    def InitTEB(seft, peb_address):
        teb = ''
        teb += pack32(0x0) * 7
        teb += pack32(0x0)  # EnvironmentPointer
        teb += pack32(0x0)  # ClientId
        teb += pack32(0x0)  # ThreadLocalStoragePointer
        teb += pack32(peb_address)  # ProcessEnvironmentBlock
        teb += pack32(0x0)  # LastErrorValue
        return teb

    def InitPEB(seft, image_base, peb_ldr_address):
        peb = ''
        peb += pack32(0x0) * 2  # InheritedAddressSpace
        peb += pack32(image_base)  # imageBaseAddress
        peb += pack32(peb_ldr_address)  # Ldr
        peb += pack32(0x0)  # process parameter
        return peb

    def InitPEBLDRData(self, ldr_address):
        peb_ldr_data = ''
        peb_ldr_data += pack32(0x0) * 3  # 0x8
        peb_ldr_data += pack32(ldr_address)  # 0x0c
        peb_ldr_data += pack32(ldr_address + 0x4)
        peb_ldr_data += pack32(ldr_address + 0x8)  # 0x14
        peb_ldr_data += pack32(ldr_address + 0xc)
        peb_ldr_data += pack32(ldr_address + 0x10)  # 0x1C
        peb_ldr_data += pack32(ldr_address + 0x14)
        return peb_ldr_data

    def InitTEB(self):
        fs_data = ''
        fs_data += pack32(0x0)  # 0x0
        fs_data += pack32(self.StackBase)  # 0x4
        fs_data += pack32(self.StackLimit)  # 0x8
        fs_data += pack32(0x0) * 3  # 0x14
        fs_data += pack32(self.FS)
        fs_data += pack32(0x0) * 4
        fs_data += pack32(self.TebAddr)
        fs_data += pack32(self.PebAddr)
        fs_data += pack32(0x0)
        return fs_data

    def SetupStack(self):
        self.StackSize = 0x1000
        self.StackLimit = self.Emulator.Memory.Map(0x1000, self.StackSize)
        self.StackBase = self.StackLimit+self.StackSize
        logger.debug("* Setup stack at 0x%.8x ~ 0x%.8x" % (self.StackLimit, self.StackBase))

        self.Emulator.Register.Write("esp", self.StackBase-0x100)
        self.Emulator.Register.Write("esp", self.StackBase-0x100)

    def LoadTib(self, tib_filename = 'tib.bin', fs_base = 0x0f4c000):
        if self.Emulator.Debugger and not tib_filename:
            tib_filename = 'tib.dmp'
            self.Emulator.Debugger.RunCmd(".writemem %s fs:0 L?0x1000" % tib_filename)

        if tib_filename:
            with open(tib_filename, 'rb') as fd:
                tib_bytes = fd.read()
                self.ParseTEB(tib_bytes)
                self.Emulator.Memory.WriteMem(fs_base, tib_bytes, debug = 0)
                logger.info("Writing TIB to 0x%.8x" % fs_base)
        else:
            self.TebAddr = 0
            self.PebAddr = 0
            tib_bytes = self.InitTEB()
            fs_base = self.Emulator.Memory.Map(fs_base, len(tib_bytes))
            self.Emulator.Memory.WriteMem(fs_base, tib_bytes, debug = 0)

    def LoadProcessMemory(self):
        self.Emulator.Debugger.SetSymbolPath()
        self.Emulator.Debugger.EnumerateModules()
        
        teb_list = []
        teb_bytes = []
        for address in self.Emulator.Debugger.GetAddressList():
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
                self.StackLimit = address['BaseAddr']
                self.StackSize = address['RgnSize']
                self.StackBase = address['BaseAddr']+address['RgnSize']
                
                logger.debug('\tStack: 0x%.8x ~ 0x%.8x (0x%.8x)' % (self.StackLimit, self.StackBase, self.StackSize))

                self.Emulator.Register.Write("esp", address['BaseAddr']+address['RgnSize']-0x1000)
                self.Emulator.Register.Write("ebp", address['BaseAddr']+address['RgnSize']-0x1000)

            if self.Emulator.Debugger:
                tmp_dmp_filename = 'tmp.dmp'
                try:
                    self.Emulator.Debugger.RunCmd(".writemem %s %x L?%x" % (tmp_dmp_filename, address['BaseAddr'], address['RgnSize']))
                except:
                    logger.debug("* Writemem failed")
                    traceback.print_exc(file = sys.stdout)

                self.Emulator.Memory.ReadMemoryFile(tmp_dmp_filename, address['BaseAddr'], size = address['RgnSize'], fixed_allocation = True)
                if address['Usage'] == 'TEB':
                    with open (tmp_dmp_filename, 'rb') as fd:
                        teb_bytes.append(fd.read())
            else:
                self.Emulator.Memory.Map(address['BaseAddr'], address['RgnSize'])

                try:
                    bytes_list = self.Emulator.Debugger.GetBytes(address['BaseAddr'], address['RgnSize'])
                except:
                    logger.debug("* loadBytes failed")
                    traceback.print_exc(file = sys.stdout)
                    continue

                bytes = ''
                for n in bytes_list:
                    bytes += chr(n)

                self.Emulator.Memory.WriteMem(address['BaseAddr'], bytes)

        if len(teb_list) > 0:
            gdt_layout = gdt.Layout(self.Emulator)
            if self.Emulator.Arch == 'x86':
                segment_limit = 0xffffffff
                logger.info("* Setting up fs: %x (len=%x)" % (teb_list[0]['BaseAddr'], teb_list[0]['RgnSize']))
                gdt_layout.Setup(fs_base = teb_list[0]['BaseAddr'], fs_limit = teb_list[0]['RgnSize'], segment_limit = segment_limit)
            elif self.Emulator.Arch == 'AMD64':
                segment_limit = 0xffffffffffffffff
                logger.info("* Setting up gs: %x (len=%x)" % (teb_list[0]['BaseAddr'], teb_list[0]['RgnSize']))
                gdt_layout.Setup(gs_base = teb_list[0]['BaseAddr'], gs_limit = teb_list[0]['RgnSize'], segment_limit = segment_limit)
                self.Emulator.Memory.Map(0, len(teb_bytes[0]))
                self.Emulator.Memory.WriteMem(0, teb_bytes[0]) #64bit hack to map TEB to 0 ~ 
