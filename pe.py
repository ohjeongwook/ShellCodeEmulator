import struct

upck32 = lambda x: struct.unpack('I', x)[0]
pck32 = lambda x: struct.pack('I', x)

class PEStructure:
    def __init__(self, tib_bytes = None, stack_base = 0, stack_limit = 0, fs = 0, teb_addr = 0, peb_addr = 0):
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
