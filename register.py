import os
import sys

import struct
import traceback
import logging
import capstone

from unicorn import *
from unicorn.x86_const import *

class Tool:
    def __init__(self, emulator):
        self.Emulator = emulator
        self.uc = emulator.uc

    def Write(self, register_name, value):
        if register_name == "esp":
            self.uc.reg_write(UC_X86_REG_ESP, value)
        elif register_name == "ebp":
            self.uc.reg_write(UC_X86_REG_EBP, value)

    def WriteReg(self, register, value):
        self.uc.reg_write(register, value)