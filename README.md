# Windows shellcode emulation tool based upon [unicorn framework](https://www.unicorn-engine.org/).

ShellcodeEmulator emulates shellcode with the help of windbg process memory dumps. You can provide process memory dump as a input with shellcode to analyze, it will emulate as much as the userland layer just above kernel calls. You can add your custom syscall handlers or any handlers in between the API calls used by shellcode and the kernel layer.

## Installation

```
pip install git+https://github.com/ohjeongwook/ShellcodeEmulator --upgrade
```
