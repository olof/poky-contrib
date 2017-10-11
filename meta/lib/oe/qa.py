import os, struct, mmap
from oe.parsers.elf import Elf

class NotELFFileError(Exception):
    pass

class ELFFile:
    def __init__(self, name):
        self.name = name
        self.objdump_output = {}

    def open(self):
        try:
            self.elf = Elf.from_file(self.name)
        except Exception as e:
            raise NotELFFileError(str(e))

    def abiSize(self):
        if self.elf.bits == Elf.Bits.b32:
            return 32
        else:
            return 64

    def isLittleEndian(self):
        return self.elf.endian == Elf.Endian.le

    def isDynamic(self):
        for p in self.elf.header.program_headers:
            if p.type == Elf.PhType.interp:
                return True
        return False

    def machine(self):
        return self.elf.header.machine.value

    def run_objdump(self, cmd, d):
        import bb.process
        import sys

        if cmd in self.objdump_output:
            return self.objdump_output[cmd]

        objdump = d.getVar('OBJDUMP')

        env = os.environ.copy()
        env["LC_ALL"] = "C"
        env["PATH"] = d.getVar('PATH')

        try:
            bb.note("%s %s %s" % (objdump, cmd, self.name))
            self.objdump_output[cmd] = bb.process.run([objdump, cmd, self.name], env=env, shell=False)[0]
            return self.objdump_output[cmd]
        except Exception as e:
            bb.note("%s %s %s failed: %s" % (objdump, cmd, self.name, e))
            return ""

def elf_machine_to_string(machine):
    """
    Return the name of a given ELF e_machine field or the hex value as a string
    if it isn't recognised.
    """
    try:
        return {
            Elf.Machine.sparc.value: "SPARC",
            Elf.Machine.x86.value: "x86",
            Elf.Machine.mips.value: "MIPS",
            Elf.Machine.powerpc.value: "PowerPC",
            Elf.Machine.arm.value: "ARM",
            Elf.Machine.superh.value: "SuperH",
            Elf.Machine.ia_64.value: "IA-64",
            Elf.Machine.x86_64.value: "x86-64",
            Elf.Machine.aarch64.value: "AArch64"
        }[machine]
    except KeyError:
        return "Unknown (%s)" % repr(machine)
