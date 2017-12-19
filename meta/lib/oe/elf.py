"""
High level class representation of ELF files.
"""
import mmap
import sys
import bb.process
from oe.parsers.elf import Elf as ElfParser


class NotELFFileError(Exception):
    pass

def elf_machine_to_string(machine):
    """
    Return the name of a given ELF e_machine field or the hex value as a string
    if it isn't recognised.
    """
    try:
        return {
            ElfParser.Machine.sparc.value: "SPARC",
            ElfParser.Machine.x86.value: "x86",
            ElfParser.Machine.mips.value: "MIPS",
            ElfParser.Machine.powerpc.value: "PowerPC",
            ElfParser.Machine.arm.value: "ARM",
            ElfParser.Machine.superh.value: "SuperH",
            ElfParser.Machine.ia_64.value: "IA-64",
            ElfParser.Machine.x86_64.value: "x86-64",
            ElfParser.Machine.aarch64.value: "AArch64"
        }[machine]
    except KeyError:
        return "Unknown (%s)" % repr(machine)

def is_kernel_module(path):
    """
    Static function; returns True if the elf file given as argument looks
    like a kernel module. It tries to determine this by searching for
    "vermagic=" string and looking for a .ko filename extension.
    """
    if not path.endswith('.ko'):
        return False

    with open(path) as f:
        return mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ). \
                    find(b"vermagic=") >= 0

class Elf(object):
    def __init__(self, name, elf=None):
        """
        A class representing an ELF file. Takes a name argument for the
        filename. An optional elf argument can be provided, which should be
        an Elf object. If this is not provided, the filename specified by
        name is read and parsed instead.
        """
        self.name = name
        self.objdump_cache = {}
        try:
            self.elf = elf if elf else ElfParser.from_file(name)
        except Exception as e:
            raise NotELFFileError(str(e))

    def get_dict(self):
        """
        Serializable dump of attributes.
        """
        return {
            'name': self.name,
            'machine': self.machine,
            'endian': 'little' if self.is_little_endian() else 'big',
            'executable': self.is_executable(),
            'stripped': self.is_stripped(),
            'dynamic': self.is_dynamic(),
            'dyn_so': self.is_dyn_so(),
            'module': self.is_module(),
        }

    @staticmethod
    def is_elf(path):
        try:
            Elf(path)
        except NotELFFileError:
            return False
        return True

    @property
    def machine(self):
        """
        Name of the targetted machine.
        """
        return elf_machine_to_string(self.machine_id)

    @property
    def machine_id(self):
        """
        Numeric ID of the targetted machine.
        """
        return self.elf.header.machine.value

    @property
    def abi_size(self):
        """
        The ABI size, 32 or 64 bits.
        """
        if self.elf.bits == ElfParser.Bits.b32:
            return 32
        else:
            return 64

    def is_stripped(self):
        """
        True if the ELF file is stripped. A binary is stripped if it lacks
        both a progbits section called .debug_info and a symbol table section.
        (This logic was based on that of file-5.29.)
        """
        return len([
            x for x in self.elf.header.section_headers if
               x.type == ElfParser.ShType.symtab or \
               (x.type == ElfParser.ShType.progbits and x.name == '.debug_info')
        ]) == 0

    def is_executable(self):
        """
        True if the ELF file is executable.
        """
        return self.elf.header.e_type == ElfParser.ObjType.executable

    def is_module(self):
        """
        True if the ELF file is a kernel module.
        """
        return self.elf.header.e_type == ElfParser.ObjType.relocatable and \
               is_kernel_module(self.name)

    def is_dynamic(self):
        """
        True if the ELF file is dynamic.
        """
        return any([
            p.type == ElfParser.PhType.interp
            for p in self.elf.header.program_headers
        ])

    def is_dyn_so(self):
        """
        True if the ELF file is a dynamic shared object.
        """
        return self.name.endswith('.so') or '.so.' in self.name and \
               self.is_dynamic()

    def is_little_endian(self):
        """
        Returns true if ELF is little endian.
        """
        return self.elf.endian == ElfParser.Endian.le

    def is_big_endian(self):
        """
        Returns true if ELF is big endian.
        """
        return self.elf.endian == ElfParser.Endian.be

    def run_objdump(self, cmd, d):
        """
        Run objdump on the ELF file and return the output. Caches the output
        so that objdump only has to be executed once.
        """
        if cmd in self.objdump_cache:
            return self.objdump_cache[cmd]

        objdump = d.getVar('OBJDUMP')

        env = os.environ.copy()
        env["LC_ALL"] = "C"
        env["PATH"] = d.getVar('PATH')

        try:
            bb.note("%s %s %s" % (objdump, cmd, self.name))
            self.objdump_cache[cmd] = bb.process.run(
                [objdump, cmd, self.name],
                env=env,
                shell=False
            )[0]
            return self.objdump_cache[cmd]
        except Exception as e:
            bb.note("%s %s %s failed: %s" % (objdump, cmd, self.name, e))
            return ""
