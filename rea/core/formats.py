"""Binary format detection and light-weight file type identification.

Everything here is implemented with the standard library so REA runs on a bare
Python install with no network access.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

MAGIC = {
    b"\x7fELF": ("elf", "ELF executable / object"),
    b"MZ": ("pe", "DOS / PE executable"),
    b"\xca\xfe\xba\xbe": ("macho", "Mach-O (fat) binary"),
    b"\xcf\xfa\xed\xfe": ("macho", "Mach-O 64-bit little endian"),
    b"\xce\xfa\xed\xfe": ("macho", "Mach-O 32-bit little endian"),
    b"\xfe\xed\xfa\xcf": ("macho", "Mach-O 64-bit big endian"),
    b"\xfe\xed\xfa\xce": ("macho", "Mach-O 32-bit big endian"),
    b"PK\x03\x04": ("zip", "ZIP / JAR / APK / Office document"),
    b"\x1f\x8b": ("gzip", "gzip compressed data"),
    b"BZh": ("bzip2", "bzip2 compressed data"),
    b"\xfd7zXZ\x00": ("xz", "XZ compressed data"),
    b"7z\xbc\xaf\x27\x1c": ("7z", "7-Zip archive"),
    b"Rar!\x1a\x07": ("rar", "RAR archive"),
    b"%PDF": ("pdf", "PDF document"),
    b"\x89PNG\r\n\x1a\n": ("png", "PNG image"),
    b"\xff\xd8\xff": ("jpeg", "JPEG image"),
    b"GIF8": ("gif", "GIF image"),
    b"\xd0\xcf\x11\xe0": ("ole", "OLE2 / legacy Office document"),
    b"dex\n": ("dex", "Android Dalvik executable"),
    b"\x00asm": ("wasm", "WebAssembly module"),
    b"#!": ("script", "Script with shebang"),
    b"<?php": ("script", "PHP script"),
    b"\x1bLua": ("lua", "Lua bytecode"),
}

# Extensions that hint at interpreted content when there is no magic match.
SCRIPT_EXT = {
    ".py": "Python script",
    ".sh": "Shell script",
    ".ps1": "PowerShell script",
    ".js": "JavaScript",
    ".php": "PHP script",
    ".pl": "Perl script",
    ".rb": "Ruby script",
    ".bat": "Windows batch file",
    ".vbs": "VBScript",
    ".hta": "HTML application",
}

ARCH_MAP_ELF = {
    0x03: "x86",
    0x3E: "x86-64",
    0x28: "ARM",
    0xB7: "AArch64",
    0x08: "MIPS",
    0x14: "PowerPC",
    0xF3: "RISC-V",
}

ARCH_MAP_MACHO = {
    7: "x86",
    0x01000007: "x86-64",
    12: "ARM",
    0x0100000C: "AArch64",
}


@dataclass
class FileType:
    """Result of sniffing a file's container format."""

    kind: str
    description: str
    arch: Optional[str] = None
    bits: Optional[int] = None
    endian: Optional[str] = None
    is_executable: bool = False

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "description": self.description,
            "arch": self.arch,
            "bits": self.bits,
            "endian": self.endian,
            "is_executable": self.is_executable,
        }


def detect(data: bytes, filename: str = "") -> FileType:
    """Identify a file's format from its leading bytes, falling back to name."""
    for magic, (kind, desc) in MAGIC.items():
        if data.startswith(magic):
            ft = FileType(kind=kind, description=desc, is_executable=kind in {"elf", "pe", "macho", "dex"})
            if kind == "elf":
                _refine_elf(ft, data)
            elif kind == "pe":
                _refine_pe(ft, data)
            elif kind == "macho":
                _refine_macho(ft, data)
            return ft

    ext = os.path.splitext(filename)[1].lower()
    if ext in SCRIPT_EXT:
        return FileType(kind="script", description=SCRIPT_EXT[ext], is_executable=True)

    if data and all(b in b"\t\n\r\f\b\x1b" or 32 <= b < 127 for b in data[:4096]):
        return FileType(kind="text", description="ASCII / UTF-8 text")

    return FileType(kind="data", description="unknown binary data")


def _refine_elf(ft: FileType, data: bytes) -> None:
    if len(data) < 20:
        return
    ft.bits = 64 if data[4] == 2 else 32
    ft.endian = "little" if data[5] == 1 else "big"
    ft.arch = ARCH_MAP_ELF.get(data[18])
    e_type = int.from_bytes(data[16:18], "little" if data[5] == 1 else "big")
    ft.is_executable = e_type in (2, 3)  # ET_EXEC / ET_DYN
    if e_type == 1:
        ft.description = "ELF relocatable object"
    elif e_type == 3:
        ft.description = "ELF shared object / PIE"


def _refine_pe(ft: FileType, data: bytes) -> None:
    if len(data) < 0x40:
        return
    try:
        e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
        if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            ft.description = "MZ / DOS executable (no PE header)"
            ft.is_executable = True
            return
        machine = int.from_bytes(data[e_lfanew + 4 : e_lfanew + 6], "little")
        ft.arch = {0x14C: "x86", 0x8664: "x86-64", 0x1C0: "ARM", 0xAA64: "AArch64"}.get(machine, f"machine 0x{machine:x}")
        ft.bits = 64 if machine in (0x8664, 0xAA64) else 32
        ft.endian = "little"
        characteristics = int.from_bytes(data[e_lfanew + 22 : e_lfanew + 24], "little")
        ft.description = "PE DLL" if characteristics & 0x2000 else "PE executable"
        ft.is_executable = True
    except Exception:
        ft.description = "MZ / DOS executable (malformed PE header)"
        ft.is_executable = True


def _refine_macho(ft: FileType, data: bytes) -> None:
    if len(data) < 8:
        return
    magic = int.from_bytes(data[:4], "big")
    if magic == 0xCAFEBABE:
        ft.description = "Mach-O universal (fat) binary"
        ft.is_executable = True
        return
    cputype = int.from_bytes(data[4:8], "little")
    ft.arch = ARCH_MAP_MACHO.get(cputype)
    ft.bits = 64 if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf") else 32
    ft.endian = "little" if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe") else "big"
    ft.is_executable = True
