"""Mach-O parser (thin and universal/fat binaries).

Covers the load-command walk and the LC_SEGMENT(_64) section table, which is
enough for entropy-based triage of macOS samples.
"""

from __future__ import annotations

import struct
from typing import List

from ..core.hashing import entropy
from ..core.model import Artifact, Section

MH_MAGIC = 0xFEEDFACE
MH_CIGAM = 0xCEFAEDFE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA

LC_SEGMENT = 0x1
LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0xC
LC_LOAD_WEAK_DYLIB = 0x8000018
LC_ID_DYLIB = 0xD
LC_MAIN = 0x80000028
LC_SYMTAB = 0x2

CPU_TYPES = {
    7: "x86", 0x01000007: "x86-64", 12: "ARM", 0x0100000C: "AArch64",
    0x01000012: "PowerPC64", 18: "PowerPC",
}

FILE_TYPES = {
    0x1: "object", 0x2: "executable", 0x3: "fixed_vm_library", 0x4: "core",
    0x5: "preload", 0x6: "dylib", 0x7: "dylinker", 0x8: "bundle", 0x9: "dylib_stub",
    0xA: "dsym", 0xB: "kext_bundle",
}


def parse(art: Artifact, data: bytes) -> None:
    if len(data) < 8:
        art.errors.append("Mach-O: file too small")
        return
    magic_be = struct.unpack_from(">I", data, 0)[0]
    if magic_be in (FAT_MAGIC, FAT_CIGAM):
        _parse_fat(art, data, magic_be)
        return
    _parse_thin(art, data, 0, len(data), arch_hint=None)


def _parse_fat(art: Artifact, data: bytes, magic_be: int) -> None:
    endian = ">" if magic_be == FAT_MAGIC else "<"
    nfat = struct.unpack_from(endian + "I", data, 4)[0]
    archs = []
    for i in range(min(nfat, 32)):
        off = 8 + i * 20
        if off + 20 > len(data):
            break
        cputype, cpusub, fat_off, size = struct.unpack_from(endian + "iiII", data, off)
        archs.append({"cpu": CPU_TYPES.get(cputype & 0xFFFFFFFF, hex(cputype)), "offset": fat_off, "size": size})
    art.metadata["macho"] = {"fat": True, "architectures": archs}
    if archs:
        first = archs[0]
        _parse_thin(art, data[first["offset"] : first["offset"] + first["size"]], 0, first["size"], arch_hint=first["cpu"])
        art.metadata["macho"]["fat"] = True
        art.metadata["macho"]["architectures"] = archs


def _parse_thin(art: Artifact, data: bytes, base: int, limit: int, arch_hint) -> None:
    magic = struct.unpack_from("<I", data, base)[0]
    if magic in (MH_MAGIC, MH_MAGIC_64):
        endian = "<"
    elif magic in (MH_CIGAM, MH_CIGAM_64):
        endian = ">"
    else:
        art.errors.append(f"Mach-O: bad magic 0x{magic:08x}")
        return

    is64 = magic in (MH_MAGIC_64, MH_CIGAM_64)
    hdr_fmt = endian + ("IiiIIIII" if is64 else "IiiIIII")
    hdr_size = 32 if is64 else 28
    if base + hdr_size > len(data):
        art.errors.append("Mach-O: truncated header")
        return
    cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(hdr_fmt, data, base + 4)

    info = art.metadata.setdefault("macho", {})
    info.update(
        {
            "magic": hex(magic),
            "is_64bit": is64,
            "cpu": CPU_TYPES.get(cputype & 0xFFFFFFFF, hex(cputype)),
            "file_type": FILE_TYPES.get(filetype, str(filetype)),
            "ncmds": ncmds,
            "flags": hex(flags),
            "endianness": "little" if endian == "<" else "big",
        }
    )

    cmd_off = base + hdr_size
    end = min(base + limit, len(data))
    dylibs: List[str] = []
    entry_point = None

    for _ in range(ncmds):
        if cmd_off + 8 > end:
            break
        cmd, cmdsize = struct.unpack_from(endian + "II", data, cmd_off)
        if cmdsize < 8 or cmd_off + cmdsize > end:
            break

        if cmd in (LC_SEGMENT, LC_SEGMENT_64):
            _parse_segment(art, data, endian, cmd == LC_SEGMENT_64, cmd_off, base)
        elif cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_ID_DYLIB):
            name_off = struct.unpack_from(endian + "I", data, cmd_off + 8)[0]
            name = _read_lc_str(data, cmd_off + name_off, cmd_off + cmdsize)
            if name and cmd != LC_ID_DYLIB:
                dylibs.append(name)
            elif name:
                info["install_name"] = name
        elif cmd == LC_MAIN:
            entry_off = struct.unpack_from(endian + "Q", data, cmd_off + 8)[0]
            entry_point = entry_off
        elif cmd == LC_SYMTAB:
            info["has_symtab"] = True

        cmd_off += cmdsize

    info["dylibs"] = dylibs
    if entry_point is not None:
        info["entry_offset"] = entry_point
    info["section_count"] = len([s for s in art.sections if True])


def _parse_segment(art: Artifact, data: bytes, endian: str, is64: bool, cmd_off: int, base: int) -> None:
    if is64:
        segname = data[cmd_off + 8 : cmd_off + 24].rstrip(b"\x00").decode("utf-8", "replace")
        vmaddr, vmsize, fileoff, filesize = struct.unpack_from(endian + "QQQQ", data, cmd_off + 24)
        nsects = struct.unpack_from(endian + "I", data, cmd_off + 64)[0]
        sect_off = cmd_off + 72
        sect_size = 80
    else:
        segname = data[cmd_off + 8 : cmd_off + 24].rstrip(b"\x00").decode("utf-8", "replace")
        vmaddr, vmsize, fileoff, filesize = struct.unpack_from(endian + "IIII", data, cmd_off + 24)
        nsects = struct.unpack_from(endian + "I", data, cmd_off + 48)[0]
        sect_off = cmd_off + 56
        sect_size = 68

    for i in range(min(nsects, 256)):
        off = sect_off + i * sect_size
        if off + sect_size > len(data):
            break
        sectname = data[off : off + 16].rstrip(b"\x00").decode("utf-8", "replace")
        segn = data[off + 16 : off + 32].rstrip(b"\x00").decode("utf-8", "replace")
        if is64:
            addr, size, offset = struct.unpack_from(endian + "QQI", data, off + 32)
        else:
            addr, size, offset = struct.unpack_from(endian + "III", data, off + 32)
        blob = data[offset : offset + size] if offset else b""
        flags = [segn] if segn else []
        art.sections.append(
            Section(
                name=f"{segn},{sectname}" if segn else sectname,
                offset=offset,
                size=size,
                entropy=round(entropy(blob), 4) if blob else 0.0,
                flags=flags,
                extra={"addr": hex(addr), "segment": segname},
            )
        )


def _read_lc_str(data: bytes, off: int, max_off: int) -> str:
    if off < 0 or off >= len(data) or off >= max_off:
        return ""
    end = data.find(b"\x00", off, max_off)
    if end == -1:
        end = max_off
    return data[off:end].decode("utf-8", "replace")
