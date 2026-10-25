"""Minimal ELF parser: sections, segments, dynamic imports/exports.

Hand-rolled against the ELF spec using struct so there is no dependency on
pyelftools. Only the parts REA needs for triage are decoded.
"""

from __future__ import annotations

import struct
from typing import List, Tuple

from ..core.hashing import entropy
from ..core.model import Artifact, Import, Section

# Program header types
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552

# Dynamic tags
DT_NULL = 0
DT_NEEDED = 1
DT_STRTAB = 5
DT_SYMTAB = 6
DT_STRSZ = 10
DT_SYMENT = 11

# Section types
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_DYNSYM = 11

SHF_EXECINSTR = 0x4
SHF_WRITE = 0x1
SHF_ALLOC = 0x2

STT_FUNC = 2
STT_OBJECT = 1


def _unpack(fmt: str, data: bytes, off: int):
    size = struct.calcsize(fmt)
    if off + size > len(data):
        return None
    return struct.unpack_from(fmt, data, off)


def parse(art: Artifact, data: bytes) -> None:
    if len(data) < 0x40:
        art.errors.append("ELF: file too small for a header")
        return

    ei_class = data[4]
    ei_data = data[5]
    is64 = ei_class == 2
    endian = "<" if ei_data == 1 else ">"

    if is64:
        hdr = _unpack(endian + "HHIQQQIHHHHHH", data, 16)
        if hdr is None:
            art.errors.append("ELF: truncated 64-bit header")
            return
        (
            e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
            e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx,
        ) = hdr
    else:
        hdr = _unpack(endian + "HHIIIIIHHHHHH", data, 16)
        if hdr is None:
            art.errors.append("ELF: truncated 32-bit header")
            return
        (
            e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
            e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx,
        ) = hdr

    art.metadata["elf"] = {
        "class": "ELF64" if is64 else "ELF32",
        "endianness": "little" if ei_data == 1 else "big",
        "type": {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}.get(e_type, str(e_type)),
        "machine": e_machine,
        "entry_point": hex(e_entry),
        "flags": hex(e_flags),
        "osabi": data[7],
    }

    sections = _parse_sections(
        data, endian, is64, e_shoff, e_shentsize, e_shnum, e_shstrndx
    )
    for s in sections:
        art.sections.append(s)
    art.metadata["elf"]["section_count"] = len(sections)
    art.metadata["elf"]["segment_count"] = e_phnum

    _parse_segments(art, data, endian, is64, e_phoff, e_phentsize, e_phnum)
    _parse_dynamic(art, data, endian, is64, e_phoff, e_phentsize, e_phnum, sections)
    _parse_symbols(art, data, endian, is64, sections)


def _parse_sections(
    data: bytes, endian: str, is64: bool, shoff: int, shentsize: int, shnum: int, shstrndx: int
) -> List[Section]:
    if not shoff or not shnum or not shentsize:
        return []

    raw = []
    for i in range(shnum):
        off = shoff + i * shentsize
        if is64:
            v = _unpack(endian + "IIQQQQIIQQ", data, off)
        else:
            v = _unpack(endian + "IIIIIIIIII", data, off)
        if v is None:
            break
        raw.append(v)

    names = b""
    if 0 <= shstrndx < len(raw):
        shstr = raw[shstrndx]
        str_off, str_size = shstr[4], shstr[5]
        names = data[str_off : str_off + str_size]

    sections: List[Section] = []
    for v in raw:
        name_off, sh_type = v[0], v[1]
        sh_flags, sh_addr, sh_offset, sh_size = v[2], v[3], v[4], v[5]
        sh_link, sh_entsize = v[6], v[9]
        name = _cstr(names, name_off) or f"section_{len(sections)}"
        flags = []
        if sh_flags & SHF_ALLOC:
            flags.append("ALLOC")
        if sh_flags & SHF_WRITE:
            flags.append("WRITE")
        if sh_flags & SHF_EXECINSTR:
            flags.append("EXEC")
        blob = data[sh_offset : sh_offset + sh_size]
        sections.append(
            Section(
                name=name,
                offset=sh_offset,
                size=sh_size,
                entropy=round(entropy(blob), 4) if blob else 0.0,
                flags=flags,
                extra={
                    "type": sh_type,
                    "addr": hex(sh_addr),
                    "link": sh_link,
                    "entsize": sh_entsize,
                },
            )
        )
    return sections


def _parse_segments(
    art: Artifact, data: bytes, endian: str, is64: bool, phoff: int, phentsize: int, phnum: int
) -> None:
    if not phoff or not phnum:
        return
    segs = []
    for i in range(phnum):
        off = phoff + i * phentsize
        if is64:
            v = _unpack(endian + "IIQQQQQQ", data, off)
        else:
            v = _unpack(endian + "IIIIIIII", data, off)
        if v is None:
            break
        p_type, p_flags = v[0], v[1]
        p_offset, p_vaddr, p_filesz, p_memsz = v[2], v[3], v[4], v[5]
        name = {
            PT_LOAD: "LOAD",
            PT_DYNAMIC: "DYNAMIC",
            PT_INTERP: "INTERP",
            PT_GNU_STACK: "GNU_STACK",
            PT_GNU_RELRO: "GNU_RELRO",
        }.get(p_type, hex(p_type))
        flags = []
        if p_flags & 1:
            flags.append("X")
        if p_flags & 2:
            flags.append("W")
        if p_flags & 4:
            flags.append("R")
        segs.append(
            {
                "type": name,
                "offset": p_offset,
                "vaddr": hex(p_vaddr),
                "filesz": p_filesz,
                "memsz": p_memsz,
                "flags": "".join(flags),
                "entropy": round(entropy(data[p_offset : p_offset + p_filesz]), 4)
                if p_filesz
                else 0.0,
            }
        )
    art.metadata["elf"]["segments"] = segs


def _parse_dynamic(
    art: Artifact, data: bytes, endian: str, is64: bool, phoff: int, phentsize: int, phnum: int, sections: List[Section]
) -> None:
    dyn_off = dyn_size = 0
    for i in range(phnum):
        off = phoff + i * phentsize
        if is64:
            v = _unpack(endian + "IIQQQQQQ", data, off)
        else:
            v = _unpack(endian + "IIIIIIII", data, off)
        if v is None:
            break
        if v[0] == PT_DYNAMIC:
            dyn_off, dyn_size = v[2], v[4]
            break

    if not dyn_off:
        for s in sections:
            if s.name == ".dynamic":
                dyn_off, dyn_size = s.offset, s.size
                break
    if not dyn_off:
        return

    entry_size = 16 if is64 else 8
    tags = []
    count = min(dyn_size // entry_size, 4096)
    for i in range(count):
        off = dyn_off + i * entry_size
        if is64:
            v = _unpack(endian + "qQ", data, off)
        else:
            v = _unpack(endian + "iI", data, off)
        if v is None:
            break
        if v[0] == DT_NULL:
            break
        tags.append(v)

    strtab = strsz = 0
    for tag, val in tags:
        if tag == DT_STRTAB:
            strtab = val
        elif tag == DT_STRSZ:
            strsz = val
    dynstr = _vaddr_to_offset(art, strtab)
    if dynstr is None:
        dynstr = strtab
    blob = data[dynstr : dynstr + strsz] if strsz else b""

    needed = [_cstr(blob, val) for tag, val in tags if tag == DT_NEEDED]
    art.metadata["elf"]["needed"] = [n for n in needed if n]
    art.metadata["elf"]["rpath"] = [
        _cstr(blob, val) for tag, val in tags if tag in (15, 29) and _cstr(blob, val)
    ]
    art.metadata["elf"]["soname"] = next(
        (_cstr(blob, val) for tag, val in tags if tag == 14), ""
    )


def _parse_symbols(art: Artifact, data: bytes, endian: str, is64: bool, sections: List[Section]) -> None:
    from ..analysis.categorize import categorize_import

    exports: List[str] = []
    imports: List[Import] = []

    for sym in sections:
        if sym.extra.get("type") not in (SHT_DYNSYM, SHT_SYMTAB):
            continue
        link = sym.extra.get("link")
        if link is None:
            continue
        # link points at the associated string table section index
        strtab = next((s for i, s in enumerate(sections) if i == link), None)
        if strtab is None:
            continue
        strblob = data[strtab.offset : strtab.offset + strtab.size]
        entsize = sym.extra.get("entsize") or (24 if is64 else 16)
        count = min(sym.size // entsize, 20000) if entsize else 0
        for i in range(count):
            off = sym.offset + i * entsize
            if is64:
                v = _unpack(endian + "IBBHQQ", data, off)
                if v is None:
                    break
                st_name, st_info, st_other, st_shndx, st_value, st_size = v
            else:
                v = _unpack(endian + "IIIBBH", data, off)
                if v is None:
                    break
                st_name, st_value, st_size, st_info, st_other, st_shndx = v
            if st_name == 0:
                continue
            name = _cstr(strblob, st_name)
            if not name:
                continue
            bind = st_info >> 4
            stype = st_info & 0xF
            if st_shndx == 0 and bind in (1, 2):  # UNDEF, GLOBAL/WEAK -> import
                imports.append(
                    Import(library="(elf)", name=name, category=categorize_import(name))
                )
            elif stype in (STT_FUNC, STT_OBJECT) and st_shndx != 0:
                exports.append(name)

    art.exports = sorted(set(exports))[:500]
    seen = set()
    for imp in imports:
        if imp.name not in seen:
            seen.add(imp.name)
            art.imports.append(imp)


def _vaddr_to_offset(art: Artifact, vaddr: int) -> int | None:
    for seg in art.metadata.get("elf", {}).get("segments", []):
        try:
            base = int(seg["vaddr"], 16)
        except (ValueError, TypeError):
            continue
        if base <= vaddr < base + seg["memsz"]:
            return seg["offset"] + (vaddr - base)
    return None


def _cstr(blob: bytes, off: int) -> str:
    if off < 0 or off >= len(blob):
        return ""
    end = blob.find(b"\x00", off)
    if end == -1:
        end = len(blob)
    return blob[off:end].decode("utf-8", "replace")
