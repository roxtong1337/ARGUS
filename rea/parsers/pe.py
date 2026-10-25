"""Pure-python PE (Portable Executable) parser.

Decodes the COFF header, optional header, section table, import directory and
export directory. Written against the PE/COFF specification; no pefile needed.
"""

from __future__ import annotations

import struct
from typing import Dict, List, Optional

from ..analysis.categorize import categorize_import
from ..core.hashing import entropy
from ..core.model import Artifact, Import, Section

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_UNINITIALIZED = 0x00000080

DIRECTORY_NAMES = {
    0: "export",
    1: "import",
    2: "resource",
    3: "exception",
    4: "security",
    5: "basereloc",
    6: "debug",
    7: "architecture",
    8: "globalptr",
    9: "tls",
    10: "load_config",
    11: "bound_import",
    12: "iat",
    13: "delay_import",
    14: "clr",
    15: "reserved",
}

SUBSYSTEMS = {1: "native", 2: "windows_gui", 3: "windows_cui", 9: "windows_ce", 10: "efi"}


def _u16(d: bytes, o: int) -> int:
    return struct.unpack_from("<H", d, o)[0] if o + 2 <= len(d) else 0


def _u32(d: bytes, o: int) -> int:
    return struct.unpack_from("<I", d, o)[0] if o + 4 <= len(d) else 0


def _cstr(blob: bytes, off: int) -> str:
    if off < 0 or off >= len(blob):
        return ""
    end = blob.find(b"\x00", off)
    if end == -1:
        end = len(blob)
    return blob[off:end].decode("utf-8", "replace")


def parse(art: Artifact, data: bytes) -> None:
    if len(data) < 0x40:
        art.errors.append("PE: file too small")
        return

    e_lfanew = _u32(data, 0x3C)
    if e_lfanew <= 0 or e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        art.errors.append("PE: invalid signature at e_lfanew")
        return

    coff = e_lfanew + 4
    machine = _u16(data, coff)
    num_sections = _u16(data, coff + 2)
    timestamp = _u32(data, coff + 4)
    opt_size = _u16(data, coff + 16)
    characteristics = _u16(data, coff + 18)

    opt = coff + 20
    magic = _u16(data, opt)
    is64 = magic == 0x20B
    if magic not in (0x10B, 0x20B):
        art.errors.append(f"PE: unknown optional header magic 0x{magic:x}")
        return

    entry = _u32(data, opt + 16)
    image_base = struct.unpack_from("<Q" if is64 else "<I", data, opt + 24)[0] if opt + 32 <= len(data) else 0
    subsystem = _u16(data, opt + (68 if is64 else 68))
    dll_characteristics = _u16(data, opt + (70 if is64 else 70))
    num_dirs = _u32(data, opt + (108 if is64 else 92))
    dirs_off = opt + (112 if is64 else 96)

    directories: Dict[str, dict] = {}
    for i in range(min(num_dirs, 16)):
        va = _u32(data, dirs_off + i * 8)
        sz = _u32(data, dirs_off + i * 8 + 4)
        if va or sz:
            directories[DIRECTORY_NAMES.get(i, str(i))] = {"va": va, "size": sz}

    art.metadata["pe"] = {
        "machine": {0x14C: "x86", 0x8664: "x86-64", 0x1C0: "ARM", 0xAA64: "AArch64"}.get(machine, hex(machine)),
        "is_64bit": is64,
        "compile_timestamp": timestamp,
        "image_base": hex(image_base),
        "entry_point": hex(entry),
        "subsystem": SUBSYSTEMS.get(subsystem, str(subsystem)),
        "characteristics": hex(characteristics),
        "is_dll": bool(characteristics & 0x2000),
        "dll_characteristics": hex(dll_characteristics),
        "aslr": bool(dll_characteristics & 0x40),
        "dep": bool(dll_characteristics & 0x100),
        "directories": directories,
        "section_count": num_sections,
    }

    sections = _parse_sections(data, coff, num_sections, opt_size)
    for s in sections:
        art.sections.append(s)

    _parse_imports(art, data, directories, sections, is64, image_base)
    _parse_exports(art, data, directories, sections)


def _parse_sections(data: bytes, coff: int, count: int, opt_size: int) -> List[Section]:
    base = coff + 20 + opt_size
    sections: List[Section] = []
    for i in range(count):
        off = base + i * 40
        if off + 40 > len(data):
            break
        name = data[off : off + 8].rstrip(b"\x00").decode("utf-8", "replace")
        vsize = _u32(data, off + 8)
        vaddr = _u32(data, off + 12)
        raw_size = _u32(data, off + 16)
        raw_ptr = _u32(data, off + 20)
        chars = _u32(data, off + 36)
        flags = []
        if chars & IMAGE_SCN_MEM_READ:
            flags.append("R")
        if chars & IMAGE_SCN_MEM_WRITE:
            flags.append("W")
        if chars & IMAGE_SCN_MEM_EXECUTE:
            flags.append("X")
        if chars & IMAGE_SCN_CNT_CODE:
            flags.append("CODE")
        if chars & IMAGE_SCN_CNT_UNINITIALIZED:
            flags.append("UNINIT")
        blob = data[raw_ptr : raw_ptr + raw_size]
        sections.append(
            Section(
                name=name,
                offset=raw_ptr,
                size=raw_size,
                entropy=round(entropy(blob), 4) if blob else 0.0,
                flags=flags,
                extra={"vaddr": hex(vaddr), "vsize": vsize, "characteristics": hex(chars)},
            )
        )
    return sections


def _rva_to_offset(rva: int, sections: List[Section]) -> Optional[int]:
    for s in sections:
        try:
            vaddr = int(s.extra["vaddr"], 16)
        except (KeyError, ValueError):
            continue
        if vaddr <= rva < vaddr + max(s.size, s.extra.get("vsize", 0)):
            return s.offset + (rva - vaddr)
    return None


def _parse_imports(
    art: Artifact, data: bytes, directories: dict, sections: List[Section], is64: bool, image_base: int
) -> None:
    imp = directories.get("import")
    if not imp or not imp["va"]:
        return
    off = _rva_to_offset(imp["va"], sections)
    if off is None:
        art.errors.append("PE: import directory RVA not mapped to a section")
        return

    names_seen = set()
    for i in range(256):
        desc = off + i * 20
        if desc + 20 > len(data):
            break
        original_first_thunk = _u32(data, desc)
        name_rva = _u32(data, desc + 12)
        first_thunk = _u32(data, desc + 16)
        if not name_rva and not first_thunk:
            break
        name_off = _rva_to_offset(name_rva, sections)
        libname = _cstr(data, name_off) if name_off is not None else f"ord_{name_rva}"
        if not libname:
            continue

        thunk_rva = original_first_thunk or first_thunk
        thunk_off = _rva_to_offset(thunk_rva, sections)
        if thunk_off is None:
            continue
        entry_size = 8 if is64 else 4
        fmt = "<Q" if is64 else "<I"
        ordinal_flag = 1 << 63 if is64 else 1 << 31
        for j in range(4096):
            toff = thunk_off + j * entry_size
            if toff + entry_size > len(data):
                break
            value = struct.unpack_from(fmt, data, toff)[0]
            if value == 0:
                break
            if value & ordinal_flag:
                func = f"ordinal_{value & 0xFFFF}"
            else:
                hint_off = _rva_to_offset(value & 0x7FFFFFFF, sections)
                func = _cstr(data, (hint_off + 2) if hint_off is not None else -1)
            if not func:
                continue
            key = (libname.lower(), func.lower())
            if key in names_seen:
                continue
            names_seen.add(key)
            art.imports.append(
                Import(library=libname, name=func, category=categorize_import(func))
            )


def _parse_exports(art: Artifact, data: bytes, directories: dict, sections: List[Section]) -> None:
    exp = directories.get("export")
    if not exp or not exp["va"]:
        return
    off = _rva_to_offset(exp["va"], sections)
    if off is None or off + 40 > len(data):
        return
    num_names = _u32(data, off + 24)
    names_rva = _u32(data, off + 32)
    names_off = _rva_to_offset(names_rva, sections)
    if names_off is None:
        return
    exports = []
    for i in range(min(num_names, 2000)):
        ptr = names_off + i * 4
        if ptr + 4 > len(data):
            break
        name_rva = _u32(data, ptr)
        name_off = _rva_to_offset(name_rva, sections)
        if name_off is None:
            continue
        name = _cstr(data, name_off)
        if name:
            exports.append(name)
    art.exports = exports
    art.metadata["pe"]["export_count"] = len(exports)
