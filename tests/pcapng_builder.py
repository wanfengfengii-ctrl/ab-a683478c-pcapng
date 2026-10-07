"""Tiny PCAPNG builder used by the test-suite / smoke fixtures."""

from __future__ import annotations

import struct

BT_SHB = 0x0A0D0D0A
BT_IDB = 1
BT_EPB = 6


def pad4(data: bytes) -> bytes:
    return data + b"\x00" * ((-len(data)) % 4)


def option(code: int, value: bytes, endian: str = "<") -> bytes:
    return struct.pack(endian + "HH", code, len(value)) + pad4(value)


def block(btype: int, body: bytes, endian: str) -> bytes:
    head = struct.pack(endian + "II", btype, 12 + len(body))
    tail = struct.pack(endian + "I", 12 + len(body))
    return head + body + tail


def shb(endian: str = "<", section_length: int = -1,
        options: bytes = b"") -> bytes:
    body = struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, section_length) + options
    body = pad4(body)
    return block(BT_SHB, body, endian)


def section(blocks: list[bytes], endian: str = "<") -> bytes:
    """Build an SHB (correct Section Length) followed by IDB/EPB blocks."""
    inner = b"".join(blocks)
    # SHB fixed body = magic(4)+version(4)+section length(8) = 16 bytes.
    shb_block_len = 12 + 16
    # Section Length excludes the 16 bytes preceding the field (block type,
    # block total length, magic, major/minor version).
    section_length = (shb_block_len + len(inner)) - 16
    body = struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, section_length)
    return block(BT_SHB, body, endian) + inner


def idb(linktype: int = 1, snaplen: int = 0, if_tsresol: int | None = None,
        if_tsoffset: int | None = None, endian: str = "<") -> bytes:
    body = struct.pack(endian + "HHI", linktype, 0, snaplen)
    opts = b""
    if if_tsresol is not None:
        opts += option(9, bytes([if_tsresol]), endian)
    if if_tsoffset is not None:
        opts += struct.pack(endian + "HH", 14, 8) + struct.pack(
            endian + "q", if_tsoffset
        )
    return block(BT_IDB, pad4(body + opts), endian)


def epb(interface_id: int, timestamp: int, packet: bytes,
        caplen: int | None = None, origlen: int | None = None,
        endian: str = "<", padding_bytes: bytes | None = None,
        options: bytes = b"") -> bytes:
    caplen = len(packet) if caplen is None else caplen
    origlen = len(packet) if origlen is None else origlen
    ts_hi = (timestamp >> 32) & 0xFFFFFFFF
    ts_lo = timestamp & 0xFFFFFFFF
    body = struct.pack(endian + "IIIII", interface_id, ts_hi, ts_lo,
                       caplen, origlen)
    body += packet[:caplen]
    body += (b"\x00" * ((-caplen) % 4)
             if padding_bytes is None else padding_bytes)
    body += options
    return block(BT_EPB, body, endian)
