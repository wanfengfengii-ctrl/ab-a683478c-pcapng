"""Minimal PCAPNG block builder used by tests and the API smoke script."""

from __future__ import annotations

from typing import List, Optional, Sequence, Tuple

BT_SHB = 0x0A0D0D0A
BT_IDB = 0x00000001
BT_EPB = 0x00000006

OPT_ENDOFOPT = 0
OPT_IF_TSRESOL = 9
OPT_IF_TSOFFSET = 14


def _u16(value: int, endian: str) -> bytes:
    return value.to_bytes(2, endian)


def _u32(value: int, endian: str) -> bytes:
    return value.to_bytes(4, endian)


def _u64(value: int, endian: str) -> bytes:
    return value.to_bytes(8, endian)


def _i64(value: int, endian: str) -> bytes:
    return value.to_bytes(8, endian, signed=True)


def _option(code: int, value: bytes, endian: str) -> bytes:
    out = _u16(code, endian) + _u16(len(value), endian) + value
    out += b"\x00" * ((-len(value)) % 4)
    return out


def _block(block_type: int, body: bytes, endian: str) -> bytes:
    total = 12 + len(body)
    return (
        _u32(block_type, endian)
        + _u32(total, endian)
        + body
        + _u32(total, endian)
    )


def shb(endian: str = "little", options: bytes = b"", section_length: int = -1) -> bytes:
    body = (
        b"\x4d\x3c\x2b\x1a"[:: (1 if endian == "little" else -1)]
        + _u16(1, endian)
        + _u16(0, endian)
        + _i64(section_length, endian)
        + options
        + _option(OPT_ENDOFOPT, b"", endian)
    )
    return _block(BT_SHB, body, endian)


def idb(
    snaplen: int = 0,
    tsresol: Optional[int] = None,
    tsoffset: Optional[int] = None,
    endian: str = "little",
    extra_options: Sequence[Tuple[int, bytes]] = (),
) -> bytes:
    options = b""
    for code, value in extra_options:
        options += _option(code, value, endian)
    if tsresol is not None:
        options += _option(OPT_IF_TSRESOL, bytes([tsresol]), endian)
    if tsoffset is not None:
        options += _option(OPT_IF_TSOFFSET, _i64(tsoffset, endian), endian)
    options += _option(OPT_ENDOFOPT, b"", endian)
    body = _u16(1, endian) + _u16(0, endian) + _u32(snaplen, endian) + options
    return _block(BT_IDB, body, endian)


def epb(
    interface_id: int,
    timestamp_raw: int,
    packet: bytes,
    orig_len: Optional[int] = None,
    endian: str = "little",
    captured: Optional[bytes] = None,
    options: bytes = b"",
) -> bytes:
    if captured is None:
        captured = packet
    if orig_len is None:
        orig_len = len(packet)
    body = (
        _u32(interface_id, endian)
        + _u32((timestamp_raw >> 32) & 0xFFFFFFFF, endian)
        + _u32(timestamp_raw & 0xFFFFFFFF, endian)
        + _u32(len(captured), endian)
        + _u32(orig_len, endian)
        + captured
        + b"\x00" * ((-len(captured)) % 4)
        + options
    )
    return _block(BT_EPB, body, endian)


def mixed_endian_sample() -> bytes:
    """Two-section capture: little-endian section then big-endian section.

    Section 1 (LE): microsecond interface then nanosecond interface with a
    +1 s offset; the fourth packet goes backwards by 1 ms.
    Section 2 (BE): default-resolution (decimal microsecond) interface.
    """
    parts: List[bytes] = [shb("little")]
    parts.append(idb(snaplen=65535, tsresol=6, endian="little"))
    parts.append(epb(0, 1_000_000, b"\xaa" * 4, endian="little"))
    parts.append(epb(0, 1_500_000, b"\xbb" * 5, endian="little"))
    parts.append(idb(snaplen=128, tsresol=9, tsoffset=10**9, endian="little"))
    parts.append(epb(1, 600_000_000, b"\xcc" * 6, endian="little"))
    # 1_599_000_000 ns vs previous 1_600_000_000 ns -> 1 ms backwards.
    parts.append(epb(1, 599_000_000, b"\xdd" * 7, endian="little"))

    parts.append(shb("big"))
    parts.append(idb(snaplen=65535, endian="big"))  # default tsresol = us
    parts.append(epb(0, 2_000_000, b"\xee" * 8, endian="big"))
    return b"".join(parts)


def rounding_sample() -> bytes:
    """Section exercising binary resolution 2^-11 s (488281.25 ns/tick)."""
    parts = [shb("little")]
    parts.append(idb(tsresol=0x8B, endian="little"))
    for raw in (0, 1, 2, 3, 6):
        parts.append(epb(0, raw, bytes([raw]) * 3, endian="little"))
    return b"".join(parts)
