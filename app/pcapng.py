"""Strict PCAPNG section/block parser and timestamp auditor.

Only Section Header Blocks (SHB), Interface Description Blocks (IDB) and
Enhanced Packet Blocks (EPB) are accepted.  Every structural rule required by
the audit API is enforced here and reported via :class:`PcapngError`.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

BT_SHB = 0x0A0D0D0A  # palindrome: identical in little- and big-endian
BT_IDB = 1
BT_EPB = 6

_MAGIC_NATIVE = 0x1A2B3C4D  # body byte order == field read order
_MAGIC_SWAPPED = 0x4D3C2B1A


class PcapngError(ValueError):
    """Raised when the PCAPNG byte stream violates the accepted structure."""


@dataclass(frozen=True)
class Interface:
    if_tsresol: int = 6  # default: decimal microseconds
    if_tsoffset: int = 0  # signed 64-bit, in units of if_tsresol
    snaplen: int = 0  # 0 means "no limit"


@dataclass(frozen=True)
class Packet:
    section_index: int  # 0-based, in capture order
    interface_id: int
    timestamp_ns: int
    captured_length: int
    original_length: int
    digest: str


def _read_u32(data: bytes, offset: int, endian: str, what: str) -> int:
    if offset + 4 > len(data):
        raise PcapngError(f"truncated {what}")
    return struct.unpack_from(endian + "I", data, offset)[0]


def _check_block_length(data: bytes, start: int, total_len: int,
                        endian: str, name: str) -> None:
    if total_len < 12 or (total_len % 4) != 0:
        raise PcapngError(f"{name}: block total length invalid or unaligned")
    if start + total_len > len(data):
        raise PcapngError(f"{name}: block total length exceeds file bounds")
    trailing = _read_u32(data, start + total_len - 4, endian,
                         f"{name} trailing length")
    if trailing != total_len:
        raise PcapngError(f"{name}: trailing block length mismatch")


def _decode_options(body: bytes, start: int, end: int, endian: str,
                    block_name: str) -> dict[int, list[bytes]]:
    """Decode TLV options, validating alignment, padding and boundaries."""
    options: dict[int, list[bytes]] = {}
    pos = start
    while pos < end:
        if end - pos < 4:
            raise PcapngError(f"{block_name}: truncated option header")
        code, length = struct.unpack_from(endian + "HH", body, pos)
        pos += 4
        if pos + length > end:
            raise PcapngError(f"{block_name}: option {code} value out of bounds")
        value = body[pos : pos + length]
        pos += length
        pad = (-length) % 4
        if pad:
            if pos + pad > end:
                raise PcapngError(f"{block_name}: option {code} padding out of bounds")
            if body[pos : pos + pad] != b"\x00" * pad:
                raise PcapngError(f"{block_name}: option {code} padding must be zero")
            pos += pad
        if code == 0:  # opt_endofopt
            if length != 0:
                raise PcapngError("opt_endofopt must be zero length")
            if body[pos:end].strip(b"\x00"):
                raise PcapngError(f"{block_name}: trailing bytes after opt_endofopt")
            break
        options.setdefault(code, []).append(value)
    return options


def timestamp_to_ns(raw_ts: int, if_tsresol: int, if_tsoffset: int) -> int:
    """Convert an EPB timestamp to canonical nanoseconds.

    ``if_tsresol`` gives resolution units per second; the MSB selects base-2
    instead of the default base-10.  The signed 64-bit offset is applied in
    resolution units first (so it stays exact); the division to nanoseconds
    uses round-half-to-even (banker's rounding / 最近偶数舍入).
    """
    if if_tsresol == 0:
        raise PcapngError("if_tsresol must be non-zero")
    total = raw_ts + if_tsoffset
    if if_tsresol & 0x80:
        denom = 1 << (if_tsresol & 0x7F)
    else:
        denom = 10 ** (if_tsresol & 0x7F)
    if denom == 1:
        return total * 1_000_000_000
    numerator = total * 1_000_000_000
    q, r = divmod(numerator, denom)
    twice_r = 2 * r
    if twice_r > denom or (twice_r == denom and (q & 1)):
        q += 1
    return q


def _parse_idb(body: bytes, endian: str) -> Interface:
    if len(body) < 8:
        raise PcapngError("IDB body too short")
    _linktype, reserved, snaplen = struct.unpack_from(endian + "HHI", body, 0)
    if reserved != 0:
        raise PcapngError("IDB reserved field must be zero")
    opts = _decode_options(body, 8, len(body), endian, "IDB")
    if_tsresol = 6  # default: 10^-6 s (decimal microseconds)
    if_tsoffset = 0
    if 9 in opts:  # if_tsresol
        vals = opts[9]
        if len(vals) != 1 or len(vals[0]) != 1:
            raise PcapngError("if_tsresol must be a single one-byte option")
        if_tsresol = vals[0][0]
    if 14 in opts:  # if_tsoffset (signed 64-bit)
        vals = opts[14]
        if len(vals) != 1 or len(vals[0]) != 8:
            raise PcapngError("if_tsoffset must be a single eight-byte option")
        if_tsoffset = struct.unpack(endian + "q", vals[0])[0]
    if if_tsresol == 0:
        raise PcapngError("if_tsresol must be non-zero")
    return Interface(if_tsresol, if_tsoffset, snaplen)


def _parse_epb(body: bytes, endian: str, section_index: int,
               interfaces: list[Interface]) -> Packet:
    if len(body) < 20:
        raise PcapngError("EPB body too short")
    interface_id, ts_hi, ts_lo, caplen, origlen = struct.unpack_from(
        endian + "IIIII", body, 0
    )
    if interface_id >= len(interfaces):
        raise PcapngError("EPB references undefined interface")
    if caplen > origlen:
        raise PcapngError("EPB captured length exceeds original length")
    iface = interfaces[interface_id]
    if iface.snaplen and caplen > iface.snaplen:
        raise PcapngError("EPB captured length exceeds interface snaplen")
    padded = (caplen + 3) & ~3
    if 20 + padded > len(body):
        raise PcapngError("EPB packet data exceeds block bounds")
    packet_data = body[20 : 20 + caplen]
    pad_len = padded - caplen
    if pad_len and body[20 + caplen : 20 + padded] != b"\x00" * pad_len:
        raise PcapngError("EPB packet padding must be zero")
    _decode_options(body, 20 + padded, len(body), endian, "EPB")

    raw_ts = (ts_hi << 32) | ts_lo
    ts_ns = timestamp_to_ns(raw_ts, iface.if_tsresol, iface.if_tsoffset)
    return Packet(
        section_index=section_index,
        interface_id=interface_id,
        timestamp_ns=ts_ns,
        captured_length=caplen,
        original_length=origlen,
        digest=hashlib.sha256(packet_data).hexdigest(),
    )


def parse_pcapng(data: bytes) -> list[Packet]:
    """Parse and validate a PCAPNG byte stream; return packets in capture order."""
    if len(data) < 28:
        raise PcapngError("file too small to contain a Section Header Block")

    packets: list[Packet] = []
    pos = 0
    section_index = -1

    while pos < len(data):
        # ---- Every section starts with an SHB ----
        if pos + 12 > len(data):
            raise PcapngError("truncated block header")
        if struct.unpack_from("<I", data, pos)[0] != BT_SHB:
            if section_index < 0:
                raise PcapngError("file must begin with a Section Header Block")
            raise PcapngError("section contains an unexpected block / SHB required")

        magic = struct.unpack_from("<I", data, pos + 8)[0]
        if magic == _MAGIC_NATIVE:
            endian = "<"
        elif magic == _MAGIC_SWAPPED:
            endian = ">"
        else:
            raise PcapngError("invalid SHB byte-order magic")

        total_len = _read_u32(data, pos + 4, endian, "SHB total length")
        if total_len < 28:
            raise PcapngError("SHB block total length too small")
        _check_block_length(data, pos, total_len, endian, "SHB")

        section_index += 1
        if section_index >= 8:
            raise PcapngError("at most 8 sections are accepted")

        # Body begins after the 8-byte block header: magic(4), version(4),
        # section length(8), then options up to the 4-byte trailing length.
        body = data[pos + 8 : pos + total_len - 4]
        if len(body) < 16:
            raise PcapngError("SHB body too short")
        declared_section_len = struct.unpack_from(endian + "q", body, 8)[0]
        _decode_options(body, 16, len(body), endian, "SHB")

        section_start = pos
        interfaces: list[Interface] = []
        pos += total_len

        # ---- Blocks belonging to this section; next SHB starts a new one ----
        while pos < len(data):
            if pos + 8 > len(data):
                raise PcapngError("truncated block header")
            btype = _read_u32(data, pos, endian, "block type")
            if btype == BT_SHB:  # palindrome value: endianness-independent
                break
            block_len = _read_u32(data, pos + 4, endian, "block total length")
            _check_block_length(data, pos, block_len, endian,
                                {BT_IDB: "IDB", BT_EPB: "EPB"}.get(
                                    btype, f"block 0x{btype:08X}"))
            block_body = data[pos + 8 : pos + block_len - 4]
            if btype == BT_IDB:
                interfaces.append(_parse_idb(block_body, endian))
            elif btype == BT_EPB:
                packets.append(
                    _parse_epb(block_body, endian, section_index, interfaces)
                )
            else:
                raise PcapngError(
                    f"unsupported block type 0x{btype:08X}; only SHB/IDB/EPB"
                )
            pos += block_len

        # Section Length counts the bytes after the 8-byte Section Length
        # field itself to the end of the section (section bytes minus 16);
        # -1 means unknown.
        if declared_section_len != -1:
            actual = pos - section_start - 16
            if declared_section_len != actual:
                raise PcapngError("inconsistent section length field")

    if section_index < 0:
        raise PcapngError("no sections found")
    return packets
