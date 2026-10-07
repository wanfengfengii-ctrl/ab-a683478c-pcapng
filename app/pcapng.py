"""Strict parser/auditor for PCAPNG capture files.

Only the block layout required by the audit API is supported:

* Section Header Block (``BT_SHB``) -- one to eight sections per file
* Interface Description Block (``BT_IDB``)
* Enhanced Packet Block (``BT_EPB``)

Every block is validated for matching trailing block lengths, four-byte
padding, option boundaries, per-section byte order and interface
references.  Timestamps are normalised to nanoseconds using each
interface's ``if_tsresol`` / ``if_tsoffset`` options.
"""

from __future__ import annotations

import hashlib
from fractions import Fraction
from typing import List, Optional, Tuple

# --- PCAPNG constants -------------------------------------------------------

BT_SHB = 0x0A0D0D0A  # palindrome: identical in both byte orders
BT_IDB = 0x00000001
BT_EPB = 0x00000006

SHB_SIGNATURE = b"\x0a\x0d\x0d\x0a"
BYTE_ORDER_MAGIC_LE = b"\x4d\x3c\x2b\x1a"  # decoded value 0x1A2B3C4D
BYTE_ORDER_MAGIC_BE = b"\x1a\x2b\x3c\x4d"

OPT_ENDOFOPT = 0
OPT_IF_TSRESOL = 9
OPT_IF_TSOFFSET = 14

MAX_SECTIONS = 8

_NS_PER_SEC = 10**9


class PcapngError(ValueError):
    """Raised when the supplied bytes do not form a valid PCAPNG file."""


def _round_half_even(value: Fraction) -> int:
    """Round an exact rational to the nearest integer, ties to even."""
    q, r = divmod(value.numerator, value.denominator)
    if r == 0:
        return q
    doubled = 2 * r
    if doubled > value.denominator:
        return q + 1
    if doubled == value.denominator and (q & 1):
        return q + 1
    return q


class _Interface:
    __slots__ = ("snaplen", "resolution_raw", "tsoffset")

    def __init__(self, snaplen: int, tsresol: Optional[int], tsoffset: int):
        self.snaplen = snaplen  # 0 == unbounded
        # Missing if_tsresol defaults to 6 (decimal microseconds). An
        # explicit zero is kept literally: per spec that means 10^0 s
        # (one-second) units, which is different from the default.
        self.resolution_raw = 6 if tsresol is None else tsresol
        self.tsoffset = tsoffset

    def timestamp_ns(self, raw_ts: int) -> int:
        """Convert a raw EPB timestamp to canonical nanoseconds.

        Resolution uses power-of-ten units with the high bit clear and
        power-of-two units with it set; the exact rational result is
        rounded to the nearest nanosecond, ties to even.
        """
        res = self.resolution_raw
        if res & 0x80:
            unit = Fraction(_NS_PER_SEC, 2 ** (res & 0x7F))
        else:
            unit = Fraction(_NS_PER_SEC, 10 ** (res & 0x7F))
        return _round_half_even(unit * raw_ts) + self.tsoffset


class _Section:
    __slots__ = (
        "number",
        "endian",
        "start",
        "shb_total",
        "declared_length",
        "interfaces",
        "packets",
    )

    def __init__(self, number: int, endian: str, start: int, declared_length: int):
        self.number = number
        self.endian = endian  # "<" little, ">" big
        self.start = start  # file offset of the SHB
        self.shb_total = 0  # total SHB block length, filled in by the parser
        self.declared_length = declared_length  # signed; -1 == unknown
        self.interfaces: List[_Interface] = []
        self.packets: List[dict] = []


def _parse_options(region: bytes, endian: str, what: str) -> dict:
    """Parse a TLV option region, validating every boundary."""
    if len(region) % 4:
        raise PcapngError(f"{what}: option region is not 4-byte aligned")
    options: dict = {}
    pos = 0
    terminated = len(region) == 0
    while pos < len(region):
        code = int.from_bytes(region[pos : pos + 2], "little" if endian == "<" else "big")
        length = int.from_bytes(
            region[pos + 2 : pos + 4], "little" if endian == "<" else "big"
        )
        if code == OPT_ENDOFOPT:
            if length != 0:
                raise PcapngError(f"{what}: opt_endofopt must carry zero length")
            padding = region[pos + 4 :]
            if padding.strip(b"\x00"):
                raise PcapngError(f"{what}: non-zero padding after opt_endofopt")
            terminated = True
            break
        end = pos + 4 + length
        if end > len(region):
            raise PcapngError(f"{what}: option {code} runs past block boundary")
        value = region[pos + 4 : end]
        pos = end
        pad = (-length) % 4
        if pos + pad > len(region):
            raise PcapngError(f"{what}: option {code} padding runs past block")
        pos += pad
        options[code] = value  # repeated options: last occurrence wins
    if not terminated:
        raise PcapngError(f"{what}: option list is not terminated by opt_endofopt")
    return options


def _block_envelope(data: bytes, start: int, endian: str, what: str) -> Tuple[int, bytes]:
    """Validate type/length/trailer of one block; return (total length, body)."""
    if start + 12 > len(data):
        raise PcapngError(f"{what}: truncated block header")
    total = int.from_bytes(
        data[start + 4 : start + 8], "little" if endian == "<" else "big"
    )
    if total < 12 or (total - 12) % 4:
        raise PcapngError(f"{what}: invalid block total length {total}")
    if start + total > len(data):
        raise PcapngError(f"{what}: block extends past end of file")
    trailer = int.from_bytes(
        data[start + total - 4 : start + total],
        "little" if endian == "<" else "big",
    )
    if trailer != total:
        raise PcapngError(f"{what}: trailing block length does not match leading length")
    body = data[start + 8 : start + total - 4]
    return total, body


def _parse_idb(body: bytes, endian: str) -> _Interface:
    if len(body) < 8:
        raise PcapngError("IDB: body shorter than 8 bytes")
    # linktype occupies the first two bytes; the following two are reserved
    # and must be zero per the specification.
    reserved = int.from_bytes(body[2:4], "little" if endian == "<" else "big")
    if reserved != 0:
        raise PcapngError("IDB: reserved field must be zero")
    snaplen = int.from_bytes(body[4:8], "little" if endian == "<" else "big")
    options = _parse_options(body[8:], endian, "IDB")

    tsresol: Optional[int] = None
    if OPT_IF_TSRESOL in options:
        raw = options[OPT_IF_TSRESOL]
        if len(raw) != 1:
            raise PcapngError("IDB: if_tsresol option must be exactly one byte")
        tsresol = raw[0]
        # Any one-byte value is structurally legal; exponents beyond what a
        # nanosecond audit can distinguish simply round to 0 or explode, which
        # Fraction handles exactly below.

    tsoffset = 0
    if OPT_IF_TSOFFSET in options:
        raw = options[OPT_IF_TSOFFSET]
        if len(raw) != 8:
            raise PcapngError("IDB: if_tsoffset option must be exactly eight bytes")
        tsoffset = int.from_bytes(raw, "little" if endian == "<" else "big", signed=True)

    return _Interface(snaplen=snaplen, tsresol=tsresol, tsoffset=tsoffset)


def _parse_epb(body: bytes, endian: str, section: _Section) -> None:
    if len(body) < 20:
        raise PcapngError("EPB: body shorter than 20 bytes")
    interface_id = int.from_bytes(body[0:4], "little" if endian == "<" else "big")
    ts_hi = int.from_bytes(body[4:8], "little" if endian == "<" else "big")
    ts_lo = int.from_bytes(body[8:12], "little" if endian == "<" else "big")
    caplen = int.from_bytes(body[12:16], "little" if endian == "<" else "big")
    origlen = int.from_bytes(body[16:20], "little" if endian == "<" else "big")

    if interface_id >= len(section.interfaces):
        raise PcapngError(
            f"EPB: interface id {interface_id} has no preceding IDB "
            f"(section {section.number} defines {len(section.interfaces)})"
        )
    if caplen > origlen:
        raise PcapngError("EPB: captured length exceeds original (on-wire) length")
    interface = section.interfaces[interface_id]
    if interface.snaplen and caplen > interface.snaplen:
        raise PcapngError("EPB: captured length exceeds interface snaplen")

    padded = (caplen + 3) & ~3
    if 20 + padded > len(body):
        raise PcapngError("EPB: packet data is truncated or caplen is wrong")
    packet = body[20 : 20 + caplen]
    # Packet padding is always present by construction (padded <= len(body));
    # the spec leaves its contents to the writer.

    # Options must still have legal boundaries even though we do not use them.
    _parse_options(body[20 + padded :], endian, "EPB")

    raw_ts = (ts_hi << 32) | ts_lo
    timestamp_ns = interface.timestamp_ns(raw_ts)
    section.packets.append(
        {
            "section": section.number,
            "interface": interface_id,
            "timestampNs": timestamp_ns,
            "packetLength": origlen,
            "capturedLength": caplen,
            "sha256": hashlib.sha256(packet).hexdigest(),
        }
    )


def parse_pcapng(data: bytes) -> List[_Section]:
    """Parse and fully validate a PCAPNG byte string.

    Each section starts with an SHB that fixes the byte order for every
    following block until the next SHB.
    """
    if not data:
        raise PcapngError("empty body")

    sections: List[_Section] = []
    pos = 0
    current: Optional[_Section] = None

    def finalise_section(section: _Section, end: int) -> None:
        """Validate the declared SHB section length against actual bytes."""
        if section.declared_length == -1:
            return
        if section.declared_length < 0:
            raise PcapngError(
                f"SHB: illegal negative section length {section.declared_length}"
            )
        actual = end - section.start - section.shb_total
        if section.declared_length != actual:
            raise PcapngError(
                f"SHB: declared section length {section.declared_length} "
                f"does not match actual length {actual}"
            )

    while pos < len(data):
        block_type = data[pos : pos + 4]
        if block_type == SHB_SIGNATURE:
            if current is not None:
                finalise_section(current, pos)
            if len(sections) >= MAX_SECTIONS:
                raise PcapngError(f"file contains more than {MAX_SECTIONS} sections")
            if pos + 12 > len(data):
                raise PcapngError("SHB: truncated block header")
            magic = data[pos + 8 : pos + 12]
            if magic == BYTE_ORDER_MAGIC_LE:
                endian = "<"
            elif magic == BYTE_ORDER_MAGIC_BE:
                endian = ">"
            else:
                raise PcapngError("SHB: invalid byte-order magic")
            total, body = _block_envelope(data, pos, endian, "SHB")
            if len(body) < 16:
                raise PcapngError("SHB: body shorter than 16 bytes")
            # body[0:4] repeats the byte-order magic.
            expected_magic = (
                BYTE_ORDER_MAGIC_LE if endian == "<" else BYTE_ORDER_MAGIC_BE
            )
            if body[0:4] != expected_magic:
                raise PcapngError("SHB: body byte-order magic does not match header")
            major = int.from_bytes(body[4:6], "little" if endian == "<" else "big")
            if major != 1:
                raise PcapngError(f"SHB: unsupported section version major {major}")
            # body[6:8] is the minor version; body[8:16] is the signed
            # section length in bytes following the SHB (-1 == unknown).
            declared_length = int.from_bytes(
                body[8:16], "little" if endian == "<" else "big", signed=True
            )
            _parse_options(body[16:], endian, "SHB")

            current = _Section(len(sections) + 1, endian, pos, declared_length)
            current.shb_total = total
            sections.append(current)
            pos += total
            continue

        if current is None:
            raise PcapngError("file must begin with a Section Header Block")

        endian = current.endian
        bt = int.from_bytes(block_type, "little" if endian == "<" else "big")
        total, blk_body = _block_envelope(data, pos, endian, f"block 0x{bt:08x}")

        if bt == BT_IDB:
            current.interfaces.append(_parse_idb(blk_body, endian))
        elif bt == BT_EPB:
            _parse_epb(blk_body, endian, current)
        else:
            raise PcapngError(
                f"section {current.number}: only IDB and EPB may follow the SHB "
                f"(got block type 0x{bt:08x})"
            )
        pos += total

    if not sections:
        raise PcapngError("no sections found")
    assert current is not None
    finalise_section(current, len(data))
    return sections
