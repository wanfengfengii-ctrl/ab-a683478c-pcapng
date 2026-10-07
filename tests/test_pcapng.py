"""Unit tests for the strict PCAPNG parser and timestamp conversion."""

from __future__ import annotations

import struct

import pytest

from app.pcapng import PcapngError, parse_pcapng, timestamp_to_ns
from tests.pcapng_builder import (
    BT_SHB,
    block,
    epb,
    idb,
    option,
    pad4,
    section,
)


def build(*blocks_per_section, endian="<"):
    return b"".join(section(list(blks), endian) for blks in blocks_per_section)


# ---------------------------------------------------------------- timestamp

class TestTimestamp:
    def test_default_decimal_microseconds(self):
        assert timestamp_to_ns(1_000_000, 6, 0) == 1_000_000_000
        assert timestamp_to_ns(0, 6, 0) == 0

    def test_decimal_nanoseconds(self):
        assert timestamp_to_ns(123, 9, 0) == 123

    def test_binary_resolution_round_half_to_even(self):
        # 1 unit of 2^-8 s = 3,906,250 ns exactly -> exact, no rounding needed
        assert timestamp_to_ns(1, 0x88, 0) == 3_906_250
        # 1 unit of 2^-7 s = 7,812,500 ns exact
        assert timestamp_to_ns(1, 0x87, 0) == 7_812_500

    def test_decimal_resolution_finer_than_ns_rounds_half_even(self):
        # 10^-10: 1 unit = 0.1 ns
        assert timestamp_to_ns(1, 10, 0) == 0    # 0.1 -> 0
        assert timestamp_to_ns(5, 10, 0) == 0    # 0.5 -> even 0
        assert timestamp_to_ns(6, 10, 0) == 1    # 0.6 -> 1
        assert timestamp_to_ns(15, 10, 0) == 2   # 1.5 -> even 2
        assert timestamp_to_ns(25, 10, 0) == 2   # 2.5 -> even 2
        assert timestamp_to_ns(35, 10, 0) == 4   # 3.5 -> even 4
        # 10^-11: ns = units * 0.01 — same rule, different scale
        assert timestamp_to_ns(50, 11, 0) == 0   # 0.5 -> even 0
        assert timestamp_to_ns(150, 11, 0) == 2  # 1.5 -> even 2
        assert timestamp_to_ns(250, 11, 0) == 2  # 2.5 -> even 2
        assert timestamp_to_ns(350, 11, 0) == 4  # 3.5 -> even 4
        # exact cases survive regardless
        assert timestamp_to_ns(10, 10, 0) == 1   # 1.0 ns
        assert timestamp_to_ns(100, 11, 0) == 1  # 1.0 ns

    def test_binary_half_to_even_ties(self):
        # 2^-10: 1e9/1024 = 976562.5 -> tie -> even 976562
        assert timestamp_to_ns(1, 0x8A, 0) == 976562
        # 3 units = 2929687.5 -> quotient odd -> round up to 2929688
        assert timestamp_to_ns(3, 0x8A, 0) == 2929688
        # 2^-8: 3906250 exact
        assert timestamp_to_ns(1, 0x88, 0) == 3_906_250

    def test_offset_applied_in_resolution_units_before_scaling(self):
        # if_tsoffset=15 at 10^-10: (0+15)*0.1 ns? 15 * 10^-10 = 1.5 ns
        # -> round half to even = 2
        assert timestamp_to_ns(0, 10, 15) == 2  # 1.5 -> 2
        assert timestamp_to_ns(0, 6, -500_000) == -500_000_000

    @pytest.mark.parametrize("res", [6, 9, 0x89, 0x81])
    def test_negative_timestamp_via_offset(self, res):
        v = timestamp_to_ns(0, res, -1)
        assert v < 0

    def test_zero_resolution_rejected(self):
        with pytest.raises(PcapngError):
            timestamp_to_ns(1, 0, 0)


# ----------------------------------------------------------------- parsing

class TestParser:
    def test_minimal_file_one_packet(self):
        data = build((idb(), epb(0, 1_000_000, b"abc")),)
        pkts = parse_pcapng(data)
        assert len(pkts) == 1
        assert pkts[0].section_index == 0
        assert pkts[0].interface_id == 0
        assert pkts[0].timestamp_ns == 1_000_000_000
        assert pkts[0].captured_length == 3
        assert pkts[0].digest == __import__("hashlib").sha256(b"abc").hexdigest()

    def test_mixed_endian_sections(self):
        sec_le = section([idb(endian="<"), epb(0, 2_000_000, b"le", endian="<")],
                         endian="<")
        sec_be = section([idb(endian=">"), epb(0, 3_000_000, b"be", endian=">")],
                         endian=">")
        pkts = parse_pcapng(sec_le + sec_be)
        assert [p.section_index for p in pkts] == [0, 1]
        assert pkts[1].timestamp_ns == 3_000_000_000
        assert pkts[1].digest == __import__("hashlib").sha256(b"be").hexdigest()

    def test_multiple_interfaces(self):
        data = build((idb(if_tsresol=9), idb(if_tsresol=6),
                      epb(0, 100, b"a"), epb(1, 200, b"bb")),)
        pkts = parse_pcapng(data)
        assert pkts[0].interface_id == 0
        assert pkts[0].timestamp_ns == 100
        assert pkts[1].interface_id == 1
        assert pkts[1].timestamp_ns == 200_000

    def test_captured_exceeds_original_rejected(self):
        bad = section([idb(), epb(0, 1, b"abc", caplen=3, origlen=2)])
        with pytest.raises(PcapngError, match="captured length exceeds original"):
            parse_pcapng(bad)

    def test_snaplen_enforced(self):
        bad = section([idb(snaplen=2), epb(0, 1, b"abc")])
        with pytest.raises(PcapngError, match="snaplen"):
            parse_pcapng(bad)
        ok = section([idb(snaplen=3), epb(0, 1, b"abc")])
        assert len(parse_pcapng(ok)) == 1

    def test_bad_interface_reference(self):
        bad = section([idb(), epb(1, 1, b"x")])
        with pytest.raises(PcapngError, match="undefined interface"):
            parse_pcapng(bad)

    def test_block_length_mismatch_head_tail(self):
        e = bytearray(epb(0, 1, b"x"))
        e[-4:] = struct.pack("<I", 999)
        bad = section([idb(), bytes(e)])
        with pytest.raises(PcapngError, match="trailing block length"):
            parse_pcapng(bad)

    def test_bad_shb_magic(self):
        good = section([idb()])
        bad = good[:8] + struct.pack("<I", 0xDEADBEEF) + good[12:]
        with pytest.raises(PcapngError, match="byte-order magic"):
            parse_pcapng(bad)

    def test_file_must_begin_with_shb(self):
        with pytest.raises(PcapngError, match="begin with"):
            parse_pcapng(b"\x01\x00\x00\x00" + b"\x00" * 40)

    def test_too_many_sections(self):
        data = b"".join(section([idb()]) for _ in range(9))
        with pytest.raises(PcapngError, match="at most 8"):
            parse_pcapng(data)

    def test_eight_sections_accepted(self):
        data = b"".join(
            section([idb(if_tsresol=9), epb(0, i, bytes([65 + i]))])
            for i in range(8)
        )
        pkts = parse_pcapng(data)
        assert [p.section_index for p in pkts] == list(range(8))

    def test_interface_scope_is_per_section(self):
        # Section 0 defines interface 0; section 1 has no IDB, so an EPB
        # referencing interface 0 there must fail.
        good = section([idb(), epb(0, 1, b"a")])
        bad = section([epb(0, 2, b"b")])
        with pytest.raises(PcapngError, match="undefined interface"):
            parse_pcapng(good + bad)

    def test_empty_section_is_structurally_valid(self):
        pkts = parse_pcapng(section([]) + section([idb(), epb(0, 1, b"x")]))
        assert len(pkts) == 1
        assert pkts[0].section_index == 1

    def test_unknown_block_type_rejected(self):
        # Simple Packet Block (type 3) not allowed.
        spb_body = pad4(struct.pack("<I", 5) + b"hello")
        spb = block(3, spb_body, "<")
        with pytest.raises(PcapngError, match="unsupported block type"):
            parse_pcapng(section([idb(), spb]))

    def test_epb_padding_must_be_zero(self):
        # caplen 5 -> 3 pad bytes; make them non-zero.
        bad = section([idb(), epb(0, 1, b"AAAAA",
                                  padding_bytes=b"\x01\x02\x03")])
        with pytest.raises(PcapngError, match="padding must be zero"):
            parse_pcapng(bad)

    def test_packet_digest_covers_captured_only(self):
        data = build((idb(snaplen=3),
                      epb(0, 1, b"abcdef", caplen=3, origlen=6)),)
        pkts = parse_pcapng(data)
        assert pkts[0].digest == __import__("hashlib").sha256(b"abc").hexdigest()

    def test_section_length_field_validated(self):
        good = section([idb()])
        # Locate the section-length int64 at SHB body offset 8.
        bad = good[:16] + struct.pack("<q", 42) + good[24:]
        with pytest.raises(PcapngError, match="section length"):
            parse_pcapng(bad)

    def test_section_length_unknown_accepted(self):
        body = pad4(struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
        shb_block = block(BT_SHB, body, "<")
        pkts = parse_pcapng(shb_block + section([idb(), epb(0, 1, b"z")]))
        assert len(pkts) == 1

    def test_truncated_block(self):
        good = section([idb(), epb(0, 1, b"zzzz")])
        with pytest.raises(PcapngError):
            parse_pcapng(good[:-6])

    def test_bad_option_padding(self):
        # 1-byte option value requires 3 zero pad bytes; corrupt one.
        good = bytearray(idb(if_tsresol=9))
        # find option bytes near the end: ...code(2) len(2) value(1) pad(3) tail
        idx = good.rfind(b"\x09\x00\x01\x00")
        assert idx >= 0
        good[idx + 5] = 0xFF
        with pytest.raises(PcapngError, match="padding must be zero"):
            parse_pcapng(section([bytes(good)]))

    def test_epb_with_options(self):
        opts = option(2, b"eth0")
        data = build((idb(), epb(0, 1_000_000, b"pkt", options=opts)),)
        pkts = parse_pcapng(data)
        assert len(pkts) == 1
        assert pkts[0].digest == __import__("hashlib").sha256(b"pkt").hexdigest()

    def test_multiple_if_tsoffset_rejected(self):
        opts = (struct.pack("<HHq", 14, 8, 100)
                + struct.pack("<HHq", 14, 8, 200))
        body = pad4(struct.pack("<HHI", 1, 0, 0) + opts)
        with pytest.raises(PcapngError, match="if_tsoffset"):
            parse_pcapng(section([block(1, body, "<")]))

    def test_unsupported_media_is_a_server_concern(self):
        # Parser-level sanity that garbage fails cleanly.
        with pytest.raises(PcapngError):
            parse_pcapng(b"not a pcapng file at all" * 3)
