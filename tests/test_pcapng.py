import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "testing"))

from sample import BT_EPB, BT_IDB, BT_SHB, epb, idb, mixed_endian_sample, rounding_sample, shb  # noqa: E402

from app.audit import audit_pcapng  # noqa: E402
from app.pcapng import PcapngError, parse_pcapng  # noqa: E402


class TestTimestamps:
    def test_default_resolution_microseconds(self):
        data = shb() + idb() + epb(0, 1_234_567, b"abc")
        result = audit_pcapng(data, 0)
        assert result["packets"][0]["timestampNs"] == 1_234_567_000

    def test_explicit_zero_resolution_is_seconds(self):
        # An explicit if_tsresol=0 means 10^0 s units (one second per tick),
        # which differs from the missing-option default of microseconds.
        data = shb() + idb(tsresol=0) + epb(0, 3, b"abc")
        result = audit_pcapng(data, 0)
        assert result["packets"][0]["timestampNs"] == 3_000_000_000

    def test_nanosecond_resolution(self):
        data = shb() + idb(tsresol=9) + epb(0, 1_234_567_899, b"abc")
        result = audit_pcapng(data, 0)
        assert result["packets"][0]["timestampNs"] == 1_234_567_899

    def test_tsoffset_applied(self):
        data = shb() + idb(tsresol=9, tsoffset=5_000_000_000) + epb(0, 100, b"x")
        result = audit_pcapng(data, 0)
        assert result["packets"][0]["timestampNs"] == 5_000_000_100

    def test_binary_resolution_round_half_even(self):
        # 2^-11 s per tick = 1e9/2048 ns = 488.28125 ... per tick is
        # actually 488281.25 ns. Values hit .25/.75/.5 fractions.
        result = audit_pcapng(rounding_sample(), 10**18)
        ts = [p["timestampNs"] for p in result["packets"]]
        # 1 tick -> 488281.25 -> 488281 (nearest); 2 -> 976562.5 -> 976562
        # (tie to even); 3 -> 1464843.75 -> 1464844; 6 -> 2929687.5 ->
        # 2929688 (tie to even).
        assert ts == [0, 488281, 976562, 1464844, 2929688]

    def test_decimal_higher_resolution_half_even(self):
        # 10^-7 s units: 15 units -> 1500 ns exact; 5 units -> 500 ns exact.
        # Use 10^-10 s: 15 ticks = 1.5 ns -> tie -> 2 (even), 25 -> 2.5 -> 2.
        data = shb() + idb(tsresol=10) + epb(0, 15, b"a") + epb(0, 25, b"b")
        result = audit_pcapng(data, 10**18)
        ts = [p["timestampNs"] for p in result["packets"]]
        assert ts == [2, 2]


class TestViolation:
    def test_forward_order_no_violation(self):
        data = (
            shb()
            + idb(tsresol=9)
            + epb(0, 100, b"a")
            + epb(0, 200, b"b")
        )
        result = audit_pcapng(data, 0)
        assert result["violation"] is None

    def test_backward_within_threshold_ok(self):
        data = (
            shb()
            + idb(tsresol=9)
            + epb(0, 200, b"a")
            + epb(0, 150, b"b")
        )
        result = audit_pcapng(data, 50)
        assert result["violation"] is None

    def test_backward_at_threshold_boundary_is_ok(self):
        data = (
            shb()
            + idb(tsresol=9)
            + epb(0, 200, b"a")
            + epb(0, 100, b"b")
        )
        result = audit_pcapng(data, 100)
        assert result["violation"] is None

    def test_backward_exceeds_threshold_flags_earliest(self):
        data = (
            shb()
            + idb(tsresol=9)
            + epb(0, 200, b"a")
            + epb(0, 100, b"b")
            + epb(0, 50, b"c")
        )
        result = audit_pcapng(data, 50)
        v = result["violation"]
        assert v is not None
        assert v["index"] == 1
        assert v["backwardNanoseconds"] == 100
        assert v["timestampNs"] == 100
        assert v["sha256"] == result["packets"][1]["sha256"]

    def test_first_pair_ok_second_bad(self):
        data = (
            shb()
            + idb(tsresol=9)
            + epb(0, 100, b"a")
            + epb(0, 90, b"b")   # 10 back, allowed
            + epb(0, 30, b"c")   # 60 back, violation
        )
        result = audit_pcapng(data, 50)
        assert result["violation"]["index"] == 2
        assert result["violation"]["backwardNanoseconds"] == 60

    def test_violation_spans_interfaces_with_different_resolutions(self):
        data = (
            shb()
            + idb(tsresol=6)
            + idb(tsresol=9, tsoffset=0)
            + epb(0, 2_000, b"a")       # 2 ms
            + epb(1, 1_500_000, b"b")   # 1.5 ms -> 500 us back
        )
        result = audit_pcapng(data, 100_000)
        assert result["violation"] is not None
        assert result["violation"]["backwardNanoseconds"] == 500_000


class TestMixedEndian:
    def test_mixed_sections(self):
        result = audit_pcapng(mixed_endian_sample(), 500_000)
        assert result["sectionCount"] == 2
        assert result["packetCount"] == 5
        ts = [p["timestampNs"] for p in result["packets"]]
        assert ts == [
            1_000_000_000,
            1_500_000_000,
            1_600_000_000,
            1_599_000_000,
            2_000_000_000,
        ]
        interfaces = [p["interface"] for p in result["packets"]]
        assert interfaces == [0, 0, 1, 1, 0]
        sections = [p["section"] for p in result["packets"]]
        assert sections == [1, 1, 1, 1, 2]

    def test_mixed_sample_violation_is_one_millisecond(self):
        result = audit_pcapng(mixed_endian_sample(), 0)
        v = result["violation"]
        assert v is not None
        assert v["index"] == 3
        assert v["backwardNanoseconds"] == 1_000_000
        # Exactly at threshold (1 ms) must not flag.
        assert audit_pcapng(mixed_endian_sample(), 1_000_000)["violation"] is None


class TestLengthsAndHashing:
    def test_packet_length_and_sha(self):
        import hashlib

        pkt = bytes(range(32))
        data = shb() + idb() + epb(0, 1, pkt)
        result = audit_pcapng(data, 0)
        p = result["packets"][0]
        assert p["packetLength"] == 32
        assert p["capturedLength"] == 32
        assert p["sha256"] == hashlib.sha256(pkt).hexdigest()

    def test_truncated_capture_smaller_than_orig(self):
        pkt = b"z" * 10
        data = shb() + idb(snaplen=64) + epb(0, 1, pkt, orig_len=1500)
        result = audit_pcapng(data, 0)
        p = result["packets"][0]
        assert p["capturedLength"] == 10
        assert p["packetLength"] == 1500

    def test_caplen_exceeds_origlen_rejected(self):
        pkt = b"z" * 10
        data = shb() + idb() + epb(0, 1, pkt, orig_len=5)
        with pytest.raises(PcapngError, match="captured length exceeds original"):
            parse_pcapng(data)

    def test_caplen_exceeds_snaplen_rejected(self):
        pkt = b"z" * 10
        data = shb() + idb(snaplen=8) + epb(0, 1, pkt, orig_len=10)
        with pytest.raises(PcapngError, match="snaplen"):
            parse_pcapng(data)

    def test_unbounded_snaplen_zero(self):
        data = shb() + idb(snaplen=0) + epb(0, 1, b"q" * 200, orig_len=200)
        assert audit_pcapng(data, 0)["packetCount"] == 1


class TestStructuralValidation:
    def test_empty(self):
        with pytest.raises(PcapngError):
            parse_pcapng(b"")

    def test_does_not_start_with_shb(self):
        data = idb()
        with pytest.raises(PcapngError, match="begin with"):
            parse_pcapng(data)

    def test_bad_byte_order_magic(self):
        data = shb()
        broken = data[:12] + b"zzzz" + data[16:]
        # Break the magic inside the SHB body too.
        broken = broken[:8] + b"zzzz" + broken[12:]
        with pytest.raises(PcapngError, match="byte-order magic"):
            parse_pcapng(broken)

    def test_mismatched_trailing_block_length(self):
        data = shb()
        broken = data[:-4] + (len(data) + 4).to_bytes(4, "little")
        with pytest.raises(PcapngError, match="trailing block length"):
            parse_pcapng(broken)

    def test_block_past_eof(self):
        data = shb()
        with pytest.raises(PcapngError, match="past end of file"):
            parse_pcapng(data[:-4])

    def test_total_length_not_multiple_of_four(self):
        body = (
            b"\x4d\x3c\x2b\x1a"
            + (1).to_bytes(2, "little")
            + (0).to_bytes(2, "little")
            + (-1).to_bytes(8, "little", signed=True)
            + b"\x00" * 3
        )
        bad = (
            BT_SHB.to_bytes(4, "little")
            + (12 + len(body)).to_bytes(4, "little")
            + body
            + (12 + len(body)).to_bytes(4, "little")
        )
        with pytest.raises(PcapngError, match="total length"):
            parse_pcapng(bad)

    def test_unknown_block_type_rejected(self):
        data = shb() + b"\x09\x00\x00\x00" + (12).to_bytes(4, "little") * 2
        with pytest.raises(PcapngError, match="only IDB and EPB"):
            parse_pcapng(data)

    def test_interface_id_without_idb(self):
        data = shb() + epb(0, 1, b"a")
        with pytest.raises(PcapngError, match="interface id"):
            parse_pcapng(data)

    def test_interface_id_out_of_range(self):
        data = shb() + idb() + epb(1, 1, b"a")
        with pytest.raises(PcapngError, match="interface id"):
            parse_pcapng(data)

    def test_epb_packet_truncated(self):
        # Valid outer envelope (matching lengths/trailer), but the body
        # carries fewer packet bytes than caplen promises.
        body = (
            (0).to_bytes(4, "little")  # interface id
            + (0).to_bytes(4, "little")  # ts high
            + (1).to_bytes(4, "little")  # ts low
            + (16).to_bytes(4, "little")  # caplen
            + (16).to_bytes(4, "little")  # origlen
            + b"abcdefgh"  # only 8 of 16 bytes
        )
        total = 12 + len(body)
        malformed = (
            BT_EPB.to_bytes(4, "little")
            + total.to_bytes(4, "little")
            + body
            + total.to_bytes(4, "little")
        )
        good_idb = idb()
        with pytest.raises(PcapngError, match="packet data is truncated"):
            parse_pcapng(shb() + good_idb + malformed)

    def test_bad_option_length(self):
        data = shb() + idb(extra_options=[(2, b"short")])
        # Corrupt option length to exceed block.
        corrupted = bytearray(data)
        # Locate the IDB and inflate its option length field.
        shb_len = int.from_bytes(data[4:8], "little")
        corrupted[shb_len + 8 + 8 + 2] = 0xFF
        with pytest.raises(PcapngError):
            parse_pcapng(bytes(corrupted))

    def test_option_region_unaligned(self):
        # Aligned block overall, but an option declares more bytes than the
        # region contains: an option-boundary violation.
        region = b"\x01\x00\x05\x00"  # code=1, length=5, no room at all
        body = (
            (1).to_bytes(2, "little")
            + (0).to_bytes(2, "little")
            + (0).to_bytes(4, "little")
            + region
        )
        assert len(body) % 4 == 0
        total = 12 + len(body)
        block = (
            BT_IDB.to_bytes(4, "little")
            + total.to_bytes(4, "little")
            + body
            + total.to_bytes(4, "little")
        )
        with pytest.raises(PcapngError, match="runs past block boundary"):
            parse_pcapng(shb() + block)

    def test_too_many_sections(self):
        data = b"".join(shb() for _ in range(9))
        with pytest.raises(PcapngError, match="more than 8 sections"):
            parse_pcapng(data)

    def test_eight_sections_allowed(self):
        data = b"".join(shb() for _ in range(8))
        assert len(parse_pcapng(data)) == 8

    def test_extreme_decimal_tsresol_is_valid_and_rounds(self):
        # Resolution 25 means 10^-25 s units (10^-16 ns per unit); the raw
        # timestamp is a uint64 so values must stay below 2^64.
        # 10^16 units make exactly one nanosecond; 5*10^15 units make half a
        # nanosecond -> tie -> round half to even (0).
        data = shb() + idb(tsresol=25) + epb(0, 10**16, b"a") + epb(0, 5 * 10**15, b"b")
        result = audit_pcapng(data, 0)
        ts = [p["timestampNs"] for p in result["packets"]]
        assert ts == [1, 0]

    def test_bad_tsresol_option_width(self):
        data = shb() + idb(extra_options=[])
        # Inject a malformed if_tsresol with two value bytes.
        from sample import _option, _u16

        options = _option(9, b"\x06\x00", "little") + _option(0, b"", "little")
        body = _u16(1, "little") + _u16(0, "little") + (0).to_bytes(4, "little") + options
        total = 12 + len(body)
        from sample import BT_IDB

        block = (
            BT_IDB.to_bytes(4, "little")
            + total.to_bytes(4, "little")
            + body
            + total.to_bytes(4, "little")
        )
        with pytest.raises(PcapngError, match="if_tsresol option"):
            parse_pcapng(shb() + block)

    def test_declared_section_length_must_match(self):
        blocks = idb() + epb(0, 1, b"abc")
        # Correct declaration: bytes following the SHB.
        good = shb(section_length=len(blocks)) + blocks
        assert len(parse_pcapng(good)) == 1

        # Wrong declaration in a single-section file.
        bad = shb(section_length=len(blocks) - 4) + blocks
        with pytest.raises(PcapngError, match="declared section length"):
            parse_pcapng(bad)

    def test_declared_section_length_per_section_multisection(self):
        first_blocks = idb() + epb(0, 1, b"abc")
        second_blocks = idb(endian="big") + epb(0, 2, b"defg", endian="big")
        good = (
            shb(section_length=len(first_blocks))
            + first_blocks
            + shb("big", section_length=len(second_blocks))
            + second_blocks
        )
        sections = parse_pcapng(good)
        assert len(sections) == 2
        assert sections[1].endian == ">"
        result = audit_pcapng(good, 0)
        assert result["packets"][1]["timestampNs"] == 2000

    def test_idb_reserved_must_be_zero(self):
        from sample import _option, _u16

        options = _option(0, b"", "little")
        body = _u16(1, "little") + _u16(0x1234, "little") + (0).to_bytes(4, "little") + options
        total = 12 + len(body)
        block = (
            BT_IDB.to_bytes(4, "little")
            + total.to_bytes(4, "little")
            + body
            + total.to_bytes(4, "little")
        )
        with pytest.raises(PcapngError, match="reserved field"):
            parse_pcapng(shb() + block)

    def test_options_must_end_with_endofopt(self):
        # Aligned region holding one option but no terminating opt_endofopt.
        region = (2).to_bytes(2, "little") + (4).to_bytes(2, "little") + b"abcd"
        body = (
            (1).to_bytes(2, "little")
            + (0).to_bytes(2, "little")
            + (0).to_bytes(4, "little")
            + region
        )
        total = 12 + len(body)
        block = (
            BT_IDB.to_bytes(4, "little")
            + total.to_bytes(4, "little")
            + body
            + total.to_bytes(4, "little")
        )
        with pytest.raises(PcapngError, match="opt_endofopt"):
            parse_pcapng(shb() + block)

    def test_endofopt_with_nonzero_length_rejected(self):
        # code=0 (endofopt) but length=2; pad to a 4-aligned region.
        region = (
            (0).to_bytes(2, "little")
            + (2).to_bytes(2, "little")
            + b"\x00" * 2  # option value
            + b"\x00" * 2  # option padding -> whole option is 8 bytes
        )
        assert len(region) % 4 == 0
        body = (
            (1).to_bytes(2, "little")
            + (0).to_bytes(2, "little")
            + (0).to_bytes(4, "little")
            + region
        )
        total = 12 + len(body)
        assert total % 4 == 0
        block = (
            BT_IDB.to_bytes(4, "little")
            + total.to_bytes(4, "little")
            + body
            + total.to_bytes(4, "little")
        )
        with pytest.raises(PcapngError, match="opt_endofopt must carry zero"):
            parse_pcapng(shb() + block)


class TestNegativeThreshold:
    def test_negative_rejected(self):
        with pytest.raises(ValueError):
            audit_pcapng(shb(), -1)
