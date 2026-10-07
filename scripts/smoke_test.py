#!/usr/bin/env python3
"""API smoke test against a running pcapng-audit instance.

Generates two PCAPNG fixtures (mixed section endianness, multiple interfaces,
if_tsresol/if_tsoffset combinations) under samples/ and exercises the audit
endpoint including the reordering-violation path. Exits non-zero on failure.

Usage: smoke_test.py [base_url]   (default http://127.0.0.1:${PORT:-8080})
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.pcapng_builder import epb, idb, section  # noqa: E402

API_PATH = "/api/pcapng/audit"


def check(cond: bool, message: str) -> None:
    if not cond:
        print(f"SMOKE FAIL: {message}", file=sys.stderr)
        raise SystemExit(1)
    print(f"  ok: {message}")


def request(base_url: str, payload: bytes, threshold: int,
            content_type: str = "application/x-pcapng"):
    url = f"{base_url}{API_PATH}?maxBackwardNanoseconds={threshold}"
    req = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": content_type}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def main() -> int:
    base_url = sys.argv[1] if len(sys.argv) > 1 else (
        f"http://127.0.0.1:{os.environ.get('PORT', '8080')}"
    )

    samples_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "..", "samples")
    os.makedirs(samples_dir, exist_ok=True)

    # ---- Fixture 1: clean, mixed-endian, three interfaces -----------------
    le = section(
        [
            idb(if_tsresol=9),                                   # if0 ns
            idb(if_tsresol=6),                                   # if1 us
            idb(if_tsresol=9, snaplen=4),                        # if2 ns snap
            epb(0, 1_000_000_000, b"\x00le-if0"),
            epb(1, 2_000_000, b"\x01le-if1"),                    # us -> 2e9 ns
            epb(2, 2_500_000_000, b"snapXXXXXXXXX", caplen=4, origlen=9),
        ],
        endian="<",
    )
    be = section(
        [
            idb(if_tsresol=9, if_tsoffset=500_000_000, endian=">"),
            epb(0, 2_500_000_000, b"\x02be-if0", endian=">"),   # +5e8 -> 3e9
        ],
        endian=">",
    )
    clean = le + be
    clean_path = os.path.join(samples_dir, "mixed_endian_clean.pcapng")
    with open(clean_path, "wb") as fh:
        fh.write(clean)

    # ---- Fixture 2: reordered, violation expected -------------------------
    bad_le = section(
        [idb(if_tsresol=9),
         epb(0, 4_000_000_000, b"first"),
         epb(0, 3_999_999_000, b"second")],   # 1000 ns backward
        endian="<",
    )
    bad_be = section(
        [idb(if_tsresol=6, endian=">"),
         epb(0, 5_000_000, b"later", endian=">")],
        endian=">",
    )
    reordered = bad_le + bad_be
    reordered_path = os.path.join(samples_dir, "mixed_endian_reordered.pcapng")
    with open(reordered_path, "wb") as fh:
        fh.write(reordered)

    print(f"target: {base_url}")
    print(f"fixtures: {clean_path}, {reordered_path}")

    # ---- Health -------------------------------------------------------------
    with urllib.request.urlopen(f"{base_url}/healthz", timeout=10) as resp:
        check(resp.status == 200, "GET /healthz -> 200")

    # ---- Clean audit --------------------------------------------------------
    status, body = request(base_url, clean, 0)
    check(status == 200, f"clean capture accepted (HTTP {status}: {body})")
    packets = body["packets"]
    check(len(packets) == 4, "four packets reported")
    check([p["section"] for p in packets] == [0, 0, 0, 1],
          "section numbers in capture order")
    check([p["interface"] for p in packets] == [0, 1, 2, 0],
          "interface numbers preserved")
    expected_ts = [1_000_000_000, 2_000_000_000, 2_500_000_000, 3_000_000_000]
    check([p["timestampNanoseconds"] for p in packets] == expected_ts,
          f"canonical nanosecond timestamps {expected_ts}")
    check(packets[0]["sha256"] == hashlib.sha256(b"\x00le-if0").hexdigest(),
          "SHA-256 of first packet")
    check(packets[2]["capturedLength"] == 4
          and packets[2]["originalLength"] == 9,
          "snaplen-captured lengths reported")
    check(body["violation"] is None, "no violation in clean capture")

    # ---- Reordered: threshold allows it, then forbids it -------------------
    status, body = request(base_url, reordered, 1000)
    check(status == 200 and body["violation"] is None,
          "1000 ns backward within threshold=1000")

    status, body = request(base_url, reordered, 999)
    check(status == 200, f"threshold=999 accepted (HTTP {status})")
    v = body["violation"]
    check(v is not None, "violation flagged beyond threshold")
    check(v["index"] == 1 and v["section"] == 0 and v["interface"] == 0,
          "earliest violating packet located (index 1)")
    check(v["backwardNanoseconds"] == 1000,
          f"actual backward amount 1000 ns (got {v and v['backwardNanoseconds']})")
    check(v["timestampNanoseconds"] == 3_999_999_000,
          "violation carries the offending timestamp")

    # ---- Error paths --------------------------------------------------------
    status, body = request(base_url, b"not a pcapng" * 8, 0)
    check(status == 400, f"garbage body rejected (HTTP {status})")

    status, body = request(base_url, clean, -1)
    check(status == 400, "negative threshold rejected")

    status, _ = request(base_url, clean, 0,
                        content_type="application/octet-stream")
    check(status == 415, "wrong Content-Type rejected with 415")

    print("SMOKE OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
