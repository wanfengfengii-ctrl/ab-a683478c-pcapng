#!/usr/bin/env python3
"""Live API smoke test for POST /api/pcapng/audit.

Talks to a running server (BASE_URL env var, default http://127.0.0.1:8080)
over plain HTTP using only the standard library.  Exits non-zero if any
check fails, so container orchestration can report the result.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "testing"))

from sample import epb, idb, mixed_endian_sample, rounding_sample, shb  # noqa: E402

BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:8080").rstrip("/")
AUDIT_URL = f"{BASE_URL}/api/pcapng/audit"

_failures = []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {name}" + (f" -- {detail}" if detail and not condition else ""))
    if not condition:
        _failures.append(name)


def request_audit(payload: bytes, threshold: int, content_type: str = "application/x-pcapng"):
    url = f"{AUDIT_URL}?maxBackwardNanoseconds={threshold}"
    req = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={"Content-Type": content_type},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())


def get_health() -> int:
    try:
        with urllib.request.urlopen(f"{BASE_URL}/healthz", timeout=10) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code


def main() -> int:
    print(f"Smoke testing PCAPNG audit API at {BASE_URL}")

    check("health endpoint returns 200", get_health() == 200)

    # --- Mixed-endian file: little-endian section then big-endian section ---
    sample = mixed_endian_sample()
    code, body = request_audit(sample, threshold=0)
    check("mixed-endian file accepted", code == 200, f"status={code} body={body}")
    if code == 200:
        check("two sections parsed", body["sectionCount"] == 2)
        check("five packets parsed", body["packetCount"] == 5)
        ts = [p["timestampNs"] for p in body["packets"]]
        expected_ts = [
            1_000_000_000,
            1_500_000_000,
            1_600_000_000,
            1_599_000_000,
            2_000_000_000,
        ]
        check("canonical timestamps across byte orders", ts == expected_ts, f"{ts}")
        check(
            "packet ordering/sections",
            [p["section"] for p in body["packets"]] == [1, 1, 1, 1, 2],
        )
        v = body["violation"]
        check("earliest violation located at packet index 3", bool(v) and v["index"] == 3)
        check(
            "reported backwards delta is exactly 1 ms",
            bool(v) and v["backwardNanoseconds"] == 1_000_000,
            f"{v}",
        )
        expected_shas = [
            hashlib.sha256(bytes([c]) * n).hexdigest()
            for c, n in ((0xAA, 4), (0xBB, 5), (0xCC, 6), (0xDD, 7), (0xEE, 8))
        ]
        check(
            "sha256 per packet in capture order",
            [p["sha256"] for p in body["packets"]] == expected_shas,
        )

    # Same capture, threshold exactly equal to the 1 ms delta: must pass.
    code, body = request_audit(sample, threshold=1_000_000)
    check(
        "delta at threshold boundary is allowed",
        code == 200 and body["violation"] is None,
        f"status={code} body={body}",
    )

    # --- Pure big-endian section must decode identically ---
    be = (
        shb("big")
        + idb(tsresol=9, endian="big")
        + epb(0, 42_000_000_000, b"big-endian", endian="big")
    )
    code, body = request_audit(be, threshold=0)
    check(
        "big-endian-only file decodes correctly",
        code == 200 and body["packets"][0]["timestampNs"] == 42_000_000_000,
        f"status={code} body={body}",
    )

    # --- Half-even rounding over binary resolution ---
    code, body = request_audit(rounding_sample(), threshold=10**18)
    ts = [p["timestampNs"] for p in body["packets"]] if code == 200 else []
    check(
        "round-half-to-even nanoseconds",
        ts == [0, 488281, 976562, 1464844, 2929688],
        f"{ts}",
    )

    # --- Error handling ---
    code, body = request_audit(sample, threshold=0, content_type="text/plain")
    check("wrong content type -> 415", code == 415, f"status={code}")

    code, body = request_audit(b"definitely not pcapng" * 8, threshold=0)
    check("garbage payload -> 422", code == 422, f"status={code}")

    code, body = request_audit(b"\x00" * (8 * 1024 * 1024 + 1), threshold=0)
    check("oversized body -> 413", code == 413, f"status={code}")

    url = f"{AUDIT_URL}?maxBackwardNanoseconds=-7"
    req = urllib.request.Request(
        url, data=shb(), method="POST",
        headers={"Content-Type": "application/x-pcapng"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            code = resp.status
    except urllib.error.HTTPError as exc:
        code = exc.code
    check("negative threshold -> 422", code == 422, f"status={code}")

    print()
    if _failures:
        print(f"SMOKE FAILED: {len(_failures)} check(s): {', '.join(_failures)}")
        return 1
    print("SMOKE OK: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
