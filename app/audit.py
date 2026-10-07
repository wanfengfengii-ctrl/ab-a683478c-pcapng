"""Capture-order timestamp audit built on :mod:`app.pcapng`."""

from __future__ import annotations

from typing import List, Optional

from .pcapng import PcapngError, parse_pcapng


def audit_pcapng(data: bytes, max_backward_ns: int) -> dict:
    """Parse ``data`` and flag the earliest excessive backwards time jump.

    Packets are returned in global capture order (sections and blocks in
    file order).  For every adjacent pair whose timestamp moves backwards
    by more than ``max_backward_ns``, the first (earliest) offending packet
    is reported together with the actual backwards delta.
    """
    if max_backward_ns < 0:
        raise ValueError("maxBackwardNanoseconds must be non-negative")

    sections = parse_pcapng(data)

    packets: List[dict] = []
    for section in sections:
        packets.extend(section.packets)

    violation: Optional[dict] = None
    for index in range(1, len(packets)):
        previous = packets[index - 1]["timestampNs"]
        current = packets[index]["timestampNs"]
        if current < previous:
            backward = previous - current
            if backward > max_backward_ns:
                offending = packets[index]
                violation = {
                    "index": index,
                    "section": offending["section"],
                    "interface": offending["interface"],
                    "timestampNs": offending["timestampNs"],
                    "packetLength": offending["packetLength"],
                    "sha256": offending["sha256"],
                    "previousTimestampNs": previous,
                    "backwardNanoseconds": backward,
                }
                break

    return {
        "sectionCount": len(sections),
        "packetCount": len(packets),
        "maxBackwardNanoseconds": max_backward_ns,
        "packets": [
            {
                "section": p["section"],
                "interface": p["interface"],
                "timestampNs": p["timestampNs"],
                "packetLength": p["packetLength"],
                "capturedLength": p["capturedLength"],
                "sha256": p["sha256"],
            }
            for p in packets
        ],
        "violation": violation,
    }


__all__ = ["PcapngError", "audit_pcapng"]
