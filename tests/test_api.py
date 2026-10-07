import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "testing"))

from sample import epb, idb, mixed_endian_sample, shb  # noqa: E402

from app.main import MAX_BODY_BYTES, app  # noqa: E402

client = TestClient(app)


def good_capture() -> bytes:
    return (
        shb()
        + idb(tsresol=9)
        + epb(0, 1_000, b"one-one-one")
        + epb(0, 2_000, b"two-two-two")
    )


class TestAuditEndpoint:
    def test_success_shape(self):
        resp = client.post(
            "/api/pcapng/audit?maxBackwardNanoseconds=500",
            content=good_capture(),
            headers={"Content-Type": "application/x-pcapng"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["sectionCount"] == 1
        assert body["packetCount"] == 2
        assert body["maxBackwardNanoseconds"] == 500
        assert body["violation"] is None
        first = body["packets"][0]
        assert set(first) == {
            "section",
            "interface",
            "timestampNs",
            "packetLength",
            "capturedLength",
            "sha256",
        }
        assert first["section"] == 1
        assert first["interface"] == 0
        assert first["timestampNs"] == 1000
        assert first["packetLength"] == 11

    def test_violation_reported(self):
        data = (
            shb()
            + idb(tsresol=9)
            + epb(0, 10_000, b"a")
            + epb(0, 9_000, b"b")
        )
        resp = client.post(
            "/api/pcapng/audit?maxBackwardNanoseconds=500",
            content=data,
            headers={"Content-Type": "application/x-pcapng"},
        )
        assert resp.status_code == 200
        v = resp.json()["violation"]
        assert v["index"] == 1
        assert v["backwardNanoseconds"] == 1000
        assert v["section"] == 1
        assert v["interface"] == 0
        assert v["timestampNs"] == 9000

    def test_missing_content_type(self):
        resp = client.post(
            "/api/pcapng/audit?maxBackwardNanoseconds=0", content=good_capture()
        )
        assert resp.status_code == 415

    def test_wrong_content_type(self):
        resp = client.post(
            "/api/pcapng/audit?maxBackwardNanoseconds=0",
            content=good_capture(),
            headers={"Content-Type": "application/octet-stream"},
        )
        assert resp.status_code == 415

    def test_content_type_with_charset_accepted(self):
        resp = client.post(
            "/api/pcapng/audit?maxBackwardNanoseconds=0",
            content=good_capture(),
            headers={"Content-Type": "application/x-pcapng; charset=binary"},
        )
        assert resp.status_code == 200

    def test_invalid_pcapng(self):
        resp = client.post(
            "/api/pcapng/audit?maxBackwardNanoseconds=0",
            content=b"not a pcapng file at all" * 4,
            headers={"Content-Type": "application/x-pcapng"},
        )
        assert resp.status_code == 422
        assert resp.json()["error"] == "invalid_pcapng"

    def test_body_too_large_by_content_length(self):
        big = b"\x00" * (MAX_BODY_BYTES + 1)
        resp = client.post(
            "/api/pcapng/audit?maxBackwardNanoseconds=0",
            content=big,
            headers={"Content-Type": "application/x-pcapng"},
        )
        assert resp.status_code == 413
        assert resp.json()["limitBytes"] == MAX_BODY_BYTES

    def test_exactly_size_limit_reaches_parser(self):
        # 8 MiB exactly is allowed; invalid bytes must yield 422, not 413.
        boundary = b"\x00" * MAX_BODY_BYTES
        resp = client.post(
            "/api/pcapng/audit?maxBackwardNanoseconds=0",
            content=boundary,
            headers={"Content-Type": "application/x-pcapng"},
        )
        assert resp.status_code == 422

    def test_negative_threshold_rejected(self):
        resp = client.post(
            "/api/pcapng/audit?maxBackwardNanoseconds=-1",
            content=good_capture(),
            headers={"Content-Type": "application/x-pcapng"},
        )
        assert resp.status_code == 422

    def test_missing_threshold_rejected(self):
        resp = client.post(
            "/api/pcapng/audit",
            content=good_capture(),
            headers={"Content-Type": "application/x-pcapng"},
        )
        assert resp.status_code == 422

    def test_mixed_endian_sample_via_http(self):
        resp = client.post(
            "/api/pcapng/audit?maxBackwardNanoseconds=0",
            content=mixed_endian_sample(),
            headers={"Content-Type": "application/x-pcapng"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["sectionCount"] == 2
        assert [p["section"] for p in body["packets"]] == [1, 1, 1, 1, 2]
        assert body["violation"]["backwardNanoseconds"] == 1_000_000

    def test_healthz(self):
        resp = client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


if __name__ == "__main__":  # pragma: no cover
    sys.exit(pytest.main([__file__, "-v"]))
