"""End-to-end tests for POST /api/pcapng/audit over real HTTP."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from app.server import AUDIT_PATH, AuditHandler
from tests.pcapng_builder import epb, idb, section


@pytest.fixture(scope="module")
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), AuditHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address
    yield f"http://{host}:{port}"
    httpd.shutdown()
    httpd.server_close()


def post(server, data, threshold=0, content_type="application/x-pcapng",
         query=None):
    url = f"{server}{AUDIT_PATH}?" + (
        query if query is not None else f"maxBackwardNanoseconds={threshold}"
    )
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": content_type}, method="POST"
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def mixed_endian_capture():
    # LE section: ns-resolution interface + default us interface, in order.
    le = section(
        [
            idb(if_tsresol=9),
            idb(),
            epb(0, 1_000_000_000, b"le-ns"),
            epb(1, 2_000_000, b"le-us"),  # us-resolution: 2e6 units -> 2e9 ns
        ],
        endian="<",
    )
    # BE section: one interface with a negative offset.
    be = section(
        [idb(if_tsresol=9, if_tsoffset=500, endian=">"),
         epb(0, 2_999_999_500, b"be", endian=">")],
        endian=">",
    )
    return le + be


class TestAuditAPI:
    def test_healthz(self, server):
        with urllib.request.urlopen(f"{server}/healthz") as resp:
            assert resp.status == 200
            assert json.loads(resp.read())["status"] == "ok"

    def test_mixed_endian_success(self, server):
        status, body = post(server, mixed_endian_capture(), threshold=10)
        assert status == 200, body
        packets = body["packets"]
        assert len(packets) == 3
        assert packets[0]["section"] == 0
        assert packets[0]["timestampNanoseconds"] == 1_000_000_000
        assert packets[1]["timestampNanoseconds"] == 2_000_000_000
        assert packets[2]["section"] == 1
        # 2,999,999,500 + offset 500 -> 3,000,000,000 ns
        assert packets[2]["timestampNanoseconds"] == 3_000_000_000
        for p in packets:
            assert len(p["sha256"]) == 64
        assert body["violation"] is None

    def test_monotonic_with_threshold_zero(self, server):
        data = section([idb(if_tsresol=9),
                        epb(0, 100, b"a"), epb(0, 200, b"bb")])
        status, body = post(server, data, threshold=0)
        assert status == 200
        assert body["violation"] is None

    def test_backward_within_threshold_allowed(self, server):
        data = section([idb(if_tsresol=9),
                        epb(0, 1000, b"a"), epb(0, 995, b"b")])
        status, body = post(server, data, threshold=5)
        assert status == 200
        assert body["violation"] is None  # exactly 5 ns backward == allowed

    def test_backward_beyond_threshold_flags_earliest(self, server):
        data = section([idb(if_tsresol=9),
                        epb(0, 1000, b"a"),
                        epb(0, 994, b"b"),   # -6, earliest violation
                        epb(0, 10, b"c")])   # also bad, must not be reported
        status, body = post(server, data, threshold=5)
        assert status == 200
        v = body["violation"]
        assert v is not None
        assert v["index"] == 1
        assert v["backwardNanoseconds"] == 6
        assert v["timestampNanoseconds"] == 994

    def test_representation_artifacts_do_not_trigger(self, server):
        # Same instant on us vs ns interfaces and different endianness must
        # not appear as a backward jump once normalized.
        le = section([idb(if_tsresol=9), epb(0, 5_000, b"x")], endian="<")
        be = section([idb(if_tsresol=6, if_tsoffset=0, endian=">"),
                      epb(0, 5, b"y", endian=">")], endian=">")
        status, body = post(server, le + be, threshold=0)
        assert status == 200
        assert body["violation"] is None

    def test_bad_content_type(self, server):
        status, body = post(server, b"x", content_type="application/octet-stream")
        assert status == 415
        assert "Content-Type" in body["error"]

    def test_missing_threshold(self, server):
        status, _ = post(server, section([idb()]), query="")
        assert status == 400

    def test_negative_threshold(self, server):
        status, _ = post(server, section([idb()]),
                         query="maxBackwardNanoseconds=-1")
        assert status == 400

    def test_non_integer_threshold(self, server):
        status, _ = post(server, section([idb()]),
                         query="maxBackwardNanoseconds=1.5")
        assert status == 400

    def test_malformed_pcapng(self, server):
        status, body = post(server, b"\x00" * 64, threshold=0)
        assert status == 400
        assert "error" in body

    def test_nine_sections_rejected(self, server):
        data = b"".join(section([idb()]) for _ in range(9))
        status, body = post(server, data, threshold=0)
        assert status == 400
        assert "8 sections" in body["error"]

    def test_body_too_large(self, server):
        big = b"\x00" * (8 * 1024 * 1024 + 1)
        status, body = post(server, big, threshold=0)
        assert status == 413
        assert "8 MiB" in body["error"]

    def test_unknown_route(self, server):
        req = urllib.request.Request(f"{server}/nope", data=b"", method="POST")
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(req)
        assert exc.value.code == 404
