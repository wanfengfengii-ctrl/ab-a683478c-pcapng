"""HTTP entrypoint for the PCAPNG audit API.

POST /api/pcapng/audit?maxBackwardNanoseconds=<non-negative int>
    Body: raw ``application/x-pcapng`` capture, at most 8 MiB.

GET  /healthz -> liveness probe target.
"""

from __future__ import annotations

import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from .pcapng import PcapngError, parse_pcapng

MAX_BODY_BYTES = 8 * 1024 * 1024
CONTENT_TYPE = "application/x-pcapng"
AUDIT_PATH = "/api/pcapng/audit"


def audit(data: bytes, max_backward_ns: int) -> dict:
    packets = parse_pcapng(data)
    result_packets = [
        {
            "section": p.section_index,
            "interface": p.interface_id,
            "timestampNanoseconds": p.timestamp_ns,
            "capturedLength": p.captured_length,
            "originalLength": p.original_length,
            "sha256": p.digest,
        }
        for p in packets
    ]
    violation = None
    # Adjacency is evaluated in capture order across the normalized stream:
    # per-interface resolution/offset and per-section byte order have already
    # been reduced to a common nanosecond clock, so a drop here is real
    # reordering rather than an artifact of representation.
    for i in range(1, len(packets)):
        delta = packets[i - 1].timestamp_ns - packets[i].timestamp_ns
        if delta > max_backward_ns:
            p = packets[i]
            violation = {
                "index": i,
                "section": p.section_index,
                "interface": p.interface_id,
                "timestampNanoseconds": p.timestamp_ns,
                "backwardNanoseconds": delta,
            }
            break  # earliest violating packet only
    return {"packets": result_packets, "violation": violation}


class AuditHandler(BaseHTTPRequestHandler):
    server_version = "PcapngAudit/1.0"
    protocol_version = "HTTP/1.1"

    def _send_json(self, status: HTTPStatus, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        path = urlsplit(self.path).path
        if path == "/healthz":
            self._send_json(HTTPStatus.OK, {"status": "ok"})
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        parts = urlsplit(self.path)
        if parts.path != AUDIT_PATH:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return

        media_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip()
        if media_type != CONTENT_TYPE:
            self._send_json(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                {"error": f"Content-Type must be {CONTENT_TYPE}"},
            )
            return

        query = parse_qs(parts.query)
        raw_threshold = query.get("maxBackwardNanoseconds", [""])[0]
        try:
            max_backward_ns = int(raw_threshold)
            if max_backward_ns < 0:
                raise ValueError
        except ValueError:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "maxBackwardNanoseconds must be a non-negative integer"},
            )
            return

        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            self._send_json(
                HTTPStatus.LENGTH_REQUIRED,
                {"error": "Content-Length is required (chunked transfer not accepted)"},
            )
            return

        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._send_json(
                HTTPStatus.LENGTH_REQUIRED,
                {"error": "Content-Length is required"},
            )
            return
        if length < 0 or length > MAX_BODY_BYTES:
            if length < 0:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "invalid Content-Length"},
                )
                return
            # Drain the oversized body so the keep-alive connection stays
            # usable instead of being reset mid-request.
            remaining = length
            while remaining > 0:
                chunk = self.rfile.read(min(remaining, 65536))
                if not chunk:
                    break
                remaining -= len(chunk)
            self._send_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {"error": "body must not exceed 8 MiB"},
            )
            return

        data = self.rfile.read(length)
        try:
            result = audit(data, max_backward_ns)
        except PcapngError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return
        self._send_json(HTTPStatus.OK, result)

    def log_message(self, fmt: str, *args) -> None:  # quieter, structured logs
        if os.environ.get("AUDIT_QUIET"):
            return
        super().log_message(fmt, *args)


def main() -> None:
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    server = ThreadingHTTPServer((host, port), AuditHandler)
    print(f"pcapng-audit listening on {host}:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
