"""FastAPI application exposing POST /api/pcapng/audit."""

from __future__ import annotations

from fastapi import FastAPI, Query, Request, Response
from fastapi.responses import JSONResponse

from .audit import audit_pcapng
from .pcapng import PcapngError

MAX_BODY_BYTES = 8 * 1024 * 1024  # 8 MiB
PCAPNG_MEDIA_TYPE = "application/x-pcapng"

app = FastAPI(
    title="PCAPNG Audit Platform",
    version="1.0.0",
    description="Unified timestamp/order audit for collector-produced PCAPNG.",
)


@app.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok"}


@app.post("/api/pcapng/audit")
async def audit(
    request: Request,
    max_backward_ns: int = Query(
        ...,
        alias="maxBackwardNanoseconds",
        ge=0,
        description="Permitted non-negative backwards timestamp delta (ns).",
    ),
) -> Response:
    content_type = (request.headers.get("content-type") or "").split(";", 1)[0].strip()
    if content_type.lower() != PCAPNG_MEDIA_TYPE:
        return JSONResponse(
            status_code=415,
            content={
                "error": "unsupported_media_type",
                "message": (
                    f"Content-Type must be {PCAPNG_MEDIA_TYPE}, got "
                    f"'{content_type or 'missing'}'"
                ),
            },
        )

    # Read the whole body before rejecting it: responding 413 while the
    # client is still uploading resets the connection and hides the status.
    body = await request.body()
    if len(body) > MAX_BODY_BYTES:
        return JSONResponse(
            status_code=413,
            content={
                "error": "payload_too_large",
                "message": f"body must not exceed {MAX_BODY_BYTES} bytes (8 MiB)",
                "limitBytes": MAX_BODY_BYTES,
                "actualBytes": len(body),
            },
        )

    try:
        result = audit_pcapng(body, max_backward_ns)
    except PcapngError as exc:
        return JSONResponse(
            status_code=422,
            content={"error": "invalid_pcapng", "message": str(exc)},
        )

    return JSONResponse(status_code=200, content=result)
