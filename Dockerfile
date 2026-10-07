# PCAPNG audit service image.
# A single image backs both the long-running web service and the one-shot
# `verify` service: it carries the application, the prebuilt wheel and the
# test/smoke tooling.
FROM python:3.11-slim AS builder

WORKDIR /build

COPY requirements-dev.txt ./
RUN python -m pip install --upgrade pip setuptools wheel \
    && python -m pip wheel --wheel-dir /wheels -r requirements-dev.txt

COPY pyproject.toml ./
COPY app ./app
RUN python -m pip wheel --no-build-isolation --no-deps --wheel-dir /wheels .


FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=8080

WORKDIR /srv

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Install runtime + test dependencies and the freshly built wheel.
COPY requirements-dev.txt ./
COPY --from=builder /wheels /wheels
RUN python -m pip install --no-cache-dir /wheels/*.whl \
    && rm -rf /wheels

COPY app ./app
COPY testing ./testing
COPY tests ./tests
COPY scripts ./scripts
COPY pyproject.toml ./

EXPOSE 8080

# Shell form so ${PORT} is expanded at container runtime.
HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=12 \
    CMD curl -fsS "http://127.0.0.1:${PORT}/healthz" || exit 1

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"]
