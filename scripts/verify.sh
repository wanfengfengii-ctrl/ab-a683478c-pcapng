#!/bin/sh
# One-shot verification entrypoint:
#   1. wait for the api service to report healthy
#   2. run the unit/API test suite
#   3. build the installable wheel from the source tree
#   4. run the live API smoke test (mixed-endian samples included)
# The process exit code is the aggregate result, so `docker compose`
# surfaces success/failure directly.
set -eu

API_URL="${API_URL:-http://api:8080}"

echo "==> Waiting for API at ${API_URL}/healthz"
attempt=0
while :; do
    if curl -fsS "${API_URL}/healthz" >/dev/null 2>&1; then
        echo "==> API is healthy"
        break
    fi
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 60 ]; then
        echo "!! API did not become healthy in time" >&2
        exit 1
    fi
    sleep 1
done

echo "==> Running test suite"
python -m pytest tests/ -v

echo "==> Building distribution wheel"
python -m pip wheel --no-build-isolation --no-deps --wheel-dir /tmp/dist .

echo "==> Running API smoke test"
BASE_URL="${API_URL}" python scripts/smoke.py

echo "==> Verification complete"
