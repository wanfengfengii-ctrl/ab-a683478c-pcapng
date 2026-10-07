#!/bin/sh
# One-shot verification entrypoint: unit tests, build (byte-compile) and an
# API smoke test against the healthy "web" dependency. Reports via exit code.
set -eu

BASE_URL="${BASE_URL:-http://web:8080}"

echo "==> [1/3] Unit tests"
python -m pytest -q

echo "==> [2/3] Build: byte-compiling sources"
python -m compileall -q app tests scripts

echo "==> [3/3] Waiting for ${BASE_URL}/healthz"
i=0
while :; do
    if python -c "
import sys, urllib.request
try:
    r = urllib.request.urlopen('${BASE_URL}/healthz', timeout=2)
    sys.exit(0 if r.status == 200 else 1)
except Exception:
    sys.exit(1)
"; then
        echo "    dependency healthy"
        break
    fi
    i=$((i + 1))
    if [ "$i" -ge 30 ]; then
        echo "ERROR: service did not become healthy in time" >&2
        exit 1
    fi
    sleep 1
done

echo "==> API smoke test (mixed-endian samples)"
python scripts/smoke_test.py "${BASE_URL}"

echo "ALL VERIFICATION STEPS PASSED"
