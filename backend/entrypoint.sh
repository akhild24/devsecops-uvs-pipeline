#!/bin/sh
set -eu

python -m uvicorn main:app --host 0.0.0.0 --port 8000 &
server_pid=$!

cleanup() {
  kill "$server_pid" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

if [ "${DEMO_DATA_SEED:-true}" = "true" ]; then
  python scripts/post_samples.py --api-url http://127.0.0.1:8000
fi

wait "$server_pid"
