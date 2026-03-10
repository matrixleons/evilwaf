#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "" ]]; then
  echo "usage: scripts/profile_memory.sh <target-url>"
  exit 2
fi

TARGET_URL="$1"
PROXY_HOST="${PROXY_HOST:-127.0.0.1}"
PROXY_PORT="${PROXY_PORT:-8080}"

python3 -m pip install -q memory_profiler
python3 -m memory_profiler evilwaf.py -t "${TARGET_URL}" --no-tui --listen-host "${PROXY_HOST}" --listen-port "${PROXY_PORT}" &
PID=$!
sleep 3
python3 benchmarks/proxy_benchmark.py --proxy "http://${PROXY_HOST}:${PROXY_PORT}" --target "${TARGET_URL}" --requests 100 --concurrency 10 || true
kill "${PID}" || true
wait "${PID}" || true
