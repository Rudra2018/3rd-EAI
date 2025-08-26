#!/usr/bin/env sh
set -euo pipefail
PORT="${PORT:-8080}"
echo "[start.sh] Starting API on 0.0.0.0:${PORT} with uvicorn"
exec uvicorn server.main:app --host 0.0.0.0 --port "${PORT}" --workers "${WEB_CONCURRENCY:-1}"
