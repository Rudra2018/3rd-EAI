#!/usr/bin/env bash
# start.sh
set -euo pipefail

# Cloud Run provides the PORT env var. We set a default for local testing.
PORT="${PORT:-8080}"

echo "[start.sh] Starting application on 0.0.0.0:${PORT}"

# This is the correct way to pass the command and its arguments
exec uvicorn api_scanner.services.program_fetcher:app --host 0.0.0.0 --port "${PORT}"
