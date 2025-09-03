#!/usr/bin/env bash
set -euo pipefail

PORT="${PORT:-8080}"

echo "Starting application with uvicorn on port ${PORT}"

exec uvicorn api_scanner.services.program_fetcher:app --host 0.0.0.0 --port "${PORT}"
