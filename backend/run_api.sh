#!/usr/bin/env bash
set -euo pipefail

export MONGO_URI="${MONGO_URI:-mongodb://localhost:27017/supplychain}"
export REDIS_URL="${REDIS_URL:-redis://localhost:6379/8}"
export BLOB_ROOT="${BLOB_ROOT:-/opt/openMastiff/data/blobs}"
export WORK_ROOT="${WORK_ROOT:-/opt/openMastiff/data/work}"
export SCANNER_MODE="${SCANNER_MODE:-local}"
export API_HOST="${API_HOST:-0.0.0.0}"
export API_PORT="${API_PORT:-18000}"

cd "$(dirname "$0")"
python3 -m uvicorn app.main:app --host "${API_HOST}" --port "${API_PORT}"

