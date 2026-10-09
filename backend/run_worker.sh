#!/usr/bin/env bash
set -euo pipefail

export MONGO_URI="${MONGO_URI:-mongodb://localhost:27017/supplychain}"
export REDIS_URL="${REDIS_URL:-redis://localhost:6379/8}"
export BLOB_ROOT="${BLOB_ROOT:-/opt/openMastiff/data/blobs}"
export WORK_ROOT="${WORK_ROOT:-/opt/openMastiff/data/work}"
export SCANNER_MODE="${SCANNER_MODE:-local}"
export PATH="/usr/local/bin:/usr/local/go/bin:${PATH:-/usr/bin:/bin}"
export GOPROXY="${GOPROXY:-https://goproxy.cn,direct}"
export GOPATH="${GOPATH:-/root/go}"
export GOMODCACHE="${GOMODCACHE:-/root/go/pkg/mod}"

cd "$(dirname "$0")"
# 实际同时跑的扫描由策略 runner.max_concurrent_scans 限流；线程池只负责领取排队任务。
# prefork 在 local 扫描下 gosec 易出 files:0，故用 threads。
CONC="${CELERY_CONCURRENCY:-4}"
if [ "${CONC}" = "1" ]; then
  python3 -m celery -A app.worker.celery_app worker --loglevel=INFO --pool=solo
else
  python3 -m celery -A app.worker.celery_app worker --loglevel=INFO --pool=threads --concurrency="${CONC}"
fi

