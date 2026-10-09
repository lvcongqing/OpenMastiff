#!/usr/bin/env bash
# 停止本项目的 Vite 开发服务及 HTTP :80 重定向
set -euo pipefail

WEB_DIR="$(cd "$(dirname "$0")/.." && pwd)"

pids="$(
  pgrep -f "${WEB_DIR}/node_modules/.bin/vite" 2>/dev/null || true
  pgrep -f "${WEB_DIR}/scripts/http-redirect-80.mjs" 2>/dev/null || true
)"

if [[ -z "${pids}" ]]; then
  echo "[dev:stop] 未发现运行中的开发进程"
else
  echo "[dev:stop] 停止: ${pids}"
  kill ${pids} 2>/dev/null || true
  sleep 1
  kill -9 ${pids} 2>/dev/null || true
fi

if command -v fuser >/dev/null 2>&1; then
  fuser -k "${VITE_DEV_HTTP_PORT:-80}"/tcp 2>/dev/null || true
  fuser -k "${VITE_DEV_HTTPS_PORT:-443}"/tcp 2>/dev/null || true
fi

echo "[dev:stop] 完成"
