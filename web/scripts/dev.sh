#!/usr/bin/env bash
# 开发入口：HTTPS :443（Vite）+ HTTP :80（跳转至 HTTPS）
set -euo pipefail

WEB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "${WEB_DIR}"

stop_old_dev() {
  if [[ "${OPENMASTIFF_DEV_KEEP_OLD:-}" == "1" ]]; then
    return 0
  fi
  local pids
  pids="$(
    pgrep -f "${WEB_DIR}/node_modules/.bin/vite" 2>/dev/null || true
    pgrep -f "${WEB_DIR}/scripts/http-redirect-80.mjs" 2>/dev/null || true
  )"
  if [[ -n "${pids}" ]]; then
    echo "[dev] 停止占用 80/443 的旧开发进程: ${pids}"
    kill ${pids} 2>/dev/null || true
    sleep 1
    kill -9 ${pids} 2>/dev/null || true
  fi
  if command -v fuser >/dev/null 2>&1; then
    fuser -k "${VITE_DEV_HTTP_PORT:-80}"/tcp 2>/dev/null || true
    if [[ "${VITE_DEV_HTTPS:-true}" != "false" ]]; then
      fuser -k "${VITE_DEV_HTTPS_PORT:-443}"/tcp 2>/dev/null || true
    fi
  fi
}

check_ports() {
  local ports=("${VITE_DEV_HTTP_PORT:-80}")
  local port in_use=0
  if [[ "${VITE_DEV_HTTPS:-true}" != "false" ]]; then
    ports+=("${VITE_DEV_HTTPS_PORT:-443}")
  fi
  for port in "${ports[@]}"; do
    if ss -tln "sport = :${port}" 2>/dev/null | grep -q LISTEN; then
      in_use=1
      echo "[dev] 错误: 端口 ${port} 仍被占用。请先执行: npm run dev:stop" >&2
      echo "      或查看: ss -tlnp | grep :${port}" >&2
    fi
  done
  [[ "${in_use}" -eq 0 ]]
}

bash scripts/gen-dev-certs.sh
stop_old_dev
check_ports

cleanup() {
  jobs -p | xargs -r kill 2>/dev/null || true
}
trap cleanup EXIT INT TERM

if [[ "${VITE_DEV_HTTPS:-true}" != "false" ]]; then
  node scripts/http-redirect-80.mjs &
fi

exec vite
