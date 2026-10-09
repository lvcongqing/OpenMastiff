#!/usr/bin/env bash
# 在内网临时托管 install.sh，便于 curl | bash 测试
# 用法: bash scripts/serve-install.sh [端口]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${1:-8765}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "需要 python3" >&2
  exit 1
fi

echo "托管目录: $ROOT"
echo "安装: OPENMASTIFF_REPO=<git> curl -fsSL http://127.0.0.1:${PORT}/install.sh | bash"
echo "更新: curl -fsSL http://127.0.0.1:${PORT}/update.sh | sudo bash -s -- -y"
echo ""
echo "按 Ctrl+C 停止"
cd "$ROOT"
exec python3 -m http.server "$PORT"
