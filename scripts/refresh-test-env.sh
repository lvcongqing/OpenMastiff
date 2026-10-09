#!/usr/bin/env bash
# 刷新本地测试环境：合并 maintenance 策略、重启 API/Worker、可选跑维护性样例
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
API_PORT="${API_PORT:-18000}"
LOG_DIR="${LOG_DIR:-/tmp/openmastiff-test}"
mkdir -p "$LOG_DIR"

echo "==> 合并 maintenance 到活跃策略 (MongoDB)"
cd "$ROOT/backend"
python3 <<'PY'
from app.db import col
from app.policy import DEFAULT_POLICY, load_active_policy, upsert_active_policy

active = load_active_policy()
raw = dict(active.raw)
maint = DEFAULT_POLICY.raw.get("maintenance")
if maint:
    raw["maintenance"] = maint
upsert_active_policy(raw)
p = load_active_policy()
print("policy keys:", sorted(p.raw.keys()))
print("maintenance.enabled:", (p.raw.get("maintenance") or {}).get("enabled"))
PY

echo "==> 打包维护性演示样例"
cd "$ROOT/test-fixtures"
zip -qr "$LOG_DIR/maintenance-demo.zip" maintenance-demo
echo "    $LOG_DIR/maintenance-demo.zip"

stop_pid() {
  local pattern="$1"
  pkill -f "$pattern" 2>/dev/null || true
  sleep 1
}

echo "==> 重启 API (port $API_PORT)"
if command -v fuser >/dev/null 2>&1; then
  fuser -k "${API_PORT}/tcp" 2>/dev/null || true
  sleep 1
fi
stop_pid "uvicorn app.main:app"
export MONGO_URI="${MONGO_URI:-mongodb://localhost:27017/supplychain}"
export REDIS_URL="${REDIS_URL:-redis://localhost:6379/8}"
export BLOB_ROOT="${BLOB_ROOT:-/opt/openMastiff/data/blobs}"
export WORK_ROOT="${WORK_ROOT:-/opt/openMastiff/data/work}"
export SCANNER_MODE="${SCANNER_MODE:-local}"
export API_PORT
cd "$ROOT/backend"
nohup bash run_api.sh >"$LOG_DIR/api.log" 2>&1 &
sleep 2
if ! curl -sf "http://127.0.0.1:${API_PORT}/bootstrap/status" >/dev/null; then
  echo "API 启动失败，见 $LOG_DIR/api.log"
  tail -20 "$LOG_DIR/api.log" || true
  exit 1
fi
echo "    API OK http://127.0.0.1:${API_PORT}"

echo "==> 启动 Celery Worker"
stop_pid "celery -A app.worker.celery_app worker"
cd "$ROOT/backend"
nohup bash run_worker.sh >"$LOG_DIR/worker.log" 2>&1 &
sleep 2
echo "    Worker 日志: $LOG_DIR/worker.log"

echo "==> 本地维护性采集冒烟（无需登录）"
python3 <<'PY'
from pathlib import Path
from app.maintenance import collect_maintenance_report
from app.policy import load_active_policy

ws = Path("/opt/openMastiff/test-fixtures/maintenance-demo")
policy = load_active_policy().raw.get("maintenance") or {}
report = collect_maintenance_report(
    workspace=ws,
    source={"type": "git", "git": {"repo_url": "https://github.com/gorilla/mux", "ref": "main"}},
    business_criticality="medium",
    maintenance_policy=policy,
)
up = report.get("upstream") or {}
print("upstream:", up.get("repo"), "score=", up.get("score"), "gate=", (up.get("gate") or {}).get("status"))
deps = report.get("dependencies") or []
print("dependencies scanned:", len(deps))
bad = [d for d in deps if (d.get("gate") or {}).get("status") in ("fail", "pending_legal")]
print("risk deps:", len(bad))
for d in bad[:5]:
    print("  -", d.get("ecosystem"), d.get("name"), "score=", d.get("score"), (d.get("gate") or {}).get("reason"))
print("overall:", report.get("overall"))
PY

echo ""
echo "==> 测试环境已就绪"
echo "  前端:  https://<主机>/  (npm run dev，HTTP :80 跳转 HTTPS :443)"
echo "  API:   http://127.0.0.1:${API_PORT}"
echo "  演示包: $LOG_DIR/maintenance-demo.zip"
echo ""
echo "UI 验证步骤:"
echo "  1. 登录后新建引入单，business_criticality 选 medium 或 high"
echo "  2. 上传 $LOG_DIR/maintenance-demo.zip 或 Git 源 https://github.com/gorilla/mux"
echo "  3. 提交扫描 → 详情「扫描」Tab 查看「项目维护性」"
echo "  4. 策略页 JSON 中应含 maintenance 段"
