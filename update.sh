#!/usr/bin/env bash
# OpenMastiff 一键更新脚本 — 从代码仓库拉取最新代码并滚动重启服务
#
# 已安装实例上更新:
#   bash /opt/openMastiff/update.sh
#   bash /opt/openMastiff/update.sh -y --with-web
#
# 远程执行（需已安装或指定目录）:
#   curl -fsSL https://<你的域名>/openMastiff/update.sh | bash
#   curl -fsSL .../update.sh | bash -s -- --branch master --restart
#
# 首次用仓库地址初始化目录并更新:
#   OPENMASTIFF_REPO=ssh://user@gerrit.example.com/openMastiff bash update.sh
#
# 环境变量:
#   OPENMASTIFF_INSTALL_DIR   安装目录（默认 /opt/openMastiff）
#   OPENMASTIFF_REPO          Git 仓库（未 clone 时必填；已存在 .git 时可省略）
#   OPENMASTIFF_BRANCH        分支（默认 master）
#   OPENMASTIFF_REVISION      指定 commit/tag（设置后 checkout 该版本，不执行 pull）
set -euo pipefail

OPENMASTIFF_VERSION="0.1.0"

INSTALL_DIR="${OPENMASTIFF_INSTALL_DIR:-/opt/openMastiff}"
REPO_URL="${OPENMASTIFF_REPO:-}"
BRANCH="${OPENMASTIFF_BRANCH:-master}"
REVISION="${OPENMASTIFF_REVISION:-}"

WITH_WEB=0
WITH_DOCKER=0
RESTART=1
SKIP_PIP=0
SKIP_FETCH=0
REFRESH_ENV=0
YES=0

# ---------- logging ----------
if [[ -t 1 ]]; then
  C_RESET='\033[0m' C_BOLD='\033[1m'
  C_GREEN='\033[32m' C_YELLOW='\033[33m' C_RED='\033[31m' C_CYAN='\033[36m'
else
  C_RESET= C_BOLD= C_GREEN= C_YELLOW= C_RED= C_CYAN=
fi

info()  { printf '%b\n' "${C_CYAN}==>${C_RESET} $*"; }
ok()    { printf '%b\n' "${C_GREEN}✓${C_RESET} $*"; }
warn()  { printf '%b\n' "${C_YELLOW}警告:${C_RESET} $*" >&2; }
die()   { printf '%b\n' "${C_RED}错误:${C_RESET} $*" >&2; exit 1; }

usage() {
  cat <<EOF
OpenMastiff 一键更新 v${OPENMASTIFF_VERSION}

从 Git 仓库拉取最新代码，更新依赖并重启服务（保留 data/ 与现有 .env）。

用法:
  bash update.sh [选项]
  curl -fsSL <update.sh URL> | bash -s -- [选项]

选项:
  --dir DIR             安装目录（默认 /opt/openMastiff）
  --repo URL            Git 仓库地址（未初始化时必填）
  --branch BRANCH       跟踪分支（默认 master）
  --revision REV        切换到指定 commit/tag（不 pull，直接 checkout）
  --with-web            重新 npm install && build 前端
  --docker              Docker Compose 模式：pull 后 compose up --build
  --no-restart          更新代码与依赖后不重启服务
  --skip-pip            跳过 Python 依赖更新
  --skip-fetch          跳过 git fetch（仅本地 merge/rebase 已有远端引用）
  --refresh-env         用模板覆盖 .env（默认保留现有 .env）
  -y, --yes             非交互
  -h, --help            显示帮助

环境变量:
  OPENMASTIFF_INSTALL_DIR, OPENMASTIFF_REPO, OPENMASTIFF_BRANCH, OPENMASTIFF_REVISION

示例:
  # 已安装目录，拉 master 并重启 systemd
  sudo bash /opt/openMastiff/update.sh -y

  # 指定版本
  bash update.sh --revision v0.1.0 -y

  # 远程
  curl -fsSL https://intranet/openMastiff/update.sh | sudo bash -s -- -y --with-web
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir) INSTALL_DIR="${2:-}"; shift 2 ;;
    --repo) REPO_URL="${2:-}"; shift 2 ;;
    --branch) BRANCH="${2:-}"; shift 2 ;;
    --revision) REVISION="${2:-}"; shift 2 ;;
    --with-web) WITH_WEB=1; shift ;;
    --docker) WITH_DOCKER=1; shift ;;
    --no-restart) RESTART=0; shift ;;
    --skip-pip) SKIP_PIP=1; shift ;;
    --skip-fetch) SKIP_FETCH=1; shift ;;
    --refresh-env) REFRESH_ENV=1; shift ;;
    -y|--yes) YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "未知参数: $1（使用 --help）" ;;
  esac
done

ensure_cmd() { command -v "$1" >/dev/null 2>&1; }

detect_mode() {
  if [[ "$WITH_DOCKER" -eq 1 ]]; then
    echo docker
    return 0
  fi
  if [[ -f "$INSTALL_DIR/docker-compose.yml" ]] && [[ -f "$INSTALL_DIR/.env" ]]; then
    local mode
    mode="$(grep -E '^SCANNER_MODE=' "$INSTALL_DIR/.env" 2>/dev/null | cut -d= -f2- | tr -d '"' || true)"
    if [[ "$mode" == "docker" ]]; then
      echo docker
      return 0
    fi
  fi
  echo local
}

load_env() {
  if [[ -f "$INSTALL_DIR/.env" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$INSTALL_DIR/.env"
    set +a
  fi
  API_PORT="${API_PORT:-18000}"
}

git_remote_url() {
  git -C "$INSTALL_DIR" remote get-url origin 2>/dev/null || true
}

ensure_git_repo() {
  if [[ -d "$INSTALL_DIR/.git" ]]; then
    return 0
  fi

  [[ -n "$REPO_URL" ]] || die "目录 $INSTALL_DIR 不是 Git 仓库，请设置 OPENMASTIFF_REPO 或 --repo"

  info "首次克隆: $REPO_URL -> $INSTALL_DIR"
  mkdir -p "$(dirname "$INSTALL_DIR")"
  if [[ -d "$INSTALL_DIR" ]] && [[ -n "$(ls -A "$INSTALL_DIR" 2>/dev/null || true)" ]]; then
    die "目录 $INSTALL_DIR 已存在且非空，无法自动克隆。请清空后重试或手动 git clone"
  fi
  git clone --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR" 2>/dev/null \
    || git clone "$REPO_URL" "$INSTALL_DIR"
  ok "仓库已克隆"
}

pull_latest() {
  ensure_git_repo
  cd "$INSTALL_DIR"

  local url
  url="$(git_remote_url)"
  [[ -n "$url" ]] && ok "origin: $url"

  if [[ -n "$REVISION" ]]; then
    info "切换到指定版本: $REVISION"
    [[ "$SKIP_FETCH" -eq 1 ]] || git fetch --all --tags --prune
    git checkout "$REVISION"
    ok "当前: $(git rev-parse --short HEAD) $(git log -1 --format='%s')"
    return 0
  fi

  info "拉取分支: $BRANCH"
  if [[ "$SKIP_FETCH" -eq 0 ]]; then
    git fetch origin "$BRANCH" --tags --prune 2>/dev/null || git fetch origin --tags --prune
  fi

  local before after
  before="$(git rev-parse HEAD 2>/dev/null || echo none)"

  if git show-ref --verify --quiet "refs/remotes/origin/$BRANCH"; then
    git checkout "$BRANCH" 2>/dev/null || git checkout -B "$BRANCH" "origin/$BRANCH"
    if git merge-base --is-ancestor HEAD "origin/$BRANCH" 2>/dev/null \
      && ! git diff --quiet HEAD "origin/$BRANCH" 2>/dev/null; then
      git merge --ff-only "origin/$BRANCH"
    elif ! git diff --quiet HEAD "origin/$BRANCH" 2>/dev/null; then
      warn "无法 fast-forward，尝试 reset 到 origin/$BRANCH"
      git reset --hard "origin/$BRANCH"
    else
      git pull --ff-only origin "$BRANCH" 2>/dev/null || git reset --hard "origin/$BRANCH"
    fi
  else
    git checkout "$BRANCH" 2>/dev/null || git checkout -B "$BRANCH"
    git pull --ff-only origin "$BRANCH" 2>/dev/null \
      || git pull origin "$BRANCH" 2>/dev/null \
      || die "git pull 失败，请检查分支 $BRANCH 与网络/权限"
  fi

  after="$(git rev-parse HEAD)"
  if [[ "$before" == "$after" ]]; then
    ok "代码已是最新 ($after)"
  else
    ok "已更新: ${before:0:7} -> ${after:0:7}"
    git log --oneline -3
  fi
}

update_python_deps() {
  [[ "$SKIP_PIP" -eq 1 ]] && { warn "跳过 Python 依赖 (--skip-pip)"; return 0; }
  info "更新 Python 依赖"
  ensure_cmd python3 || die "未找到 python3"
  python3 -m pip install -r "$INSTALL_DIR/backend/requirements.txt" -q
  local mode
  mode="$(detect_mode)"
  if [[ "$mode" == "docker" ]]; then
    python3 -m pip install docker -q 2>/dev/null || true
  fi
  ok "Python 依赖"
}

build_web() {
  [[ "$WITH_WEB" -eq 1 ]] || return 0
  ensure_cmd npm || die "未找到 npm，无法 --with-web"
  info "构建前端"
  cd "$INSTALL_DIR/web"
  npm install --prefer-offline --no-audit 2>/dev/null || npm install
  npm run build
  ok "web/dist"
}

refresh_env_file() {
  [[ "$REFRESH_ENV" -eq 1 ]] || return 0
  local env_file="$INSTALL_DIR/.env"
  local redis_db="${REDIS_URL##*/}"
  redis_db="${redis_db:-8}"
  local mode
  mode="$(detect_mode)"
  [[ "$WITH_DOCKER" -eq 1 ]] && mode="docker"
  info "重写 .env"
  cat >"$env_file" <<EOF
# OpenMastiff — 由 update.sh 刷新 ($(date -u +%Y-%m-%dT%H:%M:%SZ))
MONGO_URI=${MONGO_URI:-mongodb://localhost:27017/supplychain}
REDIS_URL=${REDIS_URL:-redis://localhost:6379/${redis_db}}
BLOB_ROOT=${INSTALL_DIR}/data/blobs
WORK_ROOT=${INSTALL_DIR}/data/work
SCANNER_MODE=${mode}
SCANNER_IMAGE=${SCANNER_IMAGE:-openmastiff-scanner:dev}
API_HOST=${API_HOST:-0.0.0.0}
API_PORT=${API_PORT:-18000}
APP_CONFIG_FILE=${INSTALL_DIR}/config/app_config.json
EOF
  chmod 600 "$env_file" 2>/dev/null || true
  ok ".env 已刷新"
}

systemd_active() {
  local unit="$1"
  systemctl is-active --quiet "$unit" 2>/dev/null
}

restart_local_services() {
  [[ "$RESTART" -eq 1 ]] || { warn "跳过服务重启 (--no-restart)"; return 0; }

  load_env
  local restarted=0

  if systemd_active openmastiff-api.service || systemctl list-unit-files openmastiff-api.service &>/dev/null 2>&1; then
    info "重启 systemd: openmastiff-api, openmastiff-worker"
    systemctl daemon-reload 2>/dev/null || true
    systemctl restart openmastiff-api.service
    systemctl restart openmastiff-worker.service
    if systemctl list-unit-files openmastiff-beat.service &>/dev/null 2>&1; then
      systemctl restart openmastiff-beat.service 2>/dev/null || true
    fi
    restarted=1
  else
    info "未检测到 systemd 单元，尝试结束旧进程"
    pkill -f "uvicorn app.main:app" 2>/dev/null || true
    pkill -f "celery -A app.worker.celery_app worker" 2>/dev/null || true
    sleep 1

    if [[ -f "$INSTALL_DIR/.env" ]]; then
      info "后台启动 API / Worker（日志见 /tmp/openmastiff-update/）"
      local log_dir="/tmp/openmastiff-update"
      mkdir -p "$log_dir"
      set -a
      # shellcheck disable=SC1090
      source "$INSTALL_DIR/.env"
      set +a
      cd "$INSTALL_DIR/backend"
      nohup bash run_api.sh >"$log_dir/api.log" 2>&1 &
      nohup bash run_worker.sh >"$log_dir/worker.log" 2>&1 &
      restarted=1
      ok "已启动，日志: $log_dir/"
    else
      warn "无 .env，请手动重启: source .env && bash backend/run_api.sh"
    fi
  fi

  if [[ "$restarted" -eq 1 ]]; then
    sleep 2
    if curl -sf "http://127.0.0.1:${API_PORT}/bootstrap/status" >/dev/null 2>&1; then
      ok "API 健康检查通过 (:${API_PORT})"
    else
      warn "API 暂未响应，请检查日志"
    fi
  fi
}

restart_docker_services() {
  [[ "$RESTART" -eq 1 ]] || { warn "跳过 Docker 重启 (--no-restart)"; return 0; }
  ensure_cmd docker || die "未找到 docker"
  info "Docker Compose 重新构建并启动"
  cd "$INSTALL_DIR"
  export MONGO_IMAGE="${MONGO_IMAGE:-mongo:7}"
  export REDIS_IMAGE="${REDIS_IMAGE:-redis:7-alpine}"
  export PYTHON_BASE_IMAGE="${PYTHON_BASE_IMAGE:-python:3.12-slim}"
  if docker compose version >/dev/null 2>&1; then
    docker compose up -d --build
  else
    docker-compose up -d --build
  fi
  ok "Docker 服务已更新"
}

print_done() {
  local host mode
  host="$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo localhost)"
  mode="$(detect_mode)"
  load_env

  cat <<EOF

${C_GREEN}${C_BOLD}OpenMastiff 更新完成${C_RESET}

  目录:      ${INSTALL_DIR}
  版本:      $(git -C "$INSTALL_DIR" rev-parse --short HEAD 2>/dev/null) ($(git -C "$INSTALL_DIR" log -1 --format='%ci' 2>/dev/null | cut -d' ' -f1))
  分支:      $(git -C "$INSTALL_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null)
  模式:      ${mode}

EOF
  if [[ "$mode" == "docker" ]]; then
    cat <<EOF
  API:       http://${host}:8000
  状态:      cd ${INSTALL_DIR} && docker compose ps

EOF
  else
    cat <<EOF
  API:       http://${host}:${API_PORT}
  服务:      systemctl status openmastiff-api openmastiff-worker
  日志:      journalctl -u openmastiff-api -n 30 --no-pager

EOF
  fi
}

main() {
  printf '\n%bOpenMastiff 更新程序 v%s%b\n\n' "$C_BOLD" "$OPENMASTIFF_VERSION" "$C_RESET"

  [[ -d "$INSTALL_DIR" ]] || mkdir -p "$INSTALL_DIR"

  # 若 update.sh 在仓库内执行，且未指定 --dir，优先使用脚本所在目录
  if [[ -n "${BASH_SOURCE[0]:-}" && "${BASH_SOURCE[0]}" != bash && -f "${BASH_SOURCE[0]}" ]]; then
    local script_root
    script_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [[ -f "$script_root/backend/requirements.txt" && "$INSTALL_DIR" == "/opt/openMastiff" ]]; then
      INSTALL_DIR="$script_root"
    fi
  fi

  mkdir -p "$INSTALL_DIR/data/blobs" "$INSTALL_DIR/data/work"

  pull_latest
  refresh_env_file
  update_python_deps
  build_web

  local mode
  mode="$(detect_mode)"
  if [[ "$mode" == "docker" ]]; then
    restart_docker_services
  else
    restart_local_services
  fi

  print_done
}

main "$@"
