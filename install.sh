#!/usr/bin/env bash
# OpenMastiff 一键安装脚本
#
# 远程安装（需可访问的 install.sh 与 Git 仓库）:
#   curl -fsSL https://<你的域名>/openMastiff/install.sh | bash
#
# 带参数:
#   curl -fsSL https://<你的域名>/openMastiff/install.sh | bash -s -- --mode local --with-systemd
#
# 本机已有源码:
#   OPENMASTIFF_REPO=ssh://user@gerrit.example.com/openMastiff bash install.sh
#   bash install.sh --from-source "$(pwd)"
#
# 环境变量:
#   OPENMASTIFF_INSTALL_DIR   安装目录（默认 /opt/openMastiff）
#   OPENMASTIFF_REPO          Git 克隆地址（远程安装必填，除非 --from-source）
#   OPENMASTIFF_BRANCH        分支（默认 master）
#   OPENMASTIFF_MODE          local | docker（默认 local）
#   OPENMASTIFF_API_PORT      API 端口（默认 18000）
#   OPENMASTIFF_REDIS_DB       Redis DB 编号（默认 8）
set -euo pipefail

OPENMASTIFF_VERSION="0.1.0"

INSTALL_DIR="${OPENMASTIFF_INSTALL_DIR:-/opt/openMastiff}"
REPO_URL="${OPENMASTIFF_REPO:-}"
BRANCH="${OPENMASTIFF_BRANCH:-master}"
MODE="${OPENMASTIFF_MODE:-local}"
API_PORT="${OPENMASTIFF_API_PORT:-18000}"
REDIS_DB="${OPENMASTIFF_REDIS_DB:-8}"

FROM_SOURCE=""
WITH_WEB=0
WITH_SCANNER_TOOLS=0
WITH_SYSTEMD=0
WITH_BEAT=0
SKIP_DEPS=0
SKIP_CLONE=0
YES=0

# ---------- logging ----------
if [[ -t 1 ]]; then
  C_RESET='\033[0m' C_BOLD='\033[1m' C_DIM='\033[2m'
  C_GREEN='\033[32m' C_YELLOW='\033[33m' C_RED='\033[31m' C_CYAN='\033[36m'
else
  C_RESET= C_BOLD= C_DIM= C_GREEN= C_YELLOW= C_RED= C_CYAN=
fi

info()  { printf '%b\n' "${C_CYAN}==>${C_RESET} $*"; }
ok()    { printf '%b\n' "${C_GREEN}✓${C_RESET} $*"; }
warn()  { printf '%b\n' "${C_YELLOW}警告:${C_RESET} $*" >&2; }
die()   { printf '%b\n' "${C_RED}错误:${C_RESET} $*" >&2; exit 1; }

usage() {
  cat <<EOF
OpenMastiff 供应链安全引入审查系统 — 一键安装 v${OPENMASTIFF_VERSION}

用法:
  curl -fsSL <install.sh URL> | bash
  curl -fsSL <install.sh URL> | bash -s -- [选项]
  bash install.sh [选项]

选项:
  --from-source DIR     使用已有源码目录，跳过 git clone
  --dir DIR               安装目录（等同 OPENMASTIFF_INSTALL_DIR）
  --repo URL              Git 仓库地址（等同 OPENMASTIFF_REPO）
  --branch BRANCH         分支名（默认 master）
  --mode local|docker       部署模式（默认 local）
  --api-port PORT           API 监听端口（默认 18000）
  --with-web                构建前端静态资源（需 Node.js >= 18）
  --with-scanner-tools      安装 syft / gosec / bandit / PMD / cargo-audit / eslint（local 模式推荐）
  --with-systemd            安装并启用 systemd 服务（需 root）
  --with-beat               同时安装 Celery Beat 定时任务服务
  --skip-deps               跳过系统包安装（redis/mongo/python 等）
  --skip-clone              不克隆仓库（安装目录须已有代码）
  -y, --yes                 非交互模式，自动确认
  -h, --help                显示本帮助

环境变量:
  OPENMASTIFF_INSTALL_DIR, OPENMASTIFF_REPO, OPENMASTIFF_BRANCH,
  OPENMASTIFF_MODE, OPENMASTIFF_API_PORT, OPENMASTIFF_REDIS_DB

示例:
  OPENMASTIFF_REPO=ssh://user@gerrit.example.com/openMastiff \\
    curl -fsSL https://intranet.example.com/openMastiff/install.sh | bash

  bash install.sh --from-source . --with-systemd -y
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --from-source) FROM_SOURCE="${2:-}"; SKIP_CLONE=1; shift 2 ;;
    --dir) INSTALL_DIR="${2:-}"; shift 2 ;;
    --repo) REPO_URL="${2:-}"; shift 2 ;;
    --branch) BRANCH="${2:-}"; shift 2 ;;
    --mode) MODE="${2:-}"; shift 2 ;;
    --api-port) API_PORT="${2:-}"; shift 2 ;;
    --with-web) WITH_WEB=1; shift ;;
    --with-scanner-tools) WITH_SCANNER_TOOLS=1; shift ;;
    --with-systemd) WITH_SYSTEMD=1; shift ;;
    --with-beat) WITH_BEAT=1; shift ;;
    --skip-deps) SKIP_DEPS=1; shift ;;
    --skip-clone) SKIP_CLONE=1; shift ;;
    -y|--yes) YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "未知参数: $1（使用 --help 查看帮助）" ;;
  esac
done

[[ "$MODE" == "local" || "$MODE" == "docker" ]] || die "--mode 仅支持 local 或 docker"

need_root() {
  [[ "$(id -u)" -eq 0 ]] || die "此步骤需要 root 权限，请使用 sudo 运行"
}

confirm() {
  local msg="$1"
  [[ "$YES" -eq 1 ]] && return 0
  printf '%s [y/N] ' "$msg"
  read -r ans || true
  [[ "${ans:-}" =~ ^[Yy]$ ]]
}

detect_pm() {
  if command -v dnf >/dev/null 2>&1; then echo dnf
  elif command -v yum >/dev/null 2>&1; then echo yum
  elif command -v apt-get >/dev/null 2>&1; then echo apt
  else echo unknown
  fi
}

pm_install() {
  local pm="$1"; shift
  case "$pm" in
    dnf|yum) "$pm" install -y "$@" ;;
    apt) DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" ;;
    *) die "未识别的包管理器，请手动安装: $*" ;;
  esac
}

ensure_cmd() {
  command -v "$1" >/dev/null 2>&1
}

start_service() {
  local name="$1"
  systemctl enable "$name" 2>/dev/null || true
  systemctl start "$name" 2>/dev/null || systemctl restart "$name" 2>/dev/null || true
}

# ---------- locate / fetch source ----------
resolve_source_dir() {
  if [[ -n "$FROM_SOURCE" ]]; then
    local src
    src="$(cd "$FROM_SOURCE" && pwd)"
    [[ -f "$src/backend/requirements.txt" ]] || die "--from-source 目录无效: $src"
    echo "$src"
    return
  fi

  if [[ -f "$INSTALL_DIR/backend/requirements.txt" ]]; then
    echo "$INSTALL_DIR"
    return
  fi

  # 脚本在仓库内执行（非 curl 管道）
  local script_dir=""
  if [[ -n "${BASH_SOURCE[0]:-}" && "${BASH_SOURCE[0]}" != bash && -f "${BASH_SOURCE[0]}" ]]; then
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [[ -f "$script_dir/backend/requirements.txt" ]]; then
      echo "$script_dir"
      return
    fi
  fi

  echo ""
}

install_source() {
  local src_dir
  src_dir="$(resolve_source_dir)"

  if [[ -n "$src_dir" && "$src_dir" != "$INSTALL_DIR" ]]; then
    info "同步源码: $src_dir -> $INSTALL_DIR"
    mkdir -p "$(dirname "$INSTALL_DIR")"
    if [[ "$src_dir" == "$INSTALL_DIR" ]]; then
      : # already there
    elif command -v rsync >/dev/null 2>&1; then
      rsync -a --delete \
        --exclude '.git' --exclude 'data/' --exclude 'web/node_modules/' --exclude 'web/dist/' \
        "$src_dir/" "$INSTALL_DIR/"
    else
      rm -rf "$INSTALL_DIR"
      mkdir -p "$INSTALL_DIR"
      cp -a "$src_dir/." "$INSTALL_DIR/"
      rm -rf "$INSTALL_DIR/.git" "$INSTALL_DIR/data" 2>/dev/null || true
    fi
    ok "源码已就位"
    return
  fi

  if [[ "$SKIP_CLONE" -eq 1 ]]; then
    [[ -f "$INSTALL_DIR/backend/requirements.txt" ]] || die "跳过克隆但 $INSTALL_DIR 中无有效代码"
    return
  fi

  [[ -n "$REPO_URL" ]] || die "未设置 OPENMASTIFF_REPO，且无法自动定位源码。请 export OPENMASTIFF_REPO=<git-url> 或使用 --from-source"

  if [[ -d "$INSTALL_DIR/.git" ]]; then
    info "更新已有仓库: $INSTALL_DIR"
    git -C "$INSTALL_DIR" fetch origin
    git -C "$INSTALL_DIR" checkout "$BRANCH"
    git -C "$INSTALL_DIR" pull --ff-only origin "$BRANCH" 2>/dev/null || git -C "$INSTALL_DIR" reset --hard "origin/$BRANCH" 2>/dev/null || true
  else
    info "克隆仓库: $REPO_URL (branch=$BRANCH) -> $INSTALL_DIR"
    mkdir -p "$(dirname "$INSTALL_DIR")"
    git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR" 2>/dev/null \
      || git clone --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
  fi
  ok "源码已下载"
}

# ---------- system dependencies ----------
install_system_deps() {
  [[ "$SKIP_DEPS" -eq 1 ]] && { warn "跳过系统依赖安装 (--skip-deps)"; return; }

  local pm
  pm="$(detect_pm)"
  info "安装系统依赖 (包管理器: $pm)"

  case "$pm" in
    dnf|yum)
      pm_install "$pm" python3 python3-pip git curl rsync
      if ! ensure_cmd redis-cli; then
        pm_install "$pm" redis || warn "redis 包安装失败，请手动安装并启动"
      fi
      if ! ss -lntp 2>/dev/null | grep -q ':27017'; then
        pm_install "$pm" mongodb mongodb-server 2>/dev/null \
          || pm_install "$pm" mongodb-server 2>/dev/null \
          || pm_install "$pm" mongodb 2>/dev/null \
          || warn "MongoDB 包名因发行版而异，请参照 docs/10-local-install.md 手动安装"
      fi
      if [[ "$WITH_SCANNER_TOOLS" -eq 1 ]]; then
        pm_install "$pm" cppcheck 2>/dev/null || warn "cppcheck 未通过 yum 安装，可稍后手动安装"
      fi
      if [[ "$MODE" == "docker" ]]; then
        if ! ensure_cmd docker; then
          pm_install "$pm" docker docker-compose-plugin 2>/dev/null \
            || pm_install "$pm" docker docker-compose 2>/dev/null \
            || warn "Docker 安装失败，请手动安装"
        fi
      fi
      ;;
    apt)
      pm_install apt python3 python3-pip python3-venv git curl rsync
      ensure_cmd redis-cli || pm_install apt redis-server
      ss -lntp 2>/dev/null | grep -q ':27017' || pm_install apt mongodb 2>/dev/null || true
      [[ "$WITH_SCANNER_TOOLS" -eq 1 ]] && pm_install apt cppcheck 2>/dev/null || true
      [[ "$MODE" == "docker" ]] && pm_install apt docker.io docker-compose-plugin 2>/dev/null || true
      ;;
    *)
      warn "无法自动安装系统包，请确保已安装: python3 pip git redis mongodb"
      ;;
  esac

  # 启动 Redis / MongoDB
  if ensure_cmd systemctl; then
    for svc in redis redis-server mongod mongodb; do
      if systemctl list-unit-files "$svc.service" &>/dev/null; then
        start_service "$svc"
      fi
    done
  fi

  if ensure_cmd redis-cli; then
    if redis-cli ping 2>/dev/null | grep -q PONG; then
      ok "Redis 可用"
    else
      warn "redis-cli ping 未返回 PONG，请检查 Redis 服务"
    fi
  else
    warn "未检测到 redis-cli"
  fi

  ok "系统依赖检查完成"
}

install_python_deps() {
  info "安装 Python 依赖"
  local py=python3
  ensure_cmd "$py" || die "未找到 python3"
  "$py" -m pip install --upgrade pip setuptools wheel 2>/dev/null || true
  "$py" -m pip install -r "$INSTALL_DIR/backend/requirements.txt"
  if [[ "$MODE" == "docker" ]]; then
    "$py" -m pip install docker 2>/dev/null || warn "docker Python SDK 安装失败，Docker 扫描模式可能不可用"
  fi
  ok "Python 依赖已安装"
}

install_grype() {
  local want_ver="0.119.0"
  local have_ver=""
  if command -v grype >/dev/null 2>&1; then
    have_ver="$(grype version 2>/dev/null | awk -F': *' '$1 ~ /Version/{print $2; exit}')"
    have_ver="${have_ver%% *}"
  fi
  if [[ "$have_ver" == "$want_ver" ]]; then
    ok "grype 已存在 (v${have_ver})"
  else
    info "安装 grype v${want_ver} (依赖 CVE / SCA${have_ver:+，替换现有 ${have_ver}})"
    local arch=""
    case "$(uname -m)" in
      x86_64|amd64) arch=amd64 ;;
      aarch64|arm64) arch=arm64 ;;
      *) warn "不支持的架构 $(uname -m)，跳过 grype"; return 0 ;;
    esac
    local ver="v${want_ver}"
    local rel="grype_${want_ver}_linux_${arch}.tar.gz"
    local tmp
    tmp="$(mktemp -d)"
    local url
    for url in \
      "https://ghfast.top/https://github.com/anchore/grype/releases/download/${ver}/${rel}" \
      "https://ghproxy.net/https://github.com/anchore/grype/releases/download/${ver}/${rel}" \
      "https://github.com/anchore/grype/releases/download/${ver}/${rel}"
    do
      info "尝试下载 grype: $url"
      if curl -fsSL --connect-timeout 15 --max-time 180 "$url" -o "$tmp/grype.tgz" && tar -xzf "$tmp/grype.tgz" -C "$tmp" grype; then
        install -m 0755 "$tmp/grype" /usr/local/bin/grype
        ok "grype ${ver} 已安装到 /usr/local/bin"
        rm -rf "$tmp"
        break
      fi
    done
    if ! command -v grype >/dev/null 2>&1; then
      warn "grype 安装失败，CVE 扫描将跳过"
      rm -rf "$tmp"
      return 0
    fi
  fi
  local db_dir="${GRYPE_DB_CACHE_DIR:-/opt/openMastiff/data/grype-db}"
  mkdir -p "$db_dir"
  if command -v grype >/dev/null 2>&1; then
    info "更新 Grype 漏洞库到 $db_dir（扫描时无外网）"
    GRYPE_DB_CACHE_DIR="$db_dir" GRYPE_CHECK_FOR_APP_UPDATE=false grype db update >/dev/null 2>&1 \
      || warn "grype db update 失败，首次 CVE 扫描需能访问漏洞库源"
    chmod -R a+rX "$db_dir" 2>/dev/null || true
  fi
}

install_syft() {
  if command -v syft >/dev/null 2>&1; then
    ok "syft 已存在 ($(syft version 2>/dev/null | awk 'NR==1{print; exit}'))"
    return 0
  fi
  info "安装 syft (默认 SBOM / 许可证扫描)"
  local arch=""
  case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) warn "不支持的架构 $(uname -m)，跳过 syft"; return 0 ;;
  esac
  local ver="v1.33.0"
  local rel="syft_${ver#v}_linux_${arch}.tar.gz"
  local tmp
  tmp="$(mktemp -d)"
  local url
  for url in \
    "https://ghfast.top/https://github.com/anchore/syft/releases/download/${ver}/${rel}" \
    "https://ghproxy.net/https://github.com/anchore/syft/releases/download/${ver}/${rel}" \
    "https://github.com/anchore/syft/releases/download/${ver}/${rel}"
  do
    info "尝试下载 syft: $url"
    if curl -fsSL --connect-timeout 15 --max-time 180 "$url" -o "$tmp/syft.tgz" && tar -xzf "$tmp/syft.tgz" -C "$tmp" syft; then
      install -m 0755 "$tmp/syft" /usr/local/bin/syft
      ok "syft ${ver} 已安装到 /usr/local/bin"
      rm -rf "$tmp"
      return 0
    fi
  done
  warn "syft 安装失败，将回退 scancode / 内置许可证检测"
  rm -rf "$tmp"
}

_download_first() {
  local dest="$1"; shift
  local url
  for url in "$@"; do
    info "尝试下载: $url"
    if curl -fL --connect-timeout 15 --max-time 240 "$url" -o "$dest"; then
      return 0
    fi
  done
  return 1
}

install_bandit() {
  if command -v bandit >/dev/null 2>&1; then
    ok "bandit 已存在 ($(bandit --version 2>/dev/null | awk 'NR==1{print; exit}'))"
    return 0
  fi
  info "安装 bandit (Python SAST)"
  local pyver
  pyver="$(python3 -c 'import sys; print("%s.%s" % sys.version_info[:2])' 2>/dev/null || echo 3.7)"
  if python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)'; then
    python3 -m pip install 'bandit>=1.7.5' && { ok "bandit 已安装"; return 0; }
  else
    python3 -m pip install 'bandit==1.7.5' && { ok "bandit 1.7.5 已安装（适配 Python ${pyver}）"; return 0; }
  fi
  warn "bandit 安装失败，Python 扫描将使用内置规则"
}

install_eslint() {
  if command -v eslint >/dev/null 2>&1; then
    ok "eslint 已存在 ($(eslint --version 2>/dev/null | awk 'NR==1{print; exit}'))"
    return 0
  fi
  if command -v npm >/dev/null 2>&1; then
    info "安装 eslint (JS/TS SAST)"
    if npm install -g eslint --silent; then
      ok "eslint 已安装"
      return 0
    fi
    warn "eslint 安装失败，JS/TS 扫描将使用内置规则"
    return 0
  fi
  warn "未安装 npm，JS/TS 扫描将使用内置规则"
}

install_pmd() {
  if command -v pmd >/dev/null 2>&1; then
    ok "pmd 已存在 ($(pmd --version 2>/dev/null | awk 'NR==1{print; exit}'))"
    return 0
  fi
  info "安装 PMD (Java SAST)"
  if ! command -v java >/dev/null 2>&1; then
    if command -v yum >/dev/null 2>&1; then
      yum install -y java-17-openjdk-headless unzip 2>/dev/null \
        || yum install -y java-11-openjdk-headless unzip 2>/dev/null \
        || warn "yum 安装 OpenJDK 失败"
    fi
  fi
  if ! command -v java >/dev/null 2>&1; then
    warn "未找到 java，跳过 PMD"
    return 0
  fi
  command -v unzip >/dev/null 2>&1 || yum install -y unzip 2>/dev/null || true
  local ver="7.27.0"
  local zip="pmd-dist-${ver}-bin.zip"
  local tmp
  tmp="$(mktemp -d)"
  if ! _download_first "$tmp/$zip" \
    "https://ghfast.top/https://github.com/pmd/pmd/releases/download/pmd_releases%2F${ver}/${zip}" \
    "https://ghproxy.net/https://github.com/pmd/pmd/releases/download/pmd_releases%2F${ver}/${zip}" \
    "https://github.com/pmd/pmd/releases/download/pmd_releases/${ver}/${zip}" \
    "https://repo1.maven.org/maven2/net/sourceforge/pmd/pmd-dist/${ver}/${zip}"
  then
    warn "PMD 下载失败，Java 扫描将使用内置规则"
    rm -rf "$tmp"
    return 0
  fi
  mkdir -p /opt
  rm -rf "/opt/pmd-bin-${ver}" /opt/pmd
  unzip -q "$tmp/$zip" -d /opt
  if [ ! -d "/opt/pmd-bin-${ver}" ]; then
    local found
    found="$(find /opt -maxdepth 1 -type d -name 'pmd-bin-*' | sort | tail -1)"
    if [ -n "$found" ]; then
      ln -sfn "$found" /opt/pmd
    fi
  else
    ln -sfn "/opt/pmd-bin-${ver}" /opt/pmd
  fi
  if [ -x /opt/pmd/bin/pmd ]; then
    cat >/usr/local/bin/pmd <<'EOF'
#!/bin/sh
if [ -z "$JAVA_HOME" ]; then
  for d in /usr/lib/jvm/java-17-openjdk /usr/lib/jvm/java-17 /usr/lib/jvm/java-11-openjdk /usr/lib/jvm/jre-17 /usr/lib/jvm/jre-11; do
    if [ -x "$d/bin/java" ]; then
      export JAVA_HOME="$d"
      break
    fi
  done
fi
exec /opt/pmd/bin/pmd "$@"
EOF
    chmod 0755 /usr/local/bin/pmd
    ok "PMD ${ver} 已安装到 /opt/pmd"
  else
    warn "PMD 解压后未找到 bin/pmd"
  fi
  rm -rf "$tmp"
}

install_cargo_audit() {
  if command -v cargo-audit >/dev/null 2>&1; then
    ok "cargo-audit 已存在 ($(cargo-audit --version 2>/dev/null | awk 'NR==1{print; exit}'))"
  else
    info "安装 cargo-audit (Rust 依赖审计)"
    local arch=""
    case "$(uname -m)" in
      x86_64|amd64) arch=x86_64-unknown-linux-musl ;;
      aarch64|arm64) arch=aarch64-unknown-linux-gnu ;;
      *) warn "不支持的架构 $(uname -m)，跳过 cargo-audit"; return 0 ;;
    esac
    local ver="0.22.2"
    local rel="cargo-audit-${arch}-v${ver}.tgz"
    local tmp
    tmp="$(mktemp -d)"
    if ! _download_first "$tmp/ca.tgz" \
      "https://ghfast.top/https://github.com/rustsec/rustsec/releases/download/cargo-audit/v${ver}/${rel}" \
      "https://ghproxy.net/https://github.com/rustsec/rustsec/releases/download/cargo-audit/v${ver}/${rel}" \
      "https://github.com/rustsec/rustsec/releases/download/cargo-audit/v${ver}/${rel}"
    then
      ver="0.22.1"
      rel="cargo-audit-${arch}-v${ver}.tgz"
      _download_first "$tmp/ca.tgz" \
        "https://ghfast.top/https://github.com/rustsec/rustsec/releases/download/cargo-audit/v${ver}/${rel}" \
        "https://github.com/rustsec/rustsec/releases/download/cargo-audit/v${ver}/${rel}" \
        || { warn "cargo-audit 下载失败，Rust 扫描将使用内置规则"; rm -rf "$tmp"; return 0; }
    fi
    tar -xzf "$tmp/ca.tgz" -C "$tmp"
    local bin
    bin="$(find "$tmp" -type f -name cargo-audit | head -1)"
    if [ -n "$bin" ]; then
      install -m 0755 "$bin" /usr/local/bin/cargo-audit
      ok "cargo-audit ${ver} 已安装到 /usr/local/bin"
    else
      warn "cargo-audit 压缩包中未找到二进制"
    fi
    rm -rf "$tmp"
  fi
  if command -v cargo-audit >/dev/null 2>&1 && command -v git >/dev/null 2>&1; then
    local db="${CARGO_HOME:-$HOME/.cargo}/advisory-db"
    if [ ! -d "$db/.git" ]; then
      info "预拉 RustSec advisory-db（扫描时无外网也能用）"
      mkdir -p "$(dirname "$db")"
      git clone --depth 1 https://github.com/RustSec/advisory-db.git "$db" 2>/dev/null \
        || git clone --depth 1 https://ghfast.top/https://github.com/RustSec/advisory-db.git "$db" 2>/dev/null \
        || warn "advisory-db 预拉失败，首次 cargo-audit 需联网"
    fi
  fi
}

install_scanner_tools() {
  [[ "$WITH_SCANNER_TOOLS" -eq 1 ]] || return 0
  info "安装扫描工具 (local 模式)"

  install_syft
  install_grype

  if ! command -v scancode >/dev/null 2>&1; then
    python3 -m pip install scancode-toolkit 2>/dev/null \
      || warn "scancode-toolkit 安装失败（已优先使用 syft，缺失时再回退内置检测）"
  else
    ok "scancode 已存在"
  fi

  if ! command -v gosec >/dev/null 2>&1; then
    if command -v go >/dev/null 2>&1; then
      export GOTOOLCHAIN=local
      go install github.com/securego/gosec/v2/cmd/gosec@latest 2>/dev/null || warn "gosec 安装失败"
      if [[ -x "${HOME}/go/bin/gosec" ]]; then
        ln -sf "${HOME}/go/bin/gosec" /usr/local/bin/gosec 2>/dev/null || true
      fi
    else
      warn "未安装 Go，跳过 gosec（可: yum install golang 后重跑 --with-scanner-tools）"
    fi
  else
    ok "gosec 已存在"
  fi

  if command -v cppcheck >/dev/null 2>&1; then
    ok "cppcheck 已存在"
  else
    warn "cppcheck 未安装，C/C++ 扫描在识别到相关代码时可能 gate fail"
  fi

  install_bandit
  install_pmd
  install_cargo_audit
  install_eslint
}

setup_data_dirs() {
  info "创建数据目录"
  mkdir -p "$INSTALL_DIR/data/blobs" "$INSTALL_DIR/data/work"
  ok "data/blobs, data/work"
}

write_env_file() {
  local env_file="$INSTALL_DIR/.env"
  info "写入环境配置: $env_file"
  cat >"$env_file" <<EOF
# OpenMastiff — 由 install.sh 生成 ($(date -u +%Y-%m-%dT%H:%M:%SZ))
MONGO_URI=mongodb://localhost:27017/supplychain
REDIS_URL=redis://localhost:6379/${REDIS_DB}
BLOB_ROOT=${INSTALL_DIR}/data/blobs
WORK_ROOT=${INSTALL_DIR}/data/work
SCANNER_MODE=${MODE}
SCANNER_IMAGE=openmastiff-scanner:dev
API_HOST=0.0.0.0
API_PORT=${API_PORT}
APP_CONFIG_FILE=${INSTALL_DIR}/config/app_config.json
EOF
  chmod 600 "$env_file" 2>/dev/null || true
  ok ".env"
}

install_systemd_units() {
  [[ "$WITH_SYSTEMD" -eq 1 ]] || return 0
  need_root
  info "安装 systemd 服务"

  local unit_dir="/etc/systemd/system"
  local env_file="$INSTALL_DIR/.env"

  for svc in api worker; do
    cat >"${unit_dir}/openmastiff-${svc}.service" <<EOF
[Unit]
Description=OpenMastiff ${svc}
After=network.target redis.service mongod.service
Wants=redis.service

[Service]
Type=simple
EnvironmentFile=${env_file}
WorkingDirectory=${INSTALL_DIR}/backend
ExecStart=/usr/bin/bash ${INSTALL_DIR}/backend/run_${svc}.sh
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    ok "openmastiff-${svc}.service"
  done

  if [[ "$WITH_BEAT" -eq 1 ]]; then
    cat >"${unit_dir}/openmastiff-beat.service" <<EOF
[Unit]
Description=OpenMastiff Celery Beat
After=network.target openmastiff-worker.service

[Service]
Type=simple
EnvironmentFile=${env_file}
WorkingDirectory=${INSTALL_DIR}/backend
ExecStart=/usr/bin/bash ${INSTALL_DIR}/backend/run_beat.sh
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    ok "openmastiff-beat.service"
  fi

  systemctl daemon-reload
  systemctl enable openmastiff-api.service openmastiff-worker.service
  systemctl restart openmastiff-api.service openmastiff-worker.service
  [[ "$WITH_BEAT" -eq 1 ]] && systemctl enable --now openmastiff-beat.service

  sleep 2
  if curl -sf "http://127.0.0.1:${API_PORT}/bootstrap/status" >/dev/null 2>&1; then
    ok "API 健康检查通过"
  else
    warn "API 暂未响应，请检查: journalctl -u openmastiff-api -n 50"
  fi
}

deploy_docker() {
  info "Docker Compose 部署"
  need_root
  ensure_cmd docker || die "未找到 docker"
  cd "$INSTALL_DIR"
  export MONGO_IMAGE="${MONGO_IMAGE:-mongo:7}"
  export REDIS_IMAGE="${REDIS_IMAGE:-redis:7-alpine}"
  export PYTHON_BASE_IMAGE="${PYTHON_BASE_IMAGE:-python:3.12-slim}"
  if docker compose version >/dev/null 2>&1; then
    docker compose up -d --build
  else
    docker-compose up -d --build
  fi
  ok "Docker 服务已启动（API 默认端口 8000，见 docker-compose.yml）"
}

build_web() {
  [[ "$WITH_WEB" -eq 1 ]] || return 0
  info "构建前端"
  if ! command -v npm >/dev/null 2>&1; then
    warn "未找到 npm，跳过前端构建。可安装 Node.js 18+ 后执行: cd web && npm install && npm run build"
    return
  fi
  cd "$INSTALL_DIR/web"
  npm install
  npm run build
  ok "前端已构建: web/dist/"
}

print_success() {
  local host
  host="$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo localhost)"

  cat <<EOF

${C_GREEN}${C_BOLD}OpenMastiff 安装完成${C_RESET} (v${OPENMASTIFF_VERSION})

  安装目录:  ${INSTALL_DIR}
  部署模式:  ${MODE}
  配置文件:  ${INSTALL_DIR}/.env

EOF

  if [[ "$MODE" == "local" ]]; then
    if [[ "$WITH_SYSTEMD" -eq 1 ]]; then
      cat <<EOF
  API:       http://${host}:${API_PORT}
  服务管理:  systemctl status openmastiff-api openmastiff-worker
  日志:      journalctl -u openmastiff-api -f

EOF
    else
      cat <<EOF
  启动 API（终端 1）:
    set -a && source ${INSTALL_DIR}/.env && set +a
    bash ${INSTALL_DIR}/backend/run_api.sh

  启动 Worker（终端 2）:
    set -a && source ${INSTALL_DIR}/.env && set +a
    bash ${INSTALL_DIR}/backend/run_worker.sh

  API:       http://${host}:${API_PORT}
  冒烟测试:  见 ${INSTALL_DIR}/docs/08-mvp-smoke-test.md

EOF
    fi
    cat <<EOF
  前端开发:  cd ${INSTALL_DIR}/web && npm install && npm run dev
             （HTTPS https://<主机>/ ，HTTP :80 自动跳转）
             （生产构建: bash install.sh --from-source ${INSTALL_DIR} --with-web）

EOF
  else
    cat <<EOF
  Docker API:  http://${host}:8000
  查看状态:    cd ${INSTALL_DIR} && docker compose ps

EOF
  fi

  cat <<EOF
  文档:      ${INSTALL_DIR}/docs/
  卸载:      删除 ${INSTALL_DIR}；systemd 单元在 /etc/systemd/system/openmastiff-*.service

EOF
}

# ---------- main ----------
main() {
  printf '\n%bOpenMastiff 安装程序 v%s%b\n\n' "$C_BOLD" "$OPENMASTIFF_VERSION" "$C_RESET"

  if [[ "$SKIP_DEPS" -eq 0 && "$(id -u)" -ne 0 ]]; then
    warn "未以 root 运行，系统包安装可能失败。建议使用: curl ... | sudo bash"
  fi

  install_source
  install_system_deps
  setup_data_dirs
  write_env_file
  install_python_deps
  install_scanner_tools

  if [[ "$MODE" == "docker" ]]; then
    deploy_docker
  else
    install_systemd_units
  fi

  build_web
  print_success
}

main "$@"
