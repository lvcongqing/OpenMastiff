#!/usr/bin/env sh
set -eu

INPUT_DIR="${INPUT_DIR:-/input}"
OUTPUT_DIR="${OUTPUT_DIR:-/output}"
POLICY_FILE="${POLICY_FILE:-/policy/policy.json}"
SCANNER_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

now() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

mkdir -p "$OUTPUT_DIR"
# 勿 truncate：worker 可能在扫描前已写入 go mod download 日志
touch "$OUTPUT_DIR/logs.txt"
export GOPROXY="${GOPROXY:-https://goproxy.cn,direct}"
export PATH="${HOME:-/root}/.cargo/bin:/usr/local/bin:/usr/local/go/bin:${PATH:-/usr/bin:/bin}"
export GOPATH="${GOPATH:-/root/go}"
export GOMODCACHE="${GOMODCACHE:-/root/go/pkg/mod}"

cleanup_children() {
  # Best-effort cleanup for any lingering subprocesses (gosec/go/cppcheck, etc.).
  pkill -TERM -P "$$" 2>/dev/null || true
  sleep 1
  pkill -KILL -P "$$" 2>/dev/null || true
}

# 仅在异常中断时清理子进程；EXIT 时 pkill 可能在 gosec 仍运行时就杀掉分析进程
trap 'cleanup_children' INT TERM

# 本脚本遵循一期 runner 协议输出 artifacts。
# 运行策略：
# - 默认用 syft 生成 SBOM（CycloneDX/SPDX/syft-json）并从 SBOM 提取许可证。
# - syft 不可用时回退 scancode，再回退 detect_license.py。
# - gosec：探测全部 go.mod，在各自模块目录执行；启用且失败 => gate fail；策略关闭则 overall 不因 gosec 失败
# - cppcheck：仅当识别到 C/C++ 时缺失/失败 => gate fail

STARTED_AT="$(now)"

SCANCODE_VERSION=""
SYFT_VERSION=""
GOSEC_VERSION=""
CPPCHECK_VERSION=""
SCANCODE_ERROR=""
SYFT_ERROR=""
GOSEC_ERROR=""
CPPCHECK_ERROR=""
SCANCODE_EXIT=0
SYFT_EXIT=0
GOSEC_EXIT=0
CPPCHECK_EXIT=0
SYFT_STATUS="missing"
SYFT_CMD=""
LICENSE_ENGINE=""

TIMEOUT_LICENSE_MIN="${TIMEOUT_LICENSE_MIN:-30}"
TIMEOUT_SYFT_MIN="${TIMEOUT_SYFT_MIN:-15}"
TIMEOUT_GOSEC_MIN="${TIMEOUT_GOSEC_MIN:-20}"
TIMEOUT_CPPCHECK_MIN="${TIMEOUT_CPPCHECK_MIN:-30}"
TIMEOUT_CVE_MIN="${TIMEOUT_CVE_MIN:-15}"
TIMEOUT_LICENSE_SEC=$((TIMEOUT_LICENSE_MIN * 60))
TIMEOUT_SYFT_SEC=$((TIMEOUT_SYFT_MIN * 60))
TIMEOUT_GOSEC_SEC=$((TIMEOUT_GOSEC_MIN * 60))
TIMEOUT_CPPCHECK_SEC=$((TIMEOUT_CPPCHECK_MIN * 60))

has_cmd() { command -v "$1" >/dev/null 2>&1; }
json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

find_go_mod_dirs() {
  python3 - "$INPUT_DIR" "${EXCLUDE_DIRS:-}" <<'PY'
import os, sys
root = sys.argv[1]
exclude = {x.strip() for x in (sys.argv[2] or "").split(";") if x.strip()}
exclude |= {
    "vendor", "third_party", "3rdparty", "external", ".git",
    "node_modules", "build", "dist", "out", "bin", "obj",
    ".idea", ".vscode", ".cache", ".github",
}
found = []
for dirpath, dirnames, filenames in os.walk(root):
    dirnames[:] = [d for d in dirnames if d not in exclude and not d.startswith(".")]
    if "go.mod" in filenames:
        found.append(dirpath)
for p in found:
    print(p)
PY
}

detect_go() {
  [ -f "$INPUT_DIR/go.mod" ] && return 0
  _mods="$(find_go_mod_dirs || true)"
  [ -n "${_mods}" ] && return 0
  find "$INPUT_DIR" -type f -name '*.go' -not -path '*/vendor/*' -not -path '*/third_party/*' -print -quit 2>/dev/null | grep -q .
}

detect_cpp() {
  [ -f "$INPUT_DIR/CMakeLists.txt" ] && return 0
  find "$INPUT_DIR" -type f \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.h' -o -name '*.hpp' \) \
    -not -path '*/vendor/*' -not -path '*/third_party/*' -print -quit 2>/dev/null | grep -q .
}

SCOPE_MODE="${SCOPE_MODE:-auto}"
INCLUDE_PATHS="${INCLUDE_PATHS:-}"

GO_DETECTED=0
CPP_DETECTED=0
if detect_go; then GO_DETECTED=1; fi
if detect_cpp; then CPP_DETECTED=1; fi

LICENSE_STATUS="failed"
LICENSE_UNKNOWN=1
LICENSE_HITS="[]"
LICENSE_GATE=""
LICENSE_GATE_REASON=""
SCANCODE_CMD=""

load_license_json() {
  eval "$(python3 - "$OUTPUT_DIR/license.json" <<'PY'
import json, sys
p = sys.argv[1]
try:
    d = json.load(open(p, encoding="utf-8"))
except Exception:
    d = {}
hits = d.get("hits") or [x.get("spdx_license_key") for x in (d.get("licenses") or []) if isinstance(x, dict)]
hits = [h for h in hits if h]
gate = (d.get("gate") or {})
print("LICENSE_HITS='%s'" % json.dumps(hits, ensure_ascii=False).replace("'", "'\\''"))
print("LICENSE_UNKNOWN=%s" % (1 if d.get("unknown_or_low_confidence") else 0))
print("LICENSE_GATE='%s'" % str(gate.get("status") or "").replace("'", ""))
print("LICENSE_GATE_REASON='%s'" % str(gate.get("reason") or "").replace("'", ""))
PY
)"
}

syft_version() {
  syft version -o json 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("version") or "")' 2>/dev/null \
    || syft version 2>/dev/null | awk 'NR==1{print; exit}' \
    || echo unknown
}

if has_cmd cargo; then
  echo "[syft] preparing rust lockfiles" >>"$OUTPUT_DIR/logs.txt"
  python3 - "$INPUT_DIR" >>"$OUTPUT_DIR/logs.txt" 2>&1 <<'PY' || true
import os, subprocess, sys
root = sys.argv[1]
skip = {".git", ".svn", "target", "node_modules", "vendor"}
for dp, dns, fns in os.walk(root):
    dns[:] = [d for d in dns if d not in skip and not d.startswith(".")]
    if "Cargo.toml" not in fns or "Cargo.lock" in fns:
        continue
    print("[syft] cargo generate-lockfile in %s" % os.path.relpath(dp, root))
    subprocess.run(["cargo", "generate-lockfile", "--manifest-path", os.path.join(dp, "Cargo.toml")], cwd=dp)
PY
fi

if has_cmd syft; then
  SYFT_VERSION="$(syft_version)"
  if syft scan --help >/dev/null 2>&1; then
    SYFT_BIN="syft scan"
  else
    SYFT_BIN="syft"
  fi
  SYFT_EXCLUDE_FILE="$OUTPUT_DIR/.syft_excludes"
  : >"$SYFT_EXCLUDE_FILE"
  if [ -f "$SCANNER_DIR/apply_excludes.py" ]; then
    python3 "$SCANNER_DIR/apply_excludes.py" syft-args "$POLICY_FILE" >"$SYFT_EXCLUDE_FILE" 2>/dev/null || true
  fi
  SYFT_CMD="$SYFT_BIN dir:$INPUT_DIR -o cyclonedx-json=$OUTPUT_DIR/sbom.cdx.json -o spdx-json=$OUTPUT_DIR/sbom.spdx.json -o syft-json=$OUTPUT_DIR/sbom.syft.json"
  if [ -s "$SYFT_EXCLUDE_FILE" ]; then
    SYFT_CMD="$SYFT_CMD excludes=$(tr '\n' ',' <"$SYFT_EXCLUDE_FILE" | sed 's/,$//')"
  fi
  echo "[syft] $SYFT_CMD" >>"$OUTPUT_DIR/logs.txt"
  if timeout -k 15s "${TIMEOUT_SYFT_SEC}s" python3 - "$SYFT_BIN" "$INPUT_DIR" "$OUTPUT_DIR" "$SYFT_EXCLUDE_FILE" <<'PY' >>"$OUTPUT_DIR/logs.txt" 2>&1
import os, subprocess, sys
parts = sys.argv[1].split()
inp, out, excl = sys.argv[2], sys.argv[3], sys.argv[4]
cmd = parts + [
    "dir:" + inp,
    "-o", "cyclonedx-json=" + os.path.join(out, "sbom.cdx.json"),
    "-o", "spdx-json=" + os.path.join(out, "sbom.spdx.json"),
    "-o", "syft-json=" + os.path.join(out, "sbom.syft.json"),
]
if os.path.isfile(excl):
    for line in open(excl, encoding="utf-8"):
        pat = line.strip()
        if pat:
            cmd.extend(["--exclude", pat])
raise SystemExit(subprocess.call(cmd))
PY
  then
    SYFT_STATUS="succeeded"
    SYFT_EXIT=0
    if [ -f "$SCANNER_DIR/manifest_enrich.py" ]; then
      python3 "$SCANNER_DIR/manifest_enrich.py" "$INPUT_DIR" "$OUTPUT_DIR" >>"$OUTPUT_DIR/logs.txt" 2>&1 || true
    fi
    if [ -f "$SCANNER_DIR/apply_excludes.py" ]; then
      python3 "$SCANNER_DIR/apply_excludes.py" filter "$OUTPUT_DIR" "$INPUT_DIR" "$POLICY_FILE" >>"$OUTPUT_DIR/logs.txt" 2>&1 || true
    fi
    if [ -f "$OUTPUT_DIR/sbom.cdx.json" ]; then
      cp -f "$OUTPUT_DIR/sbom.cdx.json" "$OUTPUT_DIR/sbom.json"
    fi
    if [ -f "$SCANNER_DIR/syft_to_license.py" ]; then
      if python3 "$SCANNER_DIR/syft_to_license.py" "$OUTPUT_DIR" "$INPUT_DIR" "$POLICY_FILE" >>"$OUTPUT_DIR/logs.txt" 2>&1; then
        LICENSE_ENGINE="syft"
        LICENSE_STATUS="succeeded"
        load_license_json
      else
        SYFT_ERROR="syft SBOM ok, license conversion failed"
      fi
    else
      SYFT_ERROR="syft_to_license.py missing"
    fi
  else
    SYFT_EXIT=$?
    SYFT_STATUS="failed"
    if [ "$SYFT_EXIT" -eq 124 ] || [ "$SYFT_EXIT" -eq 137 ]; then
      SYFT_ERROR="syft timeout after ${TIMEOUT_SYFT_MIN} minutes"
    else
      SYFT_ERROR="syft failed (exit=${SYFT_EXIT})"
    fi
    echo "[syft] $SYFT_ERROR" >>"$OUTPUT_DIR/logs.txt"
  fi
fi

if [ "$LICENSE_STATUS" != "succeeded" ] && has_cmd scancode; then
  SCANCODE_VERSION="$(scancode --version 2>/dev/null || echo unknown)"
  SCANCODE_CMD="scancode -l --json-pp $OUTPUT_DIR/license.json $INPUT_DIR"
  LICENSE_ENGINE="scancode"
  if timeout -k 15s "${TIMEOUT_LICENSE_SEC}s" scancode -l --json-pp "$OUTPUT_DIR/license.json" "$INPUT_DIR" >/dev/null 2>&1; then
    LICENSE_STATUS="succeeded"
    LICENSE_UNKNOWN=0
  else
    SCANCODE_EXIT=$?
    LICENSE_STATUS="failed"
    LICENSE_UNKNOWN=1
    if [ "$SCANCODE_EXIT" -eq 124 ] || [ "$SCANCODE_EXIT" -eq 137 ]; then
      SCANCODE_ERROR="scancode timeout after ${TIMEOUT_LICENSE_MIN} minutes"
    else
      SCANCODE_ERROR="scancode failed (exit=${SCANCODE_EXIT})"
    fi
    cat > "$OUTPUT_DIR/license.json" <<EOF
{"licenses": [], "files": [], "note": "${SCANCODE_ERROR}"}
EOF
  fi
elif [ "$LICENSE_STATUS" != "succeeded" ] && [ -f "$SCANNER_DIR/detect_license.py" ]; then
  SCANCODE_VERSION="builtin-detect_license/1.0"
  SCANCODE_CMD="python3 $SCANNER_DIR/detect_license.py"
  LICENSE_ENGINE="builtin-detect_license"
  if timeout -k 15s "${TIMEOUT_LICENSE_SEC}s" python3 "$SCANNER_DIR/detect_license.py" "$INPUT_DIR" "$OUTPUT_DIR" "$POLICY_FILE" >>"$OUTPUT_DIR/logs.txt" 2>&1; then
    SCANCODE_EXIT=0
    LICENSE_STATUS="succeeded"
    load_license_json
  else
    SCANCODE_EXIT=$?
    LICENSE_STATUS="failed"
    LICENSE_UNKNOWN=1
    SCANCODE_ERROR="builtin license detector failed (exit=${SCANCODE_EXIT})"
    cat > "$OUTPUT_DIR/license.json" <<EOF
{"licenses": [], "files": [], "note": "${SCANCODE_ERROR}"}
EOF
  fi
elif [ "$LICENSE_STATUS" != "succeeded" ]; then
  SCANCODE_EXIT=127
  SCANCODE_ERROR="syft/scancode not installed and builtin detector missing"
  cat > "$OUTPUT_DIR/license.json" <<'EOF'
{"licenses": [], "files": [], "note": "syft/scancode not installed"}
EOF
fi

CVE_STATUS="skipped"
CVE_COUNTS='{"critical":0,"high":0,"medium":0,"low":0,"negligible":0,"unknown":0}'
CVE_ENGINE=""
GATE_CVE="skipped"
GATE_CVE_REASON="cve scan not run"
if [ -f "$SCANNER_DIR/sca.py" ]; then
  echo "[sca] dependency CVE/advisory scan" >>"$OUTPUT_DIR/logs.txt"
  python3 "$SCANNER_DIR/sca.py" "$INPUT_DIR" "$OUTPUT_DIR" "$POLICY_FILE" >>"$OUTPUT_DIR/logs.txt" 2>&1 || true
  eval "$(python3 - "$OUTPUT_DIR/cve.json" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    d = {}
counts = d.get("counts") if isinstance(d.get("counts"), dict) else {}
gate = d.get("gate") if isinstance(d.get("gate"), dict) else {}
engines = d.get("engines") if isinstance(d.get("engines"), list) else []
names = [str((e or {}).get("name") or "") for e in engines if isinstance(e, dict) and (e or {}).get("status") == "succeeded"]
print("CVE_STATUS=%s" % (d.get("status") or "skipped"))
print("CVE_COUNTS='%s'" % json.dumps({
    "critical": int(counts.get("critical") or 0),
    "high": int(counts.get("high") or 0),
    "medium": int(counts.get("medium") or 0),
    "low": int(counts.get("low") or 0),
    "negligible": int(counts.get("negligible") or 0),
    "unknown": int(counts.get("unknown") or 0),
}, separators=(",", ":")))
print("CVE_ENGINE=%s" % (",".join([x for x in names if x]) or (d.get("tool") or "sca")))
print("GATE_CVE=%s" % (gate.get("status") or "skipped"))
print("GATE_CVE_REASON='%s'" % str(gate.get("reason") or "").replace("'", ""))
PY
)"
fi

GOSEC_STATUS="skipped"
GOSEC_COUNTS='{"high":0,"medium":0,"low":0}'
GOSEC_CMD=""
GOSEC_ENABLED="${GOSEC_ENABLED:-1}"
GOSEC_FILES=0

parse_gosec_artifact() {
  python3 - "$1" <<'PY'
import json, sys
path = sys.argv[1]
out_counts = {"high": 0, "medium": 0, "low": 0}
files = 0
try:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
except Exception:
    print(json.dumps(out_counts))
    print(files)
    raise SystemExit(0)
stats = data.get("Stats") or {}
files = int(stats.get("files") or 0)
for issue in data.get("Issues") or []:
    if not isinstance(issue, dict):
        continue
    sev = str(issue.get("severity") or "").upper()
    if sev == "HIGH":
        out_counts["high"] += 1
    elif sev == "MEDIUM":
        out_counts["medium"] += 1
    elif sev == "LOW":
        out_counts["low"] += 1
print(json.dumps(out_counts))
print(files)
print(out_counts["high"] + out_counts["medium"] + out_counts["low"])
PY
}

finalize_gosec_result() {
  if [ ! -f "$OUTPUT_DIR/gosec.json" ]; then
    return 1
  fi
  # 三行输出：counts JSON、files 数、issue 总数（避免 shell 算术解析 JSON 失败）
  _gosec_parsed="$(parse_gosec_artifact "$OUTPUT_DIR/gosec.json")"
  GOSEC_COUNTS="$(printf '%s\n' "$_gosec_parsed" | sed -n '1p')"
  GOSEC_FILES="$(printf '%s\n' "$_gosec_parsed" | sed -n '2p')"
  GOSEC_ISSUE_TOTAL="$(printf '%s\n' "$_gosec_parsed" | sed -n '3p')"
  GOSEC_FILES="${GOSEC_FILES:-0}"
  GOSEC_ISSUE_TOTAL="${GOSEC_ISSUE_TOTAL:-0}"
  GOSEC_COUNTS="${GOSEC_COUNTS:-{\"high\":0,\"medium\":0,\"low\":0}}"
  return 0
}

relpath_from_input() {
  python3 -c 'import os,sys; print(os.path.relpath(sys.argv[1], sys.argv[2]))' "$1" "$INPUT_DIR"
}

prepare_go_for_gosec() {
  _mod_dir="${1:-$INPUT_DIR}"
  if ! has_cmd go || [ ! -f "$_mod_dir/go.mod" ]; then
    return 0
  fi
  _mod_rel="$(relpath_from_input "$_mod_dir")"
  echo "[gosec] module ${_mod_rel}: go list ./... (preflight)" >>"$OUTPUT_DIR/logs.txt"
  if (cd "$_mod_dir" && GOWORK=off go list ./...) >>"$OUTPUT_DIR/logs.txt" 2>&1; then
    return 0
  fi
  echo "[gosec] module ${_mod_rel}: go list failed, running go mod download" >>"$OUTPUT_DIR/logs.txt"
  (cd "$_mod_dir" && GOWORK=off go mod download) >>"$OUTPUT_DIR/logs.txt" 2>&1 \
    || echo "[gosec] module ${_mod_rel}: go mod download failed, continuing" >>"$OUTPUT_DIR/logs.txt"
  (cd "$_mod_dir" && GOWORK=off go list ./...) >>"$OUTPUT_DIR/logs.txt" 2>&1 \
    || echo "[gosec] module ${_mod_rel}: go list still failing after download" >>"$OUTPUT_DIR/logs.txt"
}

merge_gosec_reports() {
  python3 - "$OUTPUT_DIR/gosec.json" "$GO_MOD_LIST" <<'PY'
import json, os, sys
out = sys.argv[1]
mod_list_path = sys.argv[2] if len(sys.argv) > 2 else ""
partial_dir = os.path.join(os.path.dirname(out), "gosec.d")
mod_dirs = []
if mod_list_path and os.path.isfile(mod_list_path):
    with open(mod_list_path, encoding="utf-8") as f:
        mod_dirs = [ln.strip() for ln in f if ln.strip()]
paths = []
if os.path.isdir(partial_dir):
    for name in sorted(os.listdir(partial_dir)):
        if name.endswith(".json"):
            paths.append(os.path.join(partial_dir, name))
issues = []
golang_errors = {}
files = lines = nosec = found = 0
version = ""
modules = []
for i, path in enumerate(paths):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        continue
    if not isinstance(data, dict):
        continue
    issues.extend([x for x in (data.get("Issues") or []) if isinstance(x, dict)])
    ge = data.get("Golang errors") or {}
    if isinstance(ge, dict):
        golang_errors.update(ge)
    stats = data.get("Stats") or {}
    nfiles = int(stats.get("files") or 0)
    files += nfiles
    lines += int(stats.get("lines") or 0)
    nosec += int(stats.get("nosec") or 0)
    found += int(stats.get("found") or 0)
    version = data.get("GosecVersion") or version
    mod = mod_dirs[i] if i < len(mod_dirs) else os.path.basename(path)
    root = os.environ.get("INPUT_DIR") or ""
    if root and os.path.isabs(mod):
        try:
            mod = os.path.relpath(mod, root)
        except Exception:
            pass
    modules.append({"module": mod, "files": nfiles})
payload = {
    "Golang errors": golang_errors,
    "Issues": issues,
    "Stats": {"files": files, "lines": lines, "nosec": nosec, "found": found},
    "GosecVersion": version,
    "modules": modules,
}
with open(out, "w", encoding="utf-8") as f:
    json.dump(payload, f, ensure_ascii=False, indent="\t")
    f.write("\n")
PY
}

if [ "$GO_DETECTED" -eq 1 ]; then
  if has_cmd gosec; then
    GOSEC_VERSION="$(gosec -version 2>/dev/null | head -n 1 || echo unknown)"
    GO_MOD_LIST="$OUTPUT_DIR/go_mod_dirs.txt"
    find_go_mod_dirs >"$GO_MOD_LIST" || true
    if [ ! -s "$GO_MOD_LIST" ]; then
      printf '%s\n' "$INPUT_DIR" >"$GO_MOD_LIST"
      echo "[gosec] no go.mod found, scanning repo root" >>"$OUTPUT_DIR/logs.txt"
    else
      echo "[gosec] discovered go.mod:" >>"$OUTPUT_DIR/logs.txt"
      while IFS= read -r _mod_dir || [ -n "${_mod_dir:-}" ]; do
        [ -n "${_mod_dir:-}" ] || continue
        echo "[gosec]  - $(relpath_from_input "$_mod_dir")" >>"$OUTPUT_DIR/logs.txt"
      done <"$GO_MOD_LIST"
    fi
    GOSEC_CMD="gosec -fmt=json ./... in each go.mod directory"
    if has_cmd go; then
      GOSEC_CMD="go mod download (best-effort per module) && ${GOSEC_CMD}"
      while IFS= read -r _mod_dir || [ -n "${_mod_dir:-}" ]; do
        [ -n "${_mod_dir:-}" ] || continue
        prepare_go_for_gosec "$_mod_dir"
      done <"$GO_MOD_LIST"
    fi
    GOSEC_LOCK_DIR="${GOMODCACHE}/.openmastiff-locks"
    mkdir -p "$GOSEC_LOCK_DIR" "$OUTPUT_DIR/gosec.d"
    run_gosec_in_dir() {
      _mod_dir="$1"
      _out="$2"
      _mod_rel="$(relpath_from_input "$_mod_dir")"
      echo "[gosec] scanning module ${_mod_rel}" >>"$OUTPUT_DIR/logs.txt"
      if has_cmd flock; then
        (
          flock -w 600 9 || exit 1
          cd "$_mod_dir" || exit 1
          export GOPROXY GOMODCACHE GOPATH PATH
          export GOWORK=off
          GOTOOLCHAIN=local gosec -fmt=json -out "$_out" ./...
        ) >>"$OUTPUT_DIR/logs.txt" 2>>"$OUTPUT_DIR/gosec.stderr" 9>>"${GOSEC_LOCK_DIR}/gosec.lock" \
          || true
      else
        (
          cd "$_mod_dir" || exit 1
          export GOPROXY GOMODCACHE GOPATH PATH
          export GOWORK=off
          GOTOOLCHAIN=local gosec -fmt=json -out "$_out" ./...
        ) >>"$OUTPUT_DIR/logs.txt" 2>>"$OUTPUT_DIR/gosec.stderr" || true
      fi
    }
    : >"$OUTPUT_DIR/gosec.stderr"
    rm -f "$OUTPUT_DIR/gosec.json"
    _mod_idx=0
    while IFS= read -r _mod_dir || [ -n "${_mod_dir:-}" ]; do
      [ -n "${_mod_dir:-}" ] || continue
      _mod_idx=$((_mod_idx + 1))
      _partial="$OUTPUT_DIR/gosec.d/$(printf '%02d' "$_mod_idx").json"
      _gosec_attempt=0
      _gosec_max_attempts=3
      while [ "$_gosec_attempt" -lt "$_gosec_max_attempts" ]; do
        _gosec_attempt=$((_gosec_attempt + 1))
        echo "[gosec] module $(relpath_from_input "$_mod_dir") attempt ${_gosec_attempt}/${_gosec_max_attempts}" >>"$OUTPUT_DIR/logs.txt"
        if [ "$_gosec_attempt" -gt 1 ]; then
          sleep 3
          prepare_go_for_gosec "$_mod_dir"
        fi
        rm -f "$_partial"
        run_gosec_in_dir "$_mod_dir" "$_partial"
        if [ -f "$_partial" ]; then
          _mod_files="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1],encoding="utf-8")); print(int((d.get("Stats") or {}).get("files") or 0))' "$_partial" 2>/dev/null || echo 0)"
          if [ "${_mod_files:-0}" -gt 0 ]; then
            break
          fi
        fi
      done
    done <"$GO_MOD_LIST"
    merge_gosec_reports
    GOSEC_EXIT=0
    if finalize_gosec_result; then
      issue_total="${GOSEC_ISSUE_TOTAL:-0}"
      # gosec 发现问题时常返回 exit 1，有有效报告即视为成功
      if [ "$issue_total" -gt 0 ]; then
        GOSEC_STATUS="succeeded"
        GOSEC_ERROR=""
      elif [ "${GOSEC_FILES:-0}" -eq 0 ]; then
        GOSEC_STATUS="failed"
        GOSEC_ERROR="${GOSEC_ERROR:-gosec scanned 0 files (Go module deps may be missing)}"
      elif [ "$GOSEC_EXIT" -eq 0 ]; then
        GOSEC_STATUS="succeeded"
        GOSEC_ERROR=""
      else
        GOSEC_STATUS="failed"
        if [ "$GOSEC_EXIT" -eq 124 ] || [ "$GOSEC_EXIT" -eq 137 ]; then
          GOSEC_ERROR="gosec timeout after ${TIMEOUT_GOSEC_MIN} minutes"
        else
          GOSEC_ERROR="${GOSEC_ERROR:-gosec failed (exit=${GOSEC_EXIT})}"
        fi
      fi
    else
      GOSEC_STATUS="failed"
      GOSEC_ERROR="${GOSEC_ERROR:-gosec produced no report}"
    fi
    if [ "$GOSEC_STATUS" = "failed" ] && [ ! -f "$OUTPUT_DIR/gosec.json" ]; then
      cat > "$OUTPUT_DIR/gosec.json" <<EOF
{"Issues": [], "note": "${GOSEC_ERROR}"}
EOF
    fi
  else
    GOSEC_EXIT=127
    if [ "$GOSEC_ENABLED" = "1" ]; then
      GOSEC_STATUS="failed"
      GOSEC_ERROR="gosec not installed"
    else
      GOSEC_STATUS="skipped"
      GOSEC_ERROR="gosec disabled by policy"
    fi
    cat > "$OUTPUT_DIR/gosec.json" <<'EOF'
{"Issues": [], "note": "gosec not installed"}
EOF
  fi
else
  echo "[gosec] skip: go not detected" >>"$OUTPUT_DIR/logs.txt"
  rm -f "$OUTPUT_DIR/gosec.json"
fi

CPPCHECK_STATUS="skipped"
CPPCHECK_COUNTS='{"error":0,"warning":0,"style":0,"performance":0,"information":0}'
CPPCHECK_CMD=""
if [ "$CPP_DETECTED" -eq 1 ]; then
  if has_cmd cppcheck; then
    CPPCHECK_VERSION="$(cppcheck --version 2>/dev/null | head -n 1 || echo unknown)"
    CPPCHECK_CMD="cppcheck --xml --xml-version=2 $INPUT_DIR 2> $OUTPUT_DIR/cppcheck.xml"
    if timeout -k 15s "${TIMEOUT_CPPCHECK_SEC}s" sh -c "cppcheck --xml --xml-version=2 \"$INPUT_DIR\" 2> \"$OUTPUT_DIR/cppcheck.xml\" >/dev/null 2>&1"; then
      CPPCHECK_STATUS="succeeded"
      CPPCHECK_EXIT=0
    else
      CPPCHECK_EXIT=$?
      CPPCHECK_STATUS="failed"
      if [ "$CPPCHECK_EXIT" -eq 124 ] || [ "$CPPCHECK_EXIT" -eq 137 ]; then
        CPPCHECK_ERROR="cppcheck timeout after ${TIMEOUT_CPPCHECK_MIN} minutes"
      else
        CPPCHECK_ERROR="cppcheck failed (exit=${CPPCHECK_EXIT})"
      fi
      cat > "$OUTPUT_DIR/cppcheck.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<results version="2">
  <cppcheck version="timeout-or-failed"/>
  <errors/>
  <note>${CPPCHECK_ERROR}</note>
</results>
EOF
    fi
  else
    CPPCHECK_STATUS="failed"
    CPPCHECK_EXIT=127
    CPPCHECK_ERROR="cppcheck not installed"
    cat > "$OUTPUT_DIR/cppcheck.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<results version="2">
  <cppcheck version="missing"/>
  <errors/>
  <note>cppcheck not installed</note>
</results>
EOF
  fi
else
  echo "[cppcheck] skip: c/c++ not detected" >>"$OUTPUT_DIR/logs.txt"
  rm -f "$OUTPUT_DIR/cppcheck.xml"
fi

BANDIT_STATUS="skipped"
PMD_STATUS="skipped"
CARGO_AUDIT_STATUS="skipped"
ESLINT_STATUS="skipped"
BANDIT_COUNTS='{"high":0,"medium":0,"low":0}'
PMD_COUNTS='{"high":0,"medium":0,"low":0}'
CARGO_AUDIT_COUNTS='{"high":0,"medium":0,"low":0}'
ESLINT_COUNTS='{"high":0,"medium":0,"low":0}'
PY_DETECTED=0
JAVA_DETECTED=0
RUST_DETECTED=0
JS_DETECTED=0
if [ -f "$SCANNER_DIR/lang_sast.py" ]; then
  echo "[lang_sast] python/java/rust/javascript specialized scanners" >>"$OUTPUT_DIR/logs.txt"
  python3 "$SCANNER_DIR/lang_sast.py" "$INPUT_DIR" "$OUTPUT_DIR" "$INCLUDE_PATHS" >>"$OUTPUT_DIR/logs.txt" 2>&1 || true
  eval "$(python3 - "$OUTPUT_DIR/lang_sast_status.json" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    d = {}
def dump(prefix, key):
    b = d.get(key) if isinstance(d.get(key), dict) else {}
    counts = b.get("counts") if isinstance(b.get("counts"), dict) else {}
    print("%s_STATUS=%s" % (prefix, b.get("status") or "skipped"))
    print("%s_COUNTS='%s'" % (prefix, json.dumps({
        "high": int(counts.get("high") or 0),
        "medium": int(counts.get("medium") or 0),
        "low": int(counts.get("low") or 0),
    }, separators=(",", ":"))))
    print("%s_ENGINE=%s" % (prefix, b.get("engine") or ""))
dump("BANDIT", "bandit")
dump("PMD", "pmd")
dump("CARGO_AUDIT", "cargo_audit")
dump("ESLINT", "eslint")
print("PY_DETECTED=%s" % int(d.get("python_detected") or 0))
print("JAVA_DETECTED=%s" % int(d.get("java_detected") or 0))
print("RUST_DETECTED=%s" % int(d.get("rust_detected") or 0))
print("JS_DETECTED=%s" % int(d.get("javascript_detected") or 0))
PY
)"
fi

POLICY_SHA256="unknown"
if [ -f "$POLICY_FILE" ]; then
  POLICY_SHA256="$(python3 -c "import hashlib,pathlib;print(hashlib.sha256(pathlib.Path('$POLICY_FILE').read_bytes()).hexdigest())")"
fi

INPUT_SHA256="${INPUT_SHA256:-}"
if [ -z "$INPUT_SHA256" ]; then
  INPUT_SHA256="$(python3 - "$INPUT_DIR" <<'PY'
import hashlib, os, sys
root = sys.argv[1]
h = hashlib.sha256()
files = []
for dp, dns, fns in os.walk(root):
    dns[:] = [d for d in dns if d not in {".git", ".svn"}]
    for n in fns:
        files.append(os.path.join(dp, n))
for p in sorted(files):
    rel = os.path.relpath(p, root).encode("utf-8")
    h.update(rel + b"\0")
    try:
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
    except Exception:
        pass
    h.update(b"\0\0")
print(h.hexdigest())
PY
)"
fi

ENDED_AT="$(now)"

# --- Gate aggregation (overall must not fail on skipped gosec when GOSEC_ENABLED=0) ---
if [ -n "$LICENSE_GATE" ]; then
  GATE_LICENSE="$LICENSE_GATE"
  GATE_LICENSE_REASON="${LICENSE_GATE_REASON:-ok}"
elif [ "$LICENSE_STATUS" != "succeeded" ]; then
  GATE_LICENSE="pending_legal"
  GATE_LICENSE_REASON="license tool missing or scan failed"
else
  GATE_LICENSE="pass"
  GATE_LICENSE_REASON="ok"
fi

# Policy off => never block on gosec (missing binary, failed run, or skipped)
if [ "$GOSEC_ENABLED" != "1" ]; then
  GATE_GOSEC="pass"
  GATE_GOSEC_REASON="gosec disabled by policy"
elif [ "$GOSEC_STATUS" = "skipped" ]; then
  GATE_GOSEC="skipped"
  GATE_GOSEC_REASON="go not detected"
elif [ "$GOSEC_STATUS" = "failed" ]; then
  GATE_GOSEC="fail"
  GATE_GOSEC_REASON="gosec missing or scan failed"
else
  GATE_GOSEC="pass"
  GATE_GOSEC_REASON="ok"
fi

GOSEC_BLOCK_HIGH=0
CPPCHECK_BLOCK_ERROR=0
BANDIT_ENABLED="${BANDIT_ENABLED:-1}"
PMD_ENABLED="${PMD_ENABLED:-1}"
CARGO_AUDIT_ENABLED="${CARGO_AUDIT_ENABLED:-1}"
ESLINT_ENABLED="${ESLINT_ENABLED:-1}"
BANDIT_BLOCK_HIGH="${BANDIT_BLOCK_HIGH:-0}"
PMD_BLOCK_HIGH="${PMD_BLOCK_HIGH:-0}"
CARGO_AUDIT_BLOCK_HIGH="${CARGO_AUDIT_BLOCK_HIGH:-0}"
ESLINT_BLOCK_HIGH="${ESLINT_BLOCK_HIGH:-0}"
if [ -f "$POLICY_FILE" ]; then
  eval "$(python3 - "$POLICY_FILE" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    d = {}
gosec = d.get("gosec") if isinstance(d.get("gosec"), dict) else {}
cpp = d.get("cppcheck") if isinstance(d.get("cppcheck"), dict) else {}
bandit = d.get("bandit") if isinstance(d.get("bandit"), dict) else {}
pmd = d.get("pmd") if isinstance(d.get("pmd"), dict) else {}
ca = d.get("cargo_audit") if isinstance(d.get("cargo_audit"), dict) else {}
eslint = d.get("eslint") if isinstance(d.get("eslint"), dict) else {}
print("GOSEC_BLOCK_HIGH=%s" % int(gosec.get("block_if_high_gt") or 0))
print("CPPCHECK_BLOCK_ERROR=%s" % int(cpp.get("block_if_error_gt") or 0))
print("BANDIT_BLOCK_HIGH=%s" % int(bandit.get("block_if_high_gt") or 0))
print("PMD_BLOCK_HIGH=%s" % int(pmd.get("block_if_high_gt") or 0))
print("CARGO_AUDIT_BLOCK_HIGH=%s" % int(ca.get("block_if_high_gt") or 0))
print("ESLINT_BLOCK_HIGH=%s" % int(eslint.get("block_if_high_gt") or 0))
print("BANDIT_ENABLED=%s" % (1 if bandit.get("enabled", True) else 0))
print("PMD_ENABLED=%s" % (1 if pmd.get("enabled", True) else 0))
print("CARGO_AUDIT_ENABLED=%s" % (1 if ca.get("enabled", True) else 0))
print("ESLINT_ENABLED=%s" % (1 if eslint.get("enabled", True) else 0))
PY
)"
fi

if [ "$GOSEC_ENABLED" = "1" ] && [ "$GOSEC_STATUS" = "succeeded" ]; then
  GOSEC_HIGH="$(python3 - "$OUTPUT_DIR/gosec.json" <<'PY'
import json, sys
p = sys.argv[1]
high = 0
try:
    data = json.load(open(p, encoding="utf-8"))
except Exception:
    data = {}
for issue in data.get("Issues") or []:
    if isinstance(issue, dict) and str(issue.get("severity") or "").upper() == "HIGH":
        high += 1
print(high)
PY
)"
  GOSEC_HIGH="${GOSEC_HIGH:-0}"
  GOSEC_COUNTS="$(python3 - "$OUTPUT_DIR/gosec.json" <<'PY'
import json, sys
p = sys.argv[1]
out = {"high": 0, "medium": 0, "low": 0}
try:
    data = json.load(open(p, encoding="utf-8"))
except Exception:
    data = {}
for issue in data.get("Issues") or []:
    if not isinstance(issue, dict):
        continue
    sev = str(issue.get("severity") or "").upper()
    if sev == "HIGH":
        out["high"] += 1
    elif sev == "MEDIUM":
        out["medium"] += 1
    elif sev == "LOW":
        out["low"] += 1
print(json.dumps(out, separators=(",", ":")))
PY
)"
  if [ "$GOSEC_HIGH" -gt "${GOSEC_BLOCK_HIGH:-0}" ]; then
    GATE_GOSEC="fail"
    GATE_GOSEC_REASON="gosec High ${GOSEC_HIGH} > ${GOSEC_BLOCK_HIGH}"
  fi
fi

if [ "$CPP_DETECTED" -ne 1 ]; then
  GATE_CPPCHECK="skipped"
  GATE_CPPCHECK_REASON="c/c++ not detected"
elif [ "$CPPCHECK_STATUS" = "failed" ]; then
  GATE_CPPCHECK="fail"
  GATE_CPPCHECK_REASON="cppcheck missing or scan failed"
else
  GATE_CPPCHECK="pass"
  GATE_CPPCHECK_REASON="ok"
fi

if [ "$CPP_DETECTED" -eq 1 ] && [ "$CPPCHECK_STATUS" = "succeeded" ]; then
  CPP_ERR="$(python3 -c 'import json,os; d=json.loads(os.environ.get("CPPCHECK_COUNTS") or "{}"); print(int(d.get("error") or 0))' 2>/dev/null || echo 0)"
  if [ "${CPP_ERR:-0}" -gt "${CPPCHECK_BLOCK_ERROR:-0}" ]; then
    GATE_CPPCHECK="fail"
    GATE_CPPCHECK_REASON="cppcheck error ${CPP_ERR} > ${CPPCHECK_BLOCK_ERROR}"
  fi
fi

apply_high_gate() {
  _enabled="$1"
  _status="$2"
  _counts="$3"
  _block="$4"
  _label="$5"
  _out_status="pass"
  _out_reason="ok"
  if [ "$_enabled" != "1" ]; then
    _out_status="pass"
    _out_reason="${_label} disabled by policy"
  elif [ "$_status" = "skipped" ]; then
    _out_status="skipped"
    _out_reason="${_label} language not detected"
  elif [ "$_status" = "failed" ]; then
    _out_status="fail"
    _out_reason="${_label} missing or scan failed"
  elif [ "$_status" = "succeeded" ]; then
    _high="$(python3 -c 'import json,sys; d=json.loads(sys.argv[1] or "{}"); print(int(d.get("high") or 0))' "$_counts" 2>/dev/null || echo 0)"
    if [ "${_high:-0}" -gt "${_block:-0}" ]; then
      _out_status="fail"
      _out_reason="${_label} High ${_high} > ${_block}"
    fi
  fi
  echo "$_out_status"
  echo "$_out_reason"
}

_bandit_gate="$(apply_high_gate "${BANDIT_ENABLED:-1}" "$BANDIT_STATUS" "$BANDIT_COUNTS" "${BANDIT_BLOCK_HIGH:-0}" "bandit")"
GATE_BANDIT="$(printf '%s\n' "$_bandit_gate" | sed -n '1p')"
GATE_BANDIT_REASON="$(printf '%s\n' "$_bandit_gate" | sed -n '2p')"
_pmd_gate="$(apply_high_gate "${PMD_ENABLED:-1}" "$PMD_STATUS" "$PMD_COUNTS" "${PMD_BLOCK_HIGH:-0}" "pmd")"
GATE_PMD="$(printf '%s\n' "$_pmd_gate" | sed -n '1p')"
GATE_PMD_REASON="$(printf '%s\n' "$_pmd_gate" | sed -n '2p')"
_ca_gate="$(apply_high_gate "${CARGO_AUDIT_ENABLED:-1}" "$CARGO_AUDIT_STATUS" "$CARGO_AUDIT_COUNTS" "${CARGO_AUDIT_BLOCK_HIGH:-0}" "cargo-audit")"
GATE_CARGO_AUDIT="$(printf '%s\n' "$_ca_gate" | sed -n '1p')"
GATE_CARGO_AUDIT_REASON="$(printf '%s\n' "$_ca_gate" | sed -n '2p')"
_eslint_gate="$(apply_high_gate "${ESLINT_ENABLED:-1}" "$ESLINT_STATUS" "$ESLINT_COUNTS" "${ESLINT_BLOCK_HIGH:-0}" "eslint")"
GATE_ESLINT="$(printf '%s\n' "$_eslint_gate" | sed -n '1p')"
GATE_ESLINT_REASON="$(printf '%s\n' "$_eslint_gate" | sed -n '2p')"

# Overall: security fail wins; license pending_legal only if no fail
if [ "$GATE_GOSEC" = "fail" ]; then
  GATE_OVERALL="fail"
  GATE_OVERALL_REASON="$GATE_GOSEC_REASON"
elif [ "$GATE_CPPCHECK" = "fail" ]; then
  GATE_OVERALL="fail"
  GATE_OVERALL_REASON="$GATE_CPPCHECK_REASON"
elif [ "$GATE_BANDIT" = "fail" ]; then
  GATE_OVERALL="fail"
  GATE_OVERALL_REASON="$GATE_BANDIT_REASON"
elif [ "$GATE_PMD" = "fail" ]; then
  GATE_OVERALL="fail"
  GATE_OVERALL_REASON="$GATE_PMD_REASON"
elif [ "$GATE_CARGO_AUDIT" = "fail" ]; then
  GATE_OVERALL="fail"
  GATE_OVERALL_REASON="$GATE_CARGO_AUDIT_REASON"
elif [ "$GATE_ESLINT" = "fail" ]; then
  GATE_OVERALL="fail"
  GATE_OVERALL_REASON="$GATE_ESLINT_REASON"
elif [ "$GATE_CVE" = "fail" ]; then
  GATE_OVERALL="fail"
  GATE_OVERALL_REASON="$GATE_CVE_REASON"
elif [ "$GATE_LICENSE" != "pass" ]; then
  GATE_OVERALL="pending_legal"
  GATE_OVERALL_REASON="license gate not pass"
else
  GATE_OVERALL="pass"
  GATE_OVERALL_REASON="ok"
fi

if [ "$LICENSE_ENGINE" = "scancode" ]; then
  SCANCODE_TOOL_STATUS="$LICENSE_STATUS"
elif has_cmd scancode; then
  SCANCODE_TOOL_STATUS="skipped"
elif [ "$LICENSE_ENGINE" = "builtin-detect_license" ]; then
  SCANCODE_TOOL_STATUS="$LICENSE_STATUS"
else
  SCANCODE_TOOL_STATUS="missing"
fi

export SCAN_ID="${SCAN_ID:-}" REQUEST_ID="${REQUEST_ID:-}" SCOPE_MODE="${SCOPE_MODE:-auto}" INCLUDE_PATHS
export STARTED_AT ENDED_AT POLICY_SHA256 OUTPUT_DIR GO_DETECTED CPP_DETECTED PY_DETECTED JAVA_DETECTED RUST_DETECTED JS_DETECTED
export INPUT_SHA256="${INPUT_SHA256:-}"
export BANDIT_STATUS BANDIT_COUNTS BANDIT_ENGINE="${BANDIT_ENGINE:-}"
export PMD_STATUS PMD_COUNTS PMD_ENGINE="${PMD_ENGINE:-}"
export CARGO_AUDIT_STATUS CARGO_AUDIT_COUNTS CARGO_AUDIT_ENGINE="${CARGO_AUDIT_ENGINE:-}"
export ESLINT_STATUS ESLINT_COUNTS ESLINT_ENGINE="${ESLINT_ENGINE:-}"
export GATE_BANDIT GATE_BANDIT_REASON GATE_PMD GATE_PMD_REASON GATE_CARGO_AUDIT GATE_CARGO_AUDIT_REASON
export GATE_ESLINT GATE_ESLINT_REASON
export BANDIT_BLOCK_HIGH PMD_BLOCK_HIGH CARGO_AUDIT_BLOCK_HIGH ESLINT_BLOCK_HIGH
export SYFT_VERSION="${SYFT_VERSION:-}" SYFT_STATUS SYFT_EXIT SYFT_CMD="${SYFT_CMD:-}" SYFT_ERROR="${SYFT_ERROR:-}"
export SCANCODE_VERSION="${SCANCODE_VERSION:-}" SCANCODE_TOOL_STATUS SCANCODE_EXIT
export SCANCODE_CMD="${SCANCODE_CMD:-}" SCANCODE_ERROR="${SCANCODE_ERROR:-}"
export GOSEC_VERSION="${GOSEC_VERSION:-}" GOSEC_STATUS GOSEC_EXIT GOSEC_CMD="${GOSEC_CMD:-}"
export GOSEC_ERROR="${GOSEC_ERROR:-}" GOSEC_COUNTS
export CPPCHECK_VERSION="${CPPCHECK_VERSION:-}" CPPCHECK_STATUS CPPCHECK_EXIT
export CPPCHECK_CMD="${CPPCHECK_CMD:-}" CPPCHECK_ERROR="${CPPCHECK_ERROR:-}" CPPCHECK_COUNTS
export LICENSE_ENGINE="${LICENSE_ENGINE:-}" LICENSE_HITS LICENSE_UNKNOWN
export GATE_LICENSE GATE_LICENSE_REASON GATE_GOSEC GATE_GOSEC_REASON
export GATE_CPPCHECK GATE_CPPCHECK_REASON GATE_OVERALL GATE_OVERALL_REASON
export GATE_CVE GATE_CVE_REASON CVE_STATUS CVE_COUNTS CVE_ENGINE
export GOSEC_BLOCK_HIGH CPPCHECK_BLOCK_ERROR

python3 - "$OUTPUT_DIR/summary.json" <<'PY'
import json, os, sys

def _j(s, default=None):
    if not s:
        return default
    try:
        return json.loads(s)
    except Exception:
        return default

def _i(s, default=0):
    try:
        return int(s)
    except Exception:
        return default

out_dir = os.environ.get("OUTPUT_DIR") or os.path.dirname(sys.argv[1])
sbom_files = [n for n in ("sbom.json", "sbom.cdx.json", "sbom.spdx.json", "sbom.syft.json")
              if os.path.isfile(os.path.join(out_dir, n))]
ecosystems = []
if os.environ.get("GO_DETECTED") == "1":
    ecosystems.append("go")
if os.environ.get("CPP_DETECTED") == "1":
    ecosystems.append("cpp")
if os.environ.get("PY_DETECTED") == "1":
    ecosystems.append("python")
if os.environ.get("JAVA_DETECTED") == "1":
    ecosystems.append("java")
if os.environ.get("RUST_DETECTED") == "1":
    ecosystems.append("rust")
if os.environ.get("JS_DETECTED") == "1":
    ecosystems.append("javascript")
include_paths = [x for x in (os.environ.get("INCLUDE_PATHS") or "").replace(",", ";").split(";") if x.strip()]
hits = _j(os.environ.get("LICENSE_HITS") or "[]", [])
if not isinstance(hits, list):
    hits = []
gosec_counts = _j(os.environ.get("GOSEC_COUNTS") or "{}", {"high": 0, "medium": 0, "low": 0})
if not isinstance(gosec_counts, dict):
    gosec_counts = {"high": 0, "medium": 0, "low": 0}
# 以 gosec.json Issues 为准，避免环境变量与产物不一致
try:
    _gp = os.path.join(out_dir, "gosec.json")
    if os.path.isfile(_gp):
        _gd = json.load(open(_gp, encoding="utf-8"))
        _rc = {"high": 0, "medium": 0, "low": 0}
        for _iss in _gd.get("Issues") or []:
            if not isinstance(_iss, dict):
                continue
            _sev = str(_iss.get("severity") or "").upper()
            if _sev == "HIGH":
                _rc["high"] += 1
            elif _sev == "MEDIUM":
                _rc["medium"] += 1
            elif _sev == "LOW":
                _rc["low"] += 1
        gosec_counts = _rc
except Exception:
    pass
cpp_counts = _j(os.environ.get("CPPCHECK_COUNTS") or "{}", {"error": 0, "warning": 0, "style": 0})
if not isinstance(cpp_counts, dict):
    cpp_counts = {"error": 0, "warning": 0, "style": 0}

def _err(name):
    val = os.environ.get(name) or ""
    return val or None

summary = {
    "meta": {
        "scan_id": os.environ.get("SCAN_ID") or "",
        "request_id": os.environ.get("REQUEST_ID") or "",
        "started_at": os.environ.get("STARTED_AT") or "",
        "ended_at": os.environ.get("ENDED_AT") or "",
        "duration_ms": 0,
    },
    "input": {
        "source_type": None,
        "commit_hash": None,
        "input_sha256": os.environ.get("INPUT_SHA256") or "",
        "scope": {
            "mode": os.environ.get("SCOPE_MODE") or "auto",
            "include_paths": include_paths,
            "exclude_dirs": [x for x in (os.environ.get("EXCLUDE_DIRS") or "").split(";") if x.strip()],
        },
        "ecosystems_detected": ecosystems,
    },
    "policy": {
        "policy_sha256": os.environ.get("POLICY_SHA256") or "unknown",
        "license_score_threshold": 80,
        "license_deny_list": [],
        "license_legal_review_list": [],
        "gosec_block_if_high_gt": int(os.environ.get("GOSEC_BLOCK_HIGH") or 0),
        "cppcheck_block_if_error_gt": int(os.environ.get("CPPCHECK_BLOCK_ERROR") or 0),
        "bandit_block_if_high_gt": int(os.environ.get("BANDIT_BLOCK_HIGH") or 0),
        "pmd_block_if_high_gt": int(os.environ.get("PMD_BLOCK_HIGH") or 0),
        "cargo_audit_block_if_high_gt": int(os.environ.get("CARGO_AUDIT_BLOCK_HIGH") or 0),
        "eslint_block_if_high_gt": int(os.environ.get("ESLINT_BLOCK_HIGH") or 0),
    },
    "tools": {
        "syft": {
            "version": os.environ.get("SYFT_VERSION") or "",
            "status": os.environ.get("SYFT_STATUS") or "missing",
            "exit_code": _i(os.environ.get("SYFT_EXIT")),
            "command": os.environ.get("SYFT_CMD") or "",
            "duration_ms": 0,
            "error": _err("SYFT_ERROR"),
        },
        "scancode": {
            "version": os.environ.get("SCANCODE_VERSION") or "",
            "status": os.environ.get("SCANCODE_TOOL_STATUS") or "missing",
            "exit_code": _i(os.environ.get("SCANCODE_EXIT")),
            "command": os.environ.get("SCANCODE_CMD") or "placeholder",
            "duration_ms": 0,
            "error": _err("SCANCODE_ERROR"),
        },
        "gosec": {
            "version": os.environ.get("GOSEC_VERSION") or "",
            "status": os.environ.get("GOSEC_STATUS") or "skipped",
            "exit_code": _i(os.environ.get("GOSEC_EXIT")),
            "command": os.environ.get("GOSEC_CMD") or "",
            "duration_ms": 0,
            "error": _err("GOSEC_ERROR"),
            "counts": gosec_counts,
        },
        "cppcheck": {
            "version": os.environ.get("CPPCHECK_VERSION") or "",
            "status": os.environ.get("CPPCHECK_STATUS") or "skipped",
            "exit_code": _i(os.environ.get("CPPCHECK_EXIT")),
            "command": os.environ.get("CPPCHECK_CMD") or "",
            "duration_ms": 0,
            "error": _err("CPPCHECK_ERROR"),
            "counts": cpp_counts,
        },
        "bandit": {
            "status": os.environ.get("BANDIT_STATUS") or "skipped",
            "engine": os.environ.get("BANDIT_ENGINE") or "",
            "counts": _j(os.environ.get("BANDIT_COUNTS") or "{}", {"high": 0, "medium": 0, "low": 0}),
        },
        "pmd": {
            "status": os.environ.get("PMD_STATUS") or "skipped",
            "engine": os.environ.get("PMD_ENGINE") or "",
            "counts": _j(os.environ.get("PMD_COUNTS") or "{}", {"high": 0, "medium": 0, "low": 0}),
        },
        "cargo_audit": {
            "status": os.environ.get("CARGO_AUDIT_STATUS") or "skipped",
            "engine": os.environ.get("CARGO_AUDIT_ENGINE") or "",
            "counts": _j(os.environ.get("CARGO_AUDIT_COUNTS") or "{}", {"high": 0, "medium": 0, "low": 0}),
        },
        "eslint": {
            "status": os.environ.get("ESLINT_STATUS") or "skipped",
            "engine": os.environ.get("ESLINT_ENGINE") or "",
            "counts": _j(os.environ.get("ESLINT_COUNTS") or "{}", {"high": 0, "medium": 0, "low": 0}),
        },
        "cve": {
            "status": os.environ.get("CVE_STATUS") or "skipped",
            "engine": os.environ.get("CVE_ENGINE") or "",
            "counts": _j(os.environ.get("CVE_COUNTS") or "{}", {"critical": 0, "high": 0, "medium": 0, "low": 0}),
        },
    },
    "license": {
        "engine": os.environ.get("LICENSE_ENGINE") or "",
        "hits": hits,
        "unknown_or_low_confidence": os.environ.get("LICENSE_UNKNOWN") == "1",
    },
    "sbom": {
        "available": os.environ.get("SYFT_STATUS") == "succeeded",
        "formats": ["cyclonedx-json", "spdx-json", "syft-json"],
        "files": sbom_files,
    },
    "gate": {
        "license": {"status": os.environ.get("GATE_LICENSE") or "", "reason": os.environ.get("GATE_LICENSE_REASON") or ""},
        "gosec": {"status": os.environ.get("GATE_GOSEC") or "", "reason": os.environ.get("GATE_GOSEC_REASON") or ""},
        "cppcheck": {"status": os.environ.get("GATE_CPPCHECK") or "", "reason": os.environ.get("GATE_CPPCHECK_REASON") or ""},
        "bandit": {"status": os.environ.get("GATE_BANDIT") or "", "reason": os.environ.get("GATE_BANDIT_REASON") or ""},
        "pmd": {"status": os.environ.get("GATE_PMD") or "", "reason": os.environ.get("GATE_PMD_REASON") or ""},
        "cargo_audit": {"status": os.environ.get("GATE_CARGO_AUDIT") or "", "reason": os.environ.get("GATE_CARGO_AUDIT_REASON") or ""},
        "eslint": {"status": os.environ.get("GATE_ESLINT") or "", "reason": os.environ.get("GATE_ESLINT_REASON") or ""},
        "cve": {"status": os.environ.get("GATE_CVE") or "", "reason": os.environ.get("GATE_CVE_REASON") or ""},
        "overall": {"status": os.environ.get("GATE_OVERALL") or "", "reason": os.environ.get("GATE_OVERALL_REASON") or ""},
    },
}
path = sys.argv[1]
with open(path, "w", encoding="utf-8") as f:
    json.dump(summary, f, ensure_ascii=False, indent=2)
    f.write("\n")
PY

exit 0

