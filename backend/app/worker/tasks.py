from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import time
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

from celery.utils.log import get_task_logger
from git import Repo

from app import blob_store
from app.audit import append_audit_event
from app.credentials_util import git_ssh_command, https_url_with_token
from app.db import col
from app.cve_db import ensure_grype_db, grype_db_dir
from app.cve_repo import enrich_cve_json
from app.docker_runner import run_scanner_container
from app.maintenance import collect_maintenance_report
from app.maintenance.gate_merge import gate_status_to_enum_value, merge_gate_status
from app.maintenance.service import maintenance_findings
from app.findings_ingest import ingest_scan_findings
from app.finding_disposition import apply_saved_dispositions, evaluate_cve_gate, recalc_request_gate
from app.scan_queue import release_scan_slot, try_acquire_scan_slot
from app.policy import load_active_policy
from app.schemas import GateStatus, RequestStatus, now_utc
from app.settings import settings
from app.worker.celery_app import celery_app


log = get_task_logger(__name__)


def _read_log_tail(path: Path, lines: int = 40) -> str:
    if not path.is_file():
        return ""
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""
    rows = [ln for ln in text.splitlines() if ln.strip()]
    return "\n".join(rows[-lines:])


def _persist_partial_outputs(output_dir: Path, request_id: str, scan_run_id: str) -> dict:
    outputs = {}
    if not output_dir.is_dir():
        return outputs
    names = [
        "logs.txt",
        "summary.json",
        "license.json",
        "sbom.json",
        "sbom.cdx.json",
        "sbom.spdx.json",
        "sbom.syft.json",
        "eslint.json",
        "bandit.json",
        "cargo-audit.json",
        "gosec.json",
        "cppcheck.xml",
        "lang_sast_status.json",
        "maintenance.json",
        "cve.json",
    ]
    blobs = col("evidence_blobs")
    for name in names:
        p = output_dir / name
        if not p.is_file() or p.stat().st_size <= 0:
            continue
        try:
            ref = blob_store.put_file(settings.blob_root, str(p))
        except Exception:
            continue
        blob_doc = {
            "sha256": ref.sha256,
            "path": ref.path,
            "bytes": ref.bytes,
            "kind": "report",
            "request_id": request_id,
            "scan_run_id": scan_run_id,
            "created_at": now_utc(),
        }
        blobs.update_one({"sha256": ref.sha256}, {"$setOnInsert": blob_doc}, upsert=True)
        outputs[name] = {"sha256": ref.sha256, "path": ref.path, "bytes": ref.bytes}
    return outputs


def _ensure_empty_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


_GO_MOD_SKIP_DIRS = {
    "vendor",
    "third_party",
    "3rdparty",
    "external",
    ".git",
    "node_modules",
    "build",
    "dist",
    "out",
    "bin",
    "obj",
    ".idea",
    ".vscode",
    ".cache",
}


def _iter_go_module_dirs(input_dir: Path) -> List[Path]:
    """Find directories that contain go.mod (nested modules / go.work layouts)."""
    found: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(input_dir):
        dirnames[:] = [d for d in dirnames if d not in _GO_MOD_SKIP_DIRS and not d.startswith(".")]
        if "go.mod" in filenames:
            found.append(Path(dirpath))
    return found


def _validate_gosec_artifact(input_dir: Path, output_dir: Path, policy) -> None:
    """Go 项目且启用 gosec 时，报告必须存在且 files>0，避免 UI 显示全 0 的假象。"""
    if not _iter_go_module_dirs(input_dir):
        return
    if not bool((policy.raw.get("gosec") or {}).get("enabled", True)):
        return
    gosec_path = output_dir / "gosec.json"
    if not gosec_path.is_file():
        raise ValueError("gosec.json missing after scanner run")
    data = json.loads(gosec_path.read_text(encoding="utf-8"))
    stats = data.get("Stats") or {}
    files = int(stats.get("files") or 0)
    if files <= 0:
        raise ValueError("gosec scanned 0 files (Go module deps missing or scan interrupted)")


def _count_gosec_severities(output_dir: Path) -> Dict[str, int]:
    counts = {"high": 0, "medium": 0, "low": 0}
    path = output_dir / "gosec.json"
    if not path.is_file():
        return counts
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return counts
    for issue in data.get("Issues") or []:
        if not isinstance(issue, dict):
            continue
        sev = str(issue.get("severity") or "").upper()
        if sev == "HIGH":
            counts["high"] += 1
        elif sev == "MEDIUM":
            counts["medium"] += 1
        elif sev == "LOW":
            counts["low"] += 1
    return counts


def _count_cppcheck_severities(output_dir: Path) -> Dict[str, int]:
    counts = {"error": 0, "warning": 0, "style": 0}
    path = output_dir / "cppcheck.xml"
    if not path.is_file():
        return counts
    try:
        import xml.etree.ElementTree as ET

        root = ET.fromstring(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return counts
    for err in root.findall(".//error"):
        sev = str(err.get("severity") or "").lower()
        if sev == "error":
            counts["error"] += 1
        elif sev == "warning":
            counts["warning"] += 1
        else:
            counts["style"] += 1
    return counts


_LANG_ARTIFACTS = {
    "gosec.json": ("go", "gosec"),
    "cppcheck.xml": ("cpp", "cppcheck"),
    "bandit.json": ("python", "bandit"),
    "pmd.json": ("java", "pmd"),
    "cargo-audit.json": ("rust", "cargo_audit"),
    "eslint.json": ("javascript", "eslint"),
}


def _is_stub_lang_artifact(name: str, path: Path) -> bool:
    """未识别到对应语言时留下的占位报告，不应入库。"""
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return False
    note = text.lower()
    markers = (
        "not detected",
        "no python",
        "no java",
        "no rust",
        "no javascript",
        "no typescript",
        "no go",
        "language not detected",
        "c/c++ not detected",
        "cpp not detected",
    )
    if any(m in note for m in markers):
        return True
    if name.endswith(".json"):
        try:
            data = json.loads(text)
        except Exception:
            return False
        if not isinstance(data, dict):
            return False
        issues = data.get("Issues")
        engine = str(data.get("engine") or "").lower()
        if engine == "skipped" and not issues:
            return True
    return False


def _keep_scan_artifact(name: str, path: Path, summary: dict) -> bool:
    mapping = _LANG_ARTIFACTS.get(name)
    if not mapping:
        return True
    eco, tool = mapping
    ecosystems = {
        str(x).lower()
        for x in ((summary.get("input") or {}).get("ecosystems_detected") or [])
        if x
    }
    tool_status = str(((summary.get("tools") or {}).get(tool) or {}).get("status") or "").lower()
    if tool_status == "skipped" or (ecosystems and eco not in ecosystems):
        return False
    if _is_stub_lang_artifact(name, path):
        return False
    return True


def _apply_sast_policy_gates(summary: dict, output_dir: Path, policy) -> None:
    """按 policy 阈值校正 gosec/cppcheck 门禁（High>0 / error>0 默认阻断）。"""
    tools = summary.setdefault("tools", {})
    gate = summary.setdefault("gate", {})
    ecosystems = {
        str(x).lower()
        for x in ((summary.get("input") or {}).get("ecosystems_detected") or [])
        if x
    }
    for filename, (eco, tool) in _LANG_ARTIFACTS.items():
        if eco in ecosystems or (output_dir / filename).is_file():
            continue
        tools.setdefault(tool, {})["status"] = "skipped"
        tgate = gate.setdefault(tool, {})
        if str(tgate.get("status") or "").lower() != "fail":
            tgate["status"] = "skipped"
            tgate["reason"] = "%s not detected" % eco
    gosec_cfg = policy.raw.get("gosec") or {}
    cpp_cfg = policy.raw.get("cppcheck") or {}

    if bool(gosec_cfg.get("enabled", True)):
        block_high = int(gosec_cfg.get("block_if_high_gt") or 0)
        counts = _count_gosec_severities(output_dir)
        gosec_tool = tools.setdefault("gosec", {})
        gosec_tool["counts"] = counts
        gosec_gate = gate.setdefault("gosec", {})
        status = str(gosec_gate.get("status") or "").lower()
        if status not in {"fail", "skipped"} and counts["high"] > block_high:
            gosec_gate["status"] = "fail"
            gosec_gate["reason"] = "gosec High %s > %s" % (counts["high"], block_high)

    block_error = int(cpp_cfg.get("block_if_error_gt") or 0)
    cpp_counts = _count_cppcheck_severities(output_dir)
    if cpp_counts["error"] or cpp_counts["warning"] or cpp_counts["style"]:
        tools.setdefault("cppcheck", {})["counts"] = cpp_counts
    cpp_gate = gate.setdefault("cppcheck", {})
    cpp_status = str(cpp_gate.get("status") or "").lower()
    if cpp_status not in {"fail", "skipped"} and cpp_counts["error"] > block_error:
        cpp_gate["status"] = "fail"
        cpp_gate["reason"] = "cppcheck error %s > %s" % (cpp_counts["error"], block_error)

    def _apply_high_tool(name: str, filename: str, cfg_key: str) -> None:
        cfg = policy.raw.get(cfg_key) or {}
        if not bool(cfg.get("enabled", True)):
            return
        block_high = int(cfg.get("block_if_high_gt") or 0)
        path = output_dir / filename
        counts = {"high": 0, "medium": 0, "low": 0}
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                data = {}
            for issue in data.get("Issues") or []:
                if not isinstance(issue, dict):
                    continue
                sev = str(issue.get("severity") or "").upper()
                if sev == "HIGH":
                    counts["high"] += 1
                elif sev == "MEDIUM":
                    counts["medium"] += 1
                elif sev == "LOW":
                    counts["low"] += 1
        tools.setdefault(name, {})["counts"] = counts
        tgate = gate.setdefault(name, {})
        status = str(tgate.get("status") or "").lower()
        if status not in {"fail", "skipped"} and counts["high"] > block_high:
            tgate["status"] = "fail"
            tgate["reason"] = "%s High %s > %s" % (name, counts["high"], block_high)

    _apply_high_tool("bandit", "bandit.json", "bandit")
    _apply_high_tool("pmd", "pmd.json", "pmd")
    _apply_high_tool("cargo_audit", "cargo-audit.json", "cargo_audit")
    _apply_high_tool("eslint", "eslint.json", "eslint")

    cve_cfg = policy.raw.get("cve") or {}
    cve_path = output_dir / "cve.json"
    cve_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "negligible": 0, "unknown": 0}
    cve_data = {}
    if cve_path.is_file():
        try:
            cve_data = json.loads(cve_path.read_text(encoding="utf-8"))
        except Exception:
            cve_data = {}
        raw_counts = cve_data.get("counts") if isinstance(cve_data.get("counts"), dict) else {}
        for k in cve_counts:
            cve_counts[k] = int(raw_counts.get(k) or 0)
    tools.setdefault("cve", {})["counts"] = cve_counts
    if cve_data.get("engines"):
        tools["cve"]["engines"] = cve_data.get("engines")
    if cve_data.get("status"):
        tools["cve"]["status"] = cve_data.get("status")
    cve_gate = gate.setdefault("cve", {})
    if isinstance(cve_data.get("gate"), dict) and cve_data["gate"].get("status"):
        cve_gate["status"] = cve_data["gate"].get("status")
        cve_gate["reason"] = cve_data["gate"].get("reason") or ""
    if bool(cve_cfg.get("enabled", True)):
        matches = [m for m in (cve_data.get("matches") or []) if isinstance(m, dict)]
        prev = str(cve_gate.get("status") or "").lower()
        if prev == "skipped" and not matches:
            pass
        else:
            evaluated = evaluate_cve_gate(matches, cve_cfg)
            cve_gate.update(evaluated)
            if isinstance(cve_data.get("gate"), dict):
                cve_data["gate"] = dict(cve_data.get("gate") or {})
                cve_data["gate"].update(evaluated)
                try:
                    cve_path.write_text(json.dumps(cve_data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
                except OSError:
                    pass

    license_status = str((gate.get("license") or {}).get("status") or "").lower()
    fail_order = ("cve", "gosec", "cppcheck", "bandit", "pmd", "cargo_audit", "eslint")
    overall = gate.setdefault("overall", {})
    hit = next((n for n in fail_order if str((gate.get(n) or {}).get("status") or "").lower() == "fail"), None)
    if hit:
        overall["status"] = "fail"
        overall["reason"] = (gate.get(hit) or {}).get("reason") or ("%s gate fail" % hit)
    elif license_status and license_status != "pass":
        overall["status"] = "pending_legal"
        overall["reason"] = (gate.get("license") or {}).get("reason") or "license gate not pass"


def _prepare_rust_lockfiles(input_dir: Path, log_file: Optional[Path] = None) -> None:
    """无 Cargo.lock 时生成锁文件，供 syft rust-cargo-lock-cataloger 收录依赖。"""
    cargo = shutil.which("cargo") or shutil.which("cargo", path="/root/.cargo/bin:/usr/local/cargo/bin")
    env = os.environ.copy()
    env["PATH"] = "/root/.cargo/bin:/usr/local/cargo/bin:" + env.get("PATH", "")
    skip = {".git", ".svn", "target", "node_modules", "vendor"}
    for dirpath, dirnames, filenames in os.walk(input_dir):
        dirnames[:] = [d for d in dirnames if d not in skip and not d.startswith(".")]
        if "Cargo.toml" not in filenames or "Cargo.lock" in filenames:
            continue
        rel = Path(dirpath).relative_to(input_dir).as_posix() or "."
        if not cargo:
            msg = "[syft] cargo not found, skip generate-lockfile for %s\n" % rel
            if log_file:
                log_file.parent.mkdir(parents=True, exist_ok=True)
                log_file.open("a", encoding="utf-8").write(msg)
            continue
        try:
            proc = subprocess.run(
                [cargo, "generate-lockfile", "--manifest-path", str(Path(dirpath) / "Cargo.toml")],
                cwd=dirpath,
                env=env,
                timeout=180,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
            )
            if log_file:
                log_file.parent.mkdir(parents=True, exist_ok=True)
                with log_file.open("a", encoding="utf-8") as f:
                    f.write("[syft] cargo generate-lockfile %s exit=%s\n" % (rel, proc.returncode))
                    f.write(proc.stdout or "")
        except Exception as e:
            if log_file:
                log_file.parent.mkdir(parents=True, exist_ok=True)
                log_file.open("a", encoding="utf-8").write("[syft] cargo generate-lockfile %s failed: %s\n" % (rel, e))


def _prepare_go_modules(input_dir: Path, log_file: Optional[Path] = None) -> bool:
    """拉取每个 go.mod 目录的依赖，供 gosec 静态分析。"""
    mod_dirs = _iter_go_module_dirs(input_dir)
    if not mod_dirs:
        return True
    go_bin = shutil.which("go")
    if not go_bin:
        msg = "[gosec] go binary not found in PATH\n"
        log.warning(msg.strip())
        if log_file:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            with log_file.open("a", encoding="utf-8") as f:
                f.write(msg)
        return False
    env = os.environ.copy()
    env["PATH"] = "/usr/local/bin:/usr/local/go/bin:" + env.get("PATH", "")
    env["GOPROXY"] = os.environ.get("GOPROXY") or "https://goproxy.cn,direct"
    env.setdefault("GOPATH", "/root/go")
    env.setdefault("GOMODCACHE", "/root/go/pkg/mod")
    env["GOWORK"] = "off"
    ok = True
    for mod_dir in mod_dirs:
        rel = mod_dir.relative_to(input_dir).as_posix() or "."
        try:
            proc = subprocess.run(
                [go_bin, "mod", "download"],
                cwd=str(mod_dir),
                env=env,
                timeout=300,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
            )
            if log_file:
                log_file.parent.mkdir(parents=True, exist_ok=True)
                with log_file.open("a", encoding="utf-8") as f:
                    f.write("[go mod download] %s\n" % rel)
                    f.write(proc.stdout or "")
                    f.write("\nexit_code=%s\n" % proc.returncode)
            if proc.returncode != 0:
                log.warning("go mod download exit %s for %s", proc.returncode, mod_dir)
                ok = False
        except Exception as e:
            ok = False
            log.warning("go mod download failed in %s: %s", mod_dir, e)
            if log_file:
                with log_file.open("a", encoding="utf-8") as f:
                    f.write("[go mod download] %s error: %s\n" % (rel, e))
    return ok


def _workspace_tree_sha256(root: Path) -> str:
    """Deterministic hash over sorted file paths and contents (for evidence / reproducibility)."""
    h = hashlib.sha256()
    files = [p for p in root.rglob("*") if p.is_file()]
    for p in sorted(files, key=lambda x: str(x.relative_to(root))):
        rel = p.relative_to(root).as_posix().encode("utf-8")
        h.update(rel)
        h.update(b"\0")
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        h.update(b"\0\0")
    return h.hexdigest()


_TRANSIENT_GIT_MARKERS = (
    "empty reply from server",
    "connection timed out",
    "failed to connect",
    "connection reset",
    "could not resolve host",
    "the remote end hung up",
    "rpc failed",
    "gnutls_handshake",
    "ssl_error",
    "http/2",
    "unable to access",
    "git timed out",
    "operation too slow",
    "less than",
)


def _git_args(*args: str) -> List[str]:
    # HTTP/1.1 避开 git 2.27 + GitHub HTTP/2 空响应；低速阈值放宽，避免国内访问 GitHub 抖动被误杀。
    return [
        "git",
        "-c", "http.version=HTTP/1.1",
        "-c", "http.lowSpeedLimit=256",
        "-c", "http.lowSpeedTime=180",
        *args,
    ]


def _is_transient_git_error(err: str) -> bool:
    e = err.lower()
    return any(m in e for m in _TRANSIENT_GIT_MARKERS)


def _is_missing_branch_error(err: str, ref: str) -> bool:
    e = err.lower()
    if _is_transient_git_error(err):
        return False
    ref_l = (ref or "").lower()
    return (
        ("remote branch %s not found" % ref_l) in e
        or "not found in upstream" in e
        or ("pathspec '%s' did not match" % ref_l) in e
    )


def _run_git(cmd: list, *, cwd: Optional[str] = None, env: Optional[dict] = None, timeout: int = 180) -> None:
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            universal_newlines=True,
        )
    except subprocess.TimeoutExpired as e:
        out = e.stderr or e.stdout or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        raise ValueError("git timed out after %ss: %s (%s)" % (timeout, " ".join(cmd), (out or "").strip()[:300])) from e
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        raise ValueError("git failed: %s (%s)" % (" ".join(cmd), err[:500]))


def _clone_into(
    clone_url: str,
    input_dir: Path,
    env: dict,
    *,
    branch: Optional[str] = None,
    timeout: int = 420,
    attempts: int = 3,
) -> None:
    cmd = _git_args("clone", "--depth", "1")
    if branch:
        cmd += ["--branch", branch, "--single-branch"]
    cmd += [clone_url, str(input_dir)]
    last_err: Optional[BaseException] = None
    for i in range(attempts):
        _ensure_empty_dir(input_dir)
        try:
            _run_git(cmd, env=env, timeout=timeout)
            return
        except ValueError as e:
            last_err = e
            if not _is_transient_git_error(str(e)) or i >= attempts - 1:
                raise
            log.warning("git clone transient failure (%s/%s): %s", i + 1, attempts, e)
            time.sleep(2 * (i + 1))
    if last_err:
        raise last_err


def _github_slug(repo_url: str) -> Optional[Tuple[str, str]]:
    p = urlparse(repo_url)
    host = (p.hostname or "").lower()
    if host not in {"github.com", "www.github.com"}:
        return None
    parts = [x for x in (p.path or "").strip("/").split("/") if x]
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    return owner, repo


def _download_github_tarball(repo_url: str, ref: str, input_dir: Path, token: Optional[str] = None) -> None:
    slug = _github_slug(repo_url)
    if not slug:
        raise ValueError("not a github.com URL, cannot use archive fallback")
    owner, repo = slug
    ref_q = quote(ref, safe="")
    urls = [
        "https://codeload.github.com/%s/%s/tar.gz/%s" % (owner, repo, ref_q),
        "https://github.com/%s/%s/archive/refs/heads/%s.tar.gz" % (owner, repo, ref_q),
        "https://github.com/%s/%s/archive/refs/tags/%s.tar.gz" % (owner, repo, ref_q),
    ]
    headers = {"User-Agent": "openMastiff-scanner/1.0", "Accept": "application/octet-stream"}
    if token:
        headers["Authorization"] = "Bearer %s" % token
    last_err: Optional[BaseException] = None
    tmp = input_dir.parent / (input_dir.name + ".tgz")
    for url in urls:
        try:
            req = Request(url, headers=headers)
            with urlopen(req, timeout=180) as resp:
                with tmp.open("wb") as f:
                    shutil.copyfileobj(resp, f)
            _ensure_empty_dir(input_dir)
            with tarfile.open(str(tmp), "r:*") as tf:
                tf.extractall(str(input_dir))
            kids = [p for p in input_dir.iterdir()]
            if len(kids) == 1 and kids[0].is_dir():
                top = kids[0]
                for item in list(top.iterdir()):
                    item.rename(input_dir / item.name)
                top.rmdir()
            log.info("github archive fallback ok: %s", url)
            return
        except Exception as e:
            last_err = e
            log.warning("github archive fallback miss %s: %s", url, e)
        finally:
            if tmp.exists():
                tmp.unlink()
    raise ValueError("github archive fallback failed: %s" % last_err)


def _materialize_git(repo_url: str, ref: str, credential_id: Optional[str], input_dir: Path) -> str:
    """Clone and checkout; returns HEAD commit hexsha."""
    import re

    credentials = col("credentials")
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    clone_url = repo_url
    http_token: Optional[str] = None
    if credential_id:
        cred = credentials.find_one({"credential_id": credential_id}, {"_id": 0})
        if not cred:
            raise ValueError("credential not found: %s" % credential_id)
        if cred["type"] == "http_token":
            http = cred.get("http") or {}
            username = http.get("username") or "git"
            token = http.get("token")
            if not token:
                raise ValueError("credential has no http.token")
            http_token = token
            clone_url = https_url_with_token(repo_url, username, token)
        elif cred["type"] == "ssh_key":
            ssh = cred.get("ssh") or {}
            key_path = ssh.get("private_key_path")
            if not key_path or not os.path.isfile(key_path):
                raise ValueError("ssh private_key_path missing or not a readable file")
            env["GIT_SSH_COMMAND"] = git_ssh_command(key_path)
        else:
            raise ValueError("unknown credential type")

    ref = (ref or "main").strip()
    is_commit = bool(re.fullmatch(r"[0-9a-fA-F]{7,40}", ref))

    try:
        if is_commit:
            _clone_into(clone_url, input_dir, env)
            _run_git(_git_args("-C", str(input_dir), "checkout", ref), env=env, timeout=120)
        else:
            try:
                _clone_into(clone_url, input_dir, env, branch=ref)
            except ValueError as e:
                # 仅当远端确实没有 main 时才回退 master（gorilla/mux 等）
                if ref == "main" and _is_missing_branch_error(str(e), "main"):
                    log.warning("git clone branch main not found, retry master: %s", e)
                    _clone_into(clone_url, input_dir, env, branch="master")
                else:
                    raise
        return Repo(str(input_dir)).head.commit.hexsha
    except ValueError as e:
        if _github_slug(repo_url) and _is_transient_git_error(str(e)):
            log.warning("git clone failed, falling back to github archive: %s", e)
            _download_github_tarball(repo_url, ref, input_dir, http_token)
            try:
                return Repo(str(input_dir)).head.commit.hexsha
            except Exception:
                return ref
        raise


def _extract_archive(archive_path: Path, dest_dir: Path) -> None:
    # Do not rely on filename extension: blobs are content-addressed (sha256) and may not keep suffix.
    if zipfile.is_zipfile(str(archive_path)):
        with zipfile.ZipFile(archive_path, "r") as z:
            z.extractall(dest_dir)
        return
    if tarfile.is_tarfile(str(archive_path)):
        with tarfile.open(archive_path, "r:*") as t:
            t.extractall(dest_dir)
        return
    raise ValueError(f"Unsupported archive type: {archive_path.name}")


@celery_app.task(name="start_scan", bind=True, max_retries=None, default_retry_delay=20)
def start_scan(self, scan_run_id: str) -> None:
    scan_runs = col("scan_runs")
    requests = col("review_requests")
    sources = col("sources")
    blobs = col("evidence_blobs")

    scan_run = scan_runs.find_one({"scan_run_id": scan_run_id})
    if not scan_run:
        raise ValueError("scan_run not found")
    if scan_run["status"] not in {"queued"}:
        log.info("scan_run %s already processed: %s", scan_run_id, scan_run["status"])
        return
    if not try_acquire_scan_slot(scan_run_id):
        log.info("scan queue full, retry %s", scan_run_id)
        raise self.retry(countdown=20)

    request_id = scan_run["request_id"]
    req = requests.find_one({"request_id": request_id})
    if not req:
        release_scan_slot(scan_run_id)
        raise ValueError("request not found")

    append_audit_event(request_id=request_id, event_type="SCAN_STARTED", payload={"scan_run_id": scan_run_id})

    source = sources.find_one({"source_id": scan_run["source_id"]})
    if not source:
        release_scan_slot(scan_run_id)
        raise ValueError("source not found")

    work_root = Path(settings.work_root) / request_id / scan_run_id
    input_dir = work_root / "input"
    output_dir = work_root / "output"
    policy_dir = work_root / "policy"

    try:
        # Prepare workspace
        _ensure_empty_dir(input_dir)
        _ensure_empty_dir(output_dir)
        _ensure_empty_dir(policy_dir)

        log_file = output_dir / "logs.txt"

        def _note(msg: str) -> None:
            with log_file.open("a", encoding="utf-8") as f:
                f.write("%s %s\n" % (time.strftime("%H:%M:%S"), msg))
                f.flush()

        _note("[openmastiff] workspace ready")
        scan_runs.update_one({"scan_run_id": scan_run_id}, {"$set": {"work_dir": str(work_root)}})

        # Write policy snapshot
        policy = load_active_policy()
        policy_bytes = policy.to_json_bytes()
        policy_path = policy_dir / "policy.json"
        policy_path.write_bytes(policy_bytes)
        policy_hash = policy.sha256()

        # Materialize input
        if source["type"] == "upload":
            _note("[openmastiff] extracting uploaded archive")
            archive_path = Path(source["blob"]["path"])
            _extract_archive(archive_path, input_dir)
            input_sha256 = source["blob"]["sha256"]
        elif source["type"] == "git":
            g = source["git"]
            _note("[openmastiff] cloning %s @ %s" % (g.get("repo_url") or "", g.get("ref") or ""))
            input_sha256 = _materialize_git(
                g["repo_url"],
                g["ref"],
                g.get("credential_id"),
                input_dir,
            )
            _note("[openmastiff] clone complete %s" % input_sha256[:12])
        else:
            raise ValueError("unknown source type")

        ws_hash = _workspace_tree_sha256(input_dir)
        src_upd = {"workspace_sha256": ws_hash, "materialized_at": now_utc()}
        if source["type"] == "git":
            src_upd["git.commit_hash"] = input_sha256
        sources.update_one({"source_id": source["source_id"]}, {"$set": src_upd})

        # 在 gosec 之前预拉 Go 依赖（否则易出现 files:0 的空报告）
        _prepare_go_modules(input_dir, output_dir / "logs.txt")
        _prepare_rust_lockfiles(input_dir, output_dir / "logs.txt")

        scan_runs.update_one(
            {"scan_run_id": scan_run_id},
            {
                "$set": {
                    "status": "running",
                    "started_at": now_utc(),
                    "policy_hash": policy_hash,
                    "input_hash": input_sha256,
                    "work_dir": str(work_root),
                }
            },
        )

        requests.update_one(
            {"request_id": request_id, "status": RequestStatus.Submitted.value},
            {"$set": {"status": RequestStatus.Scanning.value, "updated_at": now_utc()}},
        )
        scope = req.get("scan_scope") if isinstance(req.get("scan_scope"), dict) else {}
        include_paths = [str(x).strip() for x in (scope.get("include_paths") or []) if str(x).strip()]
        env = {
            "SCAN_ID": scan_run_id,
            "REQUEST_ID": request_id,
            "SCOPE_MODE": str(scope.get("mode") or "auto"),
            "INCLUDE_PATHS": ";".join(include_paths),
            "INPUT_SHA256": input_sha256,
            "EXCLUDE_DIRS": ";".join(
                str(x).strip()
                for x in (
                    (policy.raw.get("runner") or {}).get("exclude_dirs")
                    if isinstance((policy.raw.get("runner") or {}).get("exclude_dirs"), list)
                    else str((policy.raw.get("runner") or {}).get("exclude_dirs") or "").replace(",", ";").split(";")
                )
                if str(x).strip()
            ),
            "NETWORK_MODE": str(policy.raw.get("runner", {}).get("network_mode_default", "none")),
            "TIMEOUT_LICENSE_MIN": str(policy.raw.get("runner", {}).get("timeouts_min", {}).get("license", 30)),
            "TIMEOUT_GOSEC_MIN": str(policy.raw.get("runner", {}).get("timeouts_min", {}).get("gosec", 20)),
            "TIMEOUT_CPPCHECK_MIN": str(policy.raw.get("runner", {}).get("timeouts_min", {}).get("cppcheck", 30)),
            "TIMEOUT_LANG_SAST_MIN": str(policy.raw.get("runner", {}).get("timeouts_min", {}).get("lang_sast", 20)),
            "TIMEOUT_CVE_MIN": str(policy.raw.get("runner", {}).get("timeouts_min", {}).get("cve", 15)),
            "GOSEC_ENABLED": "1" if bool(policy.raw.get("gosec", {}).get("enabled", True)) else "0",
            "GRYPE_DB_CACHE_DIR": grype_db_dir(),
            "GRYPE_CHECK_FOR_APP_UPDATE": "false",
            "GRYPE_DB_AUTO_UPDATE": "false",
        }

        maintenance_policy = policy.raw.get("maintenance") or {}
        maintenance_report = collect_maintenance_report(
            workspace=input_dir,
            source=source,
            business_criticality=str(req.get("business_criticality") or "medium"),
            maintenance_policy=maintenance_policy,
        )
        maintenance_path = output_dir / "maintenance.json"
        maintenance_path.write_text(json.dumps(maintenance_report, ensure_ascii=False, indent=2), encoding="utf-8")

        if bool((policy.raw.get("cve") or {}).get("enabled", True)):
            ensure_grype_db(log_file=output_dir / "logs.txt")

        extra_volumes = {}
        db_host = grype_db_dir()
        if os.path.isdir(db_host):
            extra_volumes[os.path.abspath(db_host)] = {"bind": db_host, "mode": "ro"}

        rr = run_scanner_container(
            image="unused-in-local-mode",
            input_dir=str(input_dir),
            output_dir=str(output_dir),
            policy_dir=str(policy_dir),
            env=env,
            network_mode="none",
            extra_volumes=extra_volumes or None,
        )
        if rr.exit_code != 0:
            raise ValueError(f"scanner exited with code {rr.exit_code}")
        summary_path = output_dir / "summary.json"
        if not summary_path.is_file():
            raise ValueError("summary.json missing after scanner run (scan may have been interrupted)")
        _validate_gosec_artifact(input_dir, output_dir, policy)

        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise ValueError("summary.json invalid: %s" % e) from e

        if bool((policy.raw.get("cve") or {}).get("enabled", True)):
            enrich_cve_json(
                input_dir=input_dir,
                output_dir=output_dir,
                source=source,
                request=req,
                policy=policy.raw,
                log_file=output_dir / "logs.txt",
            )

        _apply_sast_policy_gates(summary, output_dir, policy)
        inp = summary.setdefault("input", {})
        if not inp.get("input_sha256"):
            inp["input_sha256"] = input_sha256
        summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

        scanner_gate = (((summary.get("gate") or {}).get("overall") or {}).get("status") or "unknown").lower()
        gate = summary.setdefault("gate", {})
        maint_overall = (maintenance_report.get("overall") or {}) if maintenance_report.get("enabled") else {"status": "pass", "reason": "disabled"}
        maint_status = str(maint_overall.get("status") or "pass").lower()
        if maint_status == "pending_legal":
            maint_status = "fail"
            maint_overall = {**maint_overall, "status": "fail", "reason": maint_overall.get("reason") or "maintenance gate fail"}
        if isinstance(maintenance_report.get("overall"), dict):
            maintenance_report["overall"]["status"] = maint_status
        gate["maintenance"] = {
            "status": maint_status,
            "reason": maint_overall.get("reason", ""),
        }
        gate["overall"] = {
            "status": merge_gate_status(scanner_gate, gate["maintenance"]["status"]),
            "reason": f"scanner={scanner_gate}; maintenance={gate['maintenance']['status']}",
        }
        summary["maintenance"] = maintenance_report
        summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

        outputs: Dict[str, dict] = {}
        artifact_names = [
            "summary.json",
            "license.json",
            "gosec.json",
            "cppcheck.xml",
            "logs.txt",
            "maintenance.json",
            "sbom.json",
            "sbom.cdx.json",
            "sbom.spdx.json",
            "sbom.syft.json",
            "bandit.json",
            "pmd.json",
            "cargo-audit.json",
            "eslint.json",
            "cve.json",
            "lang_sast_status.json",
            "policy.json",
        ]
        for extra in sorted(output_dir.glob("sbom*")):
            if extra.name not in artifact_names:
                artifact_names.append(extra.name)
        for name in artifact_names:
            p = output_dir / name
            if not p.exists():
                continue
            if not _keep_scan_artifact(name, p, summary):
                continue
            ref = blob_store.put_file(settings.blob_root, str(p))
            blob_doc = {
                "sha256": ref.sha256,
                "path": ref.path,
                "bytes": ref.bytes,
                "kind": "report",
                "request_id": request_id,
                "scan_run_id": scan_run_id,
                "created_at": now_utc(),
            }
            blobs.update_one({"sha256": ref.sha256}, {"$setOnInsert": blob_doc}, upsert=True)
            outputs[name] = {"sha256": ref.sha256, "path": ref.path, "bytes": ref.bytes}

        maint_gate = maint_status
        merged = merge_gate_status(scanner_gate, maint_gate)
        overall = GateStatus(gate_status_to_enum_value(merged))

        findings = maintenance_findings(request_id, scan_run_id, maintenance_report)
        extra_fp = [str(req.get("title") or ""), str(req.get("project") or "")]
        git = (source.get("git") or {}) if isinstance(source.get("git"), dict) else {}
        extra_fp.append(str(git.get("repo_url") or ""))
        findings.extend(
            ingest_scan_findings(
                request_id=request_id,
                scan_run_id=scan_run_id,
                output_dir=output_dir,
                extra_first_party=extra_fp,
            )
        )
        apply_saved_dispositions(request_id, findings)
        findings_col = col("findings")
        findings_col.delete_many({"request_id": request_id})
        if findings:
            findings_col.insert_many(findings)

        gate_block = summary.get("gate") or {}
        col("gate_results").update_one(
            {"scan_run_id": scan_run_id},
            {
                "$set": {
                    "request_id": request_id,
                    "scan_run_id": scan_run_id,
                    "license_gate": gate_block.get("license") or {},
                    "gosec_gate": gate_block.get("gosec") or {},
                    "cppcheck_gate": gate_block.get("cppcheck") or {},
                    "bandit_gate": gate_block.get("bandit") or {},
                    "pmd_gate": gate_block.get("pmd") or {},
                    "cargo_audit_gate": gate_block.get("cargo_audit") or {},
                    "eslint_gate": gate_block.get("eslint") or {},
                    "cve_gate": gate_block.get("cve") or {},
                    "maintenance_gate": gate_block.get("maintenance") or {},
                    "overall": gate_block.get("overall") or {},
                    "updated_at": now_utc(),
                }
            },
            upsert=True,
        )
        policy_ref = blob_store.put_file(settings.blob_root, str(policy_path))
        blobs.update_one(
            {"sha256": policy_ref.sha256},
            {"$setOnInsert": {"sha256": policy_ref.sha256, "path": policy_ref.path, "bytes": policy_ref.bytes, "kind": "policy", "request_id": request_id, "scan_run_id": scan_run_id, "created_at": now_utc()}},
            upsert=True,
        )
        outputs["policy.json"] = {"sha256": policy_ref.sha256, "path": policy_ref.path, "bytes": policy_ref.bytes}

        scan_runs.update_one(
            {"scan_run_id": scan_run_id},
            {
                "$set": {
                    "status": "succeeded",
                    "ended_at": now_utc(),
                    "exit_code": rr.exit_code,
                    "outputs": outputs,
                    "gate_status": overall.value,
                }
            },
        )

        if overall == GateStatus.Fail:
            new_status = RequestStatus.Blocked
            risk_level = "high"
        elif overall == GateStatus.PendingLegal:
            new_status = RequestStatus.LegalReviewing
            risk_level = "medium"
        elif overall == GateStatus.Pass:
            new_status = RequestStatus.Reviewing
            crit = str(req.get("business_criticality") or "medium")
            risk_level = "medium" if crit in {"high", "critical"} else "low"
        else:
            new_status = RequestStatus.Reviewing
            risk_level = "medium"

        requests.update_one(
            {"request_id": request_id},
            {
                "$set": {
                    "status": new_status.value,
                    "gate_status": overall.value,
                    "latest_scan_run_id": scan_run_id,
                    "risk_level": risk_level,
                    "updated_at": now_utc(),
                }
            },
        )
        append_audit_event(
            request_id=request_id,
            event_type="SCAN_FINISHED",
            payload={"scan_run_id": scan_run_id, "status": "succeeded" if rr.exit_code == 0 else "failed", "gate_status": overall.value},
        )
        if col("finding_dispositions").find_one(
            {"request_id": request_id, "disposition": {"$in": ["false_positive", "accepted_risk"]}},
            {"_id": 1},
        ):
            recalc_request_gate(request_id)
    except Exception as e:
        log.exception("scan_run %s failed", scan_run_id)
        log_tail = _read_log_tail(output_dir / "logs.txt")
        outputs = {}
        try:
            outputs = _persist_partial_outputs(output_dir, request_id, scan_run_id)
        except Exception:
            log.exception("persist partial outputs failed for %s", scan_run_id)
        scan_runs.update_one(
            {"scan_run_id": scan_run_id},
            {
                "$set": {
                    "status": "failed",
                    "ended_at": now_utc(),
                    "error": str(e),
                    "error_detail": log_tail,
                    "outputs": outputs,
                }
            },
        )
        requests.update_one(
            {"request_id": request_id},
            {
                "$set": {
                    "status": RequestStatus.Blocked.value,
                    "latest_scan_run_id": scan_run_id,
                    "updated_at": now_utc(),
                }
            },
        )
        append_audit_event(
            request_id=request_id,
            event_type="SCAN_FINISHED",
            payload={"scan_run_id": scan_run_id, "status": "failed", "error": str(e), "log_tail": log_tail[-500:]},
        )
    finally:
        release_scan_slot(scan_run_id)


@celery_app.task(name="check_waivers")
def check_waivers() -> None:
    """
    Periodic: move expired waivers back to ReReview.
    """
    requests = col("review_requests")

    now = now_utc()
    # Waived requests with expires_at in decision
    cur = requests.find(
        {"status": RequestStatus.Waived.value, "decision.expires_at": {"$lte": now}},
        {"_id": 0, "request_id": 1, "decision.expires_at": 1},
    )
    for r in cur:
        rid = r["request_id"]
        requests.update_one(
            {"request_id": rid, "status": RequestStatus.Waived.value},
            {"$set": {"status": RequestStatus.ReReview.value, "updated_at": now_utc()}},
        )
        append_audit_event(request_id=rid, event_type="WAIVER_EXPIRED", payload={"expired_at": str(r.get("decision", {}).get("expires_at"))})

