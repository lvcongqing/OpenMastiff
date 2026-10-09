"""First-party / repo-level CVE lookup (OSV + GitHub Advisory).

Runs on the worker (scanner has network_mode=none). Failures are skipped;
Grype results are never discarded.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from app.findings_ingest import _cve_scope, _first_party_names, _read_json
from app.maintenance.upstream import parse_git_upstream

_UA = "openMastiff-cve-repo/1.0 (+https://openmastiff.local)"
OSV_QUERY = "https://api.osv.dev/v1/query"
MAX_FIRST_PARTY = 12
SKIP_DIRS = {".git", ".svn", "target", "node_modules", "vendor", "__pycache__", "dist", "build", "out"}
SEV_OK = {"critical", "high", "medium", "low", "negligible", "unknown"}


def _log(log_file: Optional[Path], msg: str) -> None:
    line = "[cve-repo] %s\n" % msg
    if log_file:
        try:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            with log_file.open("a", encoding="utf-8") as f:
                f.write(line)
        except OSError:
            pass


def _http_json(
    url: str,
    *,
    method: str = "GET",
    body: Optional[dict] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 25,
) -> Optional[Any]:
    h = {"User-Agent": _UA, "Accept": "application/json"}
    if headers:
        h.update(headers)
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        h["Content-Type"] = "application/json"
    for attempt in range(3):
        try:
            req = Request(url, data=data, headers=h, method=method)
            with urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
            if not raw:
                return None
            obj = json.loads(raw)
            return obj
        except HTTPError as e:
            if e.code in {404, 422}:
                return None
            if e.code in {403, 429} or attempt >= 2:
                return None
        except (URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
            pass
        time.sleep(1.1 * (attempt + 1))
    return None


def _github_headers() -> Dict[str, str]:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": _UA}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = "Bearer %s" % token
    return headers


def git_head_sha(input_dir: Path) -> str:
    if not input_dir.is_dir() or not (input_dir / ".git").exists():
        return ""
    try:
        out = subprocess.check_output(
            ["git", "-C", str(input_dir), "rev-parse", "HEAD"],
            timeout=15,
            stderr=subprocess.DEVNULL,
        )
        sha = out.decode("utf-8", "replace").strip()
        if re.fullmatch(r"[0-9a-fA-F]{7,40}", sha):
            return sha
    except (OSError, subprocess.SubprocessError):
        pass
    return ""


def _toml_str(text: str, section: str, key: str) -> str:
    in_sec = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("["):
            in_sec = s.strip("[]").strip() == section.strip("[]")
            continue
        if in_sec and s.startswith(key):
            _, _, val = s.partition("=")
            return val.strip().strip("\"'")
    return ""


def first_party_packages(input_dir: Path, git_ref: str = "") -> List[dict]:
    out: List[dict] = []
    if not input_dir.is_dir():
        return out
    ref_ver = git_ref.strip()
    if ref_ver.startswith("v") and re.match(r"^v?\d", ref_ver):
        pass
    elif re.match(r"^\d+\.\d+", ref_ver):
        pass
    else:
        ref_ver = ""

    for dp, dns, fns in os.walk(input_dir):
        dns[:] = [d for d in dns if d not in SKIP_DIRS and not d.startswith(".")]
        if "package.json" in fns:
            data = _read_json(Path(dp) / "package.json") or {}
            n = str(data.get("name") or "").strip()
            v = str(data.get("version") or "").strip()
            if n:
                out.append({"name": n, "version": v, "ecosystem": "npm"})
        if "go.mod" in fns:
            try:
                text = (Path(dp) / "go.mod").read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            for line in text.splitlines():
                if line.startswith("module "):
                    mod = line.split(None, 1)[-1].strip()
                    if mod:
                        out.append({"name": mod, "version": ref_ver, "ecosystem": "Go"})
                    break
        if "pyproject.toml" in fns:
            try:
                text = (Path(dp) / "pyproject.toml").read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            n = _toml_str(text, "project", "name") or _toml_str(text, "tool.poetry", "name")
            v = _toml_str(text, "project", "version") or _toml_str(text, "tool.poetry", "version")
            if n:
                out.append({"name": n, "version": v, "ecosystem": "PyPI"})
        if "Cargo.toml" in fns:
            try:
                text = (Path(dp) / "Cargo.toml").read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            n = _toml_str(text, "package", "name")
            v = _toml_str(text, "package", "version")
            if n:
                out.append({"name": n, "version": v, "ecosystem": "crates.io"})
        if len(out) >= MAX_FIRST_PARTY:
            break
    seen = set()
    uniq = []
    for p in out:
        key = (str(p.get("ecosystem")), str(p.get("name")).lower(), str(p.get("version")))
        if key in seen:
            continue
        seen.add(key)
        uniq.append(p)
        if len(uniq) >= MAX_FIRST_PARTY:
            break
    return uniq


def extra_first_party_names(request: Optional[dict], source: Optional[dict]) -> List[str]:
    names: List[str] = []
    req = request or {}
    src = source or {}
    git = src.get("git") if isinstance(src.get("git"), dict) else {}
    for raw in (req.get("title"), req.get("project"), git.get("repo_url"), src.get("url")):
        s = str(raw or "").strip().lower().rstrip("/")
        if not s:
            continue
        if s.endswith(".git"):
            s = s[:-4]
        names.append(s)
        names.append(s.rsplit("/", 1)[-1])
    return names


def annotate_cve_scope(matches: Sequence[dict], input_dir: Path, extra_names: Optional[Sequence[str]] = None) -> None:
    first = _first_party_names(input_dir)
    for n in extra_names or []:
        s = str(n or "").strip().lower().rstrip("/")
        if not s:
            continue
        if s.endswith(".git"):
            s = s[:-4]
        first.add(s)
        first.add(s.rsplit("/", 1)[-1])
    for m in matches:
        if not isinstance(m, dict):
            continue
        explicit = str(m.get("cve_scope") or "").lower()
        if explicit in {"self", "dependency"}:
            continue
        m["cve_scope"] = _cve_scope(str(m.get("package") or ""), first)


def _norm_sev(raw: Any) -> str:
    s = str(raw or "").strip().lower()
    if s in SEV_OK:
        return s
    aliases = {"crit": "critical", "severe": "high", "moderate": "medium", "mod": "medium", "info": "low"}
    return aliases.get(s, "unknown")


def _cvss_from_osv(vuln: dict) -> Optional[float]:
    best = None
    for item in vuln.get("severity") or []:
        if not isinstance(item, dict):
            continue
        score = item.get("score")
        if isinstance(score, (int, float)):
            best = max(best or 0.0, float(score))
            continue
        text = str(score or "")
        m = re.search(r"/(\d+(?:\.\d+)?)$", text.replace(" ", ""))
        if not m:
            m = re.search(r"(\d+\.\d+)", text)
        if m:
            try:
                best = max(best or 0.0, float(m.group(1)))
            except ValueError:
                pass
    return best


def _sev_from_cvss(score: Optional[float]) -> str:
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"


def _osv_to_match(vuln: dict, *, engine: str, package: str = "", version: str = "") -> Optional[dict]:
    if not isinstance(vuln, dict):
        return None
    vid = str(vuln.get("id") or "").strip()
    if not vid:
        return None
    aliases = [str(a) for a in (vuln.get("aliases") or []) if a]
    pkg = package
    ver = version
    eco = ""
    if not pkg:
        for aff in vuln.get("affected") or []:
            if not isinstance(aff, dict):
                continue
            p = aff.get("package") if isinstance(aff.get("package"), dict) else {}
            n = str(p.get("name") or "").strip()
            if n:
                pkg = n
                eco = str(p.get("ecosystem") or "")
                break
    ds = vuln.get("database_specific") if isinstance(vuln.get("database_specific"), dict) else {}
    sev = _norm_sev(ds.get("severity"))
    cvss = _cvss_from_osv(vuln)
    if sev == "unknown":
        sev = _sev_from_cvss(cvss)
    refs = []
    for r in vuln.get("references") or []:
        if isinstance(r, dict) and r.get("url"):
            refs.append(str(r.get("url")))
        elif isinstance(r, str):
            refs.append(r)
    return {
        "id": vid,
        "aliases": aliases[:8],
        "severity": sev,
        "cvss": cvss,
        "package": pkg,
        "version": ver,
        "ecosystem": eco,
        "purl": "",
        "path": "",
        "fix_state": "",
        "fix_versions": [],
        "title": str(vuln.get("summary") or vuln.get("details") or vid)[:240],
        "urls": refs[:8],
        "data_source": "osv",
        "engine": engine,
        "cve_scope": "self",
    }


def _ghsa_to_match(item: dict, *, engine: str, package: str = "") -> Optional[dict]:
    if not isinstance(item, dict):
        return None
    if item.get("withdrawn_at"):
        return None
    vid = str(item.get("ghsa_id") or item.get("id") or "").strip()
    if not vid:
        return None
    cve = str(item.get("cve_id") or "").strip()
    aliases = [cve] if cve else []
    pkg = package
    if not pkg:
        for vpkg in item.get("vulnerabilities") or []:
            if isinstance(vpkg, dict) and vpkg.get("package"):
                p = vpkg.get("package")
                pkg = str(p.get("name") if isinstance(p, dict) else p or "")
                if pkg:
                    break
        if not pkg:
            pkg = str(item.get("repository_advisory") or "")
    sev = _norm_sev(item.get("severity") or item.get("cvss_severities"))
    if sev == "unknown":
        sev = _norm_sev((item.get("cvss") or {}).get("severity") if isinstance(item.get("cvss"), dict) else "")
    score = None
    cvss = item.get("cvss") if isinstance(item.get("cvss"), dict) else {}
    try:
        if cvss.get("score") is not None:
            score = float(cvss.get("score"))
    except (TypeError, ValueError):
        score = None
    if sev == "unknown":
        sev = _sev_from_cvss(score)
    html = str(item.get("html_url") or item.get("url") or "")
    return {
        "id": vid,
        "aliases": aliases,
        "severity": sev,
        "cvss": score,
        "package": pkg,
        "version": "",
        "ecosystem": "",
        "purl": "",
        "path": "",
        "fix_state": "",
        "fix_versions": [],
        "title": str(item.get("summary") or vid)[:240],
        "urls": [html] if html else [],
        "data_source": "github-advisory",
        "engine": engine,
        "cve_scope": "self",
    }


def _dedupe_key(m: dict) -> tuple:
    return (
        str(m.get("id") or "").upper(),
        str(m.get("package") or "").lower(),
    )


def _merge_matches(existing: List[dict], added: List[dict]) -> List[dict]:
    seen = {_dedupe_key(m) for m in existing if isinstance(m, dict)}
    # also treat same advisory id as duplicate when the new one is repo-scoped
    seen_ids = {str(m.get("id") or "").upper() for m in existing if isinstance(m, dict) and m.get("id")}
    out = list(existing)
    for m in added:
        if not isinstance(m, dict):
            continue
        key = _dedupe_key(m)
        vid = str(m.get("id") or "").upper()
        if key in seen:
            continue
        if vid and vid in seen_ids:
            continue
        seen.add(key)
        if vid:
            seen_ids.add(vid)
        out.append(m)
    return out


def _query_osv_commit(sha: str) -> List[dict]:
    if not sha:
        return []
    data = _http_json(OSV_QUERY, method="POST", body={"commit": sha})
    if not isinstance(data, dict):
        return []
    matches = []
    for vuln in data.get("vulns") or []:
        m = _osv_to_match(vuln, engine="osv-repo")
        if m:
            matches.append(m)
    return matches


def _query_osv_package(name: str, ecosystem: str, version: str) -> List[dict]:
    if not name or not ecosystem or not version:
        return []
    body = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
    data = _http_json(OSV_QUERY, method="POST", body=body)
    if not isinstance(data, dict):
        return []
    matches = []
    for vuln in data.get("vulns") or []:
        m = _osv_to_match(vuln, engine="osv-repo", package=name, version=version)
        if m:
            matches.append(m)
    return matches


def _query_github_repo(slug: str) -> List[dict]:
    if not slug or "/" not in slug:
        return []
    url = "https://api.github.com/repos/%s/security-advisories?per_page=50" % quote(slug)
    data = _http_json(url, headers=_github_headers())
    items = data if isinstance(data, list) else []
    matches = []
    for item in items:
        m = _ghsa_to_match(item, engine="github-advisory", package=slug)
        if m:
            matches.append(m)
    global_url = "https://api.github.com/advisories?per_page=20&affects=%s" % quote(slug)
    gdata = _http_json(global_url, headers=_github_headers())
    if isinstance(gdata, list):
        for item in gdata:
            m = _ghsa_to_match(item, engine="github-advisory", package=slug)
            if m:
                matches.append(m)
    return matches


def lookup_repo_advisories(
    *,
    input_dir: Path,
    source: Optional[dict] = None,
    request: Optional[dict] = None,
    git_ref: str = "",
    log_file: Optional[Path] = None,
) -> List[dict]:
    added: List[dict] = []
    sha = git_head_sha(input_dir)
    if sha:
        _log(log_file, "osv commit query %s" % sha[:12])
        got = _query_osv_commit(sha)
        _log(log_file, "osv commit hits %s" % len(got))
        added.extend(got)
    src = source or {}
    git = src.get("git") if isinstance(src.get("git"), dict) else {}
    ref = git_ref or str(git.get("ref") or "")
    pkgs = first_party_packages(input_dir, git_ref=ref)
    for pkg in pkgs:
        got = _query_osv_package(str(pkg.get("name") or ""), str(pkg.get("ecosystem") or ""), str(pkg.get("version") or ""))
        if got:
            _log(log_file, "osv package %s@%s hits %s" % (pkg.get("name"), pkg.get("version"), len(got)))
        added.extend(got)
    repo_url = str(git.get("repo_url") or "")
    ref_up = parse_git_upstream(repo_url)
    if ref_up and ref_up.kind == "github" and ref_up.slug:
        got = _query_github_repo(ref_up.slug)
        _log(log_file, "github advisory %s hits %s" % (ref_up.slug, len(got)))
        added.extend(got)
    return added


def enrich_cve_json(
    *,
    input_dir: Path,
    output_dir: Path,
    source: Optional[dict] = None,
    request: Optional[dict] = None,
    policy: Optional[dict] = None,
    log_file: Optional[Path] = None,
) -> dict:
    """Annotate Grype matches with cve_scope; optionally merge repo advisories."""
    path = output_dir / "cve.json"
    report: Dict[str, Any] = {}
    if path.is_file():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                report = loaded
        except Exception:
            report = {}
    if not report:
        report = {
            "schema": "openmastiff.sca.v1",
            "tool": "sca",
            "status": "skipped",
            "matches": [],
            "engines": [],
            "counts": {},
            "gate": {},
        }
    matches = [m for m in (report.get("matches") or []) if isinstance(m, dict)]
    extra = extra_first_party_names(request, source)
    annotate_cve_scope(matches, input_dir, extra)

    raw = policy if isinstance(policy, dict) else {}
    cve_cfg = raw.get("cve") if isinstance(raw.get("cve"), dict) else {}
    maint = raw.get("maintenance") if isinstance(raw.get("maintenance"), dict) else {}
    repo_cfg = cve_cfg.get("repo_advisory") if isinstance(cve_cfg.get("repo_advisory"), dict) else {}
    fetch_ok = bool(maint.get("fetch_remote_metadata", True))
    repo_on = bool(repo_cfg.get("enabled", True))
    cve_on = bool(cve_cfg.get("enabled", True))

    engines = list(report.get("engines") or [])
    if cve_on and repo_on and fetch_ok:
        try:
            added = lookup_repo_advisories(
                input_dir=input_dir,
                source=source,
                request=request,
                log_file=log_file,
            )
            before = len(matches)
            matches = _merge_matches(matches, added)
            _log(log_file, "merged repo advisories +%s (total %s)" % (len(matches) - before, len(matches)))
            engines.append(
                {
                    "name": "osv-repo",
                    "status": "succeeded",
                    "match_count": max(0, len(matches) - before),
                    "error": None,
                }
            )
        except Exception as e:
            _log(log_file, "repo advisory failed: %s" % e)
            engines.append({"name": "osv-repo", "status": "skipped", "error": str(e)[:240], "match_count": 0})
    elif cve_on and repo_on and not fetch_ok:
        engines.append(
            {
                "name": "osv-repo",
                "status": "skipped",
                "error": "fetch_remote_metadata disabled",
                "match_count": 0,
            }
        )
    elif cve_on:
        engines.append({"name": "osv-repo", "status": "skipped", "error": "repo_advisory disabled", "match_count": 0})

    annotate_cve_scope(matches, input_dir, extra)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "negligible": 0, "unknown": 0}
    for m in matches:
        sev = _norm_sev(m.get("severity"))
        counts[sev] = counts.get(sev, 0) + 1
    report["matches"] = matches
    report["counts"] = counts
    report["engines"] = engines
    if matches and str(report.get("status") or "") in {"", "skipped"}:
        report["status"] = "succeeded"
    try:
        path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except OSError as e:
        _log(log_file, "write cve.json failed: %s" % e)
    return report
