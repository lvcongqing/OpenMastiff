from __future__ import annotations

import hashlib
import json
import os
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.schemas import new_id, now_utc


def _fp(*parts: Any) -> str:
    raw = "|".join("" if p is None else str(p) for p in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _read_json(path: Path) -> Optional[dict]:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _base(request_id: str, scan_run_id: str, category: str) -> Dict[str, Any]:
    return {
        "finding_id": new_id(),
        "request_id": request_id,
        "scan_run_id": scan_run_id,
        "category": category,
        "disposition": "open",
        "created_at": now_utc(),
    }


def _from_issues(request_id: str, scan_run_id: str, category: str, issues: List[dict]) -> List[dict]:
    out: List[dict] = []
    seen = set()
    for iss in issues:
        if not isinstance(iss, dict):
            continue
        rule = iss.get("rule_id") or iss.get("rule") or iss.get("id") or category
        loc = iss.get("file") or (iss.get("location") or {}).get("file") or ""
        line = iss.get("line") or (iss.get("location") or {}).get("line") or 0
        msg = iss.get("message") or iss.get("details") or ""
        sev = str(iss.get("severity") or "medium").lower()
        fingerprint = _fp(category, rule, loc, line, msg)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        item = _base(request_id, scan_run_id, category)
        item.update(
            {
                "fingerprint": fingerprint,
                "severity": sev,
                "rule_id": str(rule),
                "title": "%s: %s" % (rule, (msg or loc or category)[:80]),
                "detail": msg,
                "location": {"file": loc, "line": line},
            }
        )
        out.append(item)
    return out


def _input_dir(output_dir: Path) -> Path:
    parent = output_dir.parent
    candidate = parent / "input"
    return candidate if candidate.is_dir() else parent


def _first_party_names(input_dir: Path) -> set:
    """Names this repo publishes (own package.json / Cargo / go.mod / pyproject)."""
    names = set()
    skip = {".git", ".svn", "target", "node_modules", "vendor", "__pycache__", "dist", "build", "out"}
    if not input_dir.is_dir():
        return names

    def walk():
        for dp, dns, fns in os.walk(input_dir):
            dns[:] = [d for d in dns if d not in skip and not d.startswith(".")]
            yield dp, fns

    for dp, fns in walk():
        if "package.json" in fns:
            data = _read_json(Path(dp) / "package.json") or {}
            n = str(data.get("name") or "").strip()
            if n:
                names.add(n.lower())
        if "go.mod" in fns:
            try:
                text = (Path(dp) / "go.mod").read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            for line in text.splitlines():
                if line.startswith("module "):
                    mod = line.split(None, 1)[-1].strip()
                    if mod:
                        names.add(mod.lower())
                        names.add(mod.rsplit("/", 1)[-1].lower())
                    break
        if "pyproject.toml" in fns:
            try:
                text = (Path(dp) / "pyproject.toml").read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            in_proj = False
            for line in text.splitlines():
                s = line.strip()
                if s.startswith("["):
                    in_proj = s in {"[project]", "[tool.poetry]"}
                    continue
                if in_proj and s.startswith("name"):
                    _, _, val = s.partition("=")
                    n = val.strip().strip("\"'")
                    if n:
                        names.add(n.lower())
                    break
        if "Cargo.toml" in fns:
            try:
                text = (Path(dp) / "Cargo.toml").read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            in_pkg = False
            for line in text.splitlines():
                s = line.strip()
                if s.startswith("["):
                    in_pkg = s == "[package]"
                    continue
                if in_pkg and s.startswith("name"):
                    _, _, val = s.partition("=")
                    n = val.strip().strip("\"'")
                    if n:
                        names.add(n.lower())
                    break
    return names


def _cve_scope(pkg: str, first_party: set) -> str:
    n = str(pkg or "").strip().lower()
    if not n:
        return "dependency"
    if n in first_party:
        return "self"
    for own in first_party:
        if not own:
            continue
        if n.startswith("@" + own + "/"):
            return "self"
        if own.startswith("@") and "/" in own and n.startswith(own.rsplit("/", 1)[0] + "/"):
            return "self"
    return "dependency"


def ingest_scan_findings(
    *,
    request_id: str,
    scan_run_id: str,
    output_dir: Path,
    license_data: Optional[dict] = None,
    extra_first_party: Optional[List[str]] = None,
) -> List[dict]:
    findings: List[dict] = []

    gosec = _read_json(output_dir / "gosec.json") or {}
    gosec_issues = []
    for iss in gosec.get("Issues") or []:
        if not isinstance(iss, dict):
            continue
        loc = iss.get("file") or ""
        gosec_issues.append(
            {
                "severity": iss.get("severity") or "medium",
                "rule_id": iss.get("rule_id") or "gosec",
                "file": loc,
                "line": (iss.get("line") or "").split("-")[0] if iss.get("line") else 0,
                "message": iss.get("details") or iss.get("what") or "",
            }
        )
    findings.extend(_from_issues(request_id, scan_run_id, "gosec", gosec_issues))

    cpp_path = output_dir / "cppcheck.xml"
    if cpp_path.is_file():
        cpp_issues = []
        try:
            root = ET.fromstring(cpp_path.read_text(encoding="utf-8", errors="ignore"))
            for err in root.findall(".//error"):
                loc = err.find("location")
                cpp_issues.append(
                    {
                        "severity": err.get("severity") or "style",
                        "rule_id": err.get("id") or "cppcheck",
                        "file": (loc.get("file") if loc is not None else "") or "",
                        "line": (loc.get("line") if loc is not None else 0) or 0,
                        "message": err.get("msg") or "",
                    }
                )
        except Exception:
            pass
        findings.extend(_from_issues(request_id, scan_run_id, "cppcheck", cpp_issues))

    for name, category in (
        ("bandit.json", "bandit"),
        ("pmd.json", "pmd"),
        ("cargo-audit.json", "cargo_audit"),
        ("eslint.json", "eslint"),
    ):
        data = _read_json(output_dir / name) or {}
        findings.extend(_from_issues(request_id, scan_run_id, category, list(data.get("Issues") or [])))

    cve = _read_json(output_dir / "cve.json") or {}
    first_party = _first_party_names(_input_dir(output_dir))
    for n in extra_first_party or []:
        s = str(n or "").strip().lower().rstrip("/")
        if not s:
            continue
        s = s[:-4] if s.endswith(".git") else s
        first_party.add(s)
        first_party.add(s.rsplit("/", 1)[-1])
    seen_cve = set()
    for match in cve.get("matches") or []:
        if not isinstance(match, dict):
            continue
        vid = str(match.get("id") or "").strip()
        if not vid:
            continue
        pkg = str(match.get("package") or "")
        ver = str(match.get("version") or "")
        purl = str(match.get("purl") or "")
        loc = str(match.get("path") or purl or pkg)
        fingerprint = _fp("cve", vid, purl or ("%s@%s" % (pkg, ver)))
        if fingerprint in seen_cve:
            continue
        seen_cve.add(fingerprint)
        aliases = [str(a) for a in (match.get("aliases") or []) if a][:8]
        alias_s = ",".join(aliases[:6])
        fix_vers = match.get("fix_versions") or []
        fix_s = ",".join(str(x) for x in fix_vers[:4] if x)
        explicit = str(match.get("cve_scope") or "").lower()
        scope = explicit if explicit in {"self", "dependency"} else _cve_scope(pkg, first_party)
        cve_ids = [a for a in ([vid] + aliases) if str(a).upper().startswith("CVE-")]
        detail_parts = [
            "%s %s" % (pkg, ver),
            ("scope %s" % ("self" if scope == "self" else "dependency")),
            ("aliases %s" % alias_s) if alias_s else "",
            ("fix %s" % fix_s) if fix_s else ("fix_state %s" % (match.get("fix_state") or "")),
            str(match.get("title") or "")[:160],
        ]
        item = _base(request_id, scan_run_id, "cve")
        item.update(
            {
                "fingerprint": fingerprint,
                "severity": str(match.get("severity") or "medium").lower(),
                "rule_id": vid,
                "title": "%s: %s %s" % (vid, pkg or "component", ver),
                "detail": "; ".join(p for p in detail_parts if p).strip(),
                "location": {"file": loc, "line": 0},
                "package": pkg,
                "version": ver,
                "purl": purl,
                "aliases": aliases,
                "cve_ids": cve_ids,
                "cve_scope": scope,
                "fix_state": str(match.get("fix_state") or ""),
                "engine": str(match.get("engine") or "sca"),
            }
        )
        findings.append(item)

    lic = license_data if isinstance(license_data, dict) else _read_json(output_dir / "license.json") or {}
    gate = lic.get("gate") or {}
    if str(gate.get("status") or "").lower() in {"fail", "pending_legal"}:
        item = _base(request_id, scan_run_id, "license")
        item.update(
            {
                "fingerprint": _fp("license", gate.get("status"), gate.get("reason")),
                "severity": "high" if str(gate.get("status")).lower() == "fail" else "medium",
                "rule_id": "license_gate",
                "title": "许可证门禁: %s" % (gate.get("status") or ""),
                "detail": gate.get("reason") or "",
                "location": {},
            }
        )
        findings.append(item)

    return findings
