#!/usr/bin/env python3
"""Software composition analysis (CVE/advisory) with a pluggable engine list.

Canonical artifact: cve.json (schema openmastiff.sca.v1).
Engines selected by policy.cve.engines. Implemented: grype.
Reserved stubs: trivy, osv-scanner (record skipped until adapters land).
"""
from __future__ import print_function, unicode_literals

import json
import os
import shutil
import subprocess
import sys

SCHEMA = "openmastiff.sca.v1"
KNOWN_ENGINES = ("grype", "trivy", "osv-scanner")
IMPLEMENTED_ENGINES = ("grype",)

SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "negligible": 4,
    "unknown": 5,
}


def _log(msg):
    sys.stdout.write("[sca] %s\n" % msg)
    sys.stdout.flush()


def _which(name):
    return shutil.which(name)


def _load_json(path):
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _write_json(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
        f.write("\n")


def _norm_sev(raw):
    s = str(raw or "").strip().lower()
    if s in SEVERITY_RANK:
        return s
    aliases = {"crit": "critical", "severe": "high", "mod": "medium", "info": "low", "negligible": "negligible"}
    return aliases.get(s, "unknown")


def _cvss_score(vuln):
    if not isinstance(vuln, dict):
        return None
    if vuln.get("cvss") is None and isinstance(vuln.get("severity"), (int, float)):
        try:
            return float(vuln.get("severity"))
        except (TypeError, ValueError):
            return None
    best = None
    for item in vuln.get("cvss") or []:
        if not isinstance(item, dict):
            continue
        metrics = item.get("metrics") if isinstance(item.get("metrics"), dict) else item
        for key in ("baseScore", "base_score", "score"):
            val = metrics.get(key) if isinstance(metrics, dict) else None
            if val is None:
                continue
            try:
                num = float(val)
            except (TypeError, ValueError):
                continue
            if best is None or num > best:
                best = num
    return best


def _engine_slot(name, status="skipped", version="", error=None, match_count=0, command=""):
    return {
        "name": name,
        "version": version or "",
        "status": status,
        "error": error,
        "match_count": int(match_count or 0),
        "command": command or "",
    }


def _empty_report(status="skipped", error=None, engines=None):
    return {
        "schema": SCHEMA,
        "tool": "sca",
        "status": status,
        "error": error,
        "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "negligible": 0, "unknown": 0},
        "matches": [],
        "engines": engines or [],
        "gate": {"status": "skipped", "reason": error or "cve scan skipped"},
    }


def _count_matches(matches):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "negligible": 0, "unknown": 0}
    for m in matches:
        sev = _norm_sev((m or {}).get("severity"))
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _dedupe(matches):
    seen = set()
    out = []
    for m in matches:
        if not isinstance(m, dict):
            continue
        key = (
            str(m.get("id") or "").upper(),
            str(m.get("purl") or ""),
            str(m.get("package") or ""),
            str(m.get("version") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(m)
    out.sort(key=lambda x: (SEVERITY_RANK.get(_norm_sev(x.get("severity")), 9), str(x.get("id") or "")))
    return out


def _sbom_target(output_dir, input_dir):
    for name in ("sbom.syft.json", "sbom.cdx.json", "sbom.json", "sbom.spdx.json"):
        path = os.path.join(output_dir, name)
        if os.path.isfile(path):
            return "sbom:%s" % path, path
    if os.path.isdir(input_dir):
        return "dir:%s" % input_dir, None
    return None, None


def _grype_version():
    exe = _which("grype")
    if not exe:
        return "", None
    try:
        out = subprocess.check_output([exe, "version", "-o", "json"], stderr=subprocess.STDOUT, timeout=15)
        data = json.loads(out.decode("utf-8", "replace"))
        if isinstance(data, dict):
            return str(data.get("version") or data.get("Version") or ""), exe
    except Exception:
        pass
    try:
        out = subprocess.check_output([exe, "version"], stderr=subprocess.STDOUT, timeout=15)
        line = out.decode("utf-8", "replace").strip().splitlines()
        return (line[0] if line else ""), exe
    except Exception:
        return "", exe


def parse_grype(raw):
    """Normalize Grype JSON into canonical matches[]."""
    data = raw if isinstance(raw, dict) else {}
    matches = []
    for item in data.get("matches") or []:
        if not isinstance(item, dict):
            continue
        vuln = item.get("vulnerability") if isinstance(item.get("vulnerability"), dict) else {}
        art = item.get("artifact") if isinstance(item.get("artifact"), dict) else {}
        vid = str(vuln.get("id") or "").strip()
        if not vid:
            continue
        aliases = []
        for rel in (vuln.get("relatedVulnerabilities") or []) + (item.get("relatedVulnerabilities") or []):
            if isinstance(rel, dict) and rel.get("id"):
                aliases.append(str(rel.get("id")))
            elif isinstance(rel, str):
                aliases.append(rel)
        aliases = sorted(set(a for a in aliases if a and a.upper() != vid.upper()))
        fix = vuln.get("fix") if isinstance(vuln.get("fix"), dict) else {}
        fix_versions = [str(x) for x in (fix.get("versions") or []) if x]
        loc = ""
        for loc_item in art.get("locations") or []:
            if isinstance(loc_item, dict) and loc_item.get("path"):
                loc = str(loc_item.get("path"))
                break
            if isinstance(loc_item, str) and loc_item:
                loc = loc_item
                break
        matches.append(
            {
                "id": vid,
                "aliases": aliases,
                "severity": _norm_sev(vuln.get("severity")),
                "cvss": _cvss_score(vuln),
                "package": str(art.get("name") or ""),
                "version": str(art.get("version") or ""),
                "ecosystem": str(art.get("type") or art.get("language") or ""),
                "purl": str(art.get("purl") or ""),
                "path": loc,
                "fix_state": str(fix.get("state") or "unknown").lower() or "unknown",
                "fix_versions": fix_versions,
                "title": str(vuln.get("description") or vuln.get("dataSource") or vid)[:240],
                "urls": [str(u) for u in (vuln.get("urls") or []) if u][:8],
                "data_source": str(vuln.get("dataSource") or ""),
                "engine": "grype",
            }
        )
    return matches


def run_grype(input_dir, output_dir, timeout_sec):
    version, exe = _grype_version()
    if not exe:
        return [], _engine_slot("grype", status="missing", error="grype not installed")
    target, _sbom = _sbom_target(output_dir, input_dir)
    if not target:
        return [], _engine_slot("grype", version=version, status="skipped", error="no SBOM or input dir")
    raw_path = os.path.join(output_dir, "cve.grype.json")
    cmd = [exe, target, "-o", "json", "--quiet"]
    env = os.environ.copy()
    env.setdefault("GRYPE_CHECK_FOR_APP_UPDATE", "false")
    env.setdefault("GRYPE_DB_AUTO_UPDATE", "false")
    _log(" ".join(cmd))
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_sec,
            env=env,
            universal_newlines=True,
        )
    except subprocess.TimeoutExpired:
        return [], _engine_slot(
            "grype",
            version=version,
            status="failed",
            error="grype timeout after %ss" % timeout_sec,
            command=" ".join(cmd),
        )
    except OSError as e:
        return [], _engine_slot("grype", version=version, status="failed", error=str(e), command=" ".join(cmd))
    out = proc.stdout or ""
    err = (proc.stderr or "").strip()
    raw = None
    text = out.strip()
    if text.startswith("{"):
        try:
            raw = json.loads(text)
        except Exception:
            raw = None
    if isinstance(raw, dict):
        _write_json(raw_path, raw)
    matches = parse_grype(raw or {})
    # grype exits 0 even with matches; non-zero is tool/db error
    if proc.returncode not in (0, 1) and not matches:
        msg = err or ("grype failed exit=%s" % proc.returncode)
        if "update" in msg.lower() and "db" in msg.lower():
            msg = "grype vulnerability db unavailable (run grype db update, or mount GRYPE_DB_CACHE_DIR)"
        return [], _engine_slot(
            "grype",
            version=version,
            status="failed",
            error=msg[:400],
            command=" ".join(cmd),
        )
    return matches, _engine_slot(
        "grype",
        version=version,
        status="succeeded",
        match_count=len(matches),
        command=" ".join(cmd),
        error=None if proc.returncode in (0, 1) else (err[:400] or None),
    )


def run_trivy(_input_dir, _output_dir, _timeout_sec):
    """Reserved: filesystem/SBOM CVE via Aqua Trivy. Not wired yet."""
    if _which("trivy"):
        return [], _engine_slot("trivy", status="skipped", error="trivy adapter reserved, not implemented")
    return [], _engine_slot("trivy", status="skipped", error="trivy adapter reserved, not implemented")


def run_osv(_input_dir, _output_dir, _timeout_sec):
    """Reserved: OSV / lockfile advisory via Google osv-scanner. Not wired yet."""
    return [], _engine_slot("osv-scanner", status="skipped", error="osv-scanner adapter reserved, not implemented")


ENGINE_RUNNERS = {
    "grype": run_grype,
    "trivy": run_trivy,
    "osv-scanner": run_osv,
}


def _policy_cve(policy):
    cfg = policy.get("cve") if isinstance(policy, dict) and isinstance(policy.get("cve"), dict) else {}
    engines = cfg.get("engines") if isinstance(cfg.get("engines"), list) else ["grype"]
    cleaned = []
    seen = set()
    for item in engines:
        name = str(item or "").strip().lower()
        if name == "osv":
            name = "osv-scanner"
        if name in KNOWN_ENGINES and name not in seen:
            seen.add(name)
            cleaned.append(name)
    if not cleaned:
        cleaned = ["grype"]
    enabled = bool(cfg.get("enabled", True))
    try:
        block_crit = int(cfg.get("block_if_critical_gt") if cfg.get("block_if_critical_gt") is not None else 0)
    except (TypeError, ValueError):
        block_crit = 0
    try:
        block_high = int(cfg.get("block_if_high_gt") if cfg.get("block_if_high_gt") is not None else 0)
    except (TypeError, ValueError):
        block_high = 0
    return {
        "enabled": enabled,
        "engines": cleaned,
        "block_if_critical_gt": max(0, block_crit),
        "block_if_high_gt": max(0, block_high),
        "ignore_unfixed": bool(cfg.get("ignore_unfixed", False)),
        "fail_if_engine_missing": bool(cfg.get("fail_if_engine_missing", False)),
    }


def evaluate_gate(matches, cfg, engines):
    if not cfg.get("enabled"):
        return {"status": "pass", "reason": "cve disabled by policy"}
    implemented = [e for e in engines if e.get("name") in IMPLEMENTED_ENGINES]
    missing = [e for e in implemented if e.get("status") == "missing"]
    failed = [e for e in implemented if e.get("status") == "failed"]
    succeeded = [e for e in implemented if e.get("status") == "succeeded"]
    if missing and not succeeded:
        if cfg.get("fail_if_engine_missing"):
            return {"status": "fail", "reason": missing[0].get("error") or "cve engine missing"}
        return {"status": "skipped", "reason": missing[0].get("error") or "cve engine missing"}
    if failed and not succeeded:
        return {"status": "fail", "reason": failed[0].get("error") or "cve engine failed"}
    countable = []
    for m in matches:
        if cfg.get("ignore_unfixed") and str(m.get("fix_state") or "").lower() in {"not-fixed", "wont-fix"}:
            continue
        countable.append(m)
    crit = sum(1 for m in countable if _norm_sev(m.get("severity")) == "critical")
    high = sum(1 for m in countable if _norm_sev(m.get("severity")) == "high")
    if crit > cfg["block_if_critical_gt"]:
        return {"status": "fail", "reason": "cve Critical %s > %s" % (crit, cfg["block_if_critical_gt"])}
    if high > cfg["block_if_high_gt"]:
        return {"status": "fail", "reason": "cve High %s > %s" % (high, cfg["block_if_high_gt"])}
    return {"status": "pass", "reason": "within cve thresholds"}


def run_sca(input_dir, output_dir, policy_file, timeout_sec=900):
    policy = _load_json(policy_file) or {}
    cfg = _policy_cve(policy)
    if not cfg["enabled"]:
        report = _empty_report("skipped", "cve disabled by policy", engines=[])
        _write_json(os.path.join(output_dir, "cve.json"), report)
        return report
    all_matches = []
    engine_slots = []
    for name in cfg["engines"]:
        runner = ENGINE_RUNNERS.get(name)
        if not runner:
            engine_slots.append(_engine_slot(name, status="skipped", error="unknown engine"))
            continue
        matches, slot = runner(input_dir, output_dir, timeout_sec)
        engine_slots.append(slot)
        all_matches.extend(matches or [])
        _log("%s status=%s matches=%s" % (name, slot.get("status"), slot.get("match_count")))
    matches = _dedupe(all_matches)
    counts = _count_matches(matches)
    gate = evaluate_gate(matches, cfg, engine_slots)
    overall = "succeeded"
    if any(e.get("status") == "succeeded" for e in engine_slots):
        overall = "succeeded"
    elif any(e.get("status") == "failed" for e in engine_slots):
        overall = "failed"
    elif any(e.get("status") == "missing" for e in engine_slots):
        overall = "missing"
    else:
        overall = "skipped"
    report = {
        "schema": SCHEMA,
        "tool": "sca",
        "status": overall,
        "error": None,
        "counts": counts,
        "matches": matches,
        "engines": engine_slots,
        "gate": gate,
        "policy": {
            "engines": cfg["engines"],
            "block_if_critical_gt": cfg["block_if_critical_gt"],
            "block_if_high_gt": cfg["block_if_high_gt"],
            "ignore_unfixed": cfg["ignore_unfixed"],
        },
    }
    errs = [e.get("error") for e in engine_slots if e.get("status") in {"failed", "missing"} and e.get("error")]
    if errs and overall != "succeeded":
        report["error"] = errs[0]
    _write_json(os.path.join(output_dir, "cve.json"), report)
    return report


def main(argv):
    input_dir = argv[1] if len(argv) > 1 else os.environ.get("INPUT_DIR") or "/input"
    output_dir = argv[2] if len(argv) > 2 else os.environ.get("OUTPUT_DIR") or "/output"
    policy_file = argv[3] if len(argv) > 3 else os.environ.get("POLICY_FILE") or "/policy/policy.json"
    try:
        timeout_min = int(os.environ.get("TIMEOUT_CVE_MIN") or 15)
    except (TypeError, ValueError):
        timeout_min = 15
    os.makedirs(output_dir, exist_ok=True)
    run_sca(input_dir, output_dir, policy_file, timeout_sec=max(30, timeout_min * 60))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
