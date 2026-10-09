from __future__ import annotations

import json
import os
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.db import col
from app.policy import load_active_policy
from app.role_review_sync import effective_gate_status, fetch_legal_reviews, merge_role_reviews


def _read_json_path(path: str) -> Optional[dict]:
    if not path or not os.path.exists(path):
        return None
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return None


def _artifact_json(outputs: dict, name: str) -> Optional[dict]:
    ref = outputs.get(name) or {}
    path = ref.get("path")
    if not path:
        return None
    return _read_json_path(path)


def _summarize_license(license_data: Optional[dict], policy_raw: dict) -> dict:
    lic_policy = policy_raw.get("license") or {}
    deny_list = set(lic_policy.get("deny_list") or [])
    legal_list = set(lic_policy.get("legal_review_list") or [])

    if not license_data:
        return {
            "available": False,
            "note": "无许可证扫描结果",
            "top_licenses": [],
            "deny_hits": [],
            "legal_review_hits": [],
            "unknown_or_low_confidence": None,
            "file_count": 0,
        }

    note = str(license_data.get("note") or "").strip()
    counts: Counter = Counter()

    for lic in license_data.get("licenses") or []:
        if not isinstance(lic, dict):
            continue
        key = (
            lic.get("spdx_license_key")
            or lic.get("key")
            or lic.get("license_expression")
            or lic.get("name")
            or "unknown"
        )
        counts[str(key)] += int(lic.get("count") or 1)

    for f in license_data.get("files") or []:
        if not isinstance(f, dict):
            continue
        for lic in f.get("licenses") or []:
            if not isinstance(lic, dict):
                continue
            key = (
                lic.get("license_expression")
                or lic.get("spdx_license_key")
                or lic.get("key")
                or "unknown"
            )
            counts[str(key)] += 1
        expr = f.get("detected_license_expression") or f.get("license_expression")
        if expr:
            counts[str(expr)] += 1

    top_licenses = [{"license": k, "count": v} for k, v in counts.most_common(20)]
    deny_hits = [x for x in counts if x in deny_list]
    legal_hits = [x for x in counts if x in legal_list]

    return {
        "available": True,
        "note": note or None,
        "top_licenses": top_licenses,
        "deny_hits": deny_hits,
        "legal_review_hits": legal_hits,
        "unknown_or_low_confidence": bool(license_data.get("unknown_or_low_confidence")),
        "file_count": len(license_data.get("files") or []),
        "package_count": len(license_data.get("packages") or []),
        "engine": license_data.get("tool") or None,
        "policy_deny_list": sorted(deny_list),
        "policy_legal_review_list": sorted(legal_list),
    }


def _summarize_gosec(gosec_data: Optional[dict], summary: Optional[dict]) -> dict:
    counts = {"high": 0, "medium": 0, "low": 0}
    counted_from_issues = False
    if gosec_data and isinstance(gosec_data.get("Issues"), list):
        for issue in gosec_data["Issues"]:
            if not isinstance(issue, dict):
                continue
            counted_from_issues = True
            sev = str(issue.get("severity") or "").upper()
            if sev == "HIGH":
                counts["high"] += 1
            elif sev == "MEDIUM":
                counts["medium"] += 1
            elif sev == "LOW":
                counts["low"] += 1
    if not counted_from_issues and summary:
        tools = summary.get("tools") or {}
        gc = (tools.get("gosec") or {}).get("counts") or {}
        if isinstance(gc, dict):
            counts["high"] = int(gc.get("high") or 0)
            counts["medium"] = int(gc.get("medium") or 0)
            counts["low"] = int(gc.get("low") or 0)
    gate = ((summary or {}).get("gate") or {}).get("gosec") or {}
    return {
        "detected": bool(gosec_data and gosec_data.get("Issues") is not None),
        "counts": counts,
        "gate_status": gate.get("status"),
        "gate_reason": gate.get("reason"),
        "note": gosec_data.get("note") if gosec_data else None,
    }


def _summarize_lang_tool(data: Optional[dict], summary: Optional[dict], name: str) -> dict:
    counts = {"high": 0, "medium": 0, "low": 0}
    if data and isinstance(data.get("Issues"), list):
        for issue in data["Issues"]:
            if not isinstance(issue, dict):
                continue
            sev = str(issue.get("severity") or "").upper()
            if sev == "HIGH":
                counts["high"] += 1
            elif sev == "MEDIUM":
                counts["medium"] += 1
            elif sev == "LOW":
                counts["low"] += 1
    elif summary:
        gc = ((summary.get("tools") or {}).get(name) or {}).get("counts") or {}
        if isinstance(gc, dict):
            counts = {k: int(gc.get(k) or 0) for k in counts}
    gate = ((summary or {}).get("gate") or {}).get(name) or {}
    return {
        "detected": bool(data and data.get("Issues") is not None),
        "engine": (data or {}).get("engine") if data else None,
        "counts": counts,
        "gate_status": gate.get("status"),
        "gate_reason": gate.get("reason"),
        "note": data.get("note") if data else None,
    }


def _summarize_cve(data: Optional[dict], summary: Optional[dict]) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    engines = []
    if data and isinstance(data.get("counts"), dict):
        for k in counts:
            counts[k] = int((data.get("counts") or {}).get(k) or 0)
        engines = data.get("engines") or []
    elif summary:
        gc = ((summary.get("tools") or {}).get("cve") or {}).get("counts") or {}
        if isinstance(gc, dict):
            for k in counts:
                counts[k] = int(gc.get(k) or 0)
        engines = ((summary.get("tools") or {}).get("cve") or {}).get("engines") or []
    gate = ((summary or {}).get("gate") or {}).get("cve") or ((data or {}).get("gate") or {})
    top = []
    for m in (data or {}).get("matches") or []:
        if not isinstance(m, dict):
            continue
        top.append(
            {
                "id": m.get("id"),
                "severity": m.get("severity"),
                "package": m.get("package"),
                "version": m.get("version"),
                "fix_versions": m.get("fix_versions") or [],
            }
        )
        if len(top) >= 12:
            break
    return {
        "available": bool(data),
        "status": (data or {}).get("status"),
        "engine": ",".join(
            str((e or {}).get("name") or "")
            for e in engines
            if isinstance(e, dict) and e.get("status") == "succeeded"
        )
        or ((data or {}).get("tool") if data else None),
        "engines": engines,
        "counts": counts,
        "match_count": len((data or {}).get("matches") or []),
        "top": top,
        "gate_status": gate.get("status"),
        "gate_reason": gate.get("reason"),
        "error": (data or {}).get("error"),
    }


def _summarize_cppcheck(cpp_data: Optional[str], summary: Optional[dict]) -> dict:
    counts = {"error": 0, "warning": 0, "style": 0}
    if summary:
        tools = summary.get("tools") or {}
        cc = (tools.get("cppcheck") or {}).get("counts") or {}
        if isinstance(cc, dict):
            counts["error"] = int(cc.get("error") or 0)
            counts["warning"] = int(cc.get("warning") or 0)
            counts["style"] = int(cc.get("style") or 0)
    if cpp_data:
        try:
            root = ET.fromstring(cpp_data)
            for err in root.findall(".//error"):
                sev = str(err.get("severity") or "").lower()
                if sev == "error":
                    counts["error"] += 1
                elif sev == "warning":
                    counts["warning"] += 1
                else:
                    counts["style"] += 1
        except Exception:
            pass
    gate = ((summary or {}).get("gate") or {}).get("cppcheck") or {}
    return {
        "counts": counts,
        "gate_status": gate.get("status"),
        "gate_reason": gate.get("reason"),
    }


def build_review_brief(request_id: str) -> dict:
    requests = col("review_requests")
    scan_runs = col("scan_runs")
    legal_reviews = col("legal_reviews")
    remediations = col("remediations")

    req = requests.find_one({"request_id": request_id}, {"_id": 0})
    if not req:
        return {}

    policy = load_active_policy()
    scan_run_id = req.get("latest_scan_run_id")
    scan_run = scan_runs.find_one({"scan_run_id": scan_run_id}, {"_id": 0}) if scan_run_id else None
    outputs = (scan_run or {}).get("outputs") or {}

    summary = _artifact_json(outputs, "summary.json")
    license_data = _artifact_json(outputs, "license.json")
    gosec_data = _artifact_json(outputs, "gosec.json")

    cpp_xml = None
    cpp_ref = outputs.get("cppcheck.xml") or {}
    cpp_path = cpp_ref.get("path")
    if cpp_path and os.path.exists(cpp_path):
        try:
            cpp_xml = Path(cpp_path).read_text(encoding="utf-8", errors="replace")
        except Exception:
            cpp_xml = None

    maintenance = (summary or {}).get("maintenance") if summary else None
    if not maintenance:
        maintenance = _artifact_json(outputs, "maintenance.json")

    lr_items = fetch_legal_reviews(request_id)[:5]
    merged_role_reviews = merge_role_reviews(req, lr_items)
    eff_gate = effective_gate_status(req, lr_items)

    gate_block = dict((summary or {}).get("gate") or {})
    if eff_gate == "Pass" and gate_block:
        gate_block["overall"] = {
            "status": "pass",
            "reason": "法务已裁决允许"
            if (req.get("scanner_gate_status") or req.get("gate_status")) == "PendingLegal"
            else (gate_block.get("overall") or {}).get("reason", ""),
        }
        lic = gate_block.get("license") or {}
        if str(lic.get("status") or "").lower() == "pending_legal":
            gate_block["license"] = {**lic, "status": "pass", "reason": "法务已放行"}
    tools_block = (summary or {}).get("tools") or {}
    input_block = (summary or {}).get("input") or {}
    rem_open = remediations.count_documents({"request_id": request_id, "status": "open"})

    ecosystems = input_block.get("ecosystems_detected") or []
    if not ecosystems and summary:
        ecosystems = []
        if (tools_block.get("gosec") or {}).get("status") not in (None, "skipped"):
            ecosystems.append("go")
        if (tools_block.get("cppcheck") or {}).get("status") not in (None, "skipped"):
            ecosystems.append("cpp")
        if (tools_block.get("bandit") or {}).get("status") not in (None, "skipped"):
            ecosystems.append("python")
        if (tools_block.get("pmd") or {}).get("status") not in (None, "skipped"):
            ecosystems.append("java")
        if (tools_block.get("cargo_audit") or {}).get("status") not in (None, "skipped"):
            ecosystems.append("rust")
        if (tools_block.get("eslint") or {}).get("status") not in (None, "skipped"):
            ecosystems.append("javascript")

    return {
        "request_id": request_id,
        "scan_run_id": scan_run_id,
        "scan_status": (scan_run or {}).get("status"),
        "gate_status": eff_gate,
        "scanner_gate_status": req.get("scanner_gate_status") or req.get("gate_status"),
        "effective_gate_status": eff_gate,
        "request_status": req.get("status"),
        "gates": {
            "overall": gate_block.get("overall") or {},
            "license": gate_block.get("license") or {},
            "gosec": gate_block.get("gosec") or {},
            "cppcheck": gate_block.get("cppcheck") or {},
            "bandit": gate_block.get("bandit") or {},
            "pmd": gate_block.get("pmd") or {},
            "cargo_audit": gate_block.get("cargo_audit") or {},
            "eslint": gate_block.get("eslint") or {},
            "cve": gate_block.get("cve") or {},
            "maintenance": gate_block.get("maintenance") or ((maintenance or {}).get("overall") if maintenance else {}),
        },
        "tools": tools_block,
        "ecosystems_detected": ecosystems,
        "license": _summarize_license(license_data, policy.raw),
        "sbom": {
            "available": bool((summary or {}).get("sbom", {}).get("available"))
            or any(outputs.get(n) for n in ("sbom.json", "sbom.cdx.json", "sbom.spdx.json", "sbom.syft.json")),
            "files": [
                n
                for n in ("sbom.json", "sbom.cdx.json", "sbom.spdx.json", "sbom.syft.json")
                if outputs.get(n)
            ],
            "formats": ((summary or {}).get("sbom") or {}).get("formats")
            or ["cyclonedx-json", "spdx-json", "syft-json"],
        },
        "gosec": _summarize_gosec(gosec_data, summary),
        "cppcheck": _summarize_cppcheck(cpp_xml, summary),
        "bandit": _summarize_lang_tool(_artifact_json(outputs, "bandit.json"), summary, "bandit"),
        "pmd": _summarize_lang_tool(_artifact_json(outputs, "pmd.json"), summary, "pmd"),
        "cargo_audit": _summarize_lang_tool(_artifact_json(outputs, "cargo-audit.json"), summary, "cargo_audit"),
        "eslint": _summarize_lang_tool(_artifact_json(outputs, "eslint.json"), summary, "eslint"),
        "cve": _summarize_cve(_artifact_json(outputs, "cve.json"), summary),
        "maintenance": maintenance,
        "legal_reviews": lr_items,
        "role_reviews": merged_role_reviews,
        "required_review_roles": req.get("required_review_roles") or [],
        "open_remediations": rem_open,
        "policy_snapshot": {
            "license_deny_list": (policy.raw.get("license") or {}).get("deny_list") or [],
            "license_legal_review_list": (policy.raw.get("license") or {}).get("legal_review_list") or [],
            "gosec_block_if_high_gt": (policy.raw.get("gosec") or {}).get("block_if_high_gt"),
            "cppcheck_block_if_error_gt": (policy.raw.get("cppcheck") or {}).get("block_if_error_gt"),
            "bandit_block_if_high_gt": (policy.raw.get("bandit") or {}).get("block_if_high_gt"),
            "pmd_block_if_high_gt": (policy.raw.get("pmd") or {}).get("block_if_high_gt"),
            "cargo_audit_block_if_high_gt": (policy.raw.get("cargo_audit") or {}).get("block_if_high_gt"),
            "eslint_block_if_high_gt": (policy.raw.get("eslint") or {}).get("block_if_high_gt"),
            "cve_block_if_critical_gt": (policy.raw.get("cve") or {}).get("block_if_critical_gt"),
            "cve_block_if_high_gt": (policy.raw.get("cve") or {}).get("block_if_high_gt"),
            "cve_engines": (policy.raw.get("cve") or {}).get("engines") or ["grype"],
        },
    }
