from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence

from app.db import col
from app.policy import load_active_policy
from app.schemas import GateStatus, RequestStatus, now_utc


CLEARED_DISPOSITIONS = {"false_positive", "accepted_risk"}
VALID_DISPOSITIONS = {"open", "false_positive", "accepted_risk", "confirmed"}
SAST_CATEGORIES = ("gosec", "bandit", "pmd", "cargo_audit", "eslint")
HIGH_SEVERITIES = {"high", "critical"}
CPPCHECK_BLOCK_SEVERITIES = {"error", "high"}


def apply_saved_dispositions(request_id: str, findings: List[dict]) -> None:
    """复测入库前把历史处置写回，避免误报标记丢失。"""
    if not findings:
        return
    saved = {
        str(d.get("fingerprint")): d
        for d in col("finding_dispositions").find({"request_id": request_id}, {"_id": 0})
        if d.get("fingerprint")
    }
    if not saved:
        return
    for item in findings:
        fp = str(item.get("fingerprint") or "")
        prev = saved.get(fp)
        if not prev:
            continue
        item["disposition"] = prev.get("disposition") or "open"
        item["disposition_reason"] = prev.get("reason")
        item["disposition_by"] = prev.get("updated_by")
        item["disposition_at"] = prev.get("updated_at")


def _is_cleared(finding: dict) -> bool:
    return str(finding.get("disposition") or "open") in CLEARED_DISPOSITIONS


def _int_policy(val: Any, default: int = 0) -> int:
    try:
        return int(val if val is not None else default)
    except (TypeError, ValueError):
        return default


def cve_self_policy(cve_cfg: Optional[dict] = None) -> Dict[str, Any]:
    cfg = cve_cfg if isinstance(cve_cfg, dict) else {}
    self_cfg = cfg.get("self") if isinstance(cfg.get("self"), dict) else {}
    return {
        "block_if_critical_gt": _int_policy(self_cfg.get("block_if_critical_gt"), 0),
        "block_if_high_gt": _int_policy(self_cfg.get("block_if_high_gt"), 0),
        "allow_accepted_risk": bool(self_cfg.get("allow_accepted_risk", False)),
        "allow_false_positive": bool(self_cfg.get("allow_false_positive", True)),
    }


def is_self_high_cve(item: dict) -> bool:
    cat = str(item.get("category") or "cve")
    if cat != "cve":
        return False
    if str(item.get("cve_scope") or "").lower() != "self":
        return False
    return str(item.get("severity") or "").lower() in {"critical", "high"}


def _cve_cleared_for_gate(item: dict, *, self_cfg: dict, ignore_unfixed: bool) -> bool:
    if ignore_unfixed and str(item.get("fix_state") or "").lower() in {"not-fixed", "wont-fix"}:
        return True
    disp = str(item.get("disposition") or "open")
    blocking_self = is_self_high_cve(item)
    if disp == "false_positive":
        if blocking_self and not self_cfg.get("allow_false_positive", True):
            return False
        return True
    if disp == "accepted_risk":
        if blocking_self and not self_cfg.get("allow_accepted_risk", False):
            return False
        return True
    return False


def evaluate_cve_gate(items: Sequence[dict], cve_cfg: Optional[dict] = None) -> Dict[str, Any]:
    """Count remaining CVE findings/matches and apply dep + self thresholds."""
    cfg = cve_cfg if isinstance(cve_cfg, dict) else {}
    if not bool(cfg.get("enabled", True)):
        return {"status": "pass", "reason": "cve disabled by policy", "open_critical": 0, "open_high": 0}
    self_cfg = cve_self_policy(cfg)
    ignore_unfixed = bool(cfg.get("ignore_unfixed", False))
    block_crit = _int_policy(cfg.get("block_if_critical_gt"), 0)
    block_high = _int_policy(cfg.get("block_if_high_gt"), 0)
    dep_crit = dep_high = 0
    self_crit = self_high = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        cat = str(item.get("category") or "cve")
        if cat != "cve":
            continue
        if _cve_cleared_for_gate(item, self_cfg=self_cfg, ignore_unfixed=ignore_unfixed):
            continue
        sev = str(item.get("severity") or "").lower()
        scope = str(item.get("cve_scope") or "dependency").lower()
        if scope == "self":
            if sev == "critical":
                self_crit += 1
            elif sev == "high":
                self_high += 1
        else:
            if sev == "critical":
                dep_crit += 1
            elif sev == "high":
                dep_high += 1
    reasons: List[str] = []
    if self_crit > self_cfg["block_if_critical_gt"]:
        reasons.append("本软件 CVE Critical %s > %s" % (self_crit, self_cfg["block_if_critical_gt"]))
    elif self_high > self_cfg["block_if_high_gt"]:
        reasons.append("本软件 CVE High %s > %s" % (self_high, self_cfg["block_if_high_gt"]))
    if dep_crit > block_crit:
        reasons.append("cve Critical %s > %s" % (dep_crit, block_crit))
    elif dep_high > block_high:
        reasons.append("cve High %s > %s" % (dep_high, block_high))
    if reasons and "本软件" in reasons[0]:
        reasons[0] = reasons[0] + "（接受风险不消除本软件高危；误报除外）"
    elif reasons:
        reasons[0] = reasons[0] + "（已排除误报/接受风险）"
    failed = bool(reasons)
    reason = reasons[0] if reasons else ""
    if len(reasons) > 1:
        reason = "；".join(reasons)
    return {
        "status": "fail" if failed else "pass",
        "reason": reason,
        "open_critical": dep_crit + self_crit,
        "open_high": dep_high + self_high,
        "open_self_critical": self_crit,
        "open_self_high": self_high,
        "open_dep_critical": dep_crit,
        "open_dep_high": dep_high,
    }


def _count_open(findings: Sequence[dict], *, category: str, severities: Iterable[str]) -> int:
    want = {str(s).lower() for s in severities}
    n = 0
    for item in findings:
        if str(item.get("category") or "") != category:
            continue
        if str(item.get("severity") or "").lower() not in want:
            continue
        if _is_cleared(item):
            continue
        n += 1
    return n


def _enum_gate(status: str) -> str:
    raw = str(status or "").lower()
    if raw == "fail":
        return GateStatus.Fail.value
    if raw in {"pending_legal", "pendinglegal"}:
        return GateStatus.PendingLegal.value
    if raw == "pass":
        return GateStatus.Pass.value
    return GateStatus.Unknown.value


def recalc_request_gate(request_id: str) -> Dict[str, Any]:
    requests = col("review_requests")
    req = requests.find_one({"request_id": request_id}, {"_id": 0})
    if not req:
        return {"ok": False, "error": "request not found"}

    scan_run_id = str(req.get("latest_scan_run_id") or "")
    q: Dict[str, Any] = {"request_id": request_id}
    if scan_run_id:
        q["scan_run_id"] = scan_run_id
    findings = list(col("findings").find(q, {"_id": 0}))
    apply_saved_dispositions(request_id, findings)

    policy = load_active_policy()
    raw = policy.raw if isinstance(policy.raw, dict) else {}
    tool_gate: Dict[str, Any] = {}
    fail_reasons: List[str] = []

    for name in SAST_CATEGORIES:
        cfg = raw.get(name) or {}
        if not bool(cfg.get("enabled", True)):
            continue
        try:
            block_high = int(cfg.get("block_if_high_gt") or 0)
        except (TypeError, ValueError):
            block_high = 0
        open_high = _count_open(findings, category=name, severities=HIGH_SEVERITIES)
        failed = open_high > block_high
        reason = "%s High %s > %s（已排除误报/接受风险）" % (name, open_high, block_high) if failed else ""
        tool_gate[name] = {"status": "fail" if failed else "pass", "reason": reason, "open_high": open_high}
        if failed:
            fail_reasons.append(reason)

    cpp_cfg = raw.get("cppcheck") or {}
    try:
        block_error = int(cpp_cfg.get("block_if_error_gt") or 0)
    except (TypeError, ValueError):
        block_error = 0
    open_error = _count_open(findings, category="cppcheck", severities=CPPCHECK_BLOCK_SEVERITIES)
    cpp_failed = open_error > block_error
    cpp_reason = "cppcheck error %s > %s（已排除误报/接受风险）" % (open_error, block_error) if cpp_failed else ""
    tool_gate["cppcheck"] = {"status": "fail" if cpp_failed else "pass", "reason": cpp_reason, "open_error": open_error}
    if cpp_failed:
        fail_reasons.append(cpp_reason)

    cve_cfg = raw.get("cve") or {}
    if bool(cve_cfg.get("enabled", True)):
        cve_gate = evaluate_cve_gate(findings, cve_cfg)
        tool_gate["cve"] = cve_gate
        if str(cve_gate.get("status") or "") == "fail" and cve_gate.get("reason"):
            fail_reasons.append(str(cve_gate.get("reason")))

    scan_run = col("scan_runs").find_one({"scan_run_id": scan_run_id}, {"_id": 0}) if scan_run_id else None
    summary = dict((scan_run or {}).get("summary") or {})
    existing_gate = dict(summary.get("gate") or {})
    prev_result = col("gate_results").find_one({"scan_run_id": scan_run_id}, {"_id": 0}) if scan_run_id else None
    if not existing_gate and prev_result:
        existing_gate = {
            "license": prev_result.get("license_gate") or {},
            "gosec": prev_result.get("gosec_gate") or {},
            "cppcheck": prev_result.get("cppcheck_gate") or {},
            "bandit": prev_result.get("bandit_gate") or {},
            "pmd": prev_result.get("pmd_gate") or {},
            "cargo_audit": prev_result.get("cargo_audit_gate") or {},
            "eslint": prev_result.get("eslint_gate") or {},
            "cve": prev_result.get("cve_gate") or {},
            "maintenance": prev_result.get("maintenance_gate") or {},
            "overall": prev_result.get("overall") or {},
        }
    license_gate = dict(existing_gate.get("license") or {})
    if not license_gate and prev_result:
        license_gate = dict(prev_result.get("license_gate") or {})
    license_status = str(license_gate.get("status") or "").lower()

    overall: Dict[str, Any]
    if fail_reasons:
        overall = {"status": "fail", "reason": fail_reasons[0], "adjusted_by": "finding_disposition"}
    elif license_status and license_status not in {"pass", "skipped", ""}:
        overall = {
            "status": "pending_legal",
            "reason": license_gate.get("reason") or "license gate not pass",
            "adjusted_by": "finding_disposition",
        }
    else:
        overall = {"status": "pass", "reason": "open blocking findings cleared", "adjusted_by": "finding_disposition"}

    merged_gate = dict(existing_gate)
    merged_gate.update(tool_gate)
    merged_gate["overall"] = overall
    if license_gate:
        merged_gate["license"] = license_gate

    enum_gate = _enum_gate(str(overall.get("status")))
    current_status = str(req.get("status") or "")
    required_roles = [str(r).strip() for r in (req.get("required_review_roles") or []) if str(r).strip()]
    mutable = {
        RequestStatus.Reviewing.value,
        RequestStatus.Blocked.value,
        RequestStatus.LegalReviewing.value,
        RequestStatus.ReReview.value,
    }
    new_status = current_status
    if current_status in mutable:
        if enum_gate == GateStatus.PendingLegal.value:
            new_status = RequestStatus.LegalReviewing.value
        elif enum_gate == GateStatus.Fail.value:
            # 有会签角色时与 hydrate 一致：门禁失败仍停在评审中，方便处理误报后通过
            new_status = RequestStatus.Reviewing.value if required_roles else RequestStatus.Blocked.value
        else:
            new_status = RequestStatus.Reviewing.value

    now = now_utc()
    req_patch: Dict[str, Any] = {"gate_status": enum_gate, "status": new_status}
    if enum_gate != str(req.get("gate_status") or "") or new_status != current_status:
        req_patch["updated_at"] = now
    requests.update_one(
        {"request_id": request_id},
        {"$set": req_patch},
    )
    if scan_run_id:
        summary["gate"] = merged_gate
        col("scan_runs").update_one(
            {"scan_run_id": scan_run_id},
            {"$set": {"gate_status": enum_gate, "summary": summary, "updated_at": now}},
        )
        col("gate_results").update_one(
            {"scan_run_id": scan_run_id},
            {
                "$set": {
                    "request_id": request_id,
                    "scan_run_id": scan_run_id,
                    "license_gate": merged_gate.get("license") or {},
                    "gosec_gate": merged_gate.get("gosec") or {},
                    "cppcheck_gate": merged_gate.get("cppcheck") or {},
                    "bandit_gate": merged_gate.get("bandit") or {},
                    "pmd_gate": merged_gate.get("pmd") or {},
                    "cargo_audit_gate": merged_gate.get("cargo_audit") or {},
                    "eslint_gate": merged_gate.get("eslint") or {},
                    "cve_gate": merged_gate.get("cve") or {},
                    "maintenance_gate": merged_gate.get("maintenance") or {},
                    "overall": overall,
                    "updated_at": now,
                }
            },
            upsert=True,
        )

    open_high_total = sum(int((tool_gate.get(n) or {}).get("open_high") or 0) for n in SAST_CATEGORIES)
    return {
        "ok": True,
        "gate_status": enum_gate,
        "status": new_status,
        "overall": overall,
        "open_high": open_high_total,
        "open_cppcheck_error": open_error,
        "tools": tool_gate,
    }


def upsert_dispositions(
    *,
    request_id: str,
    fingerprints: Sequence[str],
    disposition: str,
    reason: Optional[str],
    username: Optional[str],
    extra: Optional[Dict[str, Any]] = None,
) -> int:
    now = now_utc()
    n = 0
    for fp in fingerprints:
        key = str(fp or "").strip()
        if not key:
            continue
        doc = {
            "request_id": request_id,
            "fingerprint": key,
            "disposition": disposition,
            "reason": (reason or "").strip(),
            "updated_by": username,
            "updated_at": now,
        }
        if extra:
            doc.update(extra)
        col("finding_dispositions").update_one(
            {"request_id": request_id, "fingerprint": key},
            {"$set": doc},
            upsert=True,
        )
        col("findings").update_many(
            {"request_id": request_id, "fingerprint": key},
            {
                "$set": {
                    "disposition": disposition,
                    "disposition_reason": doc["reason"],
                    "disposition_by": username,
                    "disposition_at": now,
                }
            },
        )
        n += 1
    if n:
        col("review_requests").update_one(
            {"request_id": request_id},
            {"$set": {"updated_at": now}},
        )
    return n
