from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple


_GATE_RANK = {"pass": 0, "unknown": 1, "pending_legal": 2, "fail": 3}


def _max_gate(a: str, b: str) -> str:
    ra = _GATE_RANK.get(a, 1)
    rb = _GATE_RANK.get(b, 1)
    return a if ra >= rb else b


def _without_legal(status: str) -> str:
    """维护性门禁不走法务：历史 pending_legal 视为不通过。"""
    s = str(status or "pass").lower()
    if s == "pending_legal":
        return "fail"
    return s


def _unknown_gate(rules: Dict[str, Any]) -> str:
    return _without_legal(str(rules.get("unknown_gate") or "pass"))


def _apply_rules(
    scored: Dict[str, Any],
    rules: Dict[str, Any],
    *,
    advisory_only: bool = False,
) -> Tuple[str, str]:
    status = str(scored.get("status") or "unknown")
    if status == "unknown":
        ug = _unknown_gate(rules)
        detail = str(scored.get("error") or "metadata unavailable")
        if ug == "pass":
            return ug, f"skipped: {detail}"
        return ug, detail

    archived = scored.get("archived")
    last_commit = scored.get("last_commit_days")
    last_release = scored.get("last_release_days")
    score = scored.get("score")

    gate = "pass"
    reasons: List[str] = []

    if rules.get("fail_if_archived") and archived is True:
        gate = "fail"
        reasons.append("repository archived")

    if rules.get("fail_if_last_commit_days_gt") is not None and isinstance(last_commit, int):
        if last_commit > int(rules["fail_if_last_commit_days_gt"]):
            gate = "fail"
            reasons.append(f"last commit {last_commit}d ago")

    if rules.get("fail_if_last_release_days_gt") is not None and isinstance(last_release, int):
        if last_release > int(rules["fail_if_last_release_days_gt"]):
            gate = _max_gate(gate, "fail")
            reasons.append(f"last release {last_release}d ago")

    if rules.get("pending_legal_if_last_release_days_gt") is not None and isinstance(last_release, int):
        if last_release > int(rules["pending_legal_if_last_release_days_gt"]):
            gate = "fail"
            reasons.append(f"stale release {last_release}d")

    if rules.get("fail_if_score_lt") is not None and isinstance(score, int):
        if score < int(rules["fail_if_score_lt"]):
            gate = _max_gate(gate, "fail")
            reasons.append(f"score {score} below threshold")

    if advisory_only and gate in {"fail", "pending_legal"}:
        return "pass", "advisory: " + "; ".join(reasons) if reasons else "advisory only"

    downgrade = rules.get("fail_downgrade_to")
    if downgrade and gate == "fail" and str(downgrade).lower() not in {"pending_legal", "pendinglegal"}:
        gate = str(downgrade)

    gate = _without_legal(gate)
    if not reasons:
        return gate, "within maintenance thresholds"
    return gate, "; ".join(reasons)


def evaluate_upstream_gate(scored: Dict[str, Any], criticality: str, maintenance_policy: Dict[str, Any]) -> Dict[str, str]:
    rules_map = (maintenance_policy or {}).get("rules_by_criticality") or {}
    rules = dict(rules_map.get(criticality) or rules_map.get("medium") or {})
    advisory = bool(rules.get("advisory_only"))
    status, reason = _apply_rules(scored, rules, advisory_only=advisory)
    return {"status": _without_legal(status), "reason": reason}


def evaluate_dependency_gate(
    scored: Dict[str, Any],
    criticality: str,
    maintenance_policy: Dict[str, Any],
) -> Dict[str, str]:
    rules_map = (maintenance_policy or {}).get("rules_by_criticality") or {}
    crit_rules = dict(rules_map.get(criticality) or rules_map.get("medium") or {})
    dep_rules = dict((maintenance_policy or {}).get("dependency_thresholds") or {})

    if crit_rules.get("advisory_only"):
        status, reason = _apply_rules(scored, crit_rules, advisory_only=True)
    else:
        merged = {**crit_rules, **dep_rules}
        merged.pop("advisory_only", None)
        merged.pop("fail_downgrade_to", None)
        status, reason = _apply_rules(scored, merged, advisory_only=False)
        downgrade = crit_rules.get("fail_downgrade_to")
        if downgrade and status == "fail" and str(downgrade).lower() not in {"pending_legal", "pendinglegal"}:
            status = str(downgrade)
    return {"status": _without_legal(status), "reason": reason}


def aggregate_maintenance_gate(parts: List[str]) -> Dict[str, str]:
    overall = "pass"
    reasons: List[str] = []
    for p in parts:
        overall = _max_gate(overall, _without_legal(p))
    if overall == "fail":
        reasons.append("one or more maintenance checks failed")
    return {"status": overall, "reason": "; ".join(reasons) if reasons else "maintenance checks passed"}
