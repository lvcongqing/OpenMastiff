from __future__ import annotations

from typing import Optional


_RANK = {"pass": 0, "unknown": 1, "pending_legal": 2, "fail": 3}


def merge_gate_status(*statuses: Optional[str]) -> str:
    best = "pass"
    for s in statuses:
        if not s:
            continue
        key = str(s).lower()
        if _RANK.get(key, 1) > _RANK.get(best, 0):
            best = key
    return best


def gate_status_to_enum_value(status: str) -> str:
    s = (status or "").lower()
    if s == "pass":
        return "Pass"
    if s == "fail":
        return "Fail"
    if s == "pending_legal":
        return "PendingLegal"
    return "Unknown"
