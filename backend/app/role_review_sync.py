from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.db import col
from app.schemas import GateStatus, LegalReviewStatus, RequestStatus, now_utc

LEGAL_ROLE = "legal"


def _latest_legal_review(legal_items: List[dict]) -> Optional[dict]:
    if not legal_items:
        return None
    return sorted(
        legal_items,
        key=lambda x: str(x.get("updated_at") or x.get("created_at") or ""),
        reverse=True,
    )[0]


def _latest_decided_legal(legal_items: List[dict]) -> Optional[dict]:
    for lr in sorted(
        legal_items,
        key=lambda x: str(x.get("updated_at") or x.get("created_at") or ""),
        reverse=True,
    ):
        if lr.get("status") in {LegalReviewStatus.Allowed.value, LegalReviewStatus.Denied.value}:
            return lr
    return None


def legal_review_to_role_entry(lr: dict) -> dict:
    status = lr.get("status")
    if status == LegalReviewStatus.Allowed.value:
        return {
            "status": "Approved",
            "decision": "Allowed",
            "comment": lr.get("rationale"),
            "updated_by": lr.get("decided_by"),
            "updated_at": lr.get("updated_at") or lr.get("created_at"),
            "source": "legal_review",
        }
    if status == LegalReviewStatus.Denied.value:
        return {
            "status": "Rejected",
            "decision": "Denied",
            "comment": lr.get("rationale"),
            "updated_by": lr.get("decided_by"),
            "updated_at": lr.get("updated_at") or lr.get("created_at"),
            "source": "legal_review",
        }
    return {
        "status": "Pending",
        "decision": None,
        "comment": None,
        "updated_by": None,
        "updated_at": lr.get("updated_at") or lr.get("created_at"),
        "source": "legal_review",
    }


def merge_role_reviews(req: dict, legal_items: Optional[List[dict]] = None) -> dict:
    """
    将 legal_reviews 裁决合并进 role_reviews（用于展示与待办判断）。
    法务门禁复核与「legal」会签角色共用同一进度。
    """
    role_reviews = dict(req.get("role_reviews") or {})
    required = [str(r).strip() for r in (req.get("required_review_roles") or []) if str(r).strip()]
    gate = str(req.get("gate_status") or "")
    needs_legal_track = LEGAL_ROLE in required or gate == GateStatus.PendingLegal.value

    if legal_items is None:
        legal_items = list(
            col("legal_reviews").find({"request_id": req.get("request_id")}, {"_id": 0})
        )

    decided = _latest_decided_legal(legal_items)
    latest = _latest_legal_review(legal_items)

    if decided:
        role_reviews[LEGAL_ROLE] = legal_review_to_role_entry(decided)
    elif latest and latest.get("status") == LegalReviewStatus.Pending.value and needs_legal_track:
        role_reviews[LEGAL_ROLE] = legal_review_to_role_entry(latest)
    elif needs_legal_track and LEGAL_ROLE not in role_reviews:
        role_reviews[LEGAL_ROLE] = {
            "status": "Pending",
            "decision": None,
            "comment": None,
            "updated_by": None,
            "updated_at": None,
            "source": "legal_review",
        }

    return role_reviews


def effective_gate_status(req: dict, legal_items: Optional[List[dict]] = None) -> str:
    """
    扫描写入的 gate_status 在法务允许后应视为已通过（用于流程展示与审批）。
    原始扫描结论保留在 scan_run / pre_legal_gate_status 中备查。
    """
    gate = str(req.get("gate_status") or GateStatus.Unknown.value)
    if legal_items is None and req.get("request_id"):
        legal_items = fetch_legal_reviews(req["request_id"])
    decided = _latest_decided_legal(legal_items or [])

    if gate == GateStatus.PendingLegal.value and decided:
        if decided.get("status") == LegalReviewStatus.Allowed.value:
            return GateStatus.Pass.value
        if decided.get("status") == LegalReviewStatus.Denied.value:
            return GateStatus.Fail.value
    return gate


def is_role_review_pending(role: str, role_reviews: dict) -> bool:
    entry = role_reviews.get(role) or {}
    st = str(entry.get("status") or "Pending")
    if st == "Approved":
        return False
    if st == "Rejected":
        return False
    if entry.get("decision") in {"Allowed", "Approved"}:
        return False
    if entry.get("decision") in {"Denied", "Rejected"}:
        return False
    return True


_PRESERVE_STATUSES = {
    RequestStatus.Draft.value,
    RequestStatus.Submitted.value,
    RequestStatus.Scanning.value,
    RequestStatus.Approved.value,
    RequestStatus.ConditionalApproved.value,
    RequestStatus.Remediating.value,
    RequestStatus.Rejected.value,
    RequestStatus.Waived.value,
}


def compute_request_status(req: dict, role_reviews: dict, legal_items: Optional[List[dict]] = None) -> str:
    required = [str(r).strip() for r in (req.get("required_review_roles") or []) if str(r).strip()]
    gate = effective_gate_status(req, legal_items)
    current = str(req.get("status") or "")

    if required:
        if any(str((role_reviews.get(r) or {}).get("status")) == "Rejected" for r in required):
            return RequestStatus.Rejected.value
        if any((role_reviews.get(r) or {}).get("decision") == "Denied" for r in required):
            return RequestStatus.Blocked.value
        if current in _PRESERVE_STATUSES:
            return current
        if all(not is_role_review_pending(r, role_reviews) for r in required):
            if all(str((role_reviews.get(r) or {}).get("status")) == "Approved" or (role_reviews.get(r) or {}).get("decision") == "Allowed" for r in required):
                return RequestStatus.Approved.value
        raw_gate = str(req.get("gate_status") or "")
        pending_legal = raw_gate == GateStatus.PendingLegal.value and is_role_review_pending(LEGAL_ROLE, role_reviews)
        if pending_legal:
            return RequestStatus.LegalReviewing.value
        return RequestStatus.Reviewing.value

    if current in _PRESERVE_STATUSES:
        return current
    raw_gate = str(req.get("gate_status") or "")
    if raw_gate == GateStatus.PendingLegal.value and is_role_review_pending(LEGAL_ROLE, role_reviews):
        return RequestStatus.LegalReviewing.value
    if gate == GateStatus.Fail.value:
        return RequestStatus.Blocked.value
    return str(req.get("status") or RequestStatus.Reviewing.value)


def _dt_key(val: Any) -> str:
    if val is None:
        return ""
    if hasattr(val, "isoformat"):
        try:
            return str(val.isoformat())
        except Exception:
            return str(val)
    return str(val)


def _reviews_signature(role_reviews: dict) -> dict:
    """Compare review outcomes, ignoring datetime object vs ISO string noise."""
    sig: Dict[str, Any] = {}
    for role, entry in (role_reviews or {}).items():
        e = entry if isinstance(entry, dict) else {}
        sig[str(role)] = {
            "status": str(e.get("status") or "Pending"),
            "decision": e.get("decision"),
            "comment": e.get("comment"),
            "updated_by": e.get("updated_by"),
            "updated_at": _dt_key(e.get("updated_at")),
        }
    return sig


def hydrate_request_review_state(req: dict, *, persist: bool = False) -> dict:
    if not req or not req.get("request_id"):
        return req

    legal_items = list(col("legal_reviews").find({"request_id": req["request_id"]}, {"_id": 0}))
    merged = merge_role_reviews(req, legal_items)
    eff_gate = effective_gate_status(req, legal_items)
    out = dict(req)
    out["role_reviews"] = merged
    out["effective_gate_status"] = eff_gate
    out["scanner_gate_status"] = req.get("scanner_gate_status") or req.get("gate_status")

    new_status = compute_request_status(req, merged, legal_items)
    out["status"] = new_status

    if persist:
        patch: Dict[str, Any] = {
            "role_reviews": merged,
            "status": new_status,
            "effective_gate_status": eff_gate,
        }
        raw_gate = str(req.get("gate_status") or "")
        if raw_gate == GateStatus.PendingLegal.value and eff_gate == GateStatus.Pass.value:
            patch["gate_status"] = GateStatus.Pass.value
            patch["scanner_gate_status"] = GateStatus.PendingLegal.value
            patch["legal_gate_cleared_at"] = now_utc()
        elif raw_gate == GateStatus.PendingLegal.value and eff_gate == GateStatus.Fail.value:
            patch["gate_status"] = GateStatus.Fail.value
            patch["scanner_gate_status"] = GateStatus.PendingLegal.value

        reviews_changed = _reviews_signature(merged) != _reviews_signature(req.get("role_reviews") or {})
        status_changed = new_status != req.get("status")
        gate_changed = "gate_status" in patch and patch.get("gate_status") != req.get("gate_status")
        derived_changed = (
            reviews_changed
            or status_changed
            or gate_changed
            or eff_gate != req.get("effective_gate_status")
        )
        # 打开列表/详情会 hydrate；更新时间只反映编辑、扫描或评审结论变化，不因只读刷新跳动。
        if status_changed or gate_changed or reviews_changed:
            patch["updated_at"] = now_utc()
        if derived_changed:
            col("review_requests").update_one(
                {"request_id": req["request_id"]},
                {"$set": patch},
            )
            out.update(patch)
    return out


def fetch_legal_reviews(request_id: str) -> List[dict]:
    return list(col("legal_reviews").find({"request_id": request_id}, {"_id": 0}).sort("created_at", -1))
