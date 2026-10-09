from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from app.audit import append_audit_event
from app.auth import role_permissions
from app.db import col
from app.finding_disposition import (
    VALID_DISPOSITIONS,
    apply_saved_dispositions,
    cve_self_policy,
    is_self_high_cve,
    recalc_request_gate,
    upsert_dispositions,
)
from app.policy import load_active_policy
from app.schemas import FindingDispositionIn


router = APIRouter()


def _can_dispose(user: dict, req: dict) -> bool:
    roles = user.get("roles") if isinstance(user.get("roles"), list) else [str(user.get("role") or "")]
    roles = [str(r).strip() for r in roles if str(r).strip()]
    perms = set()
    for r in roles:
        perms.update(role_permissions(str(r)))
    if perms.intersection({"review.manage", "request.manage", "remediation.manage"}):
        return True
    required = [str(r).strip() for r in (req.get("required_review_roles") or []) if str(r).strip()]
    return any(r in required for r in roles)


@router.get("/requests/{request_id}/findings")
def list_findings(request_id: str, scan_run_id: str = "", category: str = ""):
    requests = col("review_requests")
    req = requests.find_one({"request_id": request_id}, {"_id": 0, "latest_scan_run_id": 1})
    if not req:
        raise HTTPException(status_code=404, detail="request not found")

    q = {"request_id": request_id}
    # 默认仅返回最近一次扫描的 findings，避免复测后重复累积
    effective_scan_run_id = scan_run_id or (req.get("latest_scan_run_id") or "")
    if effective_scan_run_id:
        q["scan_run_id"] = effective_scan_run_id
    if category:
        q["category"] = category

    items = list(col("findings").find(q, {"_id": 0}).sort("created_at", -1))
    apply_saved_dispositions(request_id, items)
    return {"items": items}


@router.post("/requests/{request_id}/findings/disposition")
def dispose_findings(request_id: str, body: FindingDispositionIn, request: Request):
    user = getattr(request.state, "user", None) or {}
    if not user:
        raise HTTPException(status_code=401, detail="unauthorized")

    req = col("review_requests").find_one({"request_id": request_id}, {"_id": 0})
    if not req:
        raise HTTPException(status_code=404, detail="request not found")
    if not _can_dispose(user, req):
        raise HTTPException(status_code=403, detail="没有处理发现项的权限")

    disposition = str(body.disposition or "").strip()
    if disposition not in VALID_DISPOSITIONS:
        raise HTTPException(status_code=400, detail="无效的处置结论")
    reason = str(body.reason or "").strip()
    if disposition in {"false_positive", "accepted_risk"} and not reason:
        raise HTTPException(status_code=400, detail="误报或接受风险须填写处理说明，便于审计回溯。")

    q = {"request_id": request_id}
    scan_run_id = str(req.get("latest_scan_run_id") or "")
    if scan_run_id:
        q["scan_run_id"] = scan_run_id
    fps = [str(x).strip() for x in (body.fingerprints or []) if str(x).strip()]
    if fps:
        q["fingerprint"] = {"$in": fps}
    elif body.rule_id:
        q["rule_id"] = str(body.rule_id).strip()
        if body.category:
            q["category"] = str(body.category).strip()
    else:
        raise HTTPException(status_code=400, detail="请选择发现项，或按规则批量处理。")

    matched = list(
        col("findings").find(
            q,
            {"_id": 0, "fingerprint": 1, "rule_id": 1, "category": 1, "cve_scope": 1, "severity": 1},
        )
    )
    fingerprints = sorted({str(x.get("fingerprint")) for x in matched if x.get("fingerprint")})
    if not fingerprints:
        raise HTTPException(status_code=400, detail="没有匹配到可处理的发现项。")

    if disposition == "accepted_risk":
        self_cfg = cve_self_policy((load_active_policy().raw or {}).get("cve") or {})
        if not self_cfg.get("allow_accepted_risk", False) and any(is_self_high_cve(x) for x in matched):
            raise HTTPException(
                status_code=400,
                detail="本软件 Critical/High CVE 不允许「接受风险」。请标误报（仅限匹配错误），或走整单豁免。",
            )
    if disposition == "false_positive":
        self_cfg = cve_self_policy((load_active_policy().raw or {}).get("cve") or {})
        if not self_cfg.get("allow_false_positive", True) and any(is_self_high_cve(x) for x in matched):
            raise HTTPException(status_code=400, detail="策略禁止将本软件 Critical/High CVE 标为误报。")

    updated = upsert_dispositions(
        request_id=request_id,
        fingerprints=fingerprints,
        disposition=disposition,
        reason=reason,
        username=user.get("username"),
        extra={"rule_id": body.rule_id, "category": body.category},
    )
    gate = recalc_request_gate(request_id)
    append_audit_event(
        request_id=request_id,
        event_type="FINDINGS_DISPOSITION",
        payload={
            "disposition": disposition,
            "count": updated,
            "rule_id": body.rule_id,
            "reason": reason,
            "gate_status": gate.get("gate_status"),
            "by": user.get("username"),
        },
    )
    return {
        "ok": True,
        "updated": updated,
        "disposition": disposition,
        "gate_status": gate.get("gate_status"),
        "status": gate.get("status"),
        "open_high": gate.get("open_high"),
        "open_cppcheck_error": gate.get("open_cppcheck_error"),
        "overall": gate.get("overall") or {},
    }
