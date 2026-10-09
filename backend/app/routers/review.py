from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile

from app import blob_store
from app.auth import require_permissions, role_permissions
from app.audit import append_audit_event
from app.db import col
from app.settings import settings
from app.role_review_sync import (
    LEGAL_ROLE,
    effective_gate_status,
    hydrate_request_review_state,
    is_role_review_pending,
)
from app.schemas import (
    DecisionIn,
    DecisionType,
    GateStatus,
    LegalDecisionIn,
    LegalReviewStatus,
    RequestStatus,
    CreateLegalReviewOut,
    new_id,
    now_utc,
)


router = APIRouter()


@router.get("/review/inbox")
def review_inbox(request: Request, limit: int = 50, offset: int = 0):
    """待办：评审中 / 门禁失败 / 法务复核中。"""
    if limit < 1 or limit > 200:
        raise HTTPException(status_code=400, detail="invalid limit")
    if offset < 0:
        raise HTTPException(status_code=400, detail="invalid offset")

    me = getattr(request.state, "user", None) or {}
    my_roles = me.get("roles") if isinstance(me.get("roles"), list) else [str(me.get("role") or "")]
    my_roles = [str(r).strip() for r in my_roles if str(r).strip()]
    requests = col("review_requests")
    q = {
        "status": {
            "$in": [
                RequestStatus.Reviewing.value,
                RequestStatus.Blocked.value,
                RequestStatus.LegalReviewing.value,
            ]
        }
    }
    cur = requests.find(q, {"_id": 0}).sort("updated_at", -1).skip(offset).limit(limit)
    items = []
    for x in cur:
        hydrated = hydrate_request_review_state(x, persist=False)
        required = [str(r).strip() for r in (hydrated.get("required_review_roles") or []) if str(r).strip()]
        if required:
            role_reviews = hydrated.get("role_reviews") or {}
            mine_pending = False
            for r in my_roles:
                if r in required and is_role_review_pending(r, role_reviews):
                    mine_pending = True
                    break
            if not mine_pending:
                continue
        items.append(hydrated)
    total = requests.count_documents(q)
    return {"total": total, "items": items}


@router.get("/requests/{request_id}/legal-reviews")
def list_legal_reviews(request_id: str):
    requests = col("review_requests")
    legal_reviews = col("legal_reviews")
    if not requests.find_one({"request_id": request_id}, {"_id": 1}):
        raise HTTPException(status_code=404, detail="request not found")
    cur = legal_reviews.find({"request_id": request_id}, {"_id": 0}).sort("created_at", -1)
    return {"items": list(cur)}


@router.post("/requests/{request_id}/legal-reviews", response_model=CreateLegalReviewOut)
def create_legal_review(request_id: str, _user=Depends(require_permissions(["review.manage"]))):
    requests = col("review_requests")
    legal_reviews = col("legal_reviews")

    req = requests.find_one({"request_id": request_id}, {"_id": 0})
    if not req:
        raise HTTPException(status_code=404, detail="request not found")

    existing = legal_reviews.find_one({"request_id": request_id, "status": LegalReviewStatus.Pending.value}, {"_id": 0})
    if existing:
        return CreateLegalReviewOut(
            legal_review_id=existing["legal_review_id"],
            request_id=request_id,
            status=LegalReviewStatus.Pending,
            created_at=existing["created_at"],
        )

    legal_review_id = new_id()
    doc = {
        "legal_review_id": legal_review_id,
        "request_id": request_id,
        "status": LegalReviewStatus.Pending.value,
        "created_at": now_utc(),
        "updated_at": now_utc(),
    }
    legal_reviews.insert_one(doc)
    # Move request into legal reviewing if not already
    requests.update_one(
        {"request_id": request_id},
        {"$set": {"status": RequestStatus.LegalReviewing.value, "updated_at": now_utc()}},
    )
    append_audit_event(request_id=request_id, event_type="LEGAL_REVIEW_REQUESTED", payload={"legal_review_id": legal_review_id})
    return CreateLegalReviewOut(legal_review_id=legal_review_id, request_id=request_id, status=LegalReviewStatus.Pending, created_at=doc["created_at"])


@router.post("/legal-reviews/{legal_review_id}/decision")
def decide_legal_review(
    legal_review_id: str,
    body: LegalDecisionIn,
    request: Request,
    _user=Depends(require_permissions(["legal.decide"])),
):
    legal_reviews = col("legal_reviews")
    requests = col("review_requests")

    lr = legal_reviews.find_one({"legal_review_id": legal_review_id}, {"_id": 0})
    if not lr:
        raise HTTPException(status_code=404, detail="legal review not found")
    if lr["status"] != LegalReviewStatus.Pending.value:
        raise HTTPException(status_code=400, detail="legal review not pending")

    current_user = getattr(request.state, "user", None) or {}
    username = current_user.get("username")

    new_status = LegalReviewStatus.Allowed.value if body.decision == "Allowed" else LegalReviewStatus.Denied.value
    legal_reviews.update_one(
        {"legal_review_id": legal_review_id},
        {
            "$set": {
                "status": new_status,
                "decision": body.decision,
                "rationale": body.rationale,
                "updated_at": now_utc(),
                "decided_by": username,
            }
        },
    )
    append_audit_event(request_id=lr["request_id"], event_type="LEGAL_REVIEW_DECIDED", payload={"legal_review_id": legal_review_id, "decision": body.decision})

    req = requests.find_one({"request_id": lr["request_id"]}, {"_id": 0})
    if not req:
        return {"ok": True}

    hydrated = hydrate_request_review_state(req, persist=True)

    return {
        "ok": True,
        "status": hydrated.get("status"),
        "role_reviews": hydrated.get("role_reviews") or {},
    }


@router.post("/legal-reviews/{legal_review_id}/attachment")
def upload_legal_attachment(
    legal_review_id: str,
    artifact_file: UploadFile = File(...),
    _user=Depends(require_permissions(["legal.decide"])),
):
    legal_reviews = col("legal_reviews")
    lr = legal_reviews.find_one({"legal_review_id": legal_review_id})
    if not lr:
        raise HTTPException(status_code=404, detail="legal review not found")
    import tempfile

    with tempfile.NamedTemporaryFile(delete=False) as f:
        tmp = f.name
        while True:
            chunk = artifact_file.file.read(1024 * 1024)
            if not chunk:
                break
            f.write(chunk)
    ref = blob_store.put_file(settings.blob_root, tmp)
    att = {
        "sha256": ref.sha256,
        "path": ref.path,
        "bytes": ref.bytes,
        "filename": artifact_file.filename or "attachment",
    }
    legal_reviews.update_one({"legal_review_id": legal_review_id}, {"$push": {"attachments": att}, "$set": {"updated_at": now_utc()}})
    append_audit_event(request_id=lr["request_id"], event_type="LEGAL_ATTACHMENT_UPLOADED", payload={"legal_review_id": legal_review_id, "sha256": ref.sha256})
    return {"ok": True, "attachment": att}


def _actor_permissions(user: dict) -> set:
    roles = user.get("roles") if isinstance(user.get("roles"), list) else [str(user.get("role") or "")]
    perms = set()
    for r in roles:
        perms.update(role_permissions(str(r)))
    return perms


@router.post("/requests/{request_id}/decision")
def decide_request(request_id: str, body: DecisionIn, request: Request):
    requests = col("review_requests")
    legal_reviews = col("legal_reviews")

    req = requests.find_one({"request_id": request_id}, {"_id": 0})
    if not req:
        raise HTTPException(status_code=404, detail="request not found")

    current_user = getattr(request.state, "user", None) or {}
    if not current_user:
        raise HTTPException(status_code=401, detail="unauthorized")
    actor_roles = current_user.get("roles") if isinstance(current_user.get("roles"), list) else [str(current_user.get("role") or "")]
    actor_roles = [str(r).strip() for r in actor_roles if str(r).strip()]
    required_roles = [str(r).strip() for r in (req.get("required_review_roles") or []) if str(r).strip()]
    perms = _actor_permissions(current_user)
    can_manage = "review.manage" in perms or "request.manage" in perms
    if not can_manage and not any(r in required_roles for r in actor_roles):
        raise HTTPException(status_code=403, detail="没有录入评审结论的权限")

    gate = effective_gate_status(req)
    if body.decision in {DecisionType.Approved, DecisionType.ConditionalApproved}:
        if gate == GateStatus.Fail.value:
            raise HTTPException(
                status_code=400,
                detail="扫描门禁失败，不能「通过」或「有条件通过」。请先在「发现项」中批量处理误报并重算门禁，或选择「豁免」。",
            )
        if gate == GateStatus.PendingLegal.value:
            lr = legal_reviews.find_one({"request_id": request_id}, {"_id": 0, "status": 1})
            if not lr or lr.get("status") != LegalReviewStatus.Allowed.value:
                raise HTTPException(status_code=400, detail="许可证待法务复核通过后才能批准。")

    if body.decision == DecisionType.Waived:
        acceptor = str(body.risk_acceptor or "").strip()
        controls = str(body.compensating_controls or "").strip()
        if not (acceptor and controls and body.expires_at):
            raise HTTPException(status_code=400, detail="豁免须填写风险接受人、补偿措施和到期时间。")
        body.risk_acceptor = acceptor
        body.compensating_controls = controls

    if body.decision == DecisionType.ConditionalApproved:
        n = col("remediations").count_documents({"request_id": request_id, "status": "open"})
        if n < 1:
            raise HTTPException(status_code=400, detail="有条件通过至少需要一条未关闭的整改项。")

    target_role = str(body.review_role or "").strip()
    if required_roles:
        if not target_role:
            inter = [r for r in actor_roles if r in required_roles]
            if not inter:
                if can_manage:
                    target_role = required_roles[0]
                else:
                    raise HTTPException(status_code=403, detail="你没有本单要求的审核角色。")
            else:
                target_role = inter[0]
        if target_role not in required_roles:
            raise HTTPException(status_code=400, detail="所选角色不在本单的必审角色中。")
        if target_role not in actor_roles and not can_manage:
            raise HTTPException(status_code=403, detail="你不能以该角色录入结论。")

    # Write decision snapshot into request
    decision_doc = {
        "decision": body.decision.value,
        "comment": body.comment,
        "at": now_utc(),
    }
    if body.decision == DecisionType.Waived:
        decision_doc.update(
            {
                "risk_acceptor": body.risk_acceptor,
                "compensating_controls": body.compensating_controls,
                "expires_at": body.expires_at,
            }
        )

    role_reviews = dict(req.get("role_reviews") or {})
    if required_roles and target_role:
        role_reviews[target_role] = {
            "status": "Rejected" if body.decision == DecisionType.Rejected else "Approved",
            "decision": body.decision.value,
            "comment": body.comment,
            "updated_by": current_user.get("username"),
            "updated_at": now_utc().isoformat(),
            "source": "role_decision",
        }
        # 法务角色会签：同步写入 legal_reviews 记录
        if target_role == LEGAL_ROLE:
            legal_reviews = col("legal_reviews")
            lr_decision = "Allowed" if body.decision != DecisionType.Rejected else "Denied"
            pending = legal_reviews.find_one(
                {"request_id": request_id, "status": LegalReviewStatus.Pending.value},
                {"_id": 0},
            )
            if pending:
                legal_reviews.update_one(
                    {"legal_review_id": pending["legal_review_id"]},
                    {
                        "$set": {
                            "status": LegalReviewStatus.Allowed.value
                            if lr_decision == "Allowed"
                            else LegalReviewStatus.Denied.value,
                            "decision": lr_decision,
                            "rationale": body.comment or "",
                            "updated_at": now_utc(),
                            "decided_by": current_user.get("username"),
                        }
                    },
                )
            else:
                legal_reviews.insert_one(
                    {
                        "legal_review_id": new_id(),
                        "request_id": request_id,
                        "status": LegalReviewStatus.Allowed.value
                        if lr_decision == "Allowed"
                        else LegalReviewStatus.Denied.value,
                        "decision": lr_decision,
                        "rationale": body.comment or "",
                        "created_at": now_utc(),
                        "updated_at": now_utc(),
                        "decided_by": current_user.get("username"),
                    }
                )

    patch = {"decision": decision_doc, "role_reviews": role_reviews, "updated_at": now_utc()}
    if body.decision == DecisionType.ConditionalApproved:
        patch["status"] = RequestStatus.ConditionalApproved.value
    elif body.decision == DecisionType.Waived:
        patch["status"] = RequestStatus.Waived.value
    elif body.decision == DecisionType.Rejected:
        patch["status"] = RequestStatus.Rejected.value

    requests.update_one({"request_id": request_id}, {"$set": patch})

    updated = requests.find_one({"request_id": request_id}, {"_id": 0}) or req
    hydrated = hydrate_request_review_state(updated, persist=True)
    new_status = hydrated.get("status")
    if body.decision in {DecisionType.ConditionalApproved, DecisionType.Waived, DecisionType.Rejected}:
        new_status = patch.get("status", new_status)

    requests.update_one(
        {"request_id": request_id},
        {"$set": {"status": new_status, "role_reviews": hydrated.get("role_reviews") or {}, "updated_at": now_utc()}},
    )
    append_audit_event(
        request_id=request_id,
        event_type="DECISION_MADE",
        payload={"decision": body.decision.value, "review_role": target_role or None, "by": current_user.get("username")},
    )

    return {"ok": True, "status": new_status}

