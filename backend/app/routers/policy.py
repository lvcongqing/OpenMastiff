from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.auth import require_permissions
from app.audit import append_audit_event
from app.policy import DEFAULT_POLICY, load_active_policy, upsert_active_policy


router = APIRouter()


class PolicyOut(BaseModel):
    sha256: str
    raw: dict


class PolicyIn(BaseModel):
    raw: dict


@router.get("/policy", response_model=PolicyOut)
def get_policy():
    p = load_active_policy()
    return PolicyOut(sha256=p.sha256(), raw=p.raw)


@router.put("/policy", response_model=PolicyOut)
def put_policy(body: PolicyIn, _user=Depends(require_permissions(["policy.manage"]))):
    p = upsert_active_policy(body.raw)
    # request_id is not applicable here; we log under a synthetic bucket for now
    append_audit_event(request_id="__policy__", event_type="POLICY_UPDATED", payload={"sha256": p.sha256()})
    return PolicyOut(sha256=p.sha256(), raw=p.raw)

