from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.auth import require_permissions
from app.db import col
from app.schemas import RequestStatus, now_utc, new_id


router = APIRouter()


class CreateRemediationIn(BaseModel):
    title: str = Field(min_length=1)
    severity: str = Field(default="medium")
    owner: Optional[str] = None
    due_at: Optional[datetime] = None
    finding_fingerprints: list = Field(default_factory=list)


@router.get("/requests/{request_id}/remediations")
def list_remediations(request_id: str):
    requests = col("review_requests")
    remediations = col("remediations")

    if not requests.find_one({"request_id": request_id}, {"_id": 1}):
        raise HTTPException(status_code=404, detail="request not found")
    cur = remediations.find({"request_id": request_id}, {"_id": 0}).sort("created_at", -1)
    return {"items": list(cur)}


@router.post("/requests/{request_id}/remediations")
def create_remediation(request_id: str, body: CreateRemediationIn, _user=Depends(require_permissions(["remediation.manage"]))):
    requests = col("review_requests")
    remediations = col("remediations")

    req = requests.find_one({"request_id": request_id}, {"_id": 0})
    if not req:
        raise HTTPException(status_code=404, detail="request not found")

    remediation_id = new_id()
    doc = {
        "remediation_id": remediation_id,
        "request_id": request_id,
        "title": body.title,
        "severity": body.severity,
        "owner": body.owner,
        "due_at": body.due_at,
        "finding_fingerprints": body.finding_fingerprints,
        "status": "open",
        "created_at": now_utc(),
        "updated_at": now_utc(),
    }
    remediations.insert_one(doc)

    # If request was conditionally approved, enter remediating state
    if req.get("status") == RequestStatus.ConditionalApproved.value:
        requests.update_one(
            {"request_id": request_id},
            {"$set": {"status": RequestStatus.Remediating.value, "updated_at": now_utc()}},
        )

    return {"remediation_id": remediation_id}


class UpdateRemediationIn(BaseModel):
    title: Optional[str] = None
    severity: Optional[str] = None
    owner: Optional[str] = None
    due_at: Optional[datetime] = None
    finding_fingerprints: Optional[list] = None


@router.patch("/remediations/{remediation_id}")
def update_remediation(remediation_id: str, body: UpdateRemediationIn, _user=Depends(require_permissions(["remediation.manage"]))):
    remediations = col("remediations")
    r = remediations.find_one({"remediation_id": remediation_id}, {"_id": 0})
    if not r:
        raise HTTPException(status_code=404, detail="remediation not found")
    patch = {k: v for k, v in body.dict(exclude_unset=True).items()}
    if not patch:
        raise HTTPException(status_code=400, detail="no fields to update")
    patch["updated_at"] = now_utc()
    remediations.update_one({"remediation_id": remediation_id}, {"$set": patch})
    return remediations.find_one({"remediation_id": remediation_id}, {"_id": 0})


@router.post("/remediations/{remediation_id}/close")
def close_remediation(remediation_id: str, _user=Depends(require_permissions(["remediation.manage"]))):
    remediations = col("remediations")
    requests = col("review_requests")

    r = remediations.find_one({"remediation_id": remediation_id}, {"_id": 0})
    if not r:
        raise HTTPException(status_code=404, detail="remediation not found")
    if r.get("status") == "closed":
        return {"ok": True}

    remediations.update_one(
        {"remediation_id": remediation_id},
        {"$set": {"status": "closed", "updated_at": now_utc(), "closed_at": now_utc()}},
    )

    # If all remediations closed, move request to ReReview
    open_count = remediations.count_documents({"request_id": r["request_id"], "status": "open"})
    if open_count == 0:
        requests.update_one(
            {"request_id": r["request_id"]},
            {"$set": {"status": RequestStatus.ReReview.value, "updated_at": now_utc()}},
        )

    return {"ok": True}

