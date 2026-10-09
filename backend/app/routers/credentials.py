from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, root_validator
from typing_extensions import Literal

from app.auth import require_permissions, role_permissions
from app.audit import append_audit_event
from app.db import col
from app.schemas import new_id, now_utc

router = APIRouter()


class CreateCredentialIn(BaseModel):
    name: str = Field(min_length=1)
    type: Literal["http_token", "ssh_key"]
    http_username: Optional[str] = None
    http_token: Optional[str] = None
    ssh_private_key_path: Optional[str] = None

    @root_validator
    def _require_secret_fields(cls, values):  # noqa: N805
        t = values.get("type")
        if t == "http_token":
            if not values.get("http_token"):
                raise ValueError("http_token is required for type http_token")
        elif t == "ssh_key":
            if not values.get("ssh_private_key_path"):
                raise ValueError("ssh_private_key_path is required for type ssh_key")
        return values


class CredentialOut(BaseModel):
    credential_id: str
    name: str
    type: str
    created_at: str


@router.post("/credentials", response_model=CredentialOut)
def create_credential(body: CreateCredentialIn, _user=Depends(require_permissions(["credentials.manage"]))):
    credentials = col("credentials")
    credential_id = new_id()
    doc = {
        "credential_id": credential_id,
        "name": body.name,
        "type": body.type,
        "purpose": "git",
        "repo_scope": "",
        "created_at": now_utc(),
        "updated_at": now_utc(),
    }
    if body.type == "http_token":
        doc["http"] = {
            "username": body.http_username or "git",
            "token": body.http_token,
        }
    else:
        doc["ssh"] = {"private_key_path": body.ssh_private_key_path}

    credentials.insert_one(doc)
    append_audit_event(
        request_id="__credentials__",
        event_type="CREDENTIAL_CREATED",
        payload={"credential_id": credential_id, "name": body.name, "type": body.type},
    )
    return CredentialOut(
        credential_id=credential_id,
        name=body.name,
        type=body.type,
        created_at=doc["created_at"].isoformat(),
    )


@router.get("/credentials")
def list_credentials(request: Request, limit: int = 100, offset: int = 0):
    user = getattr(request.state, "user", None) or {}
    roles = user.get("roles") if isinstance(user.get("roles"), list) else [str(user.get("role") or "")]
    perms = set()
    for r in roles:
        perms.update(role_permissions(str(r)))
    if not perms.intersection({"credentials.manage", "request.manage"}):
        raise HTTPException(status_code=403, detail="没有查看凭据列表的权限")
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=400, detail="invalid limit")
    if offset < 0:
        raise HTTPException(status_code=400, detail="invalid offset")
    credentials = col("credentials")
    q = {}
    cur = credentials.find(q, {"_id": 0, "credential_id": 1, "name": 1, "type": 1, "created_at": 1}).sort("created_at", -1).skip(offset).limit(limit)
    items = []
    for d in cur:
        items.append(
            {
                "credential_id": d["credential_id"],
                "name": d["name"],
                "type": d["type"],
                "created_at": d["created_at"].isoformat() if hasattr(d["created_at"], "isoformat") else str(d["created_at"]),
            }
        )
    total = credentials.count_documents(q)
    return {"total": total, "items": items}


@router.get("/credentials/{credential_id}")
def get_credential(credential_id: str, _user=Depends(require_permissions(["credentials.manage"]))):
    credentials = col("credentials")
    d = credentials.find_one({"credential_id": credential_id}, {"_id": 0, "http.token": 0})
    if not d:
        raise HTTPException(status_code=404, detail="credential not found")
    out = dict(d)
    if "created_at" in out and hasattr(out["created_at"], "isoformat"):
        out["created_at"] = out["created_at"].isoformat()
    return out


class UpdateCredentialIn(BaseModel):
    name: Optional[str] = None
    purpose: Optional[str] = None
    repo_scope: Optional[str] = None
    http_username: Optional[str] = None
    http_token: Optional[str] = None
    ssh_private_key_path: Optional[str] = None


@router.patch("/credentials/{credential_id}")
def update_credential(credential_id: str, body: UpdateCredentialIn, _user=Depends(require_permissions(["credentials.manage"]))):
    credentials = col("credentials")
    d = credentials.find_one({"credential_id": credential_id})
    if not d:
        raise HTTPException(status_code=404, detail="credential not found")
    patch = {k: v for k, v in body.dict(exclude_unset=True).items() if v is not None}
    if "name" in patch:
        d["name"] = patch["name"]
    if "purpose" in patch:
        d["purpose"] = patch["purpose"]
    if "repo_scope" in patch:
        d["repo_scope"] = patch["repo_scope"]
    if d.get("type") == "http_token":
        http = dict(d.get("http") or {})
        if "http_username" in patch:
            http["username"] = patch["http_username"]
        if "http_token" in patch:
            http["token"] = patch["http_token"]
        d["http"] = http
    if d.get("type") == "ssh_key" and "ssh_private_key_path" in patch:
        d["ssh"] = {"private_key_path": patch["ssh_private_key_path"]}
    d["updated_at"] = now_utc()
    credentials.replace_one({"credential_id": credential_id}, d)
    append_audit_event(request_id="__credentials__", event_type="CREDENTIAL_UPDATED", payload={"credential_id": credential_id})
    out = credentials.find_one({"credential_id": credential_id}, {"_id": 0, "http.token": 0})
    if out and hasattr(out.get("created_at"), "isoformat"):
        out["created_at"] = out["created_at"].isoformat()
    return out


@router.delete("/credentials/{credential_id}")
def delete_credential(credential_id: str, _user=Depends(require_permissions(["credentials.manage"]))):
    credentials = col("credentials")
    sources = col("sources")

    d = credentials.find_one({"credential_id": credential_id})
    if not d:
        raise HTTPException(status_code=404, detail="credential not found")

    n = sources.count_documents({"type": "git", "git.credential_id": credential_id})
    if n > 0:
        raise HTTPException(status_code=400, detail="credential is referenced by one or more git sources")

    credentials.delete_one({"credential_id": credential_id})
    append_audit_event(
        request_id="__credentials__",
        event_type="CREDENTIAL_DELETED",
        payload={"credential_id": credential_id},
    )
    return {"ok": True}
