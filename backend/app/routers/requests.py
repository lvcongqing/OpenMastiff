from __future__ import annotations

import io
import os
import tempfile
import re
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, StreamingResponse

from app import blob_store
from app.auth import DEFAULT_REVIEW_ROLES, NON_REVIEW_ROLES, require_permissions, valid_roles
from app.batch_requests import build_template_bytes, parse_workbook, validate_item
from app.audit import append_audit_event
from app.db import col
from app.schemas import (
    BatchCreateIn,
    CreateRequestIn,
    GateStatus,
    RequestOut,
    RequestStatus,
    SetGitSourceIn,
    SubmitOut,
    UpdateRequestIn,
    new_id,
    now_utc,
)
from typing import Optional

from app.review_brief import build_review_brief
from app.role_review_sync import hydrate_request_review_state
from app.scan_console import build_console_payload
from app.settings import settings
from app.worker.celery_app import celery_app


router = APIRouter()


UPLOAD_MAX_BYTES = int(os.environ.get("OPENMASTIFF_MAX_UPLOAD_BYTES") or 200 * 1024 * 1024)


def _sanitize_review_roles(raw) -> list:
    allowed = valid_roles() - NON_REVIEW_ROLES
    out = []
    seen = set()
    for item in list(DEFAULT_REVIEW_ROLES) + list(raw or []):
        role = str(item).strip()
        if not role or role in seen:
            continue
        if role not in DEFAULT_REVIEW_ROLES and role not in allowed:
            continue
        seen.add(role)
        out.append(role)
    return out


def _assert_source_editable(req: dict) -> None:
    status = str(req.get("status") or "")
    if status == RequestStatus.Scanning.value:
        raise HTTPException(status_code=400, detail="扫描中不可修改源码工件")
    if status == RequestStatus.Approved.value:
        raise HTTPException(status_code=400, detail="已通过的引入单不可修改源码工件")


def _visible_request_query(user: Optional[dict]) -> dict:
    if not user:
        return {}
    roles = user.get("roles") if isinstance(user.get("roles"), list) else [str(user.get("role") or "")]
    roles = [str(r).strip() for r in roles if str(r).strip()]
    if "admin" in roles:
        return {}
    username = str(user.get("username") or "")
    return {
        "$or": [
            {"created_by": username},
            {"owner": username},
            {"required_review_roles": {"$in": roles}},
        ]
    }


def _scan_failure_detail(scan_run: dict) -> Optional[dict]:
    if str(scan_run.get("status") or "").lower() != "failed":
        return None
    raw_error = str(scan_run.get("error") or "").strip()
    log_tail = str(scan_run.get("error_detail") or "").strip()

    if not raw_error:
        out = {
            "reason": "扫描任务失败，但后端未记录详细错误。",
            "next_steps": [
                "打开本条扫描记录，查看 logs.txt 最后几十行。",
                "点击“触发复测”重试一次。",
                "若仍失败，请联系管理员查看 worker 日志。",
            ],
            "category": "unknown",
            "detail": "",
        }
        if log_tail:
            out["log_tail"] = log_tail
        return out

    lowered = raw_error.lower()
    if any(k in lowered for k in ["connection timed out", "timed out", "early eof", "rpc failed", "index-pack failed"]):
        classified = {
            "reason": "拉取 Git 源码超时或连接中断，扫描未能开始。",
            "next_steps": [
                "检查仓库网络连通性（出口、代理、防火墙）。",
                "确认仓库地址和分支/标签可访问后，点击“触发复测”。",
                "若频繁超时，建议切换到内网镜像仓库或上传离线压缩包。",
            ],
            "category": "source_network",
        }
    elif "authentication failed" in lowered or "could not read username" in lowered:
        classified = {
            "reason": "拉取 Git 源码鉴权失败，凭据不可用或权限不足。",
            "next_steps": [
                "检查工单绑定的凭据是否正确、是否过期。",
                "确认该凭据对目标仓库具有读取权限。",
                "更新凭据后重新触发扫描。",
            ],
            "category": "source_auth",
        }
    elif "repository not found" in lowered or re.search(r"\bfatal:.*?not found\b", lowered):
        classified = {
            "reason": "仓库地址或分支/标签不存在，无法获取源码。",
            "next_steps": [
                "核对仓库 URL 与分支/标签/提交是否正确。",
                "确认仓库可访问后重新触发扫描。",
            ],
            "category": "source_not_found",
        }
    elif "unsupported archive type" in lowered:
        classified = {
            "reason": "上传工件格式不受支持，无法解压。",
            "next_steps": [
                "请上传 zip / tar / tar.gz / tgz 格式工件。",
                "确认压缩包完整后重新提交扫描。",
            ],
            "category": "source_archive",
        }
    elif re.search(r"\bpermission denied\b", lowered):
        classified = {
            "reason": "执行扫描时出现权限不足。",
            "next_steps": [
                "联系管理员检查 worker 用户权限与目录访问权限。",
                "修复后重新触发扫描。",
            ],
            "category": "runtime_permission",
        }
    elif re.search(r"exited with code -15|signal 1?5\b|sigterm", lowered):
        classified = {
            "reason": "扫描进程被终止（SIGTERM）。常见原因：服务重启、任务超时，或管理员中止。仓库很大时更容易扫到一半被杀掉。",
            "next_steps": [
                "打开本条扫描记录，看 logs.txt 停在哪一步（许可证 / SBOM / 语言扫描）。",
                "若是服务重启或偶发中断，直接点“触发复测”。",
                "若反复被杀，缩小扫描范围或联系管理员提高超时/内存后再复测。",
            ],
            "category": "runtime_killed",
        }
    elif re.search(r"exited with code -9|signal 9\b|sigkill|killed", lowered):
        classified = {
            "reason": "扫描进程被强制杀掉（SIGKILL）。常见原因是内存不足（OOM）。",
            "next_steps": [
                "打开 logs.txt 确认停在哪一步。",
                "缩小扫描范围（排除 vendor/node_modules 等），或联系管理员提高扫描内存后再复测。",
            ],
            "category": "runtime_oom",
        }
    elif "summary.json missing" in lowered:
        classified = {
            "reason": "扫描未正常结束，没有生成 summary.json（中途中断或脚本异常退出）。",
            "next_steps": [
                "查看 logs.txt 最后一段，确认卡在许可证、SBOM 还是语言扫描。",
                "点击“触发复测”。若持续失败，把日志尾部发给管理员。",
            ],
            "category": "runtime_incomplete",
        }
    elif re.search(r"scanner exited with code", lowered):
        classified = {
            "reason": "扫描脚本异常退出：%s" % raw_error,
            "next_steps": [
                "打开本条扫描记录的 logs.txt，从最后几十行看具体失败步骤。",
                "先复测一次排除偶发；仍失败则把退出码和日志尾部发给管理员。",
            ],
            "category": "runtime_exit",
        }
    else:
        classified = {
            "reason": raw_error,
            "next_steps": [
                "打开本条扫描记录的 logs.txt，对照下方原始错误排查。",
                "先复测一次确认是否偶发。",
                "若持续失败，把原始错误和日志尾部发给管理员。",
            ],
            "category": "runtime_unknown",
        }

    classified["detail"] = raw_error
    if log_tail:
        classified["log_tail"] = log_tail
    return classified


def _decorate_scan_run(scan_run: dict) -> dict:
    out = dict(scan_run)
    failure_detail = _scan_failure_detail(scan_run)
    if failure_detail:
        out["failure_detail"] = failure_detail
    return out


def _create_draft_request(*, payload: dict, user: dict, extra_roles=None) -> dict:
    requests = col("review_requests")
    request_id = new_id()
    roles = list(payload.get("required_review_roles") or []) + list(extra_roles or [])
    required_review_roles = _sanitize_review_roles(roles)
    if not required_review_roles:
        raise HTTPException(status_code=400, detail="请至少选择一个审核角色")
    if payload.get("scan_scope") is None:
        payload["scan_scope"] = {"mode": "auto", "include_paths": []}
    title = (payload.get("title") or payload.get("project") or "").strip()
    owner = (payload.get("owner") or user.get("username") or "").strip()
    doc = {
        "request_id": request_id,
        "status": RequestStatus.Draft.value,
        "gate_status": GateStatus.Unknown.value,
        **payload,
        "title": title,
        "owner": owner,
        "created_by": user.get("username"),
        "risk_level": None,
        "required_review_roles": required_review_roles,
        "role_reviews": {r: {"status": "Pending", "updated_at": None, "decision": None, "comment": None} for r in required_review_roles},
        "source_id": None,
        "latest_scan_run_id": None,
        "created_at": now_utc(),
        "updated_at": now_utc(),
    }
    requests.insert_one(doc)
    append_audit_event(request_id=request_id, event_type="REQUEST_CREATED", payload={"project": doc["project"]}, actor_id=user.get("username"))
    return doc


@router.post("/requests", response_model=RequestOut)
def create_request(body: CreateRequestIn, user=Depends(require_permissions(["request.manage"]))):
    doc = _create_draft_request(payload=body.dict(), user=user)
    return RequestOut(**doc)


def _bind_git_source(request_id: str, *, repo_url: str, ref: str, credential_id: Optional[str] = None) -> str:
    source_id = new_id()
    doc = {
        "source_id": source_id,
        "type": "git",
        "git": {"repo_url": str(repo_url), "ref": ref or "main", "credential_id": credential_id or None},
        "created_at": now_utc(),
    }
    col("sources").insert_one(doc)
    col("review_requests").update_one({"request_id": request_id}, {"$set": {"source_id": source_id, "updated_at": now_utc()}})
    append_audit_event(request_id=request_id, event_type="SOURCE_GIT_SET", payload={"source_id": source_id, "repo_url": doc["git"]["repo_url"], "ref": doc["git"]["ref"]})
    return source_id


def _submit_now(request_id: str) -> SubmitOut:
    requests = col("review_requests")
    scan_runs = col("scan_runs")
    req = requests.find_one({"request_id": request_id})
    if not req:
        raise HTTPException(status_code=404, detail="request not found")
    if req["status"] != RequestStatus.Draft.value:
        raise HTTPException(status_code=400, detail="request not in Draft")
    if not req.get("source_id"):
        raise HTTPException(status_code=400, detail="source not set")
    required_review_roles = [str(r).strip() for r in (req.get("required_review_roles") or []) if str(r).strip()]
    scan_run_id = new_id()
    scan_runs.insert_one(
        {
            "scan_run_id": scan_run_id,
            "request_id": request_id,
            "source_id": req["source_id"],
            "status": "queued",
            "created_at": now_utc(),
        }
    )
    requests.update_one(
        {"request_id": request_id},
        {
            "$set": {
                "status": RequestStatus.Submitted.value,
                "submitted_at": now_utc(),
                "role_reviews": {r: {"status": "Pending", "updated_at": None, "decision": None, "comment": None} for r in required_review_roles},
                "updated_at": now_utc(),
            }
        },
    )
    celery_app.send_task("start_scan", args=[scan_run_id])
    append_audit_event(request_id=request_id, event_type="REQUEST_SUBMITTED", payload={"scan_run_id": scan_run_id})
    return SubmitOut(request_id=request_id, status=RequestStatus.Submitted, scan_run_id=scan_run_id)


@router.get("/requests/batch/template")
def download_batch_template(_user=Depends(require_permissions(["request.manage"]))):
    data = build_template_bytes()
    return StreamingResponse(
        io.BytesIO(data),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": 'attachment; filename="openmastiff-batch-requests.xlsx"'},
    )


@router.post("/requests/batch/parse")
def parse_batch_requests(artifact_file: UploadFile = File(...), _user=Depends(require_permissions(["request.manage"]))):
    raw = artifact_file.file.read()
    if not raw:
        raise HTTPException(status_code=400, detail="上传文件为空")
    try:
        return parse_workbook(raw)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.post("/requests/batch")
def create_batch_requests(body: BatchCreateIn, user=Depends(require_permissions(["request.manage"]))):
    raw_items = body.items if isinstance(body.items, list) else []
    if not raw_items:
        raise HTTPException(status_code=400, detail="没有可创建的引入单")
    peers: dict = {}
    created = []
    failed = []
    for idx, raw in enumerate(raw_items, 1):
        if hasattr(raw, "dict") and not isinstance(raw, dict):
            raw = raw.dict()
        if not isinstance(raw, dict):
            failed.append({"row": idx, "error": "行数据无效"})
            continue
        item = validate_item(raw, peer_keys=peers)
        if item.get("errors"):
            failed.append({"row": item.get("row") or idx, "project": item.get("project"), "error": "；".join(item["errors"])})
            continue
        try:
            include = [str(x).strip() for x in (item.get("include_paths") or []) if str(x).strip()]
            payload = {
                "project": item["project"],
                "title": item.get("title") or item["project"],
                "owner": item.get("owner"),
                "environment": item.get("environment") or "dev",
                "purpose": item["purpose"],
                "business_criticality": item.get("business_criticality") or "low",
                "exposure": item.get("exposure") or "internal",
                "rollback_plan": item.get("rollback_plan") or "version_downgrade",
                "required_review_roles": list(DEFAULT_REVIEW_ROLES) + list(item.get("extra_review_roles") or []),
                "scan_scope": {"mode": "include_paths" if include else "auto", "include_paths": include},
            }
            doc = _create_draft_request(payload=payload, user=user, extra_roles=item.get("extra_review_roles") or [])
            _bind_git_source(
                doc["request_id"],
                repo_url=item["repo_url"],
                ref=item.get("ref") or "main",
                credential_id=item.get("credential_id") or None,
            )
            scan_run_id = None
            status = RequestStatus.Draft.value
            if body.submit:
                submitted = _submit_now(doc["request_id"])
                scan_run_id = submitted.scan_run_id
                status = submitted.status.value
            created.append(
                {
                    "row": item.get("row") or idx,
                    "request_id": doc["request_id"],
                    "title": doc.get("title"),
                    "project": doc.get("project"),
                    "status": status,
                    "scan_run_id": scan_run_id,
                }
            )
        except HTTPException as e:
            failed.append({"row": item.get("row") or idx, "project": item.get("project"), "error": str(e.detail)})
        except Exception as e:
            failed.append({"row": item.get("row") or idx, "project": item.get("project"), "error": str(e)})
    return {
        "ok": not failed,
        "submit": bool(body.submit),
        "created": created,
        "failed": failed,
        "created_count": len(created),
        "failed_count": len(failed),
    }


@router.get("/requests")
def list_requests(
    request: Request,
    limit: int = 50,
    offset: int = 0,
    status: Optional[str] = None,
    gate_status: Optional[str] = None,
    project: Optional[str] = None,
    created_by: Optional[str] = None,
    risk_level: Optional[str] = None,
):
    user = getattr(request.state, "user", None) or {}
    if limit < 1 or limit > 200:
        raise HTTPException(status_code=400, detail="invalid limit")
    if offset < 0:
        raise HTTPException(status_code=400, detail="invalid offset")

    q: dict = dict(_visible_request_query(user))
    if status:
        q["status"] = status
    if gate_status:
        q["gate_status"] = gate_status
    if project:
        q["project"] = {"$regex": project, "$options": "i"}
    if created_by:
        q["created_by"] = created_by
    if risk_level:
        q["risk_level"] = risk_level

    requests = col("review_requests")
    cur = requests.find(q, {"_id": 0}).sort("updated_at", -1).skip(offset).limit(limit)
    items = [hydrate_request_review_state(x, persist=True) for x in cur]
    total = requests.count_documents(q)
    return {"total": total, "items": items}


def _assert_request_visible(request_id: str, user: Optional[dict]) -> dict:
    requests = col("review_requests")
    req = requests.find_one({"request_id": request_id})
    if not req:
        raise HTTPException(status_code=404, detail="request not found")
    vis = _visible_request_query(user or {})
    if vis and not requests.find_one({"request_id": request_id, **vis}, {"_id": 1}):
        raise HTTPException(status_code=404, detail="request not found")
    return req


@router.patch("/requests/{request_id}")
def patch_request(request_id: str, body: UpdateRequestIn, request: Request, _user=Depends(require_permissions(["request.manage"]))):
    requests = col("review_requests")
    user = getattr(request.state, "user", None) or _user
    req = _assert_request_visible(request_id, user)
    if req["status"] == RequestStatus.Scanning.value:
        raise HTTPException(status_code=400, detail="扫描中不可编辑引入单")

    patch = {k: v for k, v in body.dict(exclude_unset=True).items() if v is not None}
    if not patch:
        raise HTTPException(status_code=400, detail="no fields to update")
    status = str(req.get("status") or "")
    roles_editable = status in {RequestStatus.Draft.value, RequestStatus.ReReview.value}
    source_editable = status not in {RequestStatus.Scanning.value, RequestStatus.Approved.value}
    if "required_review_roles" in patch and not roles_editable:
        raise HTTPException(status_code=400, detail="仅草稿或复审状态可修改审核角色")
    if "scan_scope" in patch and not source_editable:
        raise HTTPException(status_code=400, detail="当前状态不可修改扫描范围")
    if "required_review_roles" in patch:
        roles = _sanitize_review_roles(patch.get("required_review_roles"))
        if not roles:
            raise HTTPException(status_code=400, detail="请至少选择一个审核角色")
        patch["required_review_roles"] = roles
        existing = req.get("role_reviews") if isinstance(req.get("role_reviews"), dict) else {}
        patch["role_reviews"] = {
            r: existing.get(r)
            or {"status": "Pending", "updated_at": None, "decision": None, "comment": None}
            for r in roles
        }
    patch["updated_at"] = now_utc()
    requests.update_one({"request_id": request_id}, {"$set": patch})
    append_audit_event(
        request_id=request_id,
        event_type="REQUEST_UPDATED",
        payload={"fields": list(patch.keys())},
        actor_id=(user or {}).get("username"),
    )
    doc = requests.find_one({"request_id": request_id}, {"_id": 0})
    return doc


@router.delete("/requests/{request_id}")
def delete_request(request_id: str, request: Request, _user=Depends(require_permissions(["request.manage"]))):
    user = getattr(request.state, "user", None) or _user
    req = _assert_request_visible(request_id, user)
    if req["status"] == RequestStatus.Scanning.value:
        raise HTTPException(status_code=400, detail="扫描中不可删除引入单")
    title = req.get("title") or req.get("project")
    col("review_requests").delete_one({"request_id": request_id})
    col("scan_runs").delete_many({"request_id": request_id})
    col("findings").delete_many({"request_id": request_id})
    col("remediations").delete_many({"request_id": request_id})
    col("legal_reviews").delete_many({"request_id": request_id})
    col("gate_results").delete_many({"request_id": request_id})
    append_audit_event(
        request_id=request_id,
        event_type="REQUEST_DELETED",
        payload={"title": title, "status": req.get("status")},
        actor_id=(user or {}).get("username"),
    )
    return {"ok": True, "request_id": request_id}


@router.get("/requests/{request_id}/review-brief")
def get_review_brief(request_id: str):
    """聚合扫描门禁、许可证、安全与法务信息，供各角色审核裁决参考。"""
    requests = col("review_requests")
    if not requests.find_one({"request_id": request_id}, {"_id": 1}):
        raise HTTPException(status_code=404, detail="request not found")
    brief = build_review_brief(request_id)
    if not brief:
        raise HTTPException(status_code=404, detail="request not found")
    return brief


@router.get("/requests/{request_id}/audit-events")
def list_audit_events(request_id: str, limit: int = 200, offset: int = 0):
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=400, detail="invalid limit")
    audit_logs = col("audit_logs")
    q = {"request_id": request_id}
    total = audit_logs.count_documents(q)
    cur = audit_logs.find(q, {"_id": 0}).sort("seq", 1).skip(offset).limit(limit)
    return {"total": total, "items": list(cur)}


@router.get("/requests/{request_id}/scan-runs")
def list_request_scan_runs(request_id: str, limit: int = 50):
    if limit < 1 or limit > 200:
        raise HTTPException(status_code=400, detail="invalid limit")
    requests = col("review_requests")
    scan_runs = col("scan_runs")
    if not requests.find_one({"request_id": request_id}, {"_id": 1}):
        raise HTTPException(status_code=404, detail="request not found")
    cur = scan_runs.find({"request_id": request_id}, {"_id": 0}).sort("created_at", -1).limit(limit)
    items = [_decorate_scan_run(x) for x in cur]
    return {"items": items}


@router.get("/requests/{request_id}")
def get_request(request_id: str, request: Request):
    requests = col("review_requests")
    scan_runs = col("scan_runs")
    sources = col("sources")

    req = requests.find_one({"request_id": request_id}, {"_id": 0})
    if not req:
        raise HTTPException(status_code=404, detail="request not found")
    vis = _visible_request_query(getattr(request.state, "user", None) or {})
    if vis and not requests.find_one({"request_id": request_id, **vis}, {"_id": 1}):
        raise HTTPException(status_code=404, detail="request not found")
    req = hydrate_request_review_state(req, persist=True)

    source = sources.find_one({"source_id": req.get("source_id")}, {"_id": 0}) if req.get("source_id") else None
    scan_run = (
        scan_runs.find_one({"scan_run_id": req.get("latest_scan_run_id")}, {"_id": 0})
        if req.get("latest_scan_run_id")
        else None
    )
    if not scan_run:
        scan_run = scan_runs.find_one({"request_id": request_id}, {"_id": 0}, sort=[("created_at", -1)])
    return {"request": req, "source": source, "latest_scan_run": _decorate_scan_run(scan_run) if scan_run else None}


@router.post("/requests/{request_id}/source/upload")
def upload_source(request_id: str, artifact_file: UploadFile = File(...), _user=Depends(require_permissions(["request.manage"]))):
    requests = col("review_requests")
    sources = col("sources")

    req = requests.find_one({"request_id": request_id})
    if not req:
        raise HTTPException(status_code=404, detail="request not found")
    _assert_source_editable(req)

    filename = artifact_file.filename or "artifact"
    lower = filename.lower()
    if not (lower.endswith(".zip") or lower.endswith(".tar.gz") or lower.endswith(".tgz") or lower.endswith(".tar")):
        raise HTTPException(status_code=400, detail="unsupported archive type")

    blob_store.ensure_dir(settings.work_root)
    with tempfile.NamedTemporaryFile(dir=settings.work_root, delete=False) as f:
        tmp_path = f.name
        written = 0
        while True:
            chunk = artifact_file.file.read(1024 * 1024)
            if not chunk:
                break
            written += len(chunk)
            if written > UPLOAD_MAX_BYTES:
                raise HTTPException(status_code=400, detail="上传超过大小上限（%s MB）" % (UPLOAD_MAX_BYTES // (1024 * 1024)))
            f.write(chunk)

    ref = blob_store.put_file(settings.blob_root, tmp_path)
    source_id = new_id()
    doc = {
        "source_id": source_id,
        "type": "upload",
        "blob": {"sha256": ref.sha256, "path": ref.path, "bytes": ref.bytes, "filename": filename},
        "created_at": now_utc(),
    }
    sources.insert_one(doc)

    requests.update_one(
        {"request_id": request_id},
        {"$set": {"source_id": source_id, "updated_at": now_utc()}},
    )
    append_audit_event(request_id=request_id, event_type="SOURCE_UPLOADED", payload={"source_id": source_id, "sha256": ref.sha256})
    return {"request_id": request_id, "source_id": source_id, "sha256": ref.sha256}


@router.post("/requests/{request_id}/source/git")
def set_git_source(request_id: str, body: SetGitSourceIn, _user=Depends(require_permissions(["request.manage"]))):
    requests = col("review_requests")
    sources = col("sources")

    req = requests.find_one({"request_id": request_id})
    if not req:
        raise HTTPException(status_code=404, detail="request not found")
    _assert_source_editable(req)

    source_id = new_id()
    doc = {
        "source_id": source_id,
        "type": "git",
        "git": {"repo_url": str(body.repo_url), "ref": body.ref, "credential_id": body.credential_id},
        "created_at": now_utc(),
    }
    sources.insert_one(doc)
    requests.update_one({"request_id": request_id}, {"$set": {"source_id": source_id, "updated_at": now_utc()}})
    append_audit_event(request_id=request_id, event_type="SOURCE_GIT_SET", payload={"source_id": source_id, "repo_url": doc["git"]["repo_url"], "ref": doc["git"]["ref"]})
    return {"request_id": request_id, "source_id": source_id}


@router.post("/requests/{request_id}/submit", response_model=SubmitOut)
def submit_request(request_id: str, _user=Depends(require_permissions(["request.manage"]))):
    return _submit_now(request_id)


@router.post("/requests/{request_id}/trigger-scan", response_model=SubmitOut)
def trigger_scan(request_id: str, _user=Depends(require_permissions(["request.manage"]))):
    """非 Draft 的复测：再次排队扫描（需已有 source）。"""
    requests = col("review_requests")
    scan_runs = col("scan_runs")

    req = requests.find_one({"request_id": request_id})
    if not req:
        raise HTTPException(status_code=404, detail="request not found")
    if not req.get("source_id"):
        raise HTTPException(status_code=400, detail="source not set")
    required_review_roles = [str(r).strip() for r in (req.get("required_review_roles") or []) if str(r).strip()]
    if req["status"] == RequestStatus.Draft.value:
        raise HTTPException(status_code=400, detail="Draft 请使用 POST /submit")
    if req["status"] == RequestStatus.Scanning.value:
        raise HTTPException(status_code=400, detail="当前已在扫描中")

    scan_run_id = new_id()
    scan_runs.insert_one(
        {
            "scan_run_id": scan_run_id,
            "request_id": request_id,
            "source_id": req["source_id"],
            "status": "queued",
            "created_at": now_utc(),
        }
    )

    requests.update_one(
        {"request_id": request_id},
        {
            "$set": {
                "status": RequestStatus.Scanning.value,
                "role_reviews": {r: {"status": "Pending", "updated_at": None, "decision": None, "comment": None} for r in required_review_roles},
                "updated_at": now_utc(),
            }
        },
    )

    celery_app.send_task("start_scan", args=[scan_run_id])
    append_audit_event(request_id=request_id, event_type="REQUEST_RESCAN", payload={"scan_run_id": scan_run_id})

    return SubmitOut(request_id=request_id, status=RequestStatus.Scanning, scan_run_id=scan_run_id)


@router.get("/scan-runs/{scan_run_id}")
def get_scan_run(scan_run_id: str):
    scan_runs = col("scan_runs")
    sr = scan_runs.find_one({"scan_run_id": scan_run_id}, {"_id": 0})
    if not sr:
        raise HTTPException(status_code=404, detail="scan_run not found")
    return _decorate_scan_run(sr)


@router.get("/scan-runs/{scan_run_id}/console")
def get_scan_console(scan_run_id: str):
    """Live tail of workspace logs.txt while the scan is queued or running."""
    scan_runs = col("scan_runs")
    sr = scan_runs.find_one({"scan_run_id": scan_run_id}, {"_id": 0})
    if not sr:
        raise HTTPException(status_code=404, detail="scan_run not found")
    return build_console_payload(sr)


@router.get("/scan-runs/{scan_run_id}/artifacts/{name}")
def get_scan_artifact(scan_run_id: str, name: str):
    scan_runs = col("scan_runs")
    sr = scan_runs.find_one({"scan_run_id": scan_run_id}, {"_id": 0})
    if not sr:
        raise HTTPException(status_code=404, detail="scan_run not found")
    outputs = sr.get("outputs") or {}
    ref = outputs.get(name)
    if not ref:
        raise HTTPException(status_code=404, detail="artifact not found")
    path = ref["path"]
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="artifact missing on disk")
    filename = f"{scan_run_id}-{name}"
    return FileResponse(path, filename=filename, media_type="application/octet-stream")

