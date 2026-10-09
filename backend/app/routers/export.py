from __future__ import annotations

import hashlib
import json
import os
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, Response

from app.auth import require_permissions
from app.db import col
from app.review_report import build_review_report_pdf
from app.routers.requests import _visible_request_query
from app.schemas import now_utc, new_id


router = APIRouter()


def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


@router.get("/requests/{request_id}/review-report")
def download_review_report(request_id: str, request: Request):
    """生成并下载引入审查 PDF 报告（最近一次扫描结果摘要）。"""
    user = getattr(request.state, "user", None) or {}
    requests = col("review_requests")
    req = requests.find_one({"request_id": request_id}, {"_id": 1})
    if not req:
        raise HTTPException(status_code=404, detail="request not found")
    vis = _visible_request_query(user)
    if vis and not requests.find_one({"request_id": request_id, **vis}, {"_id": 1}):
        raise HTTPException(status_code=404, detail="request not found")
    try:
        pdf, filename = build_review_report_pdf(request_id, user=user)
    except KeyError:
        raise HTTPException(status_code=404, detail="request not found")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail="生成审查报告失败：%s" % e)
    quoted = quote(filename)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": "attachment; filename*=UTF-8''%s" % quoted,
            "Cache-Control": "no-store",
        },
    )


@router.post("/requests/{request_id}/export")
def export_request(request_id: str, _user=Depends(require_permissions(["export.create"]))):
    requests = col("review_requests")
    sources = col("sources")
    scan_runs = col("scan_runs")
    audit_logs = col("audit_logs")

    req = requests.find_one({"request_id": request_id}, {"_id": 0})
    if not req:
        raise HTTPException(status_code=404, detail="request not found")

    source = sources.find_one({"source_id": req.get("source_id")}, {"_id": 0}) if req.get("source_id") else None
    runs = list(scan_runs.find({"request_id": request_id}, {"_id": 0}).sort("created_at", 1))
    audits = list(audit_logs.find({"request_id": request_id}, {"_id": 0}).sort("seq", 1))

    export_id = new_id()
    out_dir = Path("/opt/openMastiff/data/exports")
    out_dir.mkdir(parents=True, exist_ok=True)
    zip_path = out_dir / f"evidence-{request_id}-{export_id}.zip"

    manifest = {
        "export_version": "1.0",
        "request_id": request_id,
        "export_id": export_id,
        "generated_at": now_utc().isoformat(),
        "scan_runs": [r.get("scan_run_id") for r in runs],
    }

    hashes = {}

    def _writestr(z: zipfile.ZipFile, arc: str, content: bytes):
        z.writestr(arc, content)
        hashes[arc] = {"sha256": _sha256_bytes(content), "bytes": len(content)}

    def _writefile(z: zipfile.ZipFile, arc: str, fpath: Path):
        z.write(str(fpath), arcname=arc)
        hashes[arc] = {"sha256": _sha256_file(fpath), "bytes": fpath.stat().st_size}

    with zipfile.ZipFile(str(zip_path), "w", compression=zipfile.ZIP_DEFLATED) as z:
        _writestr(z, "manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8"))
        _writestr(z, "request/request.json", json.dumps(req, ensure_ascii=False, indent=2, default=str).encode("utf-8"))
        if source:
            _writestr(z, "source/source.json", json.dumps(source, ensure_ascii=False, indent=2, default=str).encode("utf-8"))
        _writestr(z, "audit/audit_logs.jsonl", ("\n".join(json.dumps(a, ensure_ascii=False, default=str) for a in audits) + "\n").encode("utf-8"))

        for r in runs:
            rid = r["scan_run_id"]
            _writestr(z, f"scans/{rid}/scan_run.json", json.dumps(r, ensure_ascii=False, indent=2, default=str).encode("utf-8"))
            outputs = r.get("outputs") or {}
            for name, ref in outputs.items():
                p = Path(ref["path"])
                if p.exists():
                    _writefile(z, f"scans/{rid}/reports/{name}", p)

        chain_ok = True
        broken_at = None
        prev = "GENESIS"
        for a in audits:
            expected_prev = a.get("prev_hash")
            if expected_prev != prev:
                chain_ok = False
                broken_at = a.get("seq")
                break
            prev = a.get("hash") or prev
        verify = {
            "ok": chain_ok,
            "events": len(audits),
            "broken_at_seq": broken_at,
            "note": "per-request prev_hash -> hash chain",
        }
        _writestr(z, "audit/audit_verify.json", json.dumps(verify, ensure_ascii=False, indent=2).encode("utf-8"))
        _writestr(z, "hashes.json", json.dumps(hashes, ensure_ascii=False, indent=2).encode("utf-8"))

    exports = col("exports")
    exports.insert_one({"export_id": export_id, "request_id": request_id, "path": str(zip_path), "created_at": now_utc()})
    return {"export_id": export_id}


@router.get("/exports/{export_id}")
def download_export(export_id: str, request: Request, _user=Depends(require_permissions(["export.create"]))):
    exports = col("exports")
    ex = exports.find_one({"export_id": export_id}, {"_id": 0})
    if not ex:
        raise HTTPException(status_code=404, detail="export not found")
    if not os.path.exists(ex["path"]):
        raise HTTPException(status_code=404, detail="export missing on disk")
    return FileResponse(ex["path"], filename=os.path.basename(ex["path"]), media_type="application/zip")

