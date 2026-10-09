from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Optional

from app.db import col
from app.schemas import now_utc, new_id


def _stable_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def append_audit_event(
    *,
    request_id: str,
    event_type: str,
    actor_id: str = "system",
    payload: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Append-only audit log with per-request hash chain.
    """
    audit_logs = col("audit_logs")

    last = audit_logs.find_one({"request_id": request_id}, sort=[("seq", -1)], projection={"_id": 0, "seq": 1, "hash": 1})
    prev_seq = int(last["seq"]) if last else 0
    prev_hash = last["hash"] if last else "GENESIS"

    seq = prev_seq + 1
    doc = {
        "audit_id": new_id(),
        "request_id": request_id,
        "ts": now_utc(),
        "seq": seq,
        "actor_id": actor_id,
        "event_type": event_type,
        "payload": payload or {},
        "prev_hash": prev_hash,
    }
    h = hashlib.sha256((_stable_json(doc) + prev_hash).encode("utf-8")).hexdigest()
    doc["hash"] = h

    audit_logs.insert_one(doc)
    return doc

