from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from app.db import col


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def get_cached(key: str, ttl_hours: int) -> Optional[Dict[str, Any]]:
    doc = col("maintenance_snapshots").find_one({"key": key}, {"_id": 0})
    if not doc:
        return None
    fetched = doc.get("fetched_at")
    if not isinstance(fetched, datetime):
        return None
    if fetched.tzinfo is None:
        fetched = fetched.replace(tzinfo=timezone.utc)
    if _utcnow() - fetched > timedelta(hours=max(1, ttl_hours)):
        return None
    data = doc.get("data")
    return data if isinstance(data, dict) else None


def set_cached(key: str, data: Dict[str, Any]) -> None:
    col("maintenance_snapshots").update_one(
        {"key": key},
        {"$set": {"key": key, "data": data, "fetched_at": _utcnow()}},
        upsert=True,
    )
