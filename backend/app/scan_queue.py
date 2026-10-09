from __future__ import annotations

import redis

from app.db import col
from app.policy import load_active_policy
from app.settings import settings

_RUNNING_KEY = "openmastiff:scan:running"


def max_concurrent_scans() -> int:
    raw = load_active_policy().raw if load_active_policy() else {}
    runner = (raw or {}).get("runner") if isinstance(raw, dict) else {}
    try:
        n = int((runner or {}).get("max_concurrent_scans") or 2)
    except (TypeError, ValueError):
        n = 2
    return max(1, min(n, 64))


def _client():
    return redis.Redis.from_url(settings.redis_url, decode_responses=True)


def _reconcile(r) -> None:
    members = list(r.smembers(_RUNNING_KEY) or [])
    if not members:
        return
    alive = {
        str(x.get("scan_run_id"))
        for x in col("scan_runs").find(
            {"status": {"$in": ["queued", "running"]}, "scan_run_id": {"$in": members}},
            {"scan_run_id": 1},
        )
    }
    stale = [m for m in members if m not in alive]
    if stale:
        r.srem(_RUNNING_KEY, *stale)


def try_acquire_scan_slot(scan_run_id: str) -> bool:
    rid = str(scan_run_id or "").strip()
    if not rid:
        return False
    r = _client()
    _reconcile(r)
    r.sadd(_RUNNING_KEY, rid)
    if int(r.scard(_RUNNING_KEY) or 0) > max_concurrent_scans():
        r.srem(_RUNNING_KEY, rid)
        return False
    return True


def release_scan_slot(scan_run_id: str) -> None:
    rid = str(scan_run_id or "").strip()
    if not rid:
        return
    try:
        _client().srem(_RUNNING_KEY, rid)
    except Exception:
        pass
