from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from app.settings import settings

LIVE_STATUSES = frozenset({"queued", "running"})
CONSOLE_TAIL_BYTES = 512 * 1024


def is_live_scan_status(status: str) -> bool:
    return str(status or "").lower() in LIVE_STATUSES


def live_log_path(request_id: str, scan_run_id: str, work_dir: Optional[str] = None) -> Path:
    if work_dir:
        return Path(str(work_dir)) / "output" / "logs.txt"
    return Path(settings.work_root) / str(request_id) / str(scan_run_id) / "output" / "logs.txt"


def resolved_live_log_path(path: Path) -> Optional[Path]:
    root = Path(settings.work_root).resolve()
    try:
        resolved = path.resolve()
        resolved.relative_to(root)
    except (OSError, ValueError):
        return None
    if resolved.name != "logs.txt":
        return None
    return resolved


def read_console_text(path: Path, max_bytes: int = CONSOLE_TAIL_BYTES) -> Tuple[str, int, bool]:
    if not path.is_file():
        return "", 0, False
    size = int(path.stat().st_size)
    truncated = size > max_bytes
    with path.open("rb") as f:
        if truncated:
            f.seek(max(0, size - max_bytes))
            data = f.read()
        else:
            data = f.read()
    text = data.decode("utf-8", errors="replace")
    if truncated:
        nl = text.find("\n")
        if 0 <= nl < len(text) - 1:
            text = text[nl + 1 :]
    return text, size, truncated


def build_console_payload(scan_run: Dict[str, Any]) -> Dict[str, Any]:
    status = str(scan_run.get("status") or "")
    live = is_live_scan_status(status)
    request_id = str(scan_run.get("request_id") or "")
    scan_run_id = str(scan_run.get("scan_run_id") or "")
    work_dir = scan_run.get("work_dir")
    raw = live_log_path(request_id, scan_run_id, str(work_dir) if work_dir else None)
    safe = resolved_live_log_path(raw)
    text, size, truncated = "", 0, False
    if safe is not None:
        text, size, truncated = read_console_text(safe)
    return {
        "scan_run_id": scan_run_id,
        "request_id": request_id,
        "status": status,
        "live": live,
        "text": text,
        "bytes": size,
        "truncated": truncated,
    }
