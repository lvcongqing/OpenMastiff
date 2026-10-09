from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from typing import Optional


DEFAULT_GRYPE_DB_DIR = "/opt/openMastiff/data/grype-db"


def grype_db_dir() -> str:
    return os.environ.get("GRYPE_DB_CACHE_DIR") or DEFAULT_GRYPE_DB_DIR


def _db_age_seconds(db_dir: Path) -> Optional[float]:
    newest = None
    if not db_dir.is_dir():
        return None
    for name in ("metadata.json", "vulnerability.db", "last_update"):
        for path in db_dir.rglob(name):
            try:
                mtime = path.stat().st_mtime
            except OSError:
                continue
            if newest is None or mtime > newest:
                newest = mtime
    if newest is None:
        return None
    return max(0.0, time.time() - newest)


def ensure_grype_db(*, log_file: Optional[Path] = None, max_age_hours: int = 168) -> None:
    """Best-effort update of the Grype vulnerability DB used by offline scans."""
    exe = None
    for candidate in ("grype", "/usr/local/bin/grype"):
        if candidate == "grype":
            from shutil import which

            exe = which("grype")
        elif os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            exe = candidate
        if exe:
            break
    if not exe:
        _append(log_file, "[sca] grype not installed, skip db update\n")
        return
    db_dir = Path(grype_db_dir())
    db_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(db_dir, 0o755)
    except OSError:
        pass
    age = _db_age_seconds(db_dir)
    if age is not None and age < max(1, max_age_hours) * 3600:
        _append(log_file, "[sca] grype db fresh (age %.1fh), skip update\n" % (age / 3600.0))
        return
    env = os.environ.copy()
    env["GRYPE_DB_CACHE_DIR"] = str(db_dir)
    env["GRYPE_CHECK_FOR_APP_UPDATE"] = "false"
    _append(log_file, "[sca] grype db update -> %s\n" % db_dir)
    try:
        proc = subprocess.run(
            [exe, "db", "update"],
            env=env,
            timeout=600,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
        )
        _append(log_file, proc.stdout or "")
        _append(log_file, "[sca] grype db update exit=%s\n" % proc.returncode)
    except Exception as e:
        _append(log_file, "[sca] grype db update error: %s\n" % e)


def _append(log_file: Optional[Path], text: str) -> None:
    if not log_file:
        return
    try:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with log_file.open("a", encoding="utf-8") as f:
            f.write(text)
    except OSError:
        pass
