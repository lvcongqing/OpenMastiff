#!/usr/bin/env python3
"""在独立 Python 进程中执行 run_scan.sh，避免 Celery 长驻进程污染 gosec 子进程。"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def main() -> int:
    payload = json.loads(sys.argv[1])
    repo_root = Path(sys.argv[2])
    script = repo_root / "scanner" / "run_scan.sh"
    if not script.is_file():
        print("run_scan.sh not found", file=sys.stderr)
        return 2
    env = dict(payload["env"])
    proc = subprocess.run(["sh", str(script)], env=env)
    return int(proc.returncode)


if __name__ == "__main__":
    sys.exit(main())
