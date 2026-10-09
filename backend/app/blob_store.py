from __future__ import annotations

import hashlib
import os
import shutil
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class BlobRef:
    sha256: str
    path: str
    bytes: int


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def put_file(blob_root: str, src_path: str) -> BlobRef:
    """
    Content-addressed store (sha256). Returns reference.
    """
    root = Path(blob_root)
    ensure_dir(str(root))

    src = Path(src_path)
    sha256 = _sha256_file(src)
    dst = root / sha256[:2] / sha256
    ensure_dir(str(dst.parent))

    if not dst.exists():
        shutil.copy2(src, dst)

    st = dst.stat()
    return BlobRef(sha256=sha256, path=str(dst), bytes=st.st_size)

