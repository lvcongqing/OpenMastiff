from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.maintenance.upstream import UpstreamRef, go_module_upstream, parse_git_upstream, parse_github_repo_url

__all__ = ["parse_github_repo_url", "infer_upstream_repo", "infer_upstream_ref", "parse_direct_dependencies"]


def infer_upstream_ref(workspace: Path) -> Optional[UpstreamRef]:
    """Infer public upstream from manifests (GitHub / Gitee / GitLab / Apache / kernel 等)."""
    go_mod = workspace / "go.mod"
    if go_mod.is_file():
        text = go_mod.read_text(encoding="utf-8", errors="ignore")
        m = re.search(r"^\s*module\s+(\S+)", text, re.M)
        if m:
            ref = go_module_upstream(m.group(1).strip())
            if ref:
                return ref

    pkg = workspace / "package.json"
    if pkg.is_file():
        try:
            obj = json.loads(pkg.read_text(encoding="utf-8"))
        except Exception:
            obj = {}
        repo = obj.get("repository")
        url = ""
        if isinstance(repo, str):
            url = repo
        elif isinstance(repo, dict):
            url = str(repo.get("url") or "")
        if not url:
            url = str(obj.get("homepage") or "")
        ref = parse_git_upstream(url)
        if ref:
            return ref

    cargo = workspace / "Cargo.toml"
    if cargo.is_file():
        text = cargo.read_text(encoding="utf-8", errors="ignore")
        m = re.search(r'(?im)^\s*repository\s*=\s*["\']([^"\']+)["\']', text)
        if m:
            ref = parse_git_upstream(m.group(1))
            if ref:
                return ref

    pyproject = workspace / "pyproject.toml"
    if pyproject.is_file():
        text = pyproject.read_text(encoding="utf-8", errors="ignore")
        for m in re.finditer(r'(?im)^\s*(?:repository|homepage|source)\s*=\s*["\']([^"\']+)["\']', text):
            ref = parse_git_upstream(m.group(1))
            if ref:
                return ref

    setup = workspace / "setup.cfg"
    if setup.is_file():
        text = setup.read_text(encoding="utf-8", errors="ignore")
        m = re.search(r"(?im)^\s*url\s*=\s*(\S+)", text)
        if m:
            ref = parse_git_upstream(m.group(1))
            if ref:
                return ref

    debian_ctrl = workspace / "debian" / "control"
    if debian_ctrl.is_file():
        text = debian_ctrl.read_text(encoding="utf-8", errors="ignore")
        m = re.search(r"(?im)^Source:\s*(\S+)", text)
        if m:
            pkg_name = m.group(1).strip()
            return UpstreamRef(
                kind="debian",
                host="salsa.debian.org",
                slug="debian/%s" % pkg_name,
                display="debian/%s" % pkg_name,
            )
    return None


def infer_upstream_repo(workspace: Path) -> Optional[str]:
    ref = infer_upstream_ref(workspace)
    return ref.slug if ref and ref.kind == "github" else (ref.display if ref else None)


def parse_direct_dependencies(workspace: Path) -> List[Dict[str, str]]:
    """Parse direct dependencies from common manifest files."""
    deps: List[Dict[str, str]] = []
    seen = set()

    def add(ecosystem: str, name: str, version: str = "") -> None:
        key = f"{ecosystem}:{name.lower()}"
        if key in seen:
            return
        seen.add(key)
        deps.append({"ecosystem": ecosystem, "name": name, "version": version or ""})

    go_mod = workspace / "go.mod"
    if go_mod.is_file():
        in_require = False
        for line in go_mod.read_text(encoding="utf-8", errors="ignore").splitlines():
            s = line.strip()
            if s.startswith("require ("):
                in_require = True
                continue
            if in_require and s == ")":
                in_require = False
                continue
            if s.startswith("require ") and not s.startswith("require ("):
                parts = s.split()
                if len(parts) >= 2:
                    mod = parts[1]
                    ver = parts[2] if len(parts) > 2 else ""
                    name = mod.split("/")[-1] if "/" in mod else mod
                    add("go", mod, ver)
                continue
            if in_require:
                parts = s.split()
                if len(parts) >= 2 and not parts[0].startswith("//"):
                    mod = parts[0]
                    ver = parts[1]
                    add("go", mod, ver)

    pkg = workspace / "package.json"
    if pkg.is_file():
        try:
            obj = json.loads(pkg.read_text(encoding="utf-8"))
        except Exception:
            obj = {}
        for name, ver in (obj.get("dependencies") or {}).items():
            if isinstance(name, str):
                add("npm", name, str(ver) if ver else "")

    req_txt = workspace / "requirements.txt"
    if req_txt.is_file():
        for line in req_txt.read_text(encoding="utf-8", errors="ignore").splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            s = re.split(r"[#;]", s, 1)[0].strip()
            if not s or s.startswith("-"):
                continue
            m = re.match(r"^([A-Za-z0-9_.-]+)", s)
            if m:
                add("pypi", m.group(1), "")

    cargo = workspace / "Cargo.toml"
    if cargo.is_file():
        in_deps = False
        for line in cargo.read_text(encoding="utf-8", errors="ignore").splitlines():
            s = line.strip()
            if re.match(r"^\[(.+)?dependencies\]$", s, re.I):
                in_deps = True
                continue
            if s.startswith("[") and in_deps:
                in_deps = False
            if not in_deps or not s or s.startswith("#"):
                continue
            m = re.match(r"^([A-Za-z0-9_-]+)\s*=", s)
            if m and m.group(1) not in {"version", "features", "default-features", "optional", "path", "git", "package"}:
                add("crates", m.group(1), "")

    pyproject = workspace / "pyproject.toml"
    if pyproject.is_file():
        text = pyproject.read_text(encoding="utf-8", errors="ignore")
        block = re.search(r"(?ms)^(?:project\.)?dependencies\s*=\s*\[(.*?)\]", text)
        if block:
            for item in re.findall(r'["\']([A-Za-z0-9_.-]+)', block.group(1)):
                if item.lower() not in {"python", "setuptools", "wheel", "build", "hatchling"}:
                    add("pypi", item, "")

    debian_ctrl = workspace / "debian" / "control"
    if debian_ctrl.is_file():
        text = debian_ctrl.read_text(encoding="utf-8", errors="ignore")
        m = re.search(r"(?im)^Source:\s*(\S+)", text)
        if m:
            add("debian", m.group(1).strip(), "")

    pom = workspace / "pom.xml"
    if pom.is_file():
        text = pom.read_text(encoding="utf-8", errors="ignore")
        for m in re.finditer(
            r"<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>",
            text,
            re.S,
        ):
            gid, aid = m.group(1).strip(), m.group(2).strip()
            add("maven", f"{gid}:{aid}", "")

    return deps[:80]
