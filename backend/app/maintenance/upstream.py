from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse


GITHUB_HOSTS = {"github.com", "www.github.com"}
GITEE_HOSTS = {"gitee.com", "www.gitee.com"}
ATOMGIT_HOSTS = {"atomgit.com", "www.atomgit.com"}
GITCODE_HOSTS = {"gitcode.com", "www.gitcode.com", "gitcode.net"}
GITLAB_HOSTS = {
    "gitlab.com",
    "www.gitlab.com",
    "salsa.debian.org",
    "gitlab.gnome.org",
    "gitlab.freedesktop.org",
    "invent.kde.org",
    "gitlab.kitware.com",
    "gitlab.alpinelinux.org",
    "gitlab.haskell.org",
}
KERNEL_HOSTS = {"git.kernel.org", "kernel.org", "www.kernel.org"}
APACHE_HOSTS = {"gitbox.apache.org", "git.apache.org", "svn.apache.org"}
BITBUCKET_HOSTS = {"bitbucket.org", "www.bitbucket.org"}
SAVANNAH_HOSTS = {"git.savannah.gnu.org", "git.savannah.nongnu.org"}
SOURCEHUT_HOSTS = {"git.sr.ht", "sr.ht"}
CODEBERG_HOSTS = {"codeberg.org"}
GNOME_HOSTS = {"gitlab.gnome.org"}

SOURCE_LABELS = {
    "github": "GitHub",
    "gitee": "Gitee",
    "atomgit": "AtomGit",
    "gitcode": "GitCode",
    "gitlab": "GitLab",
    "kernel": "kernel.org",
    "apache": "Apache",
    "bitbucket": "Bitbucket",
    "savannah": "Savannah",
    "sourcehut": "SourceHut",
    "codeberg": "Codeberg",
    "gitea": "Gitea",
    "pypi": "PyPI",
    "npm": "npm",
    "crates": "crates.io",
    "go": "Go module",
    "debian": "Debian",
    "maven": "Maven",
}


@dataclass(frozen=True)
class UpstreamRef:
    kind: str
    host: str
    slug: str
    display: str

    def owner_repo(self) -> Optional[tuple]:
        parts = [p for p in self.slug.split("/") if p]
        if len(parts) >= 2:
            return parts[0], parts[1]
        return None


def _strip_git_suffix(path: str) -> str:
    p = (path or "").strip().strip("/")
    if p.endswith(".git"):
        p = p[:-4]
    return p.strip("/")


def _normalize_url(url: str) -> str:
    u = (url or "").strip()
    if not u:
        return ""
    u = u.replace("git+", "")
    ssh = re.match(r"^git@([^:]+):(.+)$", u)
    if ssh:
        return "https://%s/%s" % (ssh.group(1), ssh.group(2))
    scp = re.match(r"^ssh://(?:git@)?([^/]+)/(.+)$", u)
    if scp:
        return "https://%s/%s" % (scp.group(1), scp.group(2))
    if u.startswith("git://"):
        return "https://" + u[len("git://") :]
    if "://" not in u and u.startswith("github.com/"):
        return "https://" + u
    return u


def _kind_for_host(host: str) -> str:
    h = (host or "").lower()
    if h in GITHUB_HOSTS:
        return "github"
    if h in GITEE_HOSTS:
        return "gitee"
    if h in ATOMGIT_HOSTS:
        return "atomgit"
    if h in GITCODE_HOSTS:
        return "gitcode"
    if h in KERNEL_HOSTS:
        return "kernel"
    if h in APACHE_HOSTS:
        return "apache"
    if h in BITBUCKET_HOSTS:
        return "bitbucket"
    if h in SAVANNAH_HOSTS:
        return "savannah"
    if h in SOURCEHUT_HOSTS:
        return "sourcehut"
    if h in CODEBERG_HOSTS:
        return "codeberg"
    if h in GITLAB_HOSTS or h.startswith("gitlab."):
        return "gitlab"
    return "gitea"


def parse_git_upstream(url: str) -> Optional[UpstreamRef]:
    """Parse a git URL from GitHub / Gitee / AtomGit / GitLab / kernel.org / Apache 等."""
    raw = _normalize_url(url)
    if not raw:
        return None
    try:
        p = urlparse(raw)
    except Exception:
        return None
    host = (p.hostname or "").lower()
    if not host:
        return None
    path = _strip_git_suffix(p.path or "")
    if not path:
        return None
    kind = _kind_for_host(host)

    if kind == "kernel":
        slug = path
        if not slug.startswith("pub/") and "linux" in slug:
            slug = path
        display = "git.kernel.org/%s" % slug
        return UpstreamRef(kind="kernel", host="git.kernel.org", slug=slug, display=display)

    if kind == "apache":
        parts = [x for x in path.split("/") if x]
        repo = parts[-1] if parts else path
        if repo.endswith(".git"):
            repo = repo[:-4]
        if repo:
            return UpstreamRef(kind="apache", host=host, slug="apache/%s" % repo, display="github.com/apache/%s" % repo)
        return None

    if kind == "sourcehut":
        slug = path.lstrip("~")
        return UpstreamRef(kind=kind, host=host, slug=slug, display="%s/%s" % (host, path))

    parts = [x for x in path.split("/") if x]
    if kind == "gitlab":
        if len(parts) < 2:
            return None
        slug = "/".join(parts)
        return UpstreamRef(kind="gitlab", host=host, slug=slug, display="%s/%s" % (host, slug))

    if len(parts) < 2:
        return None
    slug = "%s/%s" % (parts[0], parts[1])
    return UpstreamRef(kind=kind, host=host, slug=slug, display="%s/%s" % (host, slug))


def parse_github_repo_url(url: str) -> Optional[str]:
    """兼容旧接口：仅 GitHub 时返回 owner/repo。"""
    ref = parse_git_upstream(url)
    if ref and ref.kind == "github":
        return ref.slug
    return None


def go_module_upstream(module: str) -> Optional[UpstreamRef]:
    mod = (module or "").strip()
    if not mod:
        return None
    if mod.startswith("golang.org/x/"):
        pkg = mod.split("/")[2] if len(mod.split("/")) >= 3 else ""
        if pkg:
            return UpstreamRef(kind="github", host="github.com", slug="golang/%s" % pkg, display="github.com/golang/%s" % pkg)
    if mod.startswith("github.com/") or mod.startswith("gitee.com/") or mod.startswith("gitlab.com/") or mod.startswith("atomgit.com/") or mod.startswith("gitcode.com/"):
        return parse_git_upstream("https://" + mod)
    if mod.startswith("git.kernel.org/"):
        return parse_git_upstream("https://" + mod)
    if mod.startswith("bitbucket.org/"):
        return parse_git_upstream("https://" + mod)
    if mod.startswith("codeberg.org/") or mod.startswith("gitlab."):
        return parse_git_upstream("https://" + mod)
    return None
