from __future__ import annotations

import json
import os
import re
import subprocess
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from app.maintenance.cache import get_cached, set_cached
from app.maintenance.upstream import SOURCE_LABELS, UpstreamRef, go_module_upstream, parse_git_upstream

JsonObj = Union[Dict[str, Any], List[Any]]

_UA = "openMastiff-maintenance/1.0 (+https://openmastiff.local)"


def _http_get(url: str, headers: Optional[Dict[str, str]] = None, timeout: int = 20) -> Optional[str]:
    h = {"User-Agent": _UA, "Accept": "*/*"}
    if headers:
        h.update(headers)
    for attempt in range(3):
        try:
            req = Request(url, headers=h)
            with urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except HTTPError as e:
            if e.code == 404:
                return None
            if e.code in (403, 429) or attempt >= 2:
                return None
        except (URLError, TimeoutError, OSError, ValueError):
            pass
        time.sleep(1.2 * (attempt + 1))
    return None


def _http_get_json(url: str, headers: Optional[Dict[str, str]] = None, timeout: int = 20) -> Optional[JsonObj]:
    raw = _http_get(url, headers=headers, timeout=timeout)
    if not raw:
        return None
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if isinstance(obj, (dict, list)):
        return obj
    return None


def _github_headers() -> Dict[str, str]:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": _UA}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = "Bearer %s" % token
    return headers


def _parse_iso_date(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        s = str(s).strip().replace("Z", "+00:00")
        if re.match(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$", s):
            s = s.replace(" ", "T") + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _days_since(dt: Optional[datetime]) -> Optional[int]:
    if not dt:
        return None
    now = datetime.now(timezone.utc)
    return max(0, (now - dt).days)


def _repo_base(source: str, repo: str) -> Dict[str, Any]:
    return {
        "source": source,
        "source_label": SOURCE_LABELS.get(source, source),
        "repo": repo,
        "status": "unknown",
        "archived": None,
        "last_commit_days": None,
        "last_release_days": None,
        "commits_90d": None,
        "open_issues_count": None,
        "stars": None,
        "contributors_count": None,
        "pushed_at": None,
        "error": None,
    }


def _fetch_contributors_count(api_url: str, headers: Optional[Dict[str, str]] = None) -> Optional[int]:
    h = {"User-Agent": _UA, "Accept": "application/json"}
    if headers:
        h.update(headers)
    try:
        req = Request(api_url, headers=h)
        with urlopen(req, timeout=20) as resp:
            link = resp.headers.get("Link") or resp.headers.get("link") or ""
            raw = resp.read().decode("utf-8", errors="replace")
        last = re.search(r"[?&]page=(\d+)>;\s*rel=\"last\"", link)
        if last:
            return int(last.group(1))
        data = json.loads(raw) if raw else []
        return len(data) if isinstance(data, list) else 0
    except Exception:
        return None


def _atom_activity(url: str) -> Dict[str, Optional[int]]:
    raw = _http_get(url, headers={"Accept": "application/atom+xml, application/xml, text/xml"})
    out = {"last_commit_days": None, "commits_90d": None}
    if not raw:
        return out
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return out
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"
    dates: List[datetime] = []
    for tag in ("updated", "published"):
        for el in root.iter("%s%s" % (ns, tag)):
            dt = _parse_iso_date(el.text)
            if dt:
                dates.append(dt)
    if not dates:
        return out
    out["last_commit_days"] = _days_since(max(dates))
    since = datetime.now(timezone.utc) - timedelta(days=90)
    out["commits_90d"] = sum(1 for d in dates if d >= since)
    return out


def fetch_local_git(workspace: Path) -> Dict[str, Any]:
    """从已物化的 Git 工作区读取提交/标签活跃度，不依赖托管平台 API。"""
    ws = Path(workspace)
    git_meta = ws / ".git"
    out: Dict[str, Any] = {
        "status": "unknown",
        "last_commit_days": None,
        "last_release_days": None,
        "commits_90d": None,
        "error": None,
    }
    if not git_meta.exists():
        out["error"] = "workspace has no .git"
        return out

    def _git(*args: str) -> str:
        try:
            r = subprocess.run(
                ["git", "-C", str(ws), *args],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired):
            return ""
        if r.returncode != 0:
            return ""
        return (r.stdout or "").strip()

    last = _parse_iso_date(_git("log", "-1", "--format=%cI"))
    count_s = _git("rev-list", "--count", "--since=90.days", "HEAD")
    tag_raw = _git(
        "for-each-ref",
        "--count=1",
        "--sort=-creatordate",
        "--format=%(creatordate:iso-strict)",
        "refs/tags",
    )
    tag_dt = _parse_iso_date(tag_raw)
    if last is None and not count_s:
        out["error"] = "local git history unavailable"
        return out
    out["status"] = "ok"
    out["last_commit_days"] = _days_since(last)
    if count_s.isdigit():
        out["commits_90d"] = int(count_s)
    if tag_dt:
        out["last_release_days"] = _days_since(tag_dt)
    return out


def merge_local_git_activity(raw: Dict[str, Any], workspace: Path) -> Dict[str, Any]:
    local = fetch_local_git(workspace)
    if local.get("status") != "ok":
        return raw
    out = dict(raw or {})
    remote_error = out.get("error")
    recovered = str(out.get("status") or "") != "ok"
    for field in ("last_commit_days", "commits_90d", "last_release_days"):
        if out.get(field) is None and local.get(field) is not None:
            out[field] = local.get(field)
    if recovered and out.get("last_commit_days") is not None:
        out["status"] = "ok"
        out["activity_source"] = "local_git"
        if remote_error:
            out["remote_error"] = remote_error
        out["error"] = None
    elif not recovered:
        out.setdefault("activity_source", out.get("source") or "remote")
    return out


def fetch_github_repo(slug: str, cache_ttl_hours: int) -> Dict[str, Any]:
    key = f"github:{slug.lower()}"
    cached = get_cached(key, cache_ttl_hours)
    if cached:
        if cached.get("status") == "ok" and cached.get("contributors_count") is None:
            cached["contributors_count"] = _fetch_contributors_count(
                "https://api.github.com/repos/%s/contributors?per_page=1&anon=true" % slug,
                _github_headers(),
            )
            set_cached(key, cached)
        cached.setdefault("source_label", SOURCE_LABELS["github"])
        return cached

    base = _repo_base("github", slug)
    repo = _http_get_json("https://api.github.com/repos/%s" % slug, headers=_github_headers())
    if not isinstance(repo, dict):
        base["error"] = "github api unavailable or repo not found"
        return base

    pushed = _parse_iso_date(repo.get("pushed_at"))
    base.update(
        {
            "status": "ok",
            "archived": bool(repo.get("archived")),
            "open_issues_count": repo.get("open_issues_count"),
            "stars": repo.get("stargazers_count"),
            "contributors_count": _fetch_contributors_count(
                "https://api.github.com/repos/%s/contributors?per_page=1&anon=true" % slug,
                _github_headers(),
            ),
            "pushed_at": repo.get("pushed_at"),
            "last_commit_days": _days_since(pushed),
        }
    )
    since_param = (datetime.now(timezone.utc) - timedelta(days=90)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    commits = _http_get_json(
        "https://api.github.com/repos/%s/commits?per_page=100&since=%s" % (slug, since_param),
        headers=_github_headers(),
    )
    if isinstance(commits, list):
        since_90 = datetime.now(timezone.utc) - timedelta(days=90)
        count_90 = 0
        for c in commits:
            if not isinstance(c, dict):
                continue
            cd = _parse_iso_date(((c.get("commit") or {}).get("author") or {}).get("date"))
            if cd and cd >= since_90:
                count_90 += 1
        base["commits_90d"] = count_90
    release = _http_get_json("https://api.github.com/repos/%s/releases/latest" % slug, headers=_github_headers())
    if isinstance(release, dict) and release.get("published_at"):
        base["last_release_days"] = _days_since(_parse_iso_date(release.get("published_at")))
    else:
        tags = _http_get_json("https://api.github.com/repos/%s/tags?per_page=1" % slug, headers=_github_headers())
        if isinstance(tags, list) and tags:
            base["last_release_days"] = base.get("last_commit_days")
    set_cached(key, base)
    return base


def fetch_gitee_repo(slug: str, cache_ttl_hours: int) -> Dict[str, Any]:
    key = f"gitee:{slug.lower()}"
    cached = get_cached(key, cache_ttl_hours)
    if cached:
        return cached
    base = _repo_base("gitee", slug)
    token = os.environ.get("GITEE_TOKEN") or ""
    q = ("?access_token=%s" % token) if token else ""
    repo = _http_get_json("https://gitee.com/api/v5/repos/%s%s" % (slug, q))
    if not isinstance(repo, dict):
        base["error"] = "gitee api unavailable or repo not found"
        return base
    pushed = _parse_iso_date(repo.get("pushed_at") or repo.get("updated_at"))
    base.update(
        {
            "status": "ok",
            "archived": None,
            "open_issues_count": repo.get("open_issues_count"),
            "stars": repo.get("stargazers_count") or repo.get("stars_count"),
            "pushed_at": repo.get("pushed_at"),
            "last_commit_days": _days_since(pushed),
        }
    )
    since_param = (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%SZ")
    commits = _http_get_json("https://gitee.com/api/v5/repos/%s/commits?since=%s&per_page=100%s" % (slug, since_param, "&access_token=%s" % token if token else ""))
    if isinstance(commits, list):
        base["commits_90d"] = len(commits)
    rel = _http_get_json("https://gitee.com/api/v5/repos/%s/releases/latest%s" % (slug, q))
    if isinstance(rel, dict) and (rel.get("created_at") or rel.get("released_at")):
        base["last_release_days"] = _days_since(_parse_iso_date(rel.get("created_at") or rel.get("released_at")))
    set_cached(key, base)
    return base


def fetch_atomgit_repo(slug: str, cache_ttl_hours: int, *, kind: str = "atomgit") -> Dict[str, Any]:
    key = f"{kind}:{slug.lower()}"
    cached = get_cached(key, cache_ttl_hours)
    if cached:
        return cached
    base = _repo_base(kind, slug)
    token = os.environ.get("ATOMGIT_TOKEN") or os.environ.get("GITCODE_TOKEN") or ""
    if not token:
        base["error"] = "atomgit api requires Private-Token; public metadata unavailable"
        return base
    headers = {
        "Accept": "application/json",
        "Authorization": "Bearer %s" % token,
        "Private-Token": token,
        "private-token": token,
    }
    api_hosts = ["https://api.atomgit.com", "https://api.gitcode.com"] if kind != "gitcode" else ["https://api.gitcode.com", "https://api.atomgit.com"]
    repo = None
    for root in api_hosts:
        repo = _http_get_json("%s/repos/%s" % (root, slug), headers=headers)
        if isinstance(repo, dict):
            break
        repo = _http_get_json("%s/api/v5/repos/%s" % (root, slug), headers=headers)
        if isinstance(repo, dict):
            break
    if not isinstance(repo, dict):
        base["error"] = "%s api unavailable or repo not found" % kind
        return base
    pushed = _parse_iso_date(repo.get("pushed_at") or repo.get("updated_at"))
    base.update(
        {
            "status": "ok",
            "archived": bool(repo.get("archived")) if repo.get("archived") is not None else None,
            "open_issues_count": repo.get("open_issues_count"),
            "stars": repo.get("stargazers_count") or repo.get("stars_count"),
            "pushed_at": repo.get("pushed_at") or repo.get("updated_at"),
            "last_commit_days": _days_since(pushed),
        }
    )
    set_cached(key, base)
    return base


def fetch_gitlab_project(host: str, slug: str, cache_ttl_hours: int) -> Dict[str, Any]:
    key = f"gitlab:{host.lower()}:{slug.lower()}"
    cached = get_cached(key, cache_ttl_hours)
    if cached:
        return cached
    display = "%s/%s" % (host, slug)
    base = _repo_base("gitlab", display)
    token = os.environ.get("GITLAB_TOKEN") or ""
    headers = {"Accept": "application/json"}
    if token:
        headers["PRIVATE-TOKEN"] = token
    pid = quote(slug, safe="")
    proj = _http_get_json("https://%s/api/v4/projects/%s" % (host, pid), headers=headers)
    if not isinstance(proj, dict):
        base["error"] = "gitlab api unavailable or project not found"
        return base
    activity = _parse_iso_date(proj.get("last_activity_at") or proj.get("updated_at"))
    base.update(
        {
            "status": "ok",
            "archived": bool(proj.get("archived")),
            "open_issues_count": proj.get("open_issues_count"),
            "stars": proj.get("star_count"),
            "pushed_at": proj.get("last_activity_at"),
            "last_commit_days": _days_since(activity),
        }
    )
    since_param = (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%SZ")
    commits = _http_get_json(
        "https://%s/api/v4/projects/%s/repository/commits?since=%s&per_page=100" % (host, pid, since_param),
        headers=headers,
    )
    if isinstance(commits, list):
        base["commits_90d"] = len(commits)
    rels = _http_get_json("https://%s/api/v4/projects/%s/releases?per_page=1" % (host, pid), headers=headers)
    if isinstance(rels, list) and rels and isinstance(rels[0], dict):
        base["last_release_days"] = _days_since(_parse_iso_date(rels[0].get("released_at") or rels[0].get("created_at")))
    set_cached(key, base)
    return base


def fetch_bitbucket_repo(slug: str, cache_ttl_hours: int) -> Dict[str, Any]:
    key = f"bitbucket:{slug.lower()}"
    cached = get_cached(key, cache_ttl_hours)
    if cached:
        return cached
    base = _repo_base("bitbucket", slug)
    repo = _http_get_json("https://api.bitbucket.org/2.0/repositories/%s" % slug)
    if not isinstance(repo, dict):
        base["error"] = "bitbucket api unavailable or repo not found"
        return base
    updated = _parse_iso_date(repo.get("updated_on"))
    base.update(
        {
            "status": "ok",
            "stars": repo.get("forks_count"),
            "pushed_at": repo.get("updated_on"),
            "last_commit_days": _days_since(updated),
        }
    )
    commits = _http_get_json("https://api.bitbucket.org/2.0/repositories/%s/commits?pagelen=100" % slug)
    if isinstance(commits, dict) and isinstance(commits.get("values"), list):
        since = datetime.now(timezone.utc) - timedelta(days=90)
        n = 0
        for c in commits["values"]:
            dt = _parse_iso_date(((c.get("date") if isinstance(c, dict) else None)))
            if dt and dt >= since:
                n += 1
        base["commits_90d"] = n
    set_cached(key, base)
    return base


def fetch_kernel_repo(slug: str, cache_ttl_hours: int) -> Dict[str, Any]:
    key = f"kernel:{slug.lower()}"
    cached = get_cached(key, cache_ttl_hours)
    if cached:
        return cached
    display = "git.kernel.org/%s" % slug.strip("/")
    base = _repo_base("kernel", display)
    path = slug.strip("/")
    if not path.endswith(".git"):
        path = path + ".git"
    atom = _atom_activity("https://git.kernel.org/%s/atom" % path)
    if atom.get("last_commit_days") is None:
        atom = _atom_activity("https://git.kernel.org/%s/log/?format=atom" % path)
    if atom.get("last_commit_days") is not None:
        base["status"] = "ok"
        base["last_commit_days"] = atom.get("last_commit_days")
        base["commits_90d"] = atom.get("commits_90d")
    if "linux" in path:
        rel = _http_get_json("https://www.kernel.org/releases.json")
        latest = None
        if isinstance(rel, dict):
            latest = rel.get("latest_stable") or rel.get("latest_stable_ts")
            releases = rel.get("releases")
            if isinstance(releases, list):
                dates = []
                for item in releases:
                    if not isinstance(item, dict):
                        continue
                    dt = _parse_iso_date(item.get("released") or item.get("releasedate") or item.get("date"))
                    if dt:
                        dates.append(dt)
                if dates:
                    base["last_release_days"] = _days_since(max(dates))
                    base["status"] = "ok"
            elif isinstance(latest, dict):
                base["last_release_days"] = _days_since(_parse_iso_date(latest.get("released")))
                base["status"] = "ok"
        if base.get("status") != "ok":
            # 镜像到 GitHub torvalds/linux 作为补充
            if "torvalds/linux" in path:
                gh = fetch_github_repo("torvalds/linux", cache_ttl_hours)
                if gh.get("status") == "ok":
                    base.update({k: gh.get(k) for k in ("last_commit_days", "last_release_days", "commits_90d", "stars", "open_issues_count", "archived")})
                    base["status"] = "ok"
                    base["mirror"] = "github.com/torvalds/linux"
    if base.get("status") != "ok":
        base["error"] = "kernel.org metadata unavailable"
        return base
    set_cached(key, base)
    return base


def fetch_gitea_repo(host: str, slug: str, cache_ttl_hours: int, *, kind: str = "gitea") -> Dict[str, Any]:
    key = f"{kind}:{host}:{slug.lower()}"
    cached = get_cached(key, cache_ttl_hours)
    if cached:
        return cached
    display = "%s/%s" % (host, slug)
    base = _repo_base(kind, display)
    repo = _http_get_json("https://%s/api/v1/repos/%s" % (host, slug))
    if not isinstance(repo, dict):
        base["error"] = "gitea api unavailable or repo not found"
        return base
    pushed = _parse_iso_date(repo.get("updated_at") or repo.get("pushed_at"))
    base.update(
        {
            "status": "ok",
            "archived": bool(repo.get("archived")) if "archived" in repo else None,
            "open_issues_count": repo.get("open_issues_count"),
            "stars": repo.get("stars_count") or repo.get("stars"),
            "pushed_at": repo.get("updated_at"),
            "last_commit_days": _days_since(pushed),
        }
    )
    set_cached(key, base)
    return base


def fetch_upstream(ref: UpstreamRef, cache_ttl_hours: int) -> Dict[str, Any]:
    if ref.kind == "github":
        data = fetch_github_repo(ref.slug, cache_ttl_hours)
    elif ref.kind == "gitee":
        data = fetch_gitee_repo(ref.slug, cache_ttl_hours)
    elif ref.kind in {"atomgit", "gitcode"}:
        data = fetch_atomgit_repo(ref.slug, cache_ttl_hours, kind=ref.kind)
    elif ref.kind == "gitlab":
        data = fetch_gitlab_project(ref.host, ref.slug, cache_ttl_hours)
    elif ref.kind == "kernel":
        data = fetch_kernel_repo(ref.slug, cache_ttl_hours)
    elif ref.kind == "apache":
        data = fetch_github_repo(ref.slug, cache_ttl_hours)
        data["source"] = "apache"
        data["source_label"] = SOURCE_LABELS["apache"]
        data["repo"] = ref.display
        if data.get("status") != "ok":
            repo = ref.slug.split("/")[-1]
            act = _atom_activity("https://gitbox.apache.org/repos/asf?p=%s.git;a=atom" % repo)
            if act.get("last_commit_days") is not None:
                data = _repo_base("apache", ref.display)
                data.update({"status": "ok", **act})
    elif ref.kind == "bitbucket":
        data = fetch_bitbucket_repo(ref.slug, cache_ttl_hours)
    elif ref.kind in {"codeberg", "gitea", "savannah", "sourcehut"}:
        data = fetch_gitea_repo(ref.host, ref.slug, cache_ttl_hours, kind=ref.kind)
        if data.get("status") != "ok" and ref.kind in {"savannah", "sourcehut"}:
            atom_urls = {
                "savannah": "https://%s/cgit/%s.git/atom" % (ref.host, ref.slug.split("/")[-1]),
                "sourcehut": "https://%s/%s/log/rss.xml" % (ref.host, ref.slug),
            }
            act = _atom_activity(atom_urls.get(ref.kind) or "")
            if act.get("last_commit_days") is not None:
                data = _repo_base(ref.kind, ref.display)
                data.update({"status": "ok", **act})
    else:
        data = fetch_gitea_repo(ref.host, ref.slug, cache_ttl_hours)
        if data.get("status") != "ok":
            data = fetch_gitlab_project(ref.host, ref.slug, cache_ttl_hours)
    data["repo"] = data.get("repo") or ref.display
    data["source"] = data.get("source") or ref.kind
    data["source_label"] = data.get("source_label") or SOURCE_LABELS.get(ref.kind, ref.kind)
    return data


def _attach_vcs(meta: Dict[str, Any], cache_ttl_hours: int, *urls: str) -> Dict[str, Any]:
    for url in urls:
        if not url:
            continue
        ref = parse_git_upstream(str(url))
        if not ref:
            continue
        vcs = fetch_upstream(ref, cache_ttl_hours)
        if vcs.get("status") == "ok":
            meta["vcs"] = vcs
            meta["github_slug"] = ref.slug if ref.kind == "github" else meta.get("github_slug")
            if ref.kind == "github":
                meta["github"] = vcs
            for field in ("last_commit_days", "last_release_days", "commits_90d", "archived", "stars", "open_issues_count"):
                if meta.get(field) is None and vcs.get(field) is not None:
                    meta[field] = vcs.get(field)
            break
    return meta


def fetch_pypi_package(name: str, cache_ttl_hours: int) -> Dict[str, Any]:
    key = f"pypi:{name.lower()}"
    cached = get_cached(key, cache_ttl_hours)
    if cached:
        return cached

    base: Dict[str, Any] = {
        "source": "pypi",
        "source_label": SOURCE_LABELS["pypi"],
        "name": name,
        "status": "unknown",
        "last_release_days": None,
        "version": None,
        "error": None,
    }
    data = _http_get_json("https://pypi.org/pypi/%s/json" % name)
    if not isinstance(data, dict):
        base["error"] = "pypi api unavailable"
        set_cached(key, base)
        return base

    info = data.get("info") or {}
    releases = data.get("releases") or {}
    latest = str(info.get("version") or "")
    base["version"] = latest
    base["status"] = "ok"

    dates: List[datetime] = []
    for _ver, files in releases.items():
        if not isinstance(files, list):
            continue
        for f in files:
            if isinstance(f, dict) and f.get("upload_time"):
                d = _parse_iso_date(f["upload_time"])
                if d:
                    dates.append(d)
    if dates:
        base["last_release_days"] = _days_since(max(dates))

    urls = []
    project_urls = info.get("project_urls") if isinstance(info.get("project_urls"), dict) else {}
    for k in ("Source", "Source Code", "Repository", "Homepage", "Home", "Code"):
        if project_urls.get(k):
            urls.append(str(project_urls.get(k)))
    if info.get("home_page"):
        urls.append(str(info.get("home_page")))
    _attach_vcs(base, cache_ttl_hours, *urls)
    set_cached(key, base)
    return base


def fetch_npm_package(name: str, cache_ttl_hours: int) -> Dict[str, Any]:
    key = f"npm:{name.lower()}"
    cached = get_cached(key, cache_ttl_hours)
    if cached:
        return cached

    base: Dict[str, Any] = {
        "source": "npm",
        "source_label": SOURCE_LABELS["npm"],
        "name": name,
        "status": "unknown",
        "last_release_days": None,
        "version": None,
        "error": None,
    }
    enc = name.replace("/", "%2F")
    data = _http_get_json("https://registry.npmjs.org/%s" % enc)
    if not isinstance(data, dict):
        base["error"] = "npm registry unavailable"
        set_cached(key, base)
        return base

    base["status"] = "ok"
    dist_tags = data.get("dist-tags") or {}
    latest = str(dist_tags.get("latest") or "")
    base["version"] = latest
    time_map = data.get("time") or {}
    if isinstance(time_map, dict):
        t = time_map.get(latest) or time_map.get("modified")
        if t:
            base["last_release_days"] = _days_since(_parse_iso_date(str(t)))

    repo = data.get("repository")
    repo_url = ""
    if isinstance(repo, str):
        repo_url = repo
    elif isinstance(repo, dict):
        repo_url = str(repo.get("url") or "")
    homepage = str(data.get("homepage") or "")
    _attach_vcs(base, cache_ttl_hours, repo_url, homepage)
    set_cached(key, base)
    return base


def fetch_crates_package(name: str, cache_ttl_hours: int) -> Dict[str, Any]:
    key = f"crates:{name.lower()}"
    cached = get_cached(key, cache_ttl_hours)
    if cached:
        return cached
    base: Dict[str, Any] = {
        "source": "crates",
        "source_label": SOURCE_LABELS["crates"],
        "name": name,
        "status": "unknown",
        "last_release_days": None,
        "version": None,
        "error": None,
    }
    data = _http_get_json("https://crates.io/api/v1/crates/%s" % name, headers={"Accept": "application/json"})
    if not isinstance(data, dict):
        base["error"] = "crates.io api unavailable"
        set_cached(key, base)
        return base
    crate = data.get("crate") if isinstance(data.get("crate"), dict) else {}
    versions = data.get("versions") if isinstance(data.get("versions"), list) else []
    base["status"] = "ok"
    base["version"] = str(crate.get("max_stable_version") or crate.get("max_version") or "")
    dates = []
    for v in versions:
        if isinstance(v, dict):
            dt = _parse_iso_date(v.get("updated_at") or v.get("created_at"))
            if dt:
                dates.append(dt)
    dt = _parse_iso_date(crate.get("updated_at"))
    if dt:
        dates.append(dt)
    if dates:
        base["last_release_days"] = _days_since(max(dates))
    _attach_vcs(base, cache_ttl_hours, str(crate.get("repository") or ""), str(crate.get("homepage") or ""))
    set_cached(key, base)
    return base


def fetch_go_module(module: str, cache_ttl_hours: int) -> Dict[str, Any]:
    key = f"go:{module.lower()}"
    cached = get_cached(key, cache_ttl_hours)
    if cached:
        return cached

    base: Dict[str, Any] = {
        "source": "go",
        "source_label": SOURCE_LABELS["go"],
        "name": module,
        "status": "unknown",
        "last_release_days": None,
        "version": None,
        "error": None,
    }
    enc = module.replace("/", "%2F")
    data = _http_get_json("https://proxy.golang.org/%s/@latest" % enc)
    if isinstance(data, dict) and data.get("Version"):
        base["status"] = "ok"
        base["version"] = str(data["Version"])
        ts = data.get("Time")
        if ts:
            base["last_release_days"] = _days_since(_parse_iso_date(str(ts)))

    ref = go_module_upstream(module)
    if ref:
        vcs = fetch_upstream(ref, cache_ttl_hours)
        if vcs.get("status") == "ok":
            base["status"] = "ok"
            base["vcs"] = vcs
            if ref.kind == "github":
                base["github"] = vcs
            for field in ("last_commit_days", "last_release_days", "commits_90d", "archived", "stars", "open_issues_count"):
                if vcs.get(field) is not None:
                    base[field] = vcs.get(field)

    set_cached(key, base)
    return base


def fetch_debian_package(name: str, cache_ttl_hours: int) -> Dict[str, Any]:
    key = f"debian:{name.lower()}"
    cached = get_cached(key, cache_ttl_hours)
    if cached:
        return cached
    base: Dict[str, Any] = {
        "source": "debian",
        "source_label": SOURCE_LABELS["debian"],
        "name": name,
        "status": "unknown",
        "last_release_days": None,
        "version": None,
        "error": None,
    }
    src = _http_get_json("https://sources.debian.org/api/src/%s/" % name)
    if isinstance(src, dict) and src.get("package"):
        base["status"] = "ok"
        versions = src.get("versions")
        if isinstance(versions, dict) and versions:
            base["version"] = sorted(versions.keys())[-1]
    madison = _http_get("https://qa.debian.org/madison.php?package=%s&text=on" % quote(name))
    if madison:
        dates = re.findall(r"(\d{4}-\d{2}-\d{2})", madison)
        if dates:
            base["last_release_days"] = _days_since(_parse_iso_date(max(dates) + "T00:00:00Z"))
            base["status"] = "ok"
        first = madison.strip().splitlines()[0] if madison.strip() else ""
        parts = first.split("|")
        if len(parts) >= 2 and not base.get("version"):
            base["version"] = parts[1].strip()
    salsa = fetch_gitlab_project("salsa.debian.org", "debian/%s" % name, cache_ttl_hours)
    if salsa.get("status") != "ok":
        salsa = fetch_gitlab_project("salsa.debian.org", "%s/%s" % (name, name), cache_ttl_hours)
    if salsa.get("status") == "ok":
        base["status"] = "ok"
        base["vcs"] = salsa
        for field in ("last_commit_days", "last_release_days", "commits_90d", "stars"):
            if salsa.get(field) is not None:
                base[field] = salsa.get(field)
    if base.get("status") != "ok":
        base["error"] = "debian metadata unavailable"
        set_cached(key, base)
        return base
    set_cached(key, base)
    return base


def fetch_dependency_meta(dep: Dict[str, str], cache_ttl_hours: int) -> Dict[str, Any]:
    eco = dep.get("ecosystem") or ""
    name = dep.get("name") or ""
    version = dep.get("version") or ""
    if eco == "pypi":
        meta = fetch_pypi_package(name, cache_ttl_hours)
    elif eco == "npm":
        meta = fetch_npm_package(name, cache_ttl_hours)
    elif eco == "go":
        meta = fetch_go_module(name, cache_ttl_hours)
    elif eco == "crates":
        meta = fetch_crates_package(name, cache_ttl_hours)
    elif eco == "debian":
        meta = fetch_debian_package(name, cache_ttl_hours)
    elif eco == "maven":
        meta = {"source": "maven", "source_label": SOURCE_LABELS["maven"], "name": name, "status": "unknown", "last_release_days": None, "error": "maven metadata not implemented"}
    else:
        meta = {"source": eco, "name": name, "status": "unknown", "error": "unsupported ecosystem"}

    meta["ecosystem"] = eco
    meta["declared_version"] = version
    slug = meta.get("github_slug")
    if slug and "github" not in meta:
        meta["github"] = fetch_github_repo(slug, cache_ttl_hours)
    return meta
