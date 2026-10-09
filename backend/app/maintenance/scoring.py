from __future__ import annotations

from typing import Any, Dict, Optional


def _dim_release(last_release_days: Optional[int]) -> int:
    if last_release_days is None:
        return 1
    if last_release_days <= 90:
        return 2
    if last_release_days <= 180:
        return 1
    if last_release_days <= 365:
        return 1
    return 0


def _dim_commit(last_commit_days: Optional[int], commits_90d: Optional[int]) -> int:
    if commits_90d is not None:
        if commits_90d >= 10:
            return 2
        if commits_90d >= 3:
            return 1
    if last_commit_days is None:
        return 1
    if last_commit_days <= 90:
        return 2
    if last_commit_days <= 180:
        return 1
    if last_commit_days <= 365:
        return 1
    return 0


def _dim_maintainer(archived: Optional[bool]) -> int:
    if archived is True:
        return 0
    if archived is False:
        return 2
    return 1


def _dim_community(open_issues: Optional[int], stars: Optional[int]) -> int:
    if stars is not None and stars >= 500:
        return 2
    if stars is not None and stars >= 50:
        return 1
    if open_issues is not None and open_issues < 200:
        return 1
    return 1


def score_entity(meta: Dict[str, Any], weights: Dict[str, float]) -> Dict[str, Any]:
    """Compute maintenance score 0-100 from collected metadata."""
    gh = meta.get("github") if isinstance(meta.get("github"), dict) else None
    vcs = None
    for key in ("vcs", "github", "gitee", "gitlab", "atomgit", "gitcode", "kernel"):
        cand = meta.get(key)
        if isinstance(cand, dict) and (cand.get("status") == "ok" or gh is None):
            vcs = cand
            if cand.get("status") == "ok":
                break
    if vcs is None:
        vcs = gh if isinstance(gh, dict) else meta
    if not isinstance(vcs, dict):
        vcs = meta

    last_release_days = meta.get("last_release_days")
    if last_release_days is None and isinstance(vcs, dict):
        last_release_days = vcs.get("last_release_days")

    last_commit_days = meta.get("last_commit_days")
    commits_90d = meta.get("commits_90d")
    archived = meta.get("archived")
    if archived is None and isinstance(vcs, dict):
        archived = vcs.get("archived")
    if last_commit_days is None and isinstance(vcs, dict):
        last_commit_days = vcs.get("last_commit_days")
    if commits_90d is None and isinstance(vcs, dict):
        commits_90d = vcs.get("commits_90d")

    open_issues = meta.get("open_issues_count")
    stars = meta.get("stars")
    contributors = meta.get("contributors_count")
    if isinstance(vcs, dict):
        open_issues = open_issues if open_issues is not None else vcs.get("open_issues_count")
        stars = stars if stars is not None else vcs.get("stars")
        contributors = contributors if contributors is not None else vcs.get("contributors_count")

    dimensions = {
        "release": _dim_release(last_release_days if isinstance(last_release_days, int) else None),
        "commit": _dim_commit(
            last_commit_days if isinstance(last_commit_days, int) else None,
            commits_90d if isinstance(commits_90d, int) else None,
        ),
        "maintainer": _dim_maintainer(archived if isinstance(archived, bool) else None),
        "community": _dim_community(
            open_issues if isinstance(open_issues, int) else None,
            stars if isinstance(stars, int) else None,
        ),
        "security": 1,
    }

    status = str(meta.get("status") or "unknown")
    w = weights or {}
    total_w = sum(float(w.get(k, 0.2)) for k in dimensions)
    if total_w <= 0:
        total_w = 1.0
    raw_score = 0.0
    for k, v in dimensions.items():
        raw_score += (v / 2.0) * 100.0 * (float(w.get(k, 0.2)) / total_w)

    return {
        # 未采到元数据时五个维度都是中性 1 分，加权后恒为 50，不能当成真实评分
        "score": None if status != "ok" else int(round(min(100, max(0, raw_score)))),
        "dimensions": dimensions,
        "last_release_days": last_release_days,
        "last_commit_days": last_commit_days,
        "commits_90d": commits_90d,
        "archived": archived,
        "status": status,
        "error": meta.get("error"),
        "stars": stars,
        "open_issues_count": open_issues,
        "contributors_count": contributors,
    }
