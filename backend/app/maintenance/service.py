from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from app.maintenance.collectors import fetch_dependency_meta, fetch_upstream, merge_local_git_activity
from app.maintenance.deps_parser import infer_upstream_ref, parse_direct_dependencies
from app.maintenance.gate import aggregate_maintenance_gate, evaluate_dependency_gate, evaluate_upstream_gate
from app.maintenance.scoring import score_entity
from app.maintenance.upstream import parse_git_upstream


def collect_maintenance_report(
    *,
    workspace: Path,
    source: Dict[str, Any],
    business_criticality: str,
    maintenance_policy: Dict[str, Any],
) -> Dict[str, Any]:
    if not maintenance_policy.get("enabled", True):
        return {
            "enabled": False,
            "upstream": None,
            "dependencies": [],
            "overall": {"status": "pass", "reason": "maintenance checks disabled"},
        }

    ttl = int(maintenance_policy.get("cache_ttl_hours") or 24)
    weights = maintenance_policy.get("score_weights") or {}
    crit = (business_criticality or "medium").lower()
    fetch_remote = maintenance_policy.get("fetch_remote_metadata", True)

    upstream_ref = None
    if source.get("type") == "git":
        git = source.get("git") or {}
        upstream_ref = parse_git_upstream(str(git.get("repo_url") or ""))
    if not upstream_ref:
        upstream_ref = infer_upstream_ref(workspace)

    upstream_block: Optional[Dict[str, Any]] = None
    upstream_gate = "pass"
    if upstream_ref:
        if fetch_remote:
            if upstream_ref.kind == "debian":
                from app.maintenance.collectors import fetch_debian_package

                raw = fetch_debian_package(upstream_ref.slug.split("/")[-1], ttl)
                raw["repo"] = raw.get("repo") or upstream_ref.display
            else:
                raw = fetch_upstream(upstream_ref, ttl)
        else:
            raw = {
                "source": upstream_ref.kind,
                "source_label": upstream_ref.kind,
                "repo": upstream_ref.display,
                "status": "unknown",
                "error": "remote metadata fetch disabled by policy",
            }
        raw = merge_local_git_activity(raw, workspace)
        scored = score_entity(raw, weights)
        scored["repo"] = raw.get("repo") or upstream_ref.display
        scored["source"] = raw.get("source") or upstream_ref.kind
        scored["source_label"] = raw.get("source_label") or upstream_ref.kind
        scored["error"] = raw.get("error")
        if raw.get("activity_source"):
            scored["activity_source"] = raw.get("activity_source")
        if raw.get("remote_error"):
            scored["remote_error"] = raw.get("remote_error")
        gate = evaluate_upstream_gate(scored, crit, maintenance_policy)
        upstream_block = {**scored, "repo": scored["repo"], "gate": gate}
        upstream_gate = gate["status"]
    else:
        display = None
        if source.get("type") == "git":
            display = str((source.get("git") or {}).get("repo_url") or "").strip() or None
        raw = {
            "source": "git",
            "source_label": "Git",
            "repo": display,
            "status": "unknown",
            "error": "no public upstream repo detected",
        }
        raw = merge_local_git_activity(raw, workspace)
        if raw.get("status") == "ok":
            scored = score_entity(raw, weights)
            scored["repo"] = raw.get("repo") or display
            scored["source"] = raw.get("source") or "git"
            scored["source_label"] = raw.get("source_label") or "Git"
            scored["error"] = raw.get("error")
            if raw.get("activity_source"):
                scored["activity_source"] = raw.get("activity_source")
            gate = evaluate_upstream_gate(scored, crit, maintenance_policy)
            upstream_block = {**scored, "repo": scored.get("repo"), "gate": gate}
            upstream_gate = gate["status"]
        else:
            rules_map = (maintenance_policy or {}).get("rules_by_criticality") or {}
            rules = rules_map.get(crit) or rules_map.get("medium") or {}
            unknown_gate = str(rules.get("unknown_gate") or "fail")
            if str(unknown_gate).lower() == "pending_legal":
                unknown_gate = "fail"
            if rules.get("advisory_only"):
                unknown_gate = "pass"
            upstream_block = {
                "repo": display,
                "status": "unknown",
                "score": None,
                "gate": {"status": unknown_gate, "reason": "no public upstream repo detected"},
            }
            upstream_gate = unknown_gate

    deps_meta: List[Dict[str, Any]] = []
    dep_gates: List[str] = []
    max_deps = int(maintenance_policy.get("max_dependencies") or 20)
    deps_list = parse_direct_dependencies(workspace)[:max_deps]
    for dep in deps_list:
        if fetch_remote:
            raw = fetch_dependency_meta(dep, ttl)
        else:
            raw = {
                "source": dep.get("ecosystem") or "unknown",
                "name": dep.get("name") or "",
                "status": "unknown",
                "error": "remote metadata fetch disabled by policy",
            }
        scored = score_entity(raw, weights)
        gate = evaluate_dependency_gate(scored, crit, maintenance_policy)
        item = {
            "name": dep["name"],
            "version": dep.get("version") or raw.get("version") or "",
            "ecosystem": dep["ecosystem"],
            **scored,
            "gate": gate,
        }
        deps_meta.append(item)
        dep_gates.append(gate["status"])

    overall = aggregate_maintenance_gate([upstream_gate] + dep_gates)
    return {
        "enabled": True,
        "upstream": upstream_block,
        "dependencies": deps_meta,
        "overall": overall,
    }


def maintenance_findings(
    request_id: str,
    scan_run_id: str,
    report: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Build finding documents for low-maintenance items."""
    from app.schemas import new_id, now_utc

    findings: List[Dict[str, Any]] = []
    ts = now_utc()

    up = report.get("upstream")
    if isinstance(up, dict) and up.get("gate", {}).get("status") in {"fail", "pending_legal"}:
        slug = up.get("repo") or "unknown"
        findings.append(
            {
                "finding_id": new_id(),
                "request_id": request_id,
                "scan_run_id": scan_run_id,
                "fingerprint": f"maintenance:upstream:{slug}",
                "category": "maintenance",
                "severity": "high" if up["gate"]["status"] == "fail" else "medium",
                "title": f"上游仓库维护性风险: {slug}",
                "detail": up.get("gate", {}).get("reason") or "",
                "score": up.get("score"),
                "created_at": ts,
            }
        )

    for dep in report.get("dependencies") or []:
        if not isinstance(dep, dict):
            continue
        g = dep.get("gate") or {}
        if g.get("status") not in {"fail", "pending_legal"}:
            continue
        eco = dep.get("ecosystem") or "unknown"
        name = dep.get("name") or "unknown"
        findings.append(
            {
                "finding_id": new_id(),
                "request_id": request_id,
                "scan_run_id": scan_run_id,
                "fingerprint": f"maintenance:dep:{eco}:{name}",
                "category": "maintenance",
                "severity": "high" if g.get("status") == "fail" else "medium",
                "title": f"依赖维护性风险: {name}",
                "detail": g.get("reason") or "",
                "score": dep.get("score"),
                "ecosystem": eco,
                "version": dep.get("version"),
                "created_at": ts,
            }
        )
    return findings
