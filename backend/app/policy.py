from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class Policy:
    raw: dict

    def to_json_bytes(self) -> bytes:
        return json.dumps(self.raw, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def sha256(self) -> str:
        return sha256(self.to_json_bytes()).hexdigest()


_ACTIVE_POLICY_ID = "active_policy"


def _promote_release_fail(rules: Dict[str, Any]) -> None:
    """原先「超期转法务」并入不通过阈值，维护性不再产生 PendingLegal。"""
    pending = rules.get("pending_legal_if_last_release_days_gt")
    if pending is None:
        return
    try:
        pending_days = int(pending)
    except (TypeError, ValueError):
        rules.pop("pending_legal_if_last_release_days_gt", None)
        return
    existing = rules.get("fail_if_last_release_days_gt")
    try:
        existing_days = int(existing) if existing is not None else None
    except (TypeError, ValueError):
        existing_days = None
    if existing_days is None or pending_days < existing_days:
        rules["fail_if_last_release_days_gt"] = pending_days
    rules.pop("pending_legal_if_last_release_days_gt", None)


def sanitize_policy_raw(raw: Dict[str, Any]) -> Dict[str, Any]:
    """法务复核仅适用于许可证；维护性门禁只保留 pass/fail。"""
    out = copy.deepcopy(raw) if isinstance(raw, dict) else {}
    for key, cfg in (
        ("bandit", {"enabled": True, "block_if_high_gt": 0}),
        ("pmd", {"enabled": True, "block_if_high_gt": 0}),
        ("cargo_audit", {"enabled": True, "block_if_high_gt": 0}),
        ("eslint", {"enabled": True, "block_if_high_gt": 0}),
        ("cve", {
            "enabled": True,
            "engines": ["grype"],
            "block_if_critical_gt": 0,
            "block_if_high_gt": 0,
            "ignore_unfixed": False,
            "fail_if_engine_missing": False,
            "repo_advisory": {"enabled": True},
            "self": {
                "block_if_critical_gt": 0,
                "block_if_high_gt": 0,
                "allow_accepted_risk": False,
                "allow_false_positive": True,
            },
        }),
    ):
        if not isinstance(out.get(key), dict):
            out[key] = dict(cfg)
        else:
            for k, v in cfg.items():
                out[key].setdefault(k, v)
            if key == "cve":
                engines = out[key].get("engines")
                if not isinstance(engines, list) or not engines:
                    out[key]["engines"] = ["grype"]
                else:
                    known = {"grype", "trivy", "osv-scanner", "osv"}
                    cleaned = []
                    seen = set()
                    for item in engines:
                        name = str(item or "").strip().lower()
                        if name == "osv":
                            name = "osv-scanner"
                        if name in known and name not in seen:
                            seen.add(name)
                            cleaned.append(name)
                    out[key]["engines"] = cleaned or ["grype"]
                repo_adv = out[key].get("repo_advisory")
                if not isinstance(repo_adv, dict):
                    repo_adv = {}
                    out[key]["repo_advisory"] = repo_adv
                repo_adv.setdefault("enabled", True)
                self_cfg = out[key].get("self")
                if not isinstance(self_cfg, dict):
                    self_cfg = {}
                    out[key]["self"] = self_cfg
                self_cfg.setdefault("block_if_critical_gt", 0)
                self_cfg.setdefault("block_if_high_gt", 0)
                self_cfg.setdefault("allow_accepted_risk", False)
                self_cfg.setdefault("allow_false_positive", True)
    runner = out.get("runner")
    if not isinstance(runner, dict):
        runner = {}
        out["runner"] = runner
    timeouts = runner.get("timeouts_min")
    if not isinstance(timeouts, dict):
        timeouts = {}
        runner["timeouts_min"] = timeouts
    timeouts.setdefault("lang_sast", 20)
    timeouts.setdefault("cve", 15)
    runner.setdefault("max_upload_mb", 200)
    try:
        concurrent = int(runner.get("max_concurrent_scans") or 2)
    except (TypeError, ValueError):
        concurrent = 2
    runner["max_concurrent_scans"] = max(1, min(concurrent, 64))
    raw_ex = runner.get("exclude_dirs")
    items = []
    if isinstance(raw_ex, str):
        items = [x.strip() for x in raw_ex.replace(",", ";").split(";") if x.strip()]
    elif isinstance(raw_ex, list):
        items = [str(x).strip() for x in raw_ex if str(x).strip()]
    cleaned = []
    seen = set()
    for item in items:
        name = item.replace("\\", "/").strip()
        while name.startswith("./"):
            name = name[2:]
        name = name.strip("/")
        if name.endswith("/**"):
            name = name[:-3].strip("/")
        if name and name not in seen:
            seen.add(name)
            cleaned.append(name)
    if cleaned:
        runner["exclude_dirs"] = cleaned
    maint = out.get("maintenance")
    if not isinstance(maint, dict):
        return out
    rules_map = maint.get("rules_by_criticality")
    if isinstance(rules_map, dict):
        for rules in rules_map.values():
            if not isinstance(rules, dict):
                continue
            if str(rules.get("unknown_gate") or "").lower() == "pending_legal":
                rules["unknown_gate"] = "fail"
            if str(rules.get("fail_downgrade_to") or "").lower() == "pending_legal":
                rules.pop("fail_downgrade_to", None)
            _promote_release_fail(rules)
    dep = maint.get("dependency_thresholds")
    if isinstance(dep, dict):
        _promote_release_fail(dep)
    return out


def load_active_policy() -> Policy:
    """
    Load active policy from MongoDB. Falls back to DEFAULT_POLICY.
    """
    try:
        from app.db import col

        doc = col("policies").find_one({"_id": _ACTIVE_POLICY_ID}, {"raw": 1})
        if doc and isinstance(doc.get("raw"), dict):
            return Policy(raw=sanitize_policy_raw(doc["raw"]))
        # legacy: any document with active=True
        doc = col("policies").find_one({"active": True}, {"_id": 0, "raw": 1})
        if doc and isinstance(doc.get("raw"), dict):
            return Policy(raw=sanitize_policy_raw(doc["raw"]))
    except Exception:
        # keep the scanner pipeline resilient even if policy store is not initialized
        pass
    return DEFAULT_POLICY


def upsert_active_policy(raw: Dict[str, Any]) -> Policy:
    from app.db import col

    cleaned = sanitize_policy_raw(raw)
    col("policies").replace_one(
        {"_id": _ACTIVE_POLICY_ID},
        {"_id": _ACTIVE_POLICY_ID, "active": True, "raw": cleaned},
        upsert=True,
    )
    return Policy(raw=cleaned)


DEFAULT_POLICY = Policy(
    raw={
        "license": {
            "deny_list": ["Commons-Clause"],
            "legal_review_list": ["GPL-2.0", "GPL-3.0", "AGPL-3.0", "SSPL-1.0"],
            "unknown_policy": "legal_review",
            "score_threshold": 80,
        },
        "gosec": {"enabled": True, "block_if_high_gt": 0},
        "cppcheck": {"block_if_error_gt": 0},
        "bandit": {"enabled": True, "block_if_high_gt": 0},
        "pmd": {"enabled": True, "block_if_high_gt": 0},
        "cargo_audit": {"enabled": True, "block_if_high_gt": 0},
        "eslint": {"enabled": True, "block_if_high_gt": 0},
        "cve": {
            "enabled": True,
            "engines": ["grype"],
            "block_if_critical_gt": 0,
            "block_if_high_gt": 0,
            "ignore_unfixed": False,
            "fail_if_engine_missing": False,
            "repo_advisory": {"enabled": True},
            "self": {
                "block_if_critical_gt": 0,
                "block_if_high_gt": 0,
                "allow_accepted_risk": False,
                "allow_false_positive": True,
            },
        },
        "waiver": {
            "max_days": 90,
            "required_fields": ["risk_acceptor", "compensating_controls", "expires_at"],
        },
        "maintenance": {
            "enabled": True,
            # 为 false 时仅解析本地 go.mod/package.json 等，不访问 GitHub/PyPI/npm（不下载软件包）
            "fetch_remote_metadata": True,
            "cache_ttl_hours": 24,
            "score_weights": {
                "release": 0.35,
                "commit": 0.25,
                "maintainer": 0.20,
                "community": 0.10,
                "security": 0.10,
            },
            "rules_by_criticality": {
                "critical": {
                    "fail_if_archived": True,
                    "fail_if_last_commit_days_gt": 365,
                    "fail_if_last_release_days_gt": 365,
                    "fail_if_score_lt": 40,
                    "unknown_gate": "fail",
                },
                "high": {
                    "fail_if_archived": True,
                    "fail_if_last_commit_days_gt": 365,
                    "fail_if_last_release_days_gt": 365,
                    "fail_if_score_lt": 40,
                    "unknown_gate": "fail",
                },
                "medium": {
                    "fail_if_archived": True,
                    "fail_if_last_commit_days_gt": 365,
                    "fail_if_last_release_days_gt": 365,
                    "fail_if_score_lt": 30,
                    "unknown_gate": "fail",
                },
                "low": {
                    "advisory_only": True,
                    "unknown_gate": "pass",
                },
            },
            "dependency_thresholds": {
                "fail_if_last_release_days_gt": 365,
                "fail_if_score_lt": 35,
            },
        },
        "runner": {
            "network_mode_default": "none",
            "exclude_dirs": [
                "vendor",
                "third_party",
                "3rdparty",
                "external",
                ".git",
                "node_modules",
                "build",
                "dist",
                "out",
                "bin",
                "obj",
                ".idea",
                ".vscode",
                ".cache",
                ".github",
            ],
            "timeouts_min": {"license": 30, "gosec": 20, "cppcheck": 30, "lang_sast": 20, "cve": 15},
            "max_upload_mb": 200,
            "max_concurrent_scans": 2,
        },
    }
)

