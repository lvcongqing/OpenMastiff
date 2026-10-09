from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from app.settings import settings


def _config_path() -> Path:
    return Path(settings.app_config_file)


def default_config() -> Dict[str, Any]:
    return {
        "initialized": False,
        "auth": {
            "mode": "http",
            "ldap": {
                "server": settings.ldap_server,
                "bind_username": settings.ldap_bind_username,
                "bind_password": settings.ldap_bind_password,
                "account_base": settings.ldap_account_base,
                "account_pattern": settings.ldap_account_pattern,
                "account_ssh_username": settings.ldap_account_ssh_username,
            },
        },
        "roles": {
            "admins": [u.strip().lower() for u in settings.auth_admin_users.split(",") if u.strip()],
            "default_role": settings.auth_default_role,
        },
        "system": {
            "database": {
                "mongo_uri": settings.mongo_uri,
                "redis_url": settings.redis_url,
            },
            "storage": {
                "blob_root": settings.blob_root,
                "work_root": settings.work_root,
            },
            "scanner_mode": settings.scanner_mode,
        },
        "security": {
            "jwt_secret": settings.jwt_secret,
            "jwt_expire_hours": settings.jwt_expire_hours,
        },
    }


def load_config() -> Dict[str, Any]:
    path = _config_path()
    if not path.exists():
        return default_config()
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(obj, dict):
            return default_config()
        merged = default_config()
        _deep_merge(merged, obj)
        return merged
    except Exception:
        return default_config()


def save_config(cfg: Dict[str, Any]) -> None:
    path = _config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")


def _deep_merge(dst: Dict[str, Any], src: Dict[str, Any]) -> None:
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            _deep_merge(dst[k], v)
        else:
            dst[k] = v

