from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, HTTPException
from ldap3 import Connection, Server
from pymongo import MongoClient
from pydantic import BaseModel, Field
from redis import Redis
from typing_extensions import Literal

from app.auth import hash_password, upsert_user_password, upsert_user_role
from app.config_store import load_config, save_config
from app.settings import settings

router = APIRouter(prefix="/bootstrap", tags=["bootstrap"])


class LdapConfigIn(BaseModel):
    server: str = Field(min_length=1)
    bind_username: str = Field(min_length=1)
    bind_password: str = ""
    account_base: str = Field(min_length=1)
    account_pattern: str = Field(min_length=1)
    account_ssh_username: str = Field(min_length=1, default="uid")


class DatabaseConfigIn(BaseModel):
    mongo_uri: str = Field(min_length=1)
    redis_url: str = Field(min_length=1)


class StorageConfigIn(BaseModel):
    blob_root: str = Field(min_length=1)
    work_root: str = Field(min_length=1)


class BootstrapInitIn(BaseModel):
    auth_mode: Literal["ldap", "http"]
    admin_username: str = Field(min_length=1)
    admin_password: str = ""
    default_role: Literal["admin", "legal", "project_manager", "rd_manager", "quality_manager", "product_manager", "viewer"] = "viewer"
    admin_users: List[str] = Field(default_factory=list)
    ldap: Optional[LdapConfigIn] = None
    database: DatabaseConfigIn
    storage: StorageConfigIn
    scanner_mode: str = "local"
    jwt_secret: str = ""
    jwt_expire_hours: int = Field(default=8, ge=1, le=168)


class BootstrapValidateIn(BaseModel):
    auth_mode: Literal["ldap", "http"] = "ldap"
    ldap: Optional[LdapConfigIn] = None
    database: DatabaseConfigIn
    storage: StorageConfigIn


@router.get("/status")
def bootstrap_status():
    cfg = load_config()
    return {
        "initialized": bool(cfg.get("initialized")),
        "auth_mode": (((cfg.get("auth") or {}).get("mode")) or "ldap"),
        "config_file": settings.app_config_file,
    }


@router.get("/config")
def get_bootstrap_config():
    return load_config()


@router.post("/init")
def bootstrap_init(body: BootstrapInitIn):
    import secrets

    cfg = load_config()
    if cfg.get("initialized"):
        raise HTTPException(status_code=400, detail="system already initialized")

    admins = {body.admin_username.strip().lower()}
    admins.update({u.strip().lower() for u in body.admin_users if u.strip()})

    auth_cfg = {"mode": body.auth_mode, "ldap": {}}
    if body.auth_mode == "ldap":
        if not body.ldap:
            raise HTTPException(status_code=400, detail="ldap config required")
        auth_cfg["ldap"] = body.ldap.dict()
    elif body.auth_mode == "http":
        if not body.admin_password:
            raise HTTPException(status_code=400, detail="http auth requires admin_password")

    cfg["initialized"] = True
    cfg["auth"] = auth_cfg
    cfg["roles"] = {"admins": sorted(admins), "default_role": body.default_role}
    cfg["system"] = {
        "database": body.database.dict(),
        "storage": body.storage.dict(),
        "scanner_mode": body.scanner_mode,
    }
    jwt_secret = (body.jwt_secret or "").strip() or secrets.token_urlsafe(48)
    if len(jwt_secret) < 8:
        raise HTTPException(status_code=400, detail="jwt_secret too short")
    cfg["security"] = {"jwt_secret": jwt_secret, "jwt_expire_hours": body.jwt_expire_hours}
    save_config(cfg)

    upsert_user_role(body.admin_username, "admin")
    if body.auth_mode == "http":
        upsert_user_password(body.admin_username, hash_password(body.admin_password))
    restart_services = ["api", "worker", "beat"]
    return {
        "ok": True,
        "initialized": True,
        "restart_required": True,
        "restart_services": restart_services,
        "restart_hint": "配置已写入配置文件。请重启 API/Worker/Beat 以使新配置完全生效。",
    }


@router.post("/validate")
def validate_bootstrap(body: BootstrapValidateIn):
    out = {
        "ldap": {"ok": True, "detail": "skipped"},
        "mongo": {"ok": False, "detail": ""},
        "redis": {"ok": False, "detail": ""},
        "storage": {"ok": False, "detail": ""},
    }

    if body.auth_mode == "ldap":
        if not body.ldap:
            raise HTTPException(status_code=400, detail="ldap config required")
        try:
            server = Server(body.ldap.server.replace("ldap://", ""), port=389, connect_timeout=5)
            conn = Connection(
                server,
                user=body.ldap.bind_username,
                password=body.ldap.bind_password,
                auto_bind=True,
                receive_timeout=5,
            )
            conn.unbind()
            out["ldap"] = {"ok": True, "detail": "connected"}
        except Exception as e:
            out["ldap"] = {"ok": False, "detail": str(e)}

    try:
        mc = MongoClient(body.database.mongo_uri, serverSelectionTimeoutMS=3000)
        mc.admin.command("ping")
        out["mongo"] = {"ok": True, "detail": "connected"}
    except Exception as e:
        out["mongo"] = {"ok": False, "detail": str(e)}

    try:
        rc = Redis.from_url(body.database.redis_url, socket_connect_timeout=3, socket_timeout=3)
        pong = rc.ping()
        out["redis"] = {"ok": bool(pong), "detail": "connected" if pong else "ping failed"}
    except Exception as e:
        out["redis"] = {"ok": False, "detail": str(e)}

    try:
        from pathlib import Path

        Path(body.storage.blob_root).mkdir(parents=True, exist_ok=True)
        Path(body.storage.work_root).mkdir(parents=True, exist_ok=True)
        out["storage"] = {"ok": True, "detail": "paths writable"}
    except Exception as e:
        out["storage"] = {"ok": False, "detail": str(e)}

    out["ok"] = all(x.get("ok") for x in out.values())
    return out

