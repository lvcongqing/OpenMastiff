from __future__ import annotations

from datetime import datetime
from typing import Dict, Iterable, List, Set
from urllib.parse import urlparse
import time

import jwt
from fastapi import HTTPException, Request
from ldap3 import ALL, Connection, Server

from app.config_store import load_config, save_config
from app.db import col

BUILTIN_ROLE_DEFINITIONS = {
    "admin": {
        "name_zh": "系统管理员",
        "permissions": [
            "auth.manage_roles",
            "auth.manage_passwords",
            "policy.manage",
            "credentials.manage",
            "request.manage",
            "review.manage",
            "legal.decide",
            "remediation.manage",
            "export.create",
        ],
    },
    "legal": {"name_zh": "法务", "permissions": ["review.read", "legal.decide", "request.read"]},
    "project_manager": {"name_zh": "项目经理", "permissions": ["request.manage", "review.manage", "export.create"]},
    "rd_manager": {"name_zh": "研发经理", "permissions": ["request.manage", "review.manage", "remediation.manage"]},
    "quality_manager": {"name_zh": "质量", "permissions": ["review.manage", "remediation.manage", "export.create"]},
    "product_manager": {"name_zh": "产品经理", "permissions": ["request.manage", "review.read"]},
    "user": {
        "name_zh": "普通用户",
        "permissions": ["request.manage", "request.read", "review.read", "export.create"],
    },
    "viewer": {"name_zh": "只读", "permissions": ["request.read", "review.read"]},
}
def merged_role_definitions() -> Dict[str, Dict[str, object]]:
    cfg = load_config()
    custom = ((cfg.get("roles") or {}).get("custom_definitions")) or {}
    out: Dict[str, Dict[str, object]] = {}
    for role, meta in BUILTIN_ROLE_DEFINITIONS.items():
        out[role] = {"name_zh": meta["name_zh"], "permissions": list(meta["permissions"])}
    if isinstance(custom, dict):
        for role, meta in custom.items():
            if role in out:
                continue
            if not isinstance(meta, dict):
                continue
            name_zh = str(meta.get("name_zh") or role).strip()
            permissions = meta.get("permissions") or []
            if not isinstance(permissions, list):
                permissions = []
            out[str(role).strip()] = {"name_zh": name_zh, "permissions": [str(p) for p in permissions if str(p).strip()]}
    return out


def valid_roles() -> set:
    return set(merged_role_definitions().keys())


def _parse_ldap_server() -> Server:
    ldap_cfg = ((load_config().get("auth") or {}).get("ldap") or {})
    server_addr = str(ldap_cfg.get("server") or "")
    parsed = urlparse(server_addr)
    host = parsed.hostname or server_addr
    port = parsed.port or 389
    return Server(host=host, port=port, get_info=ALL, connect_timeout=5)


def _admin_users() -> set:
    cfg = load_config()
    users = ((cfg.get("roles") or {}).get("admins")) or []
    if isinstance(users, list):
        return {str(u).strip().lower() for u in users if str(u).strip()}
    return set()


def _default_role() -> str:
    cfg = load_config()
    role = str(((cfg.get("roles") or {}).get("default_role")) or "viewer")
    return role if role in valid_roles() else "viewer"


def resolve_user_role(username: str) -> str:
    u = (username or "").strip().lower()
    if not u:
        return _default_role()
    if u in _admin_users():
        return "admin"

    users = col("users")
    doc = users.find_one({"username": u}, {"_id": 0, "role": 1})
    role = (doc or {}).get("role")
    if isinstance(role, str) and role in valid_roles():
        return role
    return _default_role()


def resolve_user_roles(username: str) -> List[str]:
    u = (username or "").strip().lower()
    roles: Set[str] = set()
    if u in _admin_users():
        roles.add("admin")
    if u:
        users = col("users")
        doc = users.find_one({"username": u}, {"_id": 0, "role": 1, "roles": 1})
        if isinstance((doc or {}).get("role"), str):
            role_one = str(doc.get("role")).strip()
            if role_one in valid_roles():
                roles.add(role_one)
        role_list = (doc or {}).get("roles")
        if isinstance(role_list, list):
            for r in role_list:
                rr = str(r).strip()
                if rr in valid_roles():
                    roles.add(rr)
    if not roles:
        roles.add(_default_role())
    if "admin" in roles:
        return ["admin"] + sorted([x for x in roles if x != "admin"])
    return sorted(list(roles))


def upsert_user_role(username: str, role: str) -> Dict[str, str]:
    u = (username or "").strip().lower()
    if not u:
        raise HTTPException(status_code=400, detail="username required")
    if role not in valid_roles():
        raise HTTPException(status_code=400, detail="invalid role")
    users = col("users")
    users.update_one(
        {"username": u},
        {"$set": {"username": u, "role": role, "updated_at": datetime.utcnow()}},
        upsert=True,
    )
    return {"username": u, "role": role}


def add_user_role(username: str, role: str) -> Dict[str, object]:
    u = (username or "").strip().lower()
    r = (role or "").strip()
    if not u:
        raise HTTPException(status_code=400, detail="username required")
    if r not in valid_roles():
        raise HTTPException(status_code=400, detail="invalid role")
    roles = resolve_user_roles(u)
    if r not in roles:
        roles.append(r)
    users = col("users")
    users.update_one(
        {"username": u},
        {"$set": {"username": u, "role": roles[0], "roles": sorted(list(set(roles))), "updated_at": datetime.utcnow()}},
        upsert=True,
    )
    return {"username": u, "roles": sorted(list(set(roles)))}


def remove_user_role(username: str, role: str) -> Dict[str, object]:
    u = (username or "").strip().lower()
    r = (role or "").strip()
    if not u:
        raise HTTPException(status_code=400, detail="username required")
    roles = [x for x in resolve_user_roles(u) if x != r]
    if not roles:
        roles = [_default_role()]
    users = col("users")
    users.update_one(
        {"username": u},
        {"$set": {"username": u, "role": roles[0], "roles": roles, "updated_at": datetime.utcnow()}},
        upsert=True,
    )
    return {"username": u, "roles": roles}


def list_role_definitions() -> List[Dict[str, object]]:
    defs = merged_role_definitions()
    return [
        {"role": role, "name_zh": str(meta.get("name_zh") or role), "permissions": list(meta.get("permissions") or [])}
        for role, meta in defs.items()
    ]


NON_REVIEW_ROLES = {"user", "viewer"}
DEFAULT_REVIEW_ROLES = ["project_manager", "rd_manager", "product_manager", "legal", "security"]


def list_review_role_options() -> List[Dict[str, str]]:
    """创建引入单时可选的会签角色（不含申请方/只读）。"""
    out: List[Dict[str, str]] = []
    for item in list_role_definitions():
        role = str(item.get("role") or "").strip()
        if not role or role in NON_REVIEW_ROLES:
            continue
        out.append({"role": role, "name_zh": str(item.get("name_zh") or role)})
    return out


def list_all_permissions() -> List[str]:
    out: Set[str] = set()
    for x in list_role_definitions():
        for p in (x.get("permissions") or []):
            out.add(str(p))
    return sorted(list(out))


def role_permissions(role: str) -> List[str]:
    return list((merged_role_definitions().get(role) or {}).get("permissions") or [])


def user_permissions(roles: Iterable[str]) -> List[str]:
    perms: Set[str] = set()
    for r in roles:
        perms.update(role_permissions(str(r)))
    return sorted(perms)


def create_custom_role(role: str, name_zh: str, permissions: List[str]) -> Dict[str, object]:
    r = (role or "").strip()
    if not r:
        raise HTTPException(status_code=400, detail="role required")
    if r in BUILTIN_ROLE_DEFINITIONS:
        raise HTTPException(status_code=400, detail="builtin role cannot be recreated")
    if r in valid_roles():
        raise HTTPException(status_code=400, detail="role already exists")
    n = (name_zh or "").strip()
    if not n:
        raise HTTPException(status_code=400, detail="name_zh required")
    perms = [str(p).strip() for p in (permissions or []) if str(p).strip()]
    cfg = load_config()
    roles_cfg = cfg.setdefault("roles", {})
    custom = roles_cfg.setdefault("custom_definitions", {})
    custom[r] = {"name_zh": n, "permissions": perms}
    save_config(cfg)
    return {"role": r, "name_zh": n, "permissions": perms}


def add_user_to_role(role: str, username: str) -> Dict[str, str]:
    r = (role or "").strip()
    u = (username or "").strip().lower()
    if not u:
        raise HTTPException(status_code=400, detail="username required")
    if r not in valid_roles():
        raise HTTPException(status_code=400, detail="invalid role")
    out = add_user_role(u, r)
    return {"username": u, "role": r, "roles": out["roles"]}


def remove_user_from_role(role: str, username: str) -> Dict[str, str]:
    r = (role or "").strip()
    u = (username or "").strip().lower()
    if not u:
        raise HTTPException(status_code=400, detail="username required")
    out = remove_user_role(u, r)
    return {"username": u, "role": out["roles"][0], "roles": out["roles"]}


def list_roles_with_users() -> List[Dict[str, object]]:
    defs = {d["role"]: d for d in list_role_definitions()}
    users = col("users")
    cur = users.find({}, {"_id": 0, "username": 1, "role": 1, "roles": 1}).sort("username", 1)
    members: Dict[str, List[str]] = {}
    for d in cur:
        u = str(d.get("username") or "").strip().lower()
        if not u:
            continue
        rr = []
        if isinstance(d.get("roles"), list):
            rr = [str(x).strip() for x in d.get("roles") if str(x).strip() in defs]
        if not rr:
            r = str(d.get("role") or _default_role())
            rr = [r if r in defs else _default_role()]
        for role_key in rr:
            members.setdefault(role_key, []).append(u)
    out = []
    for role, meta in defs.items():
        out.append(
            {
                "role": role,
                "name_zh": meta["name_zh"],
                "permissions": meta["permissions"],
                "users": members.get(role, []),
            }
        )
    return out


def upsert_user_password(username: str, password_hash: str) -> Dict[str, str]:
    u = (username or "").strip().lower()
    if not u:
        raise HTTPException(status_code=400, detail="username required")
    users = col("users")
    users.update_one(
        {"username": u},
        {"$set": {"username": u, "password_hash": password_hash, "updated_at": datetime.utcnow()}},
        upsert=True,
    )
    return {"username": u}


def hash_password(password: str) -> str:
    import hashlib
    import os

    salt = os.urandom(16).hex()
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120000).hex()
    return f"pbkdf2_sha256${salt}${digest}"


def verify_password(password: str, encoded: str) -> bool:
    import hashlib

    try:
        algo, salt, digest = encoded.split("$", 2)
    except Exception:
        return False
    if algo != "pbkdf2_sha256":
        return False
    check = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120000).hex()
    return check == digest


def http_authenticate(username: str, password: str) -> Dict[str, str]:
    if not username or not password:
        raise HTTPException(status_code=400, detail="username/password required")
    u = username.strip().lower()
    users = col("users")
    doc = users.find_one({"username": u}, {"_id": 0, "username": 1, "password_hash": 1})
    if not doc or not verify_password(password, str(doc.get("password_hash") or "")):
        raise HTTPException(status_code=401, detail="invalid username or password")
    role = resolve_user_role(u)
    roles = resolve_user_roles(u)
    defs = merged_role_definitions()
    return {
        "username": u,
        "display_name": u,
        "role": role,
        "roles": roles,
        "permissions": user_permissions(roles),
        "role_name_zh": str((defs.get(role) or {}).get("name_zh") or role),
    }


def ldap_authenticate(username: str, password: str) -> Dict[str, str]:
    if not username or not password:
        raise HTTPException(status_code=400, detail="username/password required")

    server = _parse_ldap_server()
    cfg = load_config()
    ldap_cfg = ((cfg.get("auth") or {}).get("ldap") or {})
    account_filter = str(ldap_cfg.get("account_pattern") or "(&(objectClass=inetOrgPerson)(uid=${username}))").replace("${username}", username)
    bind_username = str(ldap_cfg.get("bind_username") or "")
    bind_password = str(ldap_cfg.get("bind_password") or "")
    account_base = str(ldap_cfg.get("account_base") or "")
    account_ssh_username = str(ldap_cfg.get("account_ssh_username") or "uid")

    try:
        service_conn = Connection(
            server,
            user=bind_username,
            password=bind_password,
            receive_timeout=5,
            auto_bind=True,
            raise_exceptions=True,
        )
    except Exception:
        raise HTTPException(status_code=503, detail="ldap service unavailable")
    try:
        ok = service_conn.search(
            search_base=account_base,
            search_filter=account_filter,
            attributes=["cn", account_ssh_username],
            size_limit=1,
        )
        if not ok or not service_conn.entries:
            raise HTTPException(status_code=401, detail="invalid username or password")

        entry = service_conn.entries[0]
        user_dn = entry.entry_dn
        login_name = str(getattr(entry, account_ssh_username, username).value or username)
        display_name = str(getattr(entry, "cn", login_name).value or login_name)
    finally:
        service_conn.unbind()

    try:
        user_conn = Connection(
            server,
            user=user_dn,
            password=password,
            receive_timeout=5,
            auto_bind=True,
            raise_exceptions=True,
        )
        user_conn.unbind()
    except Exception:
        raise HTTPException(status_code=401, detail="invalid username or password")
    username_normalized = login_name.lower()
    role = resolve_user_role(username_normalized)
    roles = resolve_user_roles(username_normalized)
    defs = merged_role_definitions()
    return {
        "username": username_normalized,
        "display_name": display_name,
        "role": role,
        "roles": roles,
        "permissions": user_permissions(roles),
        "role_name_zh": str((defs.get(role) or {}).get("name_zh") or role),
    }


def authenticate_user(username: str, password: str) -> Dict[str, str]:
    cfg = load_config()
    mode = str(((cfg.get("auth") or {}).get("mode")) or "ldap").lower()
    if mode == "http":
        return http_authenticate(username, password)
    return ldap_authenticate(username, password)


def issue_access_token(user: Dict[str, str]) -> str:
    cfg = load_config()
    sec = cfg.get("security") or {}
    jwt_expire_hours = int(sec.get("jwt_expire_hours") or 8)
    now_ts = int(time.time())
    exp_ts = now_ts + jwt_expire_hours * 3600
    role = user.get("role") or resolve_user_role(user["username"])
    payload = {
        "sub": user["username"],
        "display_name": user.get("display_name") or user["username"],
        "role": role,
        "roles": user.get("roles") or resolve_user_roles(user["username"]),
        "permissions": user.get("permissions") or user_permissions(user.get("roles") or resolve_user_roles(user["username"])),
        "role_name_zh": user.get("role_name_zh") or merged_role_definitions().get(role, {}).get("name_zh", role),
        "iat": now_ts,
        "exp": exp_ts,
    }
    jwt_secret = str(sec.get("jwt_secret") or "openmastiff-dev-secret")
    return jwt.encode(payload, jwt_secret, algorithm="HS256")


def decode_access_token(token: str) -> Dict[str, str]:
    cfg = load_config()
    sec = cfg.get("security") or {}
    jwt_secret = str(sec.get("jwt_secret") or "openmastiff-dev-secret")
    try:
        payload = jwt.decode(token, jwt_secret, algorithms=["HS256"])
    except Exception:
        raise HTTPException(status_code=401, detail="invalid token")
    username = str(payload.get("sub") or "")
    if not username:
        raise HTTPException(status_code=401, detail="invalid token")
    role = str(payload.get("role") or resolve_user_role(username))
    if role not in valid_roles():
        role = "viewer"
    roles = payload.get("roles")
    if not isinstance(roles, list):
        roles = resolve_user_roles(username)
    roles = [str(x).strip() for x in roles if str(x).strip() in valid_roles()]
    if not roles:
        roles = [role]
    defs = merged_role_definitions()
    return {
        "username": username,
        "display_name": str(payload.get("display_name") or username),
        "role": role,
        "roles": roles,
        "permissions": user_permissions(roles),
        "role_name_zh": str(payload.get("role_name_zh") or defs.get(role, {}).get("name_zh", role)),
    }


def require_roles(allowed_roles: Iterable[str]):
    allowed = set(allowed_roles)
    if not allowed:
        raise ValueError("allowed_roles cannot be empty")

    def _dep(request: Request) -> Dict[str, str]:
        user = getattr(request.state, "user", None)
        if not user:
            raise HTTPException(status_code=401, detail="unauthorized")
        role = str(user.get("role") or "")
        if role not in allowed:
            raise HTTPException(status_code=403, detail="forbidden")
        return user

    return _dep


def require_permissions(required: Iterable[str]):
    req = set(required)
    if not req:
        raise ValueError("required permissions cannot be empty")

    def _dep(request: Request) -> Dict[str, str]:
        user = getattr(request.state, "user", None)
        if not user:
            raise HTTPException(status_code=401, detail="unauthorized")
        roles = user.get("roles")
        if not isinstance(roles, list):
            roles = [str(user.get("role") or "")]
        perms = set()
        for r in roles:
            perms.update(role_permissions(str(r)))
        if not req.issubset(perms):
            raise HTTPException(status_code=403, detail="forbidden")
        return user

    return _dep
