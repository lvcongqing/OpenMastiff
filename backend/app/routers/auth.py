from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from app.auth import (
    list_all_permissions,
    add_user_to_role,
    authenticate_user,
    create_custom_role,
    hash_password,
    issue_access_token,
    list_review_role_options,
    list_roles_with_users,
    remove_user_from_role,
    require_permissions,
    upsert_user_password,
)
from app.config_store import load_config

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginIn(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class CreateRoleIn(BaseModel):
    role: str = Field(min_length=1)
    name_zh: str = Field(min_length=1)
    permissions: list = Field(default_factory=list)


class AddRoleUserIn(BaseModel):
    username: str = Field(min_length=1)


class SetPasswordIn(BaseModel):
    password: str = Field(min_length=1)


@router.post("/login")
def login(body: LoginIn):
    if not bool(load_config().get("initialized")):
        from fastapi import HTTPException

        raise HTTPException(status_code=503, detail="system not initialized")
    user = authenticate_user(body.username, body.password)
    token = issue_access_token(user)
    return {"access_token": token, "token_type": "bearer", "user": user}


@router.get("/me")
def me(request: Request):
    user = getattr(request.state, "user", None)
    return {"user": user}


@router.post("/roles")
def create_role(body: CreateRoleIn, _user=Depends(require_permissions(["auth.manage_roles"]))):
    return create_custom_role(body.role, body.name_zh, [str(p) for p in body.permissions])


@router.post("/roles/{role}/users")
def role_add_user(role: str, body: AddRoleUserIn, _user=Depends(require_permissions(["auth.manage_roles"]))):
    return add_user_to_role(role, body.username)


@router.delete("/roles/{role}/users/{username}")
def role_remove_user(role: str, username: str, _user=Depends(require_permissions(["auth.manage_roles"]))):
    return remove_user_from_role(role, username)


@router.put("/passwords/{username}")
def set_http_password(username: str, body: SetPasswordIn, _user=Depends(require_permissions(["auth.manage_passwords"]))):
    return upsert_user_password(username, hash_password(body.password))


@router.get("/roles")
def list_roles(_user=Depends(require_permissions(["auth.manage_roles"]))):
    return {"items": list_roles_with_users(), "available_permissions": list_all_permissions()}


@router.get("/review-roles")
def list_review_roles(request: Request):
    if not getattr(request.state, "user", None):
        from fastapi import HTTPException

        raise HTTPException(status_code=401, detail="unauthorized")
    return {"items": list_review_role_options()}
