from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config_store import load_config
from app.auth import decode_access_token
from app.routers.auth import router as auth_router
from app.routers.bootstrap import router as bootstrap_router
from app.routers.credentials import router as credentials_router
from app.routers.export import router as export_router
from app.routers.findings import router as findings_router
from app.routers.policy import router as policy_router
from app.routers.requests import router as requests_router
from app.routers.remediation import router as remediation_router
from app.routers.review import router as review_router


app = FastAPI(title="供应链安全引入审查系统（一期）")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_NO_AUTH_PATHS = {
    "/docs",
    "/openapi.json",
    "/redoc",
    "/auth/login",
    "/bootstrap/status",
    "/bootstrap/init",
    "/bootstrap/config",
    "/bootstrap/validate",
}


@app.middleware("http")
async def auth_middleware(request, call_next):
    path = request.url.path
    cfg = load_config()
    initialized = bool(cfg.get("initialized"))
    if not initialized and not path.startswith("/bootstrap") and path not in {"/docs", "/openapi.json", "/redoc"} and not path.startswith("/docs/"):
        from fastapi.responses import JSONResponse

        return JSONResponse(status_code=503, content={"detail": "system not initialized"})

    if request.method == "OPTIONS" or path in _NO_AUTH_PATHS or path.startswith("/docs/"):
        return await call_next(request)

    authz = request.headers.get("authorization") or ""
    if not authz.startswith("Bearer "):
        from fastapi.responses import JSONResponse

        return JSONResponse(status_code=401, content={"detail": "missing bearer token"})

    token = authz.split(" ", 1)[1].strip()
    try:
        request.state.user = decode_access_token(token)
    except Exception:
        from fastapi.responses import JSONResponse

        return JSONResponse(status_code=401, content={"detail": "invalid token"})
    return await call_next(request)

app.include_router(bootstrap_router)
app.include_router(auth_router)
app.include_router(credentials_router)
app.include_router(requests_router)
app.include_router(review_router)
app.include_router(remediation_router)
app.include_router(export_router)
app.include_router(policy_router)
app.include_router(findings_router)

