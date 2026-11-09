"""Aplicação FastAPI: interface web + API + agendador."""
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from . import scheduler
from .auth import ensure_env_admin
from .config import APP_NAME, APP_VERSION, BASE_DIR, SECRET_KEY
from .db import SessionLocal
from .dbmigrate import upgrade
from .migrate_json import import_legacy_json
from .routes import api, pages
from .web import LoginRequired, SetupRequired


@asynccontextmanager
async def lifespan(_app: FastAPI):
    print(f"[*] {APP_NAME} {APP_VERSION} iniciando...")
    upgrade()
    with SessionLocal() as db:
        ensure_env_admin(db)
        imported = import_legacy_json(db)
    scheduler.start(run_now=True)
    if imported:
        print("[*] Os domínios importados serão verificados agora.")
    try:
        yield
    finally:
        scheduler.shutdown()


app = FastAPI(title=APP_NAME, version=APP_VERSION, lifespan=lifespan,
              docs_url="/api/docs", redoc_url=None, openapi_url="/api/openapi.json")
app.add_middleware(
    SessionMiddleware, secret_key=SECRET_KEY, session_cookie="wn_session",
    max_age=60 * 60 * 24 * 14, same_site="lax", https_only=os.getenv("COOKIE_SECURE") == "1",
)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
app.include_router(pages.router)
app.include_router(api.router)


@app.exception_handler(LoginRequired)
async def _login_required(request: Request, _exc: LoginRequired):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": "Não autenticado"}, status_code=401)
    if request.headers.get("HX-Request"):
        return JSONResponse({}, status_code=401, headers={"HX-Redirect": "/login"})
    return RedirectResponse("/login", status_code=303)


@app.exception_handler(SetupRequired)
async def _setup_required(_request: Request, _exc: SetupRequired):
    return RedirectResponse("/setup", status_code=303)


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return FileResponse(BASE_DIR / "static" / "img" / "favicon.svg", media_type="image/svg+xml")


@app.get("/healthz", include_in_schema=False)
def healthz():
    return {"status": "ok", "version": APP_VERSION}
