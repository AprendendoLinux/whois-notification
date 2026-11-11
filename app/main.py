"""Aplicação FastAPI: interface web + API + agendador."""
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from . import scheduler
from .auth import ensure_admin
from .config import APP_NAME, APP_VERSION, BASE_DIR, SECRET_KEY
from .db import SessionLocal, init_db
from .routes import admin, api, pages
from .services import settings as cfg
from .web import LoginRequired, PasswordChangeRequired


@asynccontextmanager
async def lifespan(_app: FastAPI):
    print(f"[*] {APP_NAME} {APP_VERSION} iniciando...")
    init_db()
    with SessionLocal() as db:
        ensure_admin(db)
        cfg.load_timezone(db)
    scheduler.start(run_now=True)
    try:
        yield
    finally:
        scheduler.shutdown()


app = FastAPI(title=APP_NAME, version=APP_VERSION, lifespan=lifespan,
              docs_url="/api/docs", redoc_url=None, openapi_url="/api/openapi.json")


class SecureCookieMiddleware:
    """Marca o cookie de sessão como Secure automaticamente quando a requisição chega por HTTPS."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("scheme") != "https":
            return await self.app(scope, receive, send)

        async def wrapped(message):
            if message["type"] == "http.response.start":
                message["headers"] = [
                    (k, v + b"; Secure" if k == b"set-cookie" and b"secure" not in v.lower() else v)
                    for k, v in message["headers"]
                ]
            await send(message)

        return await self.app(scope, receive, wrapped)


app.add_middleware(
    SessionMiddleware, secret_key=SECRET_KEY, session_cookie="wn_session",
    max_age=60 * 60 * 24 * 14, same_site="lax", https_only=False,
)
app.add_middleware(SecureCookieMiddleware)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
app.include_router(pages.router)
app.include_router(admin.router)
app.include_router(api.router)


@app.exception_handler(LoginRequired)
async def _login_required(request: Request, _exc: LoginRequired):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": "Não autenticado"}, status_code=401)
    if request.headers.get("HX-Request"):
        return JSONResponse({}, status_code=401, headers={"HX-Redirect": "/login"})
    return RedirectResponse("/login", status_code=303)


@app.exception_handler(PasswordChangeRequired)
async def _password_change_required(request: Request, _exc: PasswordChangeRequired):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": "Troca de senha obrigatória"}, status_code=403)
    if request.headers.get("HX-Request"):
        return JSONResponse({}, status_code=403, headers={"HX-Redirect": "/account/required"})
    return RedirectResponse("/account/required", status_code=303)


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return FileResponse(BASE_DIR / "static" / "img" / "favicon.svg", media_type="image/svg+xml")


@app.get("/healthz", include_in_schema=False)
def healthz():
    return {"status": "ok", "version": APP_VERSION}
