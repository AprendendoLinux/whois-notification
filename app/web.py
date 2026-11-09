"""Utilidades compartilhadas das rotas: templates, autenticação, CSRF e flash."""
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from . import auth
from .config import APP_NAME, APP_VERSION, BASE_DIR, LOCAL_TZ
from .db import get_db
from .models import User, utcnow


class LoginRequired(Exception):
    pass


class SetupRequired(Exception):
    pass


templates = Jinja2Templates(directory=BASE_DIR / "templates")

HEALTH = {
    "ok": ("Operacional", "ok"),
    "warning": ("Atenção", "warn"),
    "critical": ("Crítico", "crit"),
    "expired": ("Expirado", "dead"),
    "unknown": ("Sem dados", "muted"),
    "disabled": ("Pausado", "muted"),
}


def _local(dt: datetime | None) -> datetime | None:
    return dt.astimezone(LOCAL_TZ) if dt else None


def _parse(dt):
    if isinstance(dt, str):
        try:
            return datetime.fromisoformat(dt)
        except ValueError:
            return None
    return dt


def f_date(dt):
    """Datas de registro (WHOIS/SSL) são exibidas no dia oficial, em UTC."""
    d = _parse(dt)
    return d.astimezone(timezone.utc).strftime("%d/%m/%Y") if d else "—"


def f_datetime(dt):
    """Momentos do sistema (varreduras, envios) no fuso local."""
    d = _local(_parse(dt))
    return d.strftime("%d/%m/%Y %H:%M") if d else "—"


def f_ago(dt) -> str:
    if dt is None:
        return "nunca"
    secs = int((utcnow() - dt).total_seconds())
    if secs < 60:
        return "agora"
    if secs < 3600:
        return f"há {secs // 60} min"
    if secs < 86400:
        return f"há {secs // 3600} h"
    days = secs // 86400
    return f"há {days} dia{'s' if days > 1 else ''}"


def f_age(dt) -> str:
    if dt is None:
        return "—"
    months = int((utcnow() - dt).days / 30.44)
    years, months = divmod(months, 12)
    parts = []
    if years:
        parts.append(f"{years} ano{'s' if years > 1 else ''}")
    if months:
        parts.append(f"{months} {'meses' if months > 1 else 'mês'}")
    return " e ".join(parts) or "menos de 1 mês"


def f_days(n) -> str:
    if n is None:
        return "—"
    if n < 0:
        return f"expirado há {abs(n)} d"
    if n == 0:
        return "expira hoje"
    return f"{n} dia{'s' if n != 1 else ''}"


def ring(days, horizon=365) -> float:
    """Fração 0–1 para os anéis de contagem regressiva."""
    if days is None or days <= 0:
        return 0.0
    return min(days / horizon, 1.0)


templates.env.filters.update(date=f_date, datetime=f_datetime, ago=f_ago, age=f_age, days=f_days)
templates.env.globals.update(
    APP_NAME=APP_NAME, APP_VERSION=APP_VERSION, HEALTH=HEALTH, ring=ring,
    csrf_token=auth.csrf_token,
)


def flash(request: Request, message: str, kind: str = "ok") -> None:
    # Reatribuir (em vez de .append) para o Starlette marcar a sessão como modificada
    request.session["flash"] = [*request.session.get("flash", []), {"msg": message, "kind": kind}]


def pop_flash(request: Request) -> list[dict]:
    return request.session.pop("flash", [])


templates.env.globals["pop_flash"] = pop_flash


def require_user(request: Request, db: Session = Depends(get_db)) -> User:
    user = auth.current_user(request, db)
    if user is None:
        if auth.user_count(db) == 0:
            raise SetupRequired()
        raise LoginRequired()
    return user


async def csrf_protect(request: Request) -> None:
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    token = request.headers.get("X-CSRF-Token")
    if not token:
        form = await request.form()
        token = form.get("csrf")
    if not auth.check_csrf(request, token):
        raise HTTPException(status_code=403, detail="Token CSRF inválido. Recarregue a página.")


def render(request: Request, name: str, ctx: dict | None = None, status_code: int = 200):
    return templates.TemplateResponse(request, name, ctx or {}, status_code=status_code)
