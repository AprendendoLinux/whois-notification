"""Autenticação simples por sessão (cookie assinado) com hash scrypt."""
import base64
import hashlib
import hmac
import os
import secrets

from fastapi import Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import User

_N, _R, _P = 2**14, 8, 1


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return f"scrypt${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, salt_b64, dk_b64 = stored.split("$")
        if algo != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
        dk = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=len(expected))
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


def user_count(db: Session) -> int:
    return db.scalar(select(func.count(User.id))) or 0


def ensure_env_admin(db: Session) -> None:
    """Cria o administrador a partir de ADMIN_USER/ADMIN_PASSWORD, se definidos e sem usuários."""
    user = os.getenv("ADMIN_USER")
    pwd = os.getenv("ADMIN_PASSWORD")
    if user and pwd and user_count(db) == 0:
        db.add(User(username=user, password_hash=hash_password(pwd)))
        db.commit()
        print(f"[*] Usuário administrador '{user}' criado a partir das variáveis de ambiente.")


def current_user(request: Request, db: Session) -> User | None:
    uid = request.session.get("uid")
    if not uid:
        return None
    return db.get(User, uid)


def csrf_token(request: Request) -> str:
    tok = request.session.get("csrf")
    if not tok:
        tok = secrets.token_urlsafe(24)
        request.session["csrf"] = tok
    return tok


def check_csrf(request: Request, token: str | None) -> bool:
    expected = request.session.get("csrf")
    return bool(expected and token and hmac.compare_digest(expected, token))
