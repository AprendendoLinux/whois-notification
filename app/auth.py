"""Autenticação por sessão (cookie assinado), hash scrypt, recuperação de senha e limite de tentativas."""
import base64
import hashlib
import hmac
import os
import secrets
import time
from datetime import timedelta

from fastapi import Request
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from .models import PLACEHOLDER_EMAIL_DOMAIN, PasswordReset, User, utcnow

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


def generate_password(length: int = 16) -> str:
    alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def password_marker(user: User) -> str:
    """Muda a cada troca de senha: derruba as outras sessões abertas do usuário."""
    return hashlib.sha256(user.password_hash.encode()).hexdigest()[:16]


def login_session(request: Request, user: User) -> None:
    request.session.clear()
    request.session["uid"] = user.id
    request.session["pv"] = password_marker(user)


def ensure_admin(db: Session) -> None:
    """Primeira execução (sem usuários): cria o admin com senha aleatória, exibida nos logs."""
    if user_count(db) > 0:
        return
    password = generate_password()
    db.add(User(username="admin", email=f"admin{PLACEHOLDER_EMAIL_DOMAIN}", is_admin=True,
                password_hash=hash_password(password), must_change_password=True))
    db.commit()
    line = "=" * 62
    print(f"\n{line}\n  PRIMEIRO ACESSO — administrador criado\n"
          f"  Usuário: admin\n  Senha:   {password}\n"
          f"  A senha deverá ser alterada no primeiro login.\n{line}\n", flush=True)


def reset_admin_password(db: Session, username: str = "admin") -> str | None:
    user = db.scalar(select(User).where(User.username == username))
    if user is None:
        return None
    password = generate_password()
    user.password_hash = hash_password(password)
    user.must_change_password = True
    user.is_active = True
    db.commit()
    return password


def current_user(request: Request, db: Session) -> User | None:
    uid = request.session.get("uid")
    if not uid:
        return None
    user = db.get(User, uid)
    if user is None or not user.is_active:
        return None
    if request.session.get("pv") != password_marker(user):
        return None
    return user


# ---------------------------------------------------- Recuperação de senha --
RESET_TTL = timedelta(hours=1)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_reset_token(db: Session, user: User) -> str | None:
    """Gera um token de uso único. Retorna None se já houve pedido há menos de 60 s."""
    recent = db.scalar(select(PasswordReset.id).where(
        PasswordReset.user_id == user.id, PasswordReset.created_at > utcnow() - timedelta(seconds=60)))
    if recent:
        return None
    db.execute(delete(PasswordReset).where(PasswordReset.user_id == user.id))
    token = secrets.token_urlsafe(32)
    db.add(PasswordReset(user_id=user.id, token_hash=_hash_token(token),
                         expires_at=utcnow() + RESET_TTL))
    db.commit()
    return token


def find_reset(db: Session, token: str) -> PasswordReset | None:
    row = db.scalar(select(PasswordReset).where(PasswordReset.token_hash == _hash_token(token)))
    if row is None or row.used or row.expires_at < utcnow():
        return None
    return row


# ------------------------------------------------- Limite de tentativas ----
_FAILS: dict[str, list[float]] = {}
_WINDOW, _MAX_FAILS = 600, 8


def _recent(key: str) -> list[float]:
    now = time.time()
    hits = [t for t in _FAILS.get(key, []) if now - t < _WINDOW]
    _FAILS[key] = hits
    return hits


def too_many_attempts(key: str) -> bool:
    return len(_recent(key)) >= _MAX_FAILS


def register_failure(key: str) -> None:
    _recent(key).append(time.time())


def clear_failures(key: str) -> None:
    _FAILS.pop(key, None)


def csrf_token(request: Request) -> str:
    tok = request.session.get("csrf")
    if not tok:
        tok = secrets.token_urlsafe(24)
        request.session["csrf"] = tok
    return tok


def check_csrf(request: Request, token: str | None) -> bool:
    expected = request.session.get("csrf")
    return bool(expected and token and hmac.compare_digest(expected, token))
