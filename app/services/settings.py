"""Configurações: por usuário (agendamento/política) e do sistema (somente administrador)."""
from sqlalchemy.orm import Session

from .. import config
from ..crypto import decrypt, encrypt
from ..models import SystemSetting, UserSetting

USER_DEFAULTS = {
    "check_time": "09:00",
    "milestones": "60,45,30,15,7",
    "daily_below": "7",
    "alert_on_changes": "1",
    "history_days": "365",
}

SYSTEM_DEFAULTS = {
    "timezone": config.DEFAULT_TZ,
    "public_url": "",
    "sys_smtp_server": "",
    "sys_smtp_port": "587",
    "sys_smtp_security": "starttls",
    "sys_smtp_user": "",
    "sys_smtp_password": "",
    "sys_smtp_from": "",
    "sys_smtp_from_name": "Whois Notification",
}
SYSTEM_SECRETS = {"sys_smtp_password"}


# ----------------------------------------------------------------- Usuário --
def get(db: Session, user_id: int, key: str) -> str:
    row = db.get(UserSetting, (user_id, key))
    if row is not None and row.value is not None:
        return row.value
    return USER_DEFAULTS[key]


def get_int(db: Session, user_id: int, key: str) -> int:
    try:
        return int(get(db, user_id, key))
    except (TypeError, ValueError):
        return int(USER_DEFAULTS[key])


def get_int_list(db: Session, user_id: int, key: str) -> list[int]:
    out = []
    for part in get(db, user_id, key).replace(";", ",").split(","):
        part = part.strip()
        if part.lstrip("-").isdigit():
            out.append(int(part))
    return sorted(set(out), reverse=True)


def set_value(db: Session, user_id: int, key: str, value: str) -> None:
    if key not in USER_DEFAULTS:
        raise KeyError(key)
    row = db.get(UserSetting, (user_id, key))
    if row is None:
        db.add(UserSetting(user_id=user_id, key=key, value=value))
    else:
        row.value = value


def user_snapshot(db: Session, user_id: int) -> dict[str, str]:
    return {k: get(db, user_id, k) for k in USER_DEFAULTS}


# ----------------------------------------------------------------- Sistema --
def sys_get(db: Session, key: str) -> str:
    row = db.get(SystemSetting, key)
    value = row.value if row is not None and row.value is not None else SYSTEM_DEFAULTS[key]
    return decrypt(value) if key in SYSTEM_SECRETS else value


def sys_set(db: Session, key: str, value: str) -> None:
    if key not in SYSTEM_DEFAULTS:
        raise KeyError(key)
    if key in SYSTEM_SECRETS:
        value = encrypt(value)
    row = db.get(SystemSetting, key)
    if row is None:
        db.add(SystemSetting(key=key, value=value))
    else:
        row.value = value


def sys_snapshot(db: Session) -> dict[str, str]:
    snap = {k: sys_get(db, k) for k in SYSTEM_DEFAULTS}
    snap["sys_smtp_password"] = ""  # nunca devolvido à tela
    return snap


def load_timezone(db: Session) -> None:
    config.set_tz(sys_get(db, "timezone"))
