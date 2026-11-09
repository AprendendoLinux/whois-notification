"""Configurações editáveis pela interface, com prioridade para variáveis de ambiente."""
import os
from dataclasses import dataclass

from sqlalchemy.orm import Session

from ..models import Setting


@dataclass(frozen=True)
class SettingDef:
    key: str
    label: str
    default: str = ""
    env: str | None = None
    secret: bool = False
    group: str = "geral"


DEFS: list[SettingDef] = [
    SettingDef("smtp_server", "Servidor SMTP", env="SMTP_SERVER", group="smtp"),
    SettingDef("smtp_port", "Porta", "587", env="SMTP_PORT", group="smtp"),
    SettingDef("smtp_security", "Segurança", "starttls", env="SMTP_SECURITY", group="smtp"),
    SettingDef("smtp_user", "Usuário", env="SMTP_USER", group="smtp"),
    SettingDef("smtp_password", "Senha", env="SMTP_PASSWORD", secret=True, group="smtp"),
    SettingDef("smtp_from", "Remetente (e-mail)", env="SMTP_FROM", group="smtp"),
    SettingDef("smtp_from_name", "Remetente (nome)", "Whois Notification", env="SMTP_FROM_NAME", group="smtp"),
    SettingDef("telegram_token", "Token do bot", env="TELEGRAM_BOT_TOKEN", secret=True, group="telegram"),
    SettingDef("check_time", "Horário da verificação diária", "09:00", env="CHECK_TIME", group="schedule"),
    SettingDef("milestones", "Marcos de aviso (dias)", "60,45,30,15,7", group="schedule"),
    SettingDef("daily_below", "Aviso diário abaixo de (dias)", "7", group="schedule"),
    SettingDef("alert_on_changes", "Alertar mudanças críticas", "1", group="schedule"),
    SettingDef("history_days", "Manter histórico por (dias)", "365", group="schedule"),
]
DEF_BY_KEY = {d.key: d for d in DEFS}


def env_value(key: str) -> str | None:
    d = DEF_BY_KEY[key]
    if d.env:
        v = os.getenv(d.env)
        if v not in (None, ""):
            return v
    return None


def get(db: Session, key: str) -> str:
    v = env_value(key)
    if v is not None:
        return v
    row = db.get(Setting, key)
    if row is not None and row.value is not None:
        return row.value
    return DEF_BY_KEY[key].default


def get_int(db: Session, key: str) -> int:
    try:
        return int(get(db, key))
    except (TypeError, ValueError):
        return int(DEF_BY_KEY[key].default or 0)


def get_int_list(db: Session, key: str) -> list[int]:
    out = []
    for part in get(db, key).replace(";", ",").split(","):
        part = part.strip()
        if part.lstrip("-").isdigit():
            out.append(int(part))
    return sorted(set(out), reverse=True)


def set_value(db: Session, key: str, value: str) -> None:
    if key not in DEF_BY_KEY:
        raise KeyError(key)
    row = db.get(Setting, key)
    if row is None:
        db.add(Setting(key=key, value=value))
    else:
        row.value = value


def snapshot(db: Session) -> dict[str, dict]:
    """Valores para a página de configurações (segredos mascarados)."""
    out = {}
    for d in DEFS:
        locked = env_value(d.key) is not None
        val = get(db, d.key)
        out[d.key] = {
            "def": d,
            "value": "" if d.secret else val,
            "is_set": bool(val),
            "locked": locked,
        }
    return out
