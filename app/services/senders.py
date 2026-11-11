"""Resolução dos remetentes (SMTP e bot do Telegram) de cada usuário/domínio."""
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Domain, SmtpSender, TelegramBot
from . import settings as cfg


@dataclass
class SmtpConfig:
    server: str
    port: int
    security: str
    username: str
    password: str
    from_email: str
    from_name: str


def _from_sender(s: SmtpSender) -> SmtpConfig:
    return SmtpConfig(s.server, s.port, s.security, s.username, s.password,
                      s.from_email, s.from_name)


def smtp_for(db: Session, user_id: int, domain: Domain | None = None) -> SmtpConfig | None:
    """Remetente do domínio; se não definido, o padrão do usuário; senão o primeiro cadastrado."""
    sender = None
    if domain is not None and domain.smtp_sender_id:
        sender = db.get(SmtpSender, domain.smtp_sender_id)
    if sender is None or sender.user_id != user_id:
        rows = db.scalars(select(SmtpSender).where(SmtpSender.user_id == user_id)
                          .order_by(SmtpSender.is_default.desc(), SmtpSender.id)).all()
        sender = rows[0] if rows else None
    return _from_sender(sender) if sender else None


def system_smtp(db: Session) -> SmtpConfig | None:
    server = cfg.sys_get(db, "sys_smtp_server")
    from_email = cfg.sys_get(db, "sys_smtp_from") or cfg.sys_get(db, "sys_smtp_user")
    if not (server and from_email):
        return None
    try:
        port = int(cfg.sys_get(db, "sys_smtp_port"))
    except ValueError:
        port = 587
    return SmtpConfig(server, port, cfg.sys_get(db, "sys_smtp_security"),
                      cfg.sys_get(db, "sys_smtp_user"), cfg.sys_get(db, "sys_smtp_password"),
                      from_email, cfg.sys_get(db, "sys_smtp_from_name"))


def telegram_token_for(db: Session, user_id: int, domain: Domain | None = None) -> str | None:
    bot = None
    if domain is not None and domain.telegram_bot_id:
        bot = db.get(TelegramBot, domain.telegram_bot_id)
    if bot is None or bot.user_id != user_id:
        bot = db.scalars(select(TelegramBot).where(TelegramBot.user_id == user_id)
                         .order_by(TelegramBot.is_default.desc(), TelegramBot.id)).first()
    return bot.token if bot and bot.token else None
