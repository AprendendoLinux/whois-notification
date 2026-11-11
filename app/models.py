"""Modelos do banco de dados."""
from datetime import datetime, timezone

from sqlalchemy import (
    JSON, Boolean, Column, DateTime, ForeignKey, Integer, String, Table, Text, UniqueConstraint,
)
from sqlalchemy.dialects.mysql import LONGTEXT
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator

from .crypto import decrypt, encrypt
from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AwareDateTime(TypeDecorator):
    """MySQL DATETIME não guarda fuso: gravamos em UTC e devolvemos sempre aware."""
    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).replace(tzinfo=None)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return value.replace(tzinfo=timezone.utc)


domain_contacts = Table(
    "domain_contacts",
    Base.metadata,
    Column("domain_id", ForeignKey("domains.id", ondelete="CASCADE"), primary_key=True),
    Column("contact_id", ForeignKey("contacts.id", ondelete="CASCADE"), primary_key=True),
)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    email: Mapped[str] = mapped_column(String(255), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(AwareDateTime, default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(AwareDateTime, nullable=True)

    @property
    def needs_email(self) -> bool:
        return self.email.endswith(PLACEHOLDER_EMAIL_DOMAIN)


PLACEHOLDER_EMAIL_DOMAIN = "@whois.local"


class PasswordReset(Base):
    __tablename__ = "password_resets"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(AwareDateTime)
    used: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(AwareDateTime, default=utcnow)


class SystemSetting(Base):
    """Configurações globais (somente administrador)."""
    __tablename__ = "system_settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str | None] = mapped_column(Text, nullable=True)


class UserSetting(Base):
    __tablename__ = "user_settings"
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str | None] = mapped_column(Text, nullable=True)


class SmtpSender(Base):
    __tablename__ = "smtp_senders"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    server: Mapped[str] = mapped_column(String(255))
    port: Mapped[int] = mapped_column(Integer, default=587)
    security: Mapped[str] = mapped_column(String(16), default="starttls")  # starttls | ssl | none
    username: Mapped[str] = mapped_column(String(255), default="")
    password_enc: Mapped[str] = mapped_column(Text, default="")
    from_email: Mapped[str] = mapped_column(String(255))
    from_name: Mapped[str] = mapped_column(String(120), default="Whois Notification")
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(AwareDateTime, default=utcnow)

    @property
    def password(self) -> str:
        return decrypt(self.password_enc)

    @password.setter
    def password(self, value: str) -> None:
        self.password_enc = encrypt(value)


class TelegramBot(Base):
    __tablename__ = "telegram_bots"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    token_enc: Mapped[str] = mapped_column(Text, default="")
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(AwareDateTime, default=utcnow)

    @property
    def token(self) -> str:
        return decrypt(self.token_enc)

    @token.setter
    def token(self, value: str) -> None:
        self.token_enc = encrypt(value)


class Contact(Base):
    __tablename__ = "contacts"
    __table_args__ = (UniqueConstraint("user_id", "kind", "value", name="uq_contact_user_kind_value"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120), default="")
    kind: Mapped[str] = mapped_column(String(16))  # email | telegram
    value: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(AwareDateTime, default=utcnow)

    domains: Mapped[list["Domain"]] = relationship(
        secondary=domain_contacts, back_populates="contacts"
    )

    @property
    def label(self) -> str:
        return f"{self.name} ({self.value})" if self.name else self.value


class Domain(Base):
    __tablename__ = "domains"
    __table_args__ = (UniqueConstraint("user_id", "name", name="uq_domain_user_name"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    smtp_sender_id: Mapped[int | None] = mapped_column(
        ForeignKey("smtp_senders.id", ondelete="SET NULL"), nullable=True)
    telegram_bot_id: Mapped[int | None] = mapped_column(
        ForeignKey("telegram_bots.id", ondelete="SET NULL"), nullable=True)
    days_threshold: Mapped[int] = mapped_column(Integer, default=30)
    ssl_threshold: Mapped[int] = mapped_column(Integer, default=14)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    monitor_ssl: Mapped[bool] = mapped_column(Boolean, default=True)
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(AwareDateTime, default=utcnow)

    # Resumo da última verificação (desnormalizado para o dashboard)
    last_checked_at: Mapped[datetime | None] = mapped_column(AwareDateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    expiration_date: Mapped[datetime | None] = mapped_column(AwareDateTime, nullable=True)
    creation_date: Mapped[datetime | None] = mapped_column(AwareDateTime, nullable=True)
    registrar: Mapped[str | None] = mapped_column(String(255), nullable=True)
    whois_status: Mapped[list | None] = mapped_column(JSON, nullable=True)
    nameservers: Mapped[list | None] = mapped_column(JSON, nullable=True)
    dnssec: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ssl_expires_at: Mapped[datetime | None] = mapped_column(AwareDateTime, nullable=True)
    ssl_issuer: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ssl_valid: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    http_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    email_score: Mapped[int | None] = mapped_column(Integer, nullable=True)

    contacts: Mapped[list[Contact]] = relationship(
        secondary=domain_contacts, back_populates="domains", order_by="Contact.kind"
    )
    checks: Mapped[list["Check"]] = relationship(
        back_populates="domain", cascade="all, delete-orphan", passive_deletes=True,
        order_by="Check.created_at.desc()",
    )
    changes: Mapped[list["Change"]] = relationship(
        back_populates="domain", cascade="all, delete-orphan", passive_deletes=True,
        order_by="Change.created_at.desc()",
    )
    notifications: Mapped[list["Notification"]] = relationship(
        back_populates="domain", cascade="all, delete-orphan", passive_deletes=True,
        order_by="Notification.created_at.desc()",
    )

    # ---- Derivados -------------------------------------------------------
    @staticmethod
    def _days_until(dt: datetime | None) -> int | None:
        if dt is None:
            return None
        delta = dt - utcnow()
        # Arredonda para baixo em dias inteiros (expira hoje = 0)
        return int(delta.total_seconds() // 86400)

    @property
    def days_left(self) -> int | None:
        return self._days_until(self.expiration_date)

    @property
    def ssl_days_left(self) -> int | None:
        return self._days_until(self.ssl_expires_at)

    @property
    def expiry_class(self) -> str:
        """Classe visual só do prazo do registro (sem considerar SSL)."""
        d = self.days_left
        if d is None:
            return "muted"
        if d < 0:
            return "dead"
        if d <= 7:
            return "crit"
        if d <= self.days_threshold:
            return "warn"
        return "ok"

    @property
    def health(self) -> str:
        """ok | warning | critical | expired | unknown | disabled"""
        if not self.enabled:
            return "disabled"
        d = self.days_left
        s = self.ssl_days_left if self.monitor_ssl else None
        if d is None and s is None:
            return "unknown"
        if (d is not None and d < 0) or (s is not None and s < 0):
            return "expired"
        if (d is not None and d <= 7) or (s is not None and s <= 3):
            return "critical"
        if (d is not None and d <= self.days_threshold) or (
            s is not None and s <= self.ssl_threshold
        ):
            return "warning"
        return "ok"


class Check(Base):
    __tablename__ = "checks"
    id: Mapped[int] = mapped_column(primary_key=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("domains.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(AwareDateTime, default=utcnow, index=True)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    success: Mapped[bool] = mapped_column(Boolean, default=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    whois: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    whois_raw: Mapped[str | None] = mapped_column(Text().with_variant(LONGTEXT, "mysql"), nullable=True)
    dns: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    ssl: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    http: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    domain: Mapped[Domain] = relationship(back_populates="checks")


class Change(Base):
    __tablename__ = "changes"
    id: Mapped[int] = mapped_column(primary_key=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("domains.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(AwareDateTime, default=utcnow, index=True)
    field: Mapped[str] = mapped_column(String(64))
    old_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    new_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="info")  # info | warning | critical

    domain: Mapped[Domain] = relationship(back_populates="changes")


class Notification(Base):
    __tablename__ = "notifications"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    domain_id: Mapped[int | None] = mapped_column(
        ForeignKey("domains.id", ondelete="CASCADE"), index=True, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(AwareDateTime, default=utcnow, index=True)
    kind: Mapped[str] = mapped_column(String(32))  # domain_expiry | ssl_expiry | change | test
    channel: Mapped[str] = mapped_column(String(16))  # email | telegram
    target: Mapped[str] = mapped_column(String(255))
    success: Mapped[bool] = mapped_column(Boolean, default=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    days_left: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Data de referência (expiração do domínio/SSL) para deduplicar por ciclo
    ref_date: Mapped[str | None] = mapped_column(String(32), nullable=True)
    subject: Mapped[str | None] = mapped_column(String(255), nullable=True)

    domain: Mapped[Domain | None] = relationship(back_populates="notifications")
