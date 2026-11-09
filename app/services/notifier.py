"""Envio de alertas por e-mail (HTML) e Telegram, com registro no banco."""
import glob
import html
import mimetypes
import smtplib
import ssl
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email import encoders
from email.utils import formataddr, make_msgid

import httpx
from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy.orm import Session

from ..config import BASE_DIR, DATA_DIR
from ..models import Domain, Notification
from . import settings as cfg

_env = Environment(
    loader=FileSystemLoader(BASE_DIR / "templates" / "email"),
    autoescape=select_autoescape(["html"]),
)

THEME = {
    "info": {"bg": "#0b5cad", "box_bg": "#e8f1fb", "box_border": "#1e88e5", "title": "#0b5cad", "icon": "ℹ️"},
    "warning": {"bg": "#d32f2f", "box_bg": "#fff4e5", "box_border": "#ff9800", "title": "#e65100", "icon": "⚠️"},
    "critical": {"bg": "#b71c1c", "box_bg": "#ffebee", "box_border": "#f44336", "title": "#c62828", "icon": "🚨"},
}


class Alert:
    """Conteúdo neutro de canal: vira e-mail HTML ou mensagem do Telegram."""

    def __init__(self, *, subject: str, header: str, severity: str, intro: str,
                 box_title: str, box_sub: str, rows: list[tuple[str, str]], footer: str = ""):
        self.subject = subject
        self.header = header
        self.severity = severity
        self.intro = intro  # texto simples; **negrito** é convertido por canal
        self.box_title = box_title
        self.box_sub = box_sub
        self.rows = rows
        self.footer = footer


def _bold(text: str, open_tag: str, close_tag: str) -> str:
    parts = html.escape(text).split("**")
    return "".join(p if i % 2 == 0 else f"{open_tag}{p}{close_tag}" for i, p in enumerate(parts))


# ---------------------------------------------------------------- E-mail ---
def _logo_path() -> str | None:
    for path in sorted(glob.glob(str(DATA_DIR / "logo.*"))):
        ctype, _ = mimetypes.guess_type(path)
        if ctype and ctype.startswith("image/"):
            return path
    fallback = BASE_DIR / "static" / "img" / "logo.png"
    return str(fallback) if fallback.exists() else None


def build_email(alert: Alert, sender: str, sender_name: str, recipients: list[str]) -> MIMEMultipart:
    theme = THEME[alert.severity]
    logo = _logo_path()
    body = _env.get_template("alert.html").render(
        a=alert, t=theme, has_logo=bool(logo),
        intro_html=_bold(alert.intro, "<strong>", "</strong>"),
    )
    msg = MIMEMultipart("related")
    msg["Subject"] = f"{theme['icon']} {alert.subject}"
    msg["From"] = formataddr((sender_name, sender))
    msg["To"] = ", ".join(recipients)
    msg["Message-ID"] = make_msgid(domain=sender.split("@")[-1] if "@" in sender else None)

    alt = MIMEMultipart("alternative")
    plain = alert.intro.replace("**", "") + "\n\n" + "\n".join(f"{k}: {v}" for k, v in alert.rows)
    alt.attach(MIMEText(plain, "plain", "utf-8"))
    alt.attach(MIMEText(body, "html", "utf-8"))
    msg.attach(alt)

    if logo:
        ctype, _ = mimetypes.guess_type(logo)
        maintype, subtype = (ctype or "application/octet-stream").split("/", 1)
        with open(logo, "rb") as f:
            img = MIMEBase(maintype, subtype)
            img.set_payload(f.read())
        encoders.encode_base64(img)
        img.add_header("Content-ID", "<logo>")
        img.add_header("Content-Disposition", "inline", filename=logo.rsplit("/", 1)[-1])
        msg.attach(img)
    return msg


def smtp_send(db: Session, msg: MIMEMultipart, recipients: list[str]) -> None:
    server = cfg.get(db, "smtp_server")
    port = cfg.get_int(db, "smtp_port")
    security = cfg.get(db, "smtp_security").lower()
    user = cfg.get(db, "smtp_user")
    password = cfg.get(db, "smtp_password")
    if not server:
        raise RuntimeError("Servidor SMTP não configurado")
    ctx = ssl.create_default_context()
    # Porta 465 implica SSL direto, mesmo se o usuário deixou "starttls"
    if security == "ssl" or (port == 465 and security != "none"):
        conn = smtplib.SMTP_SSL(server, port, timeout=30, context=ctx)
    else:
        conn = smtplib.SMTP(server, port, timeout=30)
    try:
        conn.ehlo()
        if security == "starttls" and port != 465:
            conn.starttls(context=ctx)
            conn.ehlo()
        if user:
            conn.login(user, password)
        conn.sendmail(cfg.get(db, "smtp_from") or user, recipients, msg.as_string())
    finally:
        try:
            conn.quit()
        except smtplib.SMTPException:
            pass


def email_ready(db: Session) -> bool:
    return bool(cfg.get(db, "smtp_server") and (cfg.get(db, "smtp_from") or cfg.get(db, "smtp_user")))


def telegram_ready(db: Session) -> bool:
    return bool(cfg.get(db, "telegram_token"))


# -------------------------------------------------------------- Telegram ---
def build_telegram(alert: Alert) -> str:
    icon = THEME[alert.severity]["icon"]
    lines = [
        f"{icon} <b>Whois Notification — {html.escape(alert.header)}</b> {icon}",
        "",
        _bold(alert.intro, "<b>", "</b>"),
        "",
        f"<b>{html.escape(alert.box_title)}</b>",
        f"<i>{html.escape(alert.box_sub)}</i>",
        "",
    ]
    for k, v in alert.rows:
        lines.append(f"• <b>{html.escape(k)}:</b> {html.escape(str(v))}")
    if alert.footer:
        lines += ["", html.escape(alert.footer)]
    return "\n".join(lines)


def telegram_send(db: Session, chat_id: str, text: str) -> None:
    token = cfg.get(db, "telegram_token")
    if not token:
        raise RuntimeError("Token do bot do Telegram não configurado")
    r = httpx.post(
        f"https://api.telegram.org/bot{token}/sendMessage",
        json={"chat_id": chat_id, "text": text, "parse_mode": "HTML",
              "disable_web_page_preview": True},
        timeout=20,
    )
    data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    if r.status_code != 200 or not data.get("ok"):
        raise RuntimeError(f"Telegram {r.status_code}: {data.get('description') or r.text[:200]}")


# --------------------------------------------------------------- Dispatch ---
def _short_error(e: Exception, secret: str | None) -> str:
    msg = str(e)
    if secret:
        msg = msg.replace(secret, "***")
    return f"{type(e).__name__}: {msg}"[:500]


def dispatch(db: Session, domain: Domain | None, alert: Alert, kind: str, *,
             emails: list[str], chats: list[str], days_left: int | None = None,
             ref_date: str | None = None) -> list[Notification]:
    """Envia para todos os destinos e registra cada tentativa."""
    results: list[Notification] = []
    secret = cfg.get(db, "telegram_token")

    def log(channel: str, target: str, err: Exception | None):
        n = Notification(
            domain_id=domain.id if domain else None, kind=kind, channel=channel,
            target=target, success=err is None, error=_short_error(err, secret) if err else None,
            days_left=days_left, ref_date=ref_date, subject=alert.subject[:255],
        )
        db.add(n)
        results.append(n)

    if emails:
        try:
            sender = cfg.get(db, "smtp_from") or cfg.get(db, "smtp_user")
            msg = build_email(alert, sender, cfg.get(db, "smtp_from_name"), emails)
            smtp_send(db, msg, emails)
            for e in emails:
                log("email", e, None)
        except Exception as exc:  # noqa: BLE001 — registramos qualquer falha
            for e in emails:
                log("email", e, exc)

    if chats:
        text = build_telegram(alert)
        for chat in chats:
            try:
                telegram_send(db, chat, text)
                log("telegram", chat, None)
            except Exception as exc:  # noqa: BLE001
                log("telegram", chat, exc)

    db.commit()
    return results
