"""Envio de alertas por e-mail (HTML) e Telegram, com registro no banco."""
import html
import smtplib
import ssl
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, make_msgid

import httpx
from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy.orm import Session

from ..config import APP_VERSION, BASE_DIR
from ..models import Domain, Notification
from .senders import SmtpConfig, smtp_for, system_smtp, telegram_token_for

_env = Environment(
    loader=FileSystemLoader(BASE_DIR / "templates" / "email"),
    autoescape=select_autoescape(["html"]),
)

THEME = {
    "info": {"accent": "#00e5ff", "accent2": "#8b5cff", "box_bg": "#0d1a30", "icon": "ℹ️"},
    "warning": {"accent": "#ffb020", "accent2": "#ff7a18", "box_bg": "#1c1608", "icon": "⚠️"},
    "critical": {"accent": "#ff4d6a", "accent2": "#ff2bd6", "box_bg": "#1f0c16", "icon": "🚨"},
}

LOGO_PATH = BASE_DIR / "static" / "img" / "logo-email.png"


class Alert:
    """Conteúdo neutro de canal: vira e-mail HTML ou mensagem do Telegram."""

    def __init__(self, *, subject: str, header: str, severity: str, intro: str,
                 box_title: str, box_sub: str, rows: list[tuple[str, str]], footer: str = "",
                 action: tuple[str, str] | None = None):
        self.subject = subject
        self.header = header
        self.severity = severity
        self.intro = intro  # texto simples; **negrito** é convertido por canal
        self.box_title = box_title
        self.box_sub = box_sub
        self.rows = rows
        self.footer = footer
        self.action = action  # (rótulo, URL) opcional: botão no e-mail


def _bold(text: str, open_tag: str, close_tag: str) -> str:
    parts = html.escape(text).split("**")
    return "".join(p if i % 2 == 0 else f"{open_tag}{p}{close_tag}" for i, p in enumerate(parts))


# ---------------------------------------------------------------- E-mail ---
def build_email(alert: Alert, cfg: SmtpConfig, recipients: list[str]) -> MIMEMultipart:
    theme = THEME[alert.severity]
    has_logo = LOGO_PATH.exists()
    body = _env.get_template("alert.html").render(
        a=alert, t=theme, has_logo=has_logo, version=APP_VERSION,
        intro_html=_bold(alert.intro, "<strong>", "</strong>"),
    )
    msg = MIMEMultipart("related")
    msg["Subject"] = f"{theme['icon']} {alert.subject}"
    msg["From"] = formataddr((cfg.from_name, cfg.from_email))
    msg["To"] = ", ".join(recipients)
    msg["Message-ID"] = make_msgid(domain=cfg.from_email.split("@")[-1] if "@" in cfg.from_email else None)

    alt = MIMEMultipart("alternative")
    plain = alert.intro.replace("**", "") + "\n\n" + "\n".join(f"{k}: {v}" for k, v in alert.rows)
    if alert.action:
        plain += f"\n\n{alert.action[0]}: {alert.action[1]}"
    alt.attach(MIMEText(plain, "plain", "utf-8"))
    alt.attach(MIMEText(body, "html", "utf-8"))
    msg.attach(alt)

    if has_logo:
        img = MIMEImage(LOGO_PATH.read_bytes(), _subtype="png")
        img.add_header("Content-ID", "<logo>")
        img.add_header("Content-Disposition", "inline", filename="logo.png")
        msg.attach(img)
    return msg


def smtp_send(cfg: SmtpConfig, msg: MIMEMultipart, recipients: list[str]) -> None:
    security = cfg.security.lower()
    ctx = ssl.create_default_context()
    # Porta 465 implica SSL direto, mesmo se o usuário deixou "starttls"
    if security == "ssl" or (cfg.port == 465 and security != "none"):
        conn = smtplib.SMTP_SSL(cfg.server, cfg.port, timeout=30, context=ctx)
    else:
        conn = smtplib.SMTP(cfg.server, cfg.port, timeout=30)
    try:
        conn.ehlo()
        if security == "starttls" and cfg.port != 465:
            conn.starttls(context=ctx)
            conn.ehlo()
        if cfg.username:
            conn.login(cfg.username, cfg.password)
        conn.sendmail(cfg.from_email, recipients, msg.as_string())
    finally:
        try:
            conn.quit()
        except smtplib.SMTPException:
            pass


def email_ready(db: Session, user_id: int, domain: Domain | None = None) -> bool:
    return smtp_for(db, user_id, domain) is not None


def telegram_ready(db: Session, user_id: int, domain: Domain | None = None) -> bool:
    return telegram_token_for(db, user_id, domain) is not None


def send_system_mail(db: Session, alert: Alert, to: str, fallback_user_id: int | None = None) -> None:
    """E-mail do sistema (recuperação de senha): SMTP global ou, na falta dele, o do usuário."""
    cfg = system_smtp(db) or (smtp_for(db, fallback_user_id) if fallback_user_id else None)
    if cfg is None:
        raise RuntimeError("Nenhum servidor SMTP configurado para envio de e-mails do sistema")
    smtp_send(cfg, build_email(alert, cfg, [to]), [to])


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


def telegram_send(token: str | None, chat_id: str, text: str) -> None:
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


def dispatch(db: Session, user_id: int, domain: Domain | None, alert: Alert, kind: str, *,
             emails: list[str], chats: list[str], days_left: int | None = None,
             ref_date: str | None = None) -> list[Notification]:
    """Envia para todos os destinos (com os remetentes do usuário) e registra cada tentativa."""
    results: list[Notification] = []
    smtp = smtp_for(db, user_id, domain)
    token = telegram_token_for(db, user_id, domain)

    def log(channel: str, target: str, err: Exception | None):
        n = Notification(
            user_id=user_id, domain_id=domain.id if domain else None, kind=kind, channel=channel,
            target=target, success=err is None,
            error=_short_error(err, token) if err else None,
            days_left=days_left, ref_date=ref_date, subject=alert.subject[:255],
        )
        db.add(n)
        results.append(n)

    if emails:
        try:
            if smtp is None:
                raise RuntimeError("Nenhum remetente SMTP cadastrado")
            smtp_send(smtp, build_email(alert, smtp, emails), emails)
            for e in emails:
                log("email", e, None)
        except Exception as exc:  # noqa: BLE001 — registramos qualquer falha
            for e in emails:
                log("email", e, exc)

    if chats:
        text = build_telegram(alert)
        for chat in chats:
            try:
                telegram_send(token, chat, text)
                log("telegram", chat, None)
            except Exception as exc:  # noqa: BLE001
                log("telegram", chat, exc)

    db.commit()
    return results
