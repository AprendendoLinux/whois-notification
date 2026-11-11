"""Páginas HTML da interface (sempre restritas aos dados do usuário logado)."""
import json
import re

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session, selectinload

from .. import auth, scheduler
from ..config import DB_NAME
from ..db import get_db
from ..models import (
    Change, Check, Contact, Domain, Notification, PasswordReset, SmtpSender, TelegramBot, User, utcnow,
)
from ..services import checker
from ..services import settings as cfg
from ..services.notifier import Alert, dispatch, email_ready, send_system_mail, telegram_ready
from ..utils import CHAT_RE, DOMAIN_RE, EMAIL_RE, normalize_domain
from ..web import csrf_protect, flash, render, require_user, require_user_any

router = APIRouter(dependencies=[Depends(csrf_protect)])


def redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


def is_checking(domain_id: int) -> bool:
    return checker.is_running(domain_id) or scheduler.scheduler.get_job(f"check_{domain_id}") is not None


def public_base(request: Request, db: Session) -> str:
    configured = cfg.sys_get(db, "public_url").strip().rstrip("/")
    return configured or str(request.base_url).rstrip("/")


def _password_error(password: str, password2: str) -> str | None:
    if len(password) < 8:
        return "A senha precisa de pelo menos 8 caracteres."
    if password != password2:
        return "As senhas não conferem."
    return None


# ------------------------------------------------------------------ Auth --
@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request, db: Session = Depends(get_db)):
    if auth.current_user(request, db):
        return redirect("/")
    return render(request, "login.html")


@router.post("/login")
def login_submit(request: Request, username: str = Form(...), password: str = Form(...),
                 db: Session = Depends(get_db)):
    username = username.strip()
    key = f"{request.client.host if request.client else '-'}|{username.lower()}"
    if auth.too_many_attempts(key):
        return render(request, "login.html", {"error": "Muitas tentativas. Aguarde alguns minutos.",
                                              "username": username}, 429)
    user = db.scalar(select(User).where(User.username == username))
    ok = bool(user) and auth.verify_password(password, user.password_hash)
    if not ok:
        auth.register_failure(key)
        return render(request, "login.html", {"error": "Usuário ou senha inválidos.",
                                              "username": username}, 401)
    if not user.is_active:
        return render(request, "login.html", {"error": "Este usuário está desativado."}, 403)
    auth.clear_failures(key)
    user.last_login_at = utcnow()
    db.commit()
    auth.login_session(request, user)
    return redirect("/")


@router.post("/logout")
def logout(request: Request):
    request.session.clear()
    return redirect("/login")


@router.get("/forgot", response_class=HTMLResponse)
def forgot_form(request: Request):
    return render(request, "forgot.html")


@router.post("/forgot")
def forgot_submit(request: Request, email: str = Form(...), db: Session = Depends(get_db)):
    email = email.strip().lower()
    key = f"forgot|{request.client.host if request.client else '-'}"
    if auth.too_many_attempts(key):
        return render(request, "forgot.html", {"error": "Muitas tentativas. Aguarde alguns minutos."}, 429)
    auth.register_failure(key)
    user = db.scalar(select(User).where(func.lower(User.email) == email, User.is_active.is_(True)))
    if user and not user.needs_email:
        token = auth.create_reset_token(db, user)
        if token:
            link = f"{public_base(request, db)}/reset/{token}"
            alert = Alert(
                subject="Redefinição de senha", header="Redefinição de senha", severity="info",
                intro=f"Recebemos um pedido para redefinir a senha do usuário **{user.username}**. "
                      "O link abaixo vale por 1 hora e só pode ser usado uma vez.",
                box_title="", box_sub="", rows=[],
                footer="Se você não fez este pedido, ignore este e-mail: sua senha continua a mesma.",
                action=("Criar nova senha", link),
            )
            try:
                send_system_mail(db, alert, user.email, fallback_user_id=user.id)
            except Exception as e:  # noqa: BLE001
                print(f"[!] Falha ao enviar e-mail de recuperação para {user.username}: {e}", flush=True)
                db.execute(delete(PasswordReset).where(PasswordReset.user_id == user.id))
                db.commit()
    return render(request, "forgot.html", {"sent": True})


@router.get("/reset/{token}", response_class=HTMLResponse)
def reset_form(token: str, request: Request, db: Session = Depends(get_db)):
    if auth.find_reset(db, token) is None:
        return render(request, "forgot.html", {"error": "Link inválido ou expirado. Solicite um novo."}, 400)
    return render(request, "reset.html", {"token": token})


@router.post("/reset/{token}")
def reset_submit(token: str, request: Request, password: str = Form(...), password2: str = Form(...),
                 db: Session = Depends(get_db)):
    row = auth.find_reset(db, token)
    if row is None:
        return render(request, "forgot.html", {"error": "Link inválido ou expirado. Solicite um novo."}, 400)
    error = _password_error(password, password2)
    if error:
        return render(request, "reset.html", {"token": token, "error": error}, 400)
    user = db.get(User, row.user_id)
    user.password_hash = auth.hash_password(password)
    user.must_change_password = False
    row.used = True
    db.commit()
    request.session.clear()
    flash(request, "Senha redefinida. Entre com a nova senha.")
    return redirect("/login")


@router.get("/account/required", response_class=HTMLResponse)
def required_form(request: Request, user: User = Depends(require_user_any)):
    if not (user.must_change_password or user.needs_email):
        return redirect("/")
    return render(request, "password_required.html", {"user": user})


@router.post("/account/required")
def required_submit(request: Request, password: str = Form(...), password2: str = Form(...),
                    email: str = Form(""), user: User = Depends(require_user_any),
                    db: Session = Depends(get_db)):
    ctx = {"user": user}
    error = _password_error(password, password2)
    if not error and auth.verify_password(password, user.password_hash):
        error = "A nova senha deve ser diferente da senha temporária."
    new_email = user.email
    if not error and user.needs_email:
        new_email = email.strip().lower()
        if not EMAIL_RE.match(new_email) or new_email.endswith("@whois.local"):
            error = "Informe um e-mail válido (obrigatório)."
        elif db.scalar(select(User.id).where(func.lower(User.email) == new_email, User.id != user.id)):
            error = "Este e-mail já está em uso por outro usuário."
    if error:
        return render(request, "password_required.html", {**ctx, "error": error}, 400)
    user.password_hash = auth.hash_password(password)
    user.email = new_email
    user.must_change_password = False
    db.commit()
    auth.login_session(request, user)
    flash(request, "Senha alterada. Bem-vindo!")
    return redirect("/")


# ------------------------------------------------------------- Dashboard --
def _dashboard_ctx(db: Session, user: User) -> dict:
    domains = db.scalars(select(Domain).options(selectinload(Domain.contacts))
                         .where(Domain.user_id == user.id).order_by(Domain.name)).all()
    order = {"expired": 0, "critical": 1, "warning": 2, "unknown": 3, "ok": 4, "disabled": 5}
    domains = sorted(domains, key=lambda d: (order[d.health],
                                             d.days_left if d.days_left is not None else 10**6))
    stats = {k: 0 for k in order}
    for d in domains:
        stats[d.health] += 1
    recent_changes = db.scalars(
        select(Change).join(Domain).options(selectinload(Change.domain))
        .where(Domain.user_id == user.id).order_by(Change.created_at.desc()).limit(8)
    ).all()
    kinds = set(db.scalars(select(Contact.kind).join(Contact.domains)
                           .where(Contact.user_id == user.id).distinct()))
    channel_warnings = []
    if "email" in kinds and not email_ready(db, user.id):
        channel_warnings.append("e-mail (cadastre um remetente SMTP)")
    if "telegram" in kinds and not telegram_ready(db, user.id):
        channel_warnings.append("Telegram (cadastre um bot)")
    sent = dict(db.execute(
        select(Notification.success, func.count(Notification.id))
        .where(Notification.user_id == user.id).group_by(Notification.success)).all())
    chart = [{
        "id": d.id, "name": d.name, "health": d.health,
        "exp": d.expiration_date.isoformat() if d.expiration_date else None,
        "ssl": d.ssl_expires_at.isoformat() if d.ssl_expires_at and d.monitor_ssl else None,
        "days": d.days_left, "ssl_days": d.ssl_days_left if d.monitor_ssl else None,
    } for d in domains]
    mine = {d.id for d in domains}
    return {
        "domains_json": json.dumps(chart).replace("</", "<\\/"),
        "db_name": DB_NAME,
        "domains": domains, "stats": stats, "total": len(domains),
        "channel_warnings": channel_warnings,
        "recent_changes": recent_changes, "sent_ok": sent.get(True, 0), "sent_fail": sent.get(False, 0),
        "next_run": scheduler.next_run(user.id), "running_all": scheduler.is_running_all(user.id),
        "running": checker.running_ids() & mine,
    }


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    return render(request, "dashboard.html", {"user": user, "nav": "dashboard", **_dashboard_ctx(db, user)})


@router.get("/partials/fleet", response_class=HTMLResponse)
def fleet_partial(request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    ctx = _dashboard_ctx(db, user)
    resp = render(request, "partials/fleet.html", ctx)
    # Varredura terminou: recarrega a página para atualizar indicadores e gráficos
    if request.query_params.get("was") == "1" and not (ctx["running_all"] or ctx["running"]):
        resp.headers["HX-Refresh"] = "true"
    return resp


@router.post("/check-all")
def check_all(request: Request, user: User = Depends(require_user)):
    if scheduler.run_all_in_background(user.id):
        flash(request, "Varredura completa iniciada. Os cartões serão atualizados automaticamente.")
    else:
        flash(request, "Já existe uma varredura em andamento.", "warn")
    return redirect("/")


# --------------------------------------------------------------- Domínios --
def _domain_or_404(db: Session, domain_id: int, user: User) -> Domain:
    d = db.get(Domain, domain_id)
    if d is None or d.user_id != user.id:
        raise HTTPException(404, "Domínio não encontrado")
    return d


def _form_ctx(db: Session, user: User, domain: Domain | None, **extra) -> dict:
    contacts = db.scalars(select(Contact).where(Contact.user_id == user.id)
                          .order_by(Contact.kind, Contact.name, Contact.value)).all()
    smtp = db.scalars(select(SmtpSender).where(SmtpSender.user_id == user.id).order_by(SmtpSender.name)).all()
    bots = db.scalars(select(TelegramBot).where(TelegramBot.user_id == user.id).order_by(TelegramBot.name)).all()
    return {"domain": domain, "contacts": contacts, "smtp_senders": smtp, "bots": bots,
            "nav": "dashboard" if domain else "domains", **extra}


def _parse_list(raw: str) -> list[str]:
    return [p.strip() for p in re.split(r"[,;\s]+", raw or "") if p.strip()]


def get_or_create_contact(db: Session, user_id: int, kind: str, value: str, name: str = "") -> Contact:
    value = value.strip()
    c = db.scalar(select(Contact).where(Contact.user_id == user_id, Contact.kind == kind,
                                        Contact.value == value))
    if c is None:
        c = Contact(user_id=user_id, kind=kind, value=value, name=name)
        db.add(c)
        db.flush()
    return c


def _owned_id(db: Session, model, raw, user: User) -> int | None:
    if not str(raw or "").isdigit():
        return None
    obj = db.get(model, int(raw))
    return obj.id if obj is not None and obj.user_id == user.id else None


def _apply_form(db: Session, user: User, d: Domain, form) -> list[str]:
    errors = []
    name = normalize_domain(form.get("name", ""))
    if not DOMAIN_RE.match(name):
        errors.append("Nome de domínio inválido (ex.: suaempresa.com.br).")
    else:
        clash = db.scalar(select(Domain).where(Domain.user_id == user.id, Domain.name == name,
                                               Domain.id != (d.id or 0)))
        if clash:
            errors.append(f"O domínio {name} já está cadastrado.")
    try:
        d.days_threshold = max(1, min(int(form.get("days_threshold") or 30), 3650))
        d.ssl_threshold = max(1, min(int(form.get("ssl_threshold") or 14), 365))
    except ValueError:
        errors.append("Os limites de dias devem ser números inteiros.")
    d.user_id = user.id
    d.name = name
    d.enabled = form.get("enabled") == "on"
    d.monitor_ssl = form.get("monitor_ssl") == "on"
    d.notes = (form.get("notes") or "").strip()[:2000]
    d.smtp_sender_id = _owned_id(db, SmtpSender, form.get("smtp_sender_id"), user)
    d.telegram_bot_id = _owned_id(db, TelegramBot, form.get("telegram_bot_id"), user)

    ids = {int(i) for i in form.getlist("contact_ids") if str(i).isdigit()}
    selected = list(db.scalars(select(Contact).where(Contact.id.in_(ids), Contact.user_id == user.id))) if ids else []
    for email in _parse_list(form.get("new_emails", "")):
        if EMAIL_RE.match(email):
            selected.append(get_or_create_contact(db, user.id, "email", email.lower()))
        else:
            errors.append(f"E-mail inválido: {email}")
    for chat in _parse_list(form.get("new_telegrams", "")):
        if CHAT_RE.match(chat):
            selected.append(get_or_create_contact(db, user.id, "telegram", chat))
        else:
            errors.append(f"Chat ID do Telegram inválido: {chat}")
    d.contacts = list({c.id: c for c in selected}.values())
    return errors


@router.get("/domains/new", response_class=HTMLResponse)
def domain_new(request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    return render(request, "domain_form.html", {"user": user, **_form_ctx(db, user, None)})


@router.post("/domains/new")
async def domain_create(request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    form = await request.form()
    d = Domain()
    with db.no_autoflush:
        errors = _apply_form(db, user, d, form)
    if errors:
        db.rollback()
        return render(request, "domain_form.html",
                      {"user": user, "errors": errors, "form": form, **_form_ctx(db, user, None)}, 400)
    db.add(d)
    db.commit()
    scheduler.run_one_in_background(d.id)
    flash(request, f"{d.name} cadastrado. A primeira varredura já começou.")
    return redirect(f"/domains/{d.id}")


@router.get("/domains/{domain_id}", response_class=HTMLResponse)
def domain_detail(domain_id: int, request: Request, user: User = Depends(require_user),
                  db: Session = Depends(get_db)):
    d = _domain_or_404(db, domain_id, user)
    checks = db.scalars(
        select(Check).where(Check.domain_id == d.id).order_by(Check.created_at.desc()).limit(60)
    ).all()
    latest = next((c for c in checks), None)
    last_ok = next((c for c in checks if c.success), None)
    return render(request, "domain_detail.html", {
        "user": user, "nav": "dashboard", "d": d, "latest": latest, "last_ok": last_ok,
        "checks": checks, "checking": is_checking(d.id),
        "changes": d.changes[:50], "notifications": d.notifications[:50],
    })


@router.get("/domains/{domain_id}/status", response_class=HTMLResponse)
def domain_status(domain_id: int, request: Request, user: User = Depends(require_user),
                  db: Session = Depends(get_db)):
    d = _domain_or_404(db, domain_id, user)
    checking = is_checking(d.id)
    resp = render(request, "partials/check_button.html", {"d": d, "checking": checking})
    # Quando terminar, recarrega a página para mostrar os dados novos
    if not checking and request.query_params.get("was") == "1":
        resp.headers["HX-Refresh"] = "true"
    return resp


@router.post("/domains/{domain_id}/check", response_class=HTMLResponse)
def domain_check(domain_id: int, request: Request, user: User = Depends(require_user),
                 db: Session = Depends(get_db)):
    d = _domain_or_404(db, domain_id, user)
    if not is_checking(d.id):
        scheduler.run_one_in_background(d.id)
    if request.headers.get("HX-Request"):
        return render(request, "partials/check_button.html", {"d": d, "checking": True})
    return redirect(f"/domains/{d.id}")


@router.get("/domains/{domain_id}/edit", response_class=HTMLResponse)
def domain_edit(domain_id: int, request: Request, user: User = Depends(require_user),
                db: Session = Depends(get_db)):
    d = _domain_or_404(db, domain_id, user)
    return render(request, "domain_form.html", {"user": user, **_form_ctx(db, user, d)})


@router.post("/domains/{domain_id}/edit")
async def domain_update(domain_id: int, request: Request, user: User = Depends(require_user),
                        db: Session = Depends(get_db)):
    d = _domain_or_404(db, domain_id, user)
    old_name = d.name
    form = await request.form()
    with db.no_autoflush:
        errors = _apply_form(db, user, d, form)
    if errors:
        db.rollback()
        d = _domain_or_404(db, domain_id, user)
        return render(request, "domain_form.html",
                      {"user": user, "errors": errors, "form": form, **_form_ctx(db, user, d)}, 400)
    renamed = d.name != old_name
    if renamed:
        # Dados antigos pertencem a outro domínio
        for attr in ("expiration_date", "creation_date", "registrar", "whois_status", "nameservers",
                     "dnssec", "ssl_expires_at", "ssl_issuer", "ssl_valid", "http_status", "http_ms",
                     "email_score", "last_checked_at", "last_error"):
            setattr(d, attr, None)
        for c in list(d.checks):
            db.delete(c)
    db.commit()
    if renamed:
        scheduler.run_one_in_background(d.id)
    flash(request, "Alterações salvas.")
    return redirect(f"/domains/{d.id}")


@router.post("/domains/{domain_id}/delete")
def domain_delete(domain_id: int, request: Request, user: User = Depends(require_user),
                  db: Session = Depends(get_db)):
    d = _domain_or_404(db, domain_id, user)
    name = d.name
    db.delete(d)
    db.commit()
    flash(request, f"{name} removido do monitoramento.")
    return redirect("/")


# --------------------------------------------------------------- Contatos --
def _own_contact(db: Session, contact_id: int, user: User) -> Contact | None:
    c = db.get(Contact, contact_id)
    return c if c is not None and c.user_id == user.id else None


@router.get("/contacts", response_class=HTMLResponse)
def contacts_page(request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    contacts = db.scalars(
        select(Contact).options(selectinload(Contact.domains)).where(Contact.user_id == user.id)
        .order_by(Contact.kind, Contact.name, Contact.value)
    ).all()
    return render(request, "contacts.html", {"user": user, "nav": "contacts", "contacts": contacts})


@router.post("/contacts")
def contacts_create(request: Request, kind: str = Form(...), value: str = Form(...), name: str = Form(""),
                    user: User = Depends(require_user), db: Session = Depends(get_db)):
    value = value.strip()
    if kind == "email" and EMAIL_RE.match(value):
        value = value.lower()
    elif not (kind == "telegram" and CHAT_RE.match(value)):
        flash(request, "Contato inválido. Use um e-mail ou um Chat ID numérico do Telegram.", "err")
        return redirect("/contacts")
    c = get_or_create_contact(db, user.id, kind, value, name.strip())
    if name.strip():
        c.name = name.strip()[:120]
    db.commit()
    flash(request, "Contato salvo.")
    return redirect("/contacts")


@router.post("/contacts/{contact_id}/rename")
def contacts_rename(contact_id: int, request: Request, name: str = Form(""),
                    user: User = Depends(require_user), db: Session = Depends(get_db)):
    c = _own_contact(db, contact_id, user)
    if c:
        c.name = name.strip()[:120]
        db.commit()
        flash(request, "Contato atualizado.")
    return redirect("/contacts")


@router.post("/contacts/{contact_id}/test")
def contacts_test(contact_id: int, request: Request, user: User = Depends(require_user),
                  db: Session = Depends(get_db)):
    c = _own_contact(db, contact_id, user)
    if c:
        _send_test(request, db, user, c.kind, c.value)
    return redirect("/contacts")


@router.post("/contacts/{contact_id}/delete")
def contacts_delete(contact_id: int, request: Request, user: User = Depends(require_user),
                    db: Session = Depends(get_db)):
    c = _own_contact(db, contact_id, user)
    if c:
        db.delete(c)
        db.commit()
        flash(request, "Contato removido.")
    return redirect("/contacts")


def _send_test(request: Request, db: Session, user: User, channel: str, target: str,
               smtp_id: int | None = None, bot_id: int | None = None) -> None:
    alert = Alert(
        subject="Teste de notificação", header="Teste de notificação", severity="info",
        intro="Se você recebeu esta mensagem, o canal está configurado corretamente no **Whois Notification**.",
        box_title="Tudo certo!", box_sub="Mensagem de teste enviada pela interface",
        rows=[("Canal", "E-mail" if channel == "email" else "Telegram"), ("Destino", target)],
    )
    if channel == "email" and not email_ready(db, user.id):
        flash(request, "Cadastre um remetente SMTP em Remetentes antes de testar o e-mail.", "err")
        return
    if channel == "telegram" and not telegram_ready(db, user.id):
        flash(request, "Cadastre um bot do Telegram em Remetentes antes de testar.", "err")
        return
    probe = Domain(smtp_sender_id=smtp_id, telegram_bot_id=bot_id) if (smtp_id or bot_id) else None
    res = dispatch(db, user.id, probe, alert, "test",
                   emails=[target] if channel == "email" else [],
                   chats=[target] if channel == "telegram" else [])
    if res and res[0].success:
        flash(request, f"Mensagem de teste enviada para {target}.")
    else:
        flash(request, f"Falha ao enviar para {target}: {res[0].error if res else 'sem resultado'}", "err")


# ------------------------------------------------------------- Remetentes --
@router.get("/senders", response_class=HTMLResponse)
def senders_page(request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    smtp = db.scalars(select(SmtpSender).where(SmtpSender.user_id == user.id)
                      .order_by(SmtpSender.is_default.desc(), SmtpSender.name)).all()
    bots = db.scalars(select(TelegramBot).where(TelegramBot.user_id == user.id)
                      .order_by(TelegramBot.is_default.desc(), TelegramBot.name)).all()
    return render(request, "senders.html", {"user": user, "nav": "senders", "smtp": smtp, "bots": bots})


def _own(db: Session, model, obj_id: int, user: User):
    obj = db.get(model, obj_id)
    if obj is None or obj.user_id != user.id:
        raise HTTPException(404, "Registro não encontrado")
    return obj


def _make_default(db: Session, model, user: User, keep) -> None:
    for row in db.scalars(select(model).where(model.user_id == user.id)):
        row.is_default = row is keep


@router.post("/senders/smtp")
@router.post("/senders/smtp/{sender_id}")
def smtp_save(request: Request, sender_id: int | None = None, name: str = Form(...),
              server: str = Form(...), port: int = Form(587), security: str = Form("starttls"),
              username: str = Form(""), password: str = Form(""), from_email: str = Form(...),
              from_name: str = Form("Whois Notification"), clear_password: str = Form(""),
              user: User = Depends(require_user), db: Session = Depends(get_db)):
    from_email = from_email.strip()
    if not EMAIL_RE.match(from_email) or not name.strip() or not server.strip():
        flash(request, "Preencha nome, servidor e um e-mail de remetente válido.", "err")
        return redirect("/senders")
    if security not in ("starttls", "ssl", "none") or not (1 <= port <= 65535):
        flash(request, "Segurança ou porta inválida.", "err")
        return redirect("/senders")
    s = _own(db, SmtpSender, sender_id, user) if sender_id else SmtpSender(user_id=user.id)
    s.name, s.server, s.port, s.security = name.strip()[:120], server.strip(), port, security
    s.username, s.from_email, s.from_name = username.strip(), from_email, from_name.strip()[:120]
    if clear_password == "on":
        s.password = ""
    elif password:
        s.password = password
    if not sender_id:
        db.add(s)
        db.flush()
        if not db.scalar(select(SmtpSender.id).where(SmtpSender.user_id == user.id,
                                                     SmtpSender.is_default.is_(True))):
            s.is_default = True
    db.commit()
    flash(request, "Remetente SMTP salvo.")
    return redirect("/senders")


@router.post("/senders/smtp/{sender_id}/default")
def smtp_default(sender_id: int, user: User = Depends(require_user), db: Session = Depends(get_db)):
    _make_default(db, SmtpSender, user, _own(db, SmtpSender, sender_id, user))
    db.commit()
    return redirect("/senders")


@router.post("/senders/smtp/{sender_id}/test")
def smtp_test(sender_id: int, request: Request, user: User = Depends(require_user),
              db: Session = Depends(get_db)):
    s = _own(db, SmtpSender, sender_id, user)
    _send_test(request, db, user, "email", user.email, smtp_id=s.id)
    return redirect("/senders")


@router.post("/senders/smtp/{sender_id}/delete")
def smtp_delete(sender_id: int, request: Request, user: User = Depends(require_user),
                db: Session = Depends(get_db)):
    s = _own(db, SmtpSender, sender_id, user)
    was_default = s.is_default
    db.delete(s)
    db.flush()
    if was_default:
        nxt = db.scalars(select(SmtpSender).where(SmtpSender.user_id == user.id)).first()
        if nxt:
            nxt.is_default = True
    db.commit()
    flash(request, "Remetente removido.")
    return redirect("/senders")


@router.post("/senders/telegram")
@router.post("/senders/telegram/{bot_id}")
def bot_save(request: Request, bot_id: int | None = None, name: str = Form(...), token: str = Form(""),
             user: User = Depends(require_user), db: Session = Depends(get_db)):
    token = token.strip()
    if not name.strip() or (not bot_id and not re.fullmatch(r"\d{5,}:[A-Za-z0-9_-]{20,}", token)) or \
            (bot_id and token and not re.fullmatch(r"\d{5,}:[A-Za-z0-9_-]{20,}", token)):
        flash(request, "Informe um nome e um token de bot válido (123456789:ABC...).", "err")
        return redirect("/senders")
    b = _own(db, TelegramBot, bot_id, user) if bot_id else TelegramBot(user_id=user.id)
    b.name = name.strip()[:120]
    if token:
        b.token = token
    if not bot_id:
        db.add(b)
        db.flush()
        if not db.scalar(select(TelegramBot.id).where(TelegramBot.user_id == user.id,
                                                      TelegramBot.is_default.is_(True))):
            b.is_default = True
    db.commit()
    flash(request, "Bot do Telegram salvo.")
    return redirect("/senders")


@router.post("/senders/telegram/{bot_id}/default")
def bot_default(bot_id: int, user: User = Depends(require_user), db: Session = Depends(get_db)):
    _make_default(db, TelegramBot, user, _own(db, TelegramBot, bot_id, user))
    db.commit()
    return redirect("/senders")


@router.post("/senders/telegram/{bot_id}/test")
def bot_test(bot_id: int, request: Request, chat_id: str = Form(...), user: User = Depends(require_user),
             db: Session = Depends(get_db)):
    b = _own(db, TelegramBot, bot_id, user)
    chat_id = chat_id.strip()
    if not CHAT_RE.match(chat_id):
        flash(request, "Chat ID inválido.", "err")
    else:
        _send_test(request, db, user, "telegram", chat_id, bot_id=b.id)
    return redirect("/senders")


@router.post("/senders/telegram/{bot_id}/delete")
def bot_delete(bot_id: int, request: Request, user: User = Depends(require_user),
               db: Session = Depends(get_db)):
    b = _own(db, TelegramBot, bot_id, user)
    was_default = b.is_default
    db.delete(b)
    db.flush()
    if was_default:
        nxt = db.scalars(select(TelegramBot).where(TelegramBot.user_id == user.id)).first()
        if nxt:
            nxt.is_default = True
    db.commit()
    flash(request, "Bot removido.")
    return redirect("/senders")


# ----------------------------------------------------------- Notificações --
@router.get("/notifications", response_class=HTMLResponse)
def notifications_page(request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    items = db.scalars(
        select(Notification).options(selectinload(Notification.domain))
        .where(Notification.user_id == user.id)
        .order_by(Notification.created_at.desc()).limit(300)
    ).all()
    changes = db.scalars(
        select(Change).join(Domain).options(selectinload(Change.domain))
        .where(Domain.user_id == user.id).order_by(Change.created_at.desc()).limit(100)
    ).all()
    return render(request, "notifications.html",
                  {"user": user, "nav": "notifications", "items": items, "changes": changes})


# ---------------------------------------------------------- Configurações --
@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    return render(request, "settings.html", {
        "user": user, "nav": "settings", "s": cfg.user_snapshot(db, user.id),
        "next_run": scheduler.next_run(user.id),
    })


@router.post("/settings")
async def settings_save(request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    form = await request.form()
    check_time = str(form.get("check_time", "")).strip()
    if not re.fullmatch(r"([01]?\d|2[0-3]):[0-5]\d", check_time):
        flash(request, "Horário inválido. Use HH:MM.", "err")
        return redirect("/settings")
    ints = {}
    for key, lo, hi in (("daily_below", 0, 365), ("history_days", 0, 3650)):
        try:
            ints[key] = str(max(lo, min(int(form.get(key, "")), hi)))
        except ValueError:
            flash(request, "Os campos numéricos devem ser números inteiros.", "err")
            return redirect("/settings")
    milestones = ",".join(str(n) for n in sorted(
        {int(p) for p in re.split(r"[,;\s]+", str(form.get("milestones", ""))) if p.isdigit()}, reverse=True))
    cfg.set_value(db, user.id, "check_time", check_time)
    cfg.set_value(db, user.id, "milestones", milestones)
    cfg.set_value(db, user.id, "alert_on_changes", "1" if form.get("alert_on_changes") == "on" else "0")
    for k, v in ints.items():
        cfg.set_value(db, user.id, k, v)
    db.commit()
    scheduler.schedule_user(user.id)
    flash(request, "Configurações salvas.")
    return redirect("/settings")


@router.post("/settings/email")
def settings_email(request: Request, email: str = Form(...), current: str = Form(...),
                   user: User = Depends(require_user), db: Session = Depends(get_db)):
    email = email.strip().lower()
    if not auth.verify_password(current, user.password_hash):
        flash(request, "Senha atual incorreta.", "err")
    elif not EMAIL_RE.match(email):
        flash(request, "E-mail inválido.", "err")
    elif db.scalar(select(User.id).where(func.lower(User.email) == email, User.id != user.id)):
        flash(request, "Este e-mail já está em uso por outro usuário.", "err")
    else:
        user.email = email
        db.commit()
        flash(request, "E-mail atualizado.")
    return redirect("/settings")


@router.post("/settings/password")
def settings_password(request: Request, current: str = Form(...), new: str = Form(...),
                      new2: str = Form(...), user: User = Depends(require_user),
                      db: Session = Depends(get_db)):
    error = None
    if not auth.verify_password(current, user.password_hash):
        error = "Senha atual incorreta."
    else:
        error = _password_error(new, new2)
    if error:
        flash(request, error, "err")
    else:
        user.password_hash = auth.hash_password(new)
        user.must_change_password = False
        db.commit()
        auth.login_session(request, user)
        flash(request, "Senha alterada.")
    return redirect("/settings")
