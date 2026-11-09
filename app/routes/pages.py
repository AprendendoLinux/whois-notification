"""Páginas HTML da interface."""
import json
import re

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from .. import auth, scheduler
from ..db import get_db
from ..migrate_json import DOMAIN_RE, get_or_create_contact, normalize_domain
from ..models import Change, Check, Contact, Domain, Notification, User
from ..services import checker
from ..services import settings as cfg
from ..services.notifier import Alert, dispatch, email_ready, telegram_ready
from ..web import csrf_protect, flash, render, require_user

router = APIRouter(dependencies=[Depends(csrf_protect)])

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
CHAT_RE = re.compile(r"^(-?\d{3,20}|@[A-Za-z0-9_]{4,64})$")


def redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


def is_checking(domain_id: int) -> bool:
    return checker.is_running(domain_id) or scheduler.scheduler.get_job(f"check_{domain_id}") is not None


# ------------------------------------------------------------------ Auth --
@router.get("/setup", response_class=HTMLResponse)
def setup_form(request: Request, db: Session = Depends(get_db)):
    if auth.user_count(db) > 0:
        return redirect("/login")
    return render(request, "setup.html")


@router.post("/setup")
def setup_submit(request: Request, username: str = Form(...), password: str = Form(...),
                 password2: str = Form(...), db: Session = Depends(get_db)):
    if auth.user_count(db) > 0:
        return redirect("/login")
    username = username.strip()
    error = None
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", username):
        error = "Usuário deve ter 3 a 64 caracteres (letras, números, _ . -)."
    elif len(password) < 8:
        error = "A senha precisa de pelo menos 8 caracteres."
    elif password != password2:
        error = "As senhas não conferem."
    if error:
        return render(request, "setup.html", {"error": error, "username": username}, 400)
    user = User(username=username, password_hash=auth.hash_password(password))
    db.add(user)
    db.commit()
    request.session.clear()
    request.session["uid"] = user.id
    flash(request, "Administrador criado. Bem-vindo!")
    return redirect("/")


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request, db: Session = Depends(get_db)):
    if auth.user_count(db) == 0:
        return redirect("/setup")
    if auth.current_user(request, db):
        return redirect("/")
    return render(request, "login.html")


@router.post("/login")
def login_submit(request: Request, username: str = Form(...), password: str = Form(...),
                 db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.username == username.strip()))
    if not user or not auth.verify_password(password, user.password_hash):
        return render(request, "login.html", {"error": "Usuário ou senha inválidos.",
                                              "username": username}, 401)
    request.session.clear()
    request.session["uid"] = user.id
    return redirect("/")


@router.post("/logout")
def logout(request: Request):
    request.session.clear()
    return redirect("/login")


# ------------------------------------------------------------- Dashboard --
def _dashboard_ctx(db: Session) -> dict:
    domains = db.scalars(select(Domain).options(selectinload(Domain.contacts)).order_by(Domain.name)).all()
    order = {"expired": 0, "critical": 1, "warning": 2, "unknown": 3, "ok": 4, "disabled": 5}
    domains = sorted(domains, key=lambda d: (order[d.health],
                                             d.days_left if d.days_left is not None else 10**6))
    stats = {k: 0 for k in order}
    for d in domains:
        stats[d.health] += 1
    recent_changes = db.scalars(
        select(Change).options(selectinload(Change.domain)).order_by(Change.created_at.desc()).limit(8)
    ).all()
    kinds = set(db.scalars(select(Contact.kind).join(Contact.domains).distinct()))
    channel_warnings = []
    if "email" in kinds and not email_ready(db):
        channel_warnings.append("e-mail (SMTP)")
    if "telegram" in kinds and not telegram_ready(db):
        channel_warnings.append("Telegram")
    sent_ok = db.scalar(select(func.count(Notification.id)).where(Notification.success.is_(True))) or 0
    sent_fail = db.scalar(select(func.count(Notification.id)).where(Notification.success.is_(False))) or 0
    chart = [{
        "id": d.id, "name": d.name, "health": d.health,
        "exp": d.expiration_date.isoformat() if d.expiration_date else None,
        "ssl": d.ssl_expires_at.isoformat() if d.ssl_expires_at and d.monitor_ssl else None,
        "days": d.days_left, "ssl_days": d.ssl_days_left if d.monitor_ssl else None,
    } for d in domains]
    return {
        "domains_json": json.dumps(chart).replace("</", "<\\/"),
        "domains": domains, "stats": stats, "total": len(domains),
        "channel_warnings": channel_warnings,
        "recent_changes": recent_changes, "sent_ok": sent_ok, "sent_fail": sent_fail,
        "next_run": scheduler.next_run(), "running_all": scheduler.is_running_all(),
        "running": checker.running_ids(),
    }


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    return render(request, "dashboard.html", {"user": user, "nav": "dashboard", **_dashboard_ctx(db)})


@router.get("/partials/fleet", response_class=HTMLResponse)
def fleet_partial(request: Request, _u: User = Depends(require_user), db: Session = Depends(get_db)):
    ctx = _dashboard_ctx(db)
    resp = render(request, "partials/fleet.html", ctx)
    # Varredura terminou: recarrega a página para atualizar indicadores e gráficos
    if request.query_params.get("was") == "1" and not (ctx["running_all"] or ctx["running"]):
        resp.headers["HX-Refresh"] = "true"
    return resp


@router.post("/check-all")
def check_all(request: Request, _u: User = Depends(require_user)):
    if scheduler.run_all_in_background():
        flash(request, "Varredura completa iniciada. Os cartões serão atualizados automaticamente.")
    else:
        flash(request, "Já existe uma varredura em andamento.", "warn")
    return redirect("/")


# --------------------------------------------------------------- Domínios --
def _domain_or_404(db: Session, domain_id: int) -> Domain:
    d = db.get(Domain, domain_id)
    if d is None:
        raise HTTPException(404, "Domínio não encontrado")
    return d


def _form_ctx(db: Session, domain: Domain | None, **extra) -> dict:
    contacts = db.scalars(select(Contact).order_by(Contact.kind, Contact.name, Contact.value)).all()
    return {"domain": domain, "contacts": contacts, "nav": "dashboard" if domain else "domains", **extra}


def _parse_list(raw: str) -> list[str]:
    return [p.strip() for p in re.split(r"[,;\s]+", raw or "") if p.strip()]


def _apply_form(db: Session, d: Domain, form) -> list[str]:
    errors = []
    name = normalize_domain(form.get("name", ""))
    if not DOMAIN_RE.match(name):
        errors.append("Nome de domínio inválido (ex.: suaempresa.com.br).")
    else:
        clash = db.scalar(select(Domain).where(Domain.name == name, Domain.id != (d.id or 0)))
        if clash:
            errors.append(f"O domínio {name} já está cadastrado.")
    try:
        d.days_threshold = max(1, min(int(form.get("days_threshold") or 30), 3650))
        d.ssl_threshold = max(1, min(int(form.get("ssl_threshold") or 14), 365))
    except ValueError:
        errors.append("Os limites de dias devem ser números inteiros.")
    d.name = name
    d.enabled = form.get("enabled") == "on"
    d.monitor_ssl = form.get("monitor_ssl") == "on"
    d.notes = (form.get("notes") or "").strip()[:2000]

    ids = {int(i) for i in form.getlist("contact_ids") if str(i).isdigit()}
    selected = list(db.scalars(select(Contact).where(Contact.id.in_(ids)))) if ids else []
    for email in _parse_list(form.get("new_emails", "")):
        if EMAIL_RE.match(email):
            selected.append(get_or_create_contact(db, "email", email.lower()))
        else:
            errors.append(f"E-mail inválido: {email}")
    for chat in _parse_list(form.get("new_telegrams", "")):
        if CHAT_RE.match(chat):
            selected.append(get_or_create_contact(db, "telegram", chat))
        else:
            errors.append(f"Chat ID do Telegram inválido: {chat}")
    d.contacts = list({c.id: c for c in selected}.values())
    return errors


@router.get("/domains/new", response_class=HTMLResponse)
def domain_new(request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    return render(request, "domain_form.html", {"user": user, **_form_ctx(db, None)})


@router.post("/domains/new")
async def domain_create(request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    form = await request.form()
    d = Domain()
    with db.no_autoflush:
        errors = _apply_form(db, d, form)
    if errors:
        db.rollback()
        return render(request, "domain_form.html",
                      {"user": user, "errors": errors, "form": form, **_form_ctx(db, None)}, 400)
    db.add(d)
    db.commit()
    scheduler.run_one_in_background(d.id)
    flash(request, f"{d.name} cadastrado. A primeira varredura já começou.")
    return redirect(f"/domains/{d.id}")


@router.get("/domains/{domain_id}", response_class=HTMLResponse)
def domain_detail(domain_id: int, request: Request, user: User = Depends(require_user),
                  db: Session = Depends(get_db)):
    d = _domain_or_404(db, domain_id)
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
def domain_status(domain_id: int, request: Request, _u: User = Depends(require_user),
                  db: Session = Depends(get_db)):
    d = _domain_or_404(db, domain_id)
    checking = is_checking(d.id)
    resp = render(request, "partials/check_button.html", {"d": d, "checking": checking})
    # Quando terminar, recarrega a página para mostrar os dados novos
    if not checking and request.query_params.get("was") == "1":
        resp.headers["HX-Refresh"] = "true"
    return resp


@router.post("/domains/{domain_id}/check", response_class=HTMLResponse)
def domain_check(domain_id: int, request: Request, _u: User = Depends(require_user),
                 db: Session = Depends(get_db)):
    d = _domain_or_404(db, domain_id)
    if not is_checking(d.id):
        scheduler.run_one_in_background(d.id)
    if request.headers.get("HX-Request"):
        return render(request, "partials/check_button.html", {"d": d, "checking": True})
    return redirect(f"/domains/{d.id}")


@router.get("/domains/{domain_id}/edit", response_class=HTMLResponse)
def domain_edit(domain_id: int, request: Request, user: User = Depends(require_user),
                db: Session = Depends(get_db)):
    d = _domain_or_404(db, domain_id)
    return render(request, "domain_form.html", {"user": user, **_form_ctx(db, d)})


@router.post("/domains/{domain_id}/edit")
async def domain_update(domain_id: int, request: Request, user: User = Depends(require_user),
                        db: Session = Depends(get_db)):
    d = _domain_or_404(db, domain_id)
    old_name = d.name
    form = await request.form()
    with db.no_autoflush:
        errors = _apply_form(db, d, form)
    if errors:
        db.rollback()
        d = _domain_or_404(db, domain_id)
        return render(request, "domain_form.html",
                      {"user": user, "errors": errors, "form": form, **_form_ctx(db, d)}, 400)
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
def domain_delete(domain_id: int, request: Request, _u: User = Depends(require_user),
                  db: Session = Depends(get_db)):
    d = _domain_or_404(db, domain_id)
    name = d.name
    db.delete(d)
    db.commit()
    flash(request, f"{name} removido do monitoramento.")
    return redirect("/")


# --------------------------------------------------------------- Contatos --
@router.get("/contacts", response_class=HTMLResponse)
def contacts_page(request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    contacts = db.scalars(
        select(Contact).options(selectinload(Contact.domains)).order_by(Contact.kind, Contact.name, Contact.value)
    ).all()
    return render(request, "contacts.html", {"user": user, "nav": "contacts", "contacts": contacts})


@router.post("/contacts")
def contacts_create(request: Request, kind: str = Form(...), value: str = Form(...), name: str = Form(""),
                    _u: User = Depends(require_user), db: Session = Depends(get_db)):
    value = value.strip()
    if kind == "email" and EMAIL_RE.match(value):
        value = value.lower()
    elif not (kind == "telegram" and CHAT_RE.match(value)):
        flash(request, "Contato inválido. Use um e-mail ou um Chat ID numérico do Telegram.", "err")
        return redirect("/contacts")
    c = get_or_create_contact(db, kind, value, name.strip())
    if name.strip():
        c.name = name.strip()[:120]
    db.commit()
    flash(request, "Contato salvo.")
    return redirect("/contacts")


@router.post("/contacts/{contact_id}/rename")
def contacts_rename(contact_id: int, request: Request, name: str = Form(""),
                    _u: User = Depends(require_user), db: Session = Depends(get_db)):
    c = db.get(Contact, contact_id)
    if c:
        c.name = name.strip()[:120]
        db.commit()
        flash(request, "Contato atualizado.")
    return redirect("/contacts")


@router.post("/contacts/{contact_id}/test")
def contacts_test(contact_id: int, request: Request, _u: User = Depends(require_user),
                  db: Session = Depends(get_db)):
    c = db.get(Contact, contact_id)
    if not c:
        return redirect("/contacts")
    _send_test(request, db, c.kind, c.value)
    return redirect("/contacts")


@router.post("/contacts/{contact_id}/delete")
def contacts_delete(contact_id: int, request: Request, _u: User = Depends(require_user),
                    db: Session = Depends(get_db)):
    c = db.get(Contact, contact_id)
    if c:
        db.delete(c)
        db.commit()
        flash(request, "Contato removido.")
    return redirect("/contacts")


# ----------------------------------------------------------- Notificações --
@router.get("/notifications", response_class=HTMLResponse)
def notifications_page(request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    items = db.scalars(
        select(Notification).options(selectinload(Notification.domain))
        .order_by(Notification.created_at.desc()).limit(300)
    ).all()
    changes = db.scalars(
        select(Change).options(selectinload(Change.domain)).order_by(Change.created_at.desc()).limit(100)
    ).all()
    return render(request, "notifications.html",
                  {"user": user, "nav": "notifications", "items": items, "changes": changes})


# ---------------------------------------------------------- Configurações --
def _send_test(request: Request, db: Session, channel: str, target: str) -> None:
    alert = Alert(
        subject="Teste de notificação", header="Teste de notificação", severity="info",
        intro="Se você recebeu esta mensagem, o canal está configurado corretamente no **Whois Notification**.",
        box_title="Tudo certo!", box_sub="Mensagem de teste enviada pela interface",
        rows=[("Canal", "E-mail" if channel == "email" else "Telegram"), ("Destino", target)],
    )
    if channel == "email" and not email_ready(db):
        flash(request, "Configure o servidor SMTP antes de testar o e-mail.", "err")
        return
    res = dispatch(db, None, alert, "test",
                   emails=[target] if channel == "email" else [],
                   chats=[target] if channel == "telegram" else [])
    if res and res[0].success:
        flash(request, f"Mensagem de teste enviada para {target}.")
    else:
        flash(request, f"Falha ao enviar para {target}: {res[0].error if res else 'sem resultado'}", "err")


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    return render(request, "settings.html", {
        "user": user, "nav": "settings", "s": cfg.snapshot(db), "next_run": scheduler.next_run(),
    })


@router.post("/settings")
async def settings_save(request: Request, _u: User = Depends(require_user), db: Session = Depends(get_db)):
    form = await request.form()
    for d in cfg.DEFS:
        if cfg.env_value(d.key) is not None:
            continue  # definido por variável de ambiente
        if d.key == "alert_on_changes":
            if form.get("_group") == "schedule":
                cfg.set_value(db, d.key, "1" if form.get(d.key) == "on" else "0")
            continue
        if d.key not in form:
            continue
        val = str(form.get(d.key, "")).strip()
        if d.secret:
            if form.get(f"{d.key}__clear") == "on":
                cfg.set_value(db, d.key, "")
            elif val:
                cfg.set_value(db, d.key, val)
            continue
        if d.key == "check_time" and not re.fullmatch(r"([01]?\d|2[0-3]):[0-5]\d", val):
            flash(request, "Horário inválido. Use HH:MM.", "err")
            return redirect("/settings")
        cfg.set_value(db, d.key, val)
    db.commit()
    scheduler.schedule_daily()
    flash(request, "Configurações salvas.")
    return redirect("/settings")


@router.post("/settings/test")
def settings_test(request: Request, channel: str = Form(...), target: str = Form(...),
                  _u: User = Depends(require_user), db: Session = Depends(get_db)):
    _send_test(request, db, channel, target.strip())
    return redirect("/settings")


@router.post("/settings/password")
def settings_password(request: Request, current: str = Form(...), new: str = Form(...),
                      new2: str = Form(...), user: User = Depends(require_user),
                      db: Session = Depends(get_db)):
    if not auth.verify_password(current, user.password_hash):
        flash(request, "Senha atual incorreta.", "err")
    elif len(new) < 8:
        flash(request, "A nova senha precisa de pelo menos 8 caracteres.", "err")
    elif new != new2:
        flash(request, "As senhas não conferem.", "err")
    else:
        user.password_hash = auth.hash_password(new)
        db.commit()
        flash(request, "Senha alterada.")
    return redirect("/settings")
