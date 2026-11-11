"""Área exclusiva do administrador: usuários e configurações do sistema."""
from zoneinfo import available_timezones

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from .. import auth, config, scheduler
from ..db import get_db
from ..models import Domain, User
from ..services import settings as cfg
from ..services.notifier import Alert, build_email, smtp_send
from ..services.senders import SmtpConfig
from ..utils import EMAIL_RE, USERNAME_RE
from ..web import csrf_protect, flash, render, require_admin

router = APIRouter(prefix="/admin", dependencies=[Depends(csrf_protect)])


def redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


def _active_admins(db: Session) -> int:
    return db.scalar(select(func.count(User.id)).where(User.is_admin.is_(True),
                                                       User.is_active.is_(True))) or 0


def _target(db: Session, user_id: int) -> User:
    u = db.get(User, user_id)
    if u is None:
        raise HTTPException(404, "Usuário não encontrado")
    return u


# --------------------------------------------------------------- Usuários --
@router.get("/users", response_class=HTMLResponse)
def users_page(request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    users = db.scalars(select(User).order_by(User.username)).all()
    counts = dict(db.execute(select(Domain.user_id, func.count(Domain.id)).group_by(Domain.user_id)).all())
    return render(request, "admin_users.html", {"user": admin, "nav": "admin_users",
                                                "users": users, "counts": counts})


@router.post("/users")
def users_create(request: Request, username: str = Form(...), email: str = Form(...),
                 password: str = Form(""), is_admin: str = Form(""),
                 admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    username, email = username.strip(), email.strip().lower()
    password = password or auth.generate_password()
    if not USERNAME_RE.match(username):
        flash(request, "Usuário deve ter 3 a 64 caracteres (letras, números, _ . -).", "err")
    elif not EMAIL_RE.match(email) or email.endswith("@whois.local"):
        flash(request, "Informe um e-mail válido (obrigatório).", "err")
    elif len(password) < 8:
        flash(request, "A senha temporária precisa de pelo menos 8 caracteres.", "err")
    elif db.scalar(select(User.id).where(User.username == username)):
        flash(request, "Já existe um usuário com este nome.", "err")
    elif db.scalar(select(User.id).where(func.lower(User.email) == email)):
        flash(request, "Já existe um usuário com este e-mail.", "err")
    else:
        u = User(username=username, email=email, is_admin=is_admin == "on",
                 password_hash=auth.hash_password(password), must_change_password=True)
        db.add(u)
        db.commit()
        scheduler.schedule_user(u.id)
        flash(request, f"Usuário {username} criado. Senha temporária: {password} "
                       "(será exigida a troca no primeiro login).")
    return redirect("/admin/users")


@router.post("/users/{user_id}/admin")
def users_toggle_admin(user_id: int, request: Request, admin: User = Depends(require_admin),
                       db: Session = Depends(get_db)):
    u = _target(db, user_id)
    if u.id == admin.id:
        flash(request, "Você não pode alterar o seu próprio nível de acesso.", "err")
    elif u.is_admin and _active_admins(db) <= 1:
        flash(request, "É preciso manter pelo menos um administrador ativo.", "err")
    else:
        u.is_admin = not u.is_admin
        db.commit()
        flash(request, f"{u.username} agora é {'administrador' if u.is_admin else 'usuário comum'}.")
    return redirect("/admin/users")


@router.post("/users/{user_id}/active")
def users_toggle_active(user_id: int, request: Request, admin: User = Depends(require_admin),
                        db: Session = Depends(get_db)):
    u = _target(db, user_id)
    if u.id == admin.id:
        flash(request, "Você não pode desativar a si mesmo.", "err")
    elif u.is_active and u.is_admin and _active_admins(db) <= 1:
        flash(request, "É preciso manter pelo menos um administrador ativo.", "err")
    else:
        u.is_active = not u.is_active
        db.commit()
        (scheduler.schedule_user if u.is_active else scheduler.unschedule_user)(u.id)
        flash(request, f"{u.username} {'reativado' if u.is_active else 'desativado'}.")
    return redirect("/admin/users")


@router.post("/users/{user_id}/reset")
def users_reset_password(user_id: int, request: Request, admin: User = Depends(require_admin),
                         db: Session = Depends(get_db)):
    u = _target(db, user_id)
    password = auth.generate_password()
    u.password_hash = auth.hash_password(password)
    u.must_change_password = True
    db.commit()
    flash(request, f"Nova senha temporária de {u.username}: {password} (troca obrigatória no próximo login).")
    return redirect("/admin/users")


@router.post("/users/{user_id}/delete")
def users_delete(user_id: int, request: Request, admin: User = Depends(require_admin),
                 db: Session = Depends(get_db)):
    u = _target(db, user_id)
    if u.id == admin.id:
        flash(request, "Você não pode excluir a si mesmo.", "err")
    elif u.is_admin and u.is_active and _active_admins(db) <= 1:
        flash(request, "É preciso manter pelo menos um administrador ativo.", "err")
    else:
        name = u.username
        scheduler.unschedule_user(u.id)
        # O banco apaga em cascata domínios, contatos, remetentes, histórico e configurações
        db.execute(delete(User).where(User.id == u.id))
        db.commit()
        flash(request, f"Usuário {name} e todos os seus dados foram excluídos.")
    return redirect("/admin/users")


# ---------------------------------------------------------------- Sistema --
@router.get("/system", response_class=HTMLResponse)
def system_page(request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    snap = cfg.sys_snapshot(db)
    return render(request, "admin_system.html", {
        "user": admin, "nav": "admin_system", "s": snap,
        "has_password": bool(cfg.sys_get(db, "sys_smtp_password")),
        "request_base": str(request.base_url).rstrip("/"),
        "timezones": sorted(available_timezones()),
    })


@router.post("/system")
async def system_save(request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    form = await request.form()
    tz = str(form.get("timezone", "")).strip()
    if not config.valid_tz(tz):
        flash(request, "Fuso horário inválido (ex.: America/Sao_Paulo).", "err")
        return redirect("/admin/system")
    public_url = str(form.get("public_url", "")).strip().rstrip("/")
    if public_url and not public_url.startswith(("http://", "https://")):
        flash(request, "A URL pública deve começar com http:// ou https://.", "err")
        return redirect("/admin/system")
    try:
        port = int(form.get("sys_smtp_port") or 587)
    except ValueError:
        flash(request, "Porta SMTP inválida.", "err")
        return redirect("/admin/system")
    from_email = str(form.get("sys_smtp_from", "")).strip()
    if from_email and not EMAIL_RE.match(from_email):
        flash(request, "E-mail do remetente inválido.", "err")
        return redirect("/admin/system")
    values = {
        "timezone": tz, "public_url": public_url,
        "sys_smtp_server": str(form.get("sys_smtp_server", "")).strip(), "sys_smtp_port": str(port),
        "sys_smtp_security": str(form.get("sys_smtp_security", "starttls")),
        "sys_smtp_user": str(form.get("sys_smtp_user", "")).strip(), "sys_smtp_from": from_email,
        "sys_smtp_from_name": str(form.get("sys_smtp_from_name", "")).strip() or "Whois Notification",
    }
    for k, v in values.items():
        cfg.sys_set(db, k, v)
    if form.get("sys_smtp_password_clear") == "on":
        cfg.sys_set(db, "sys_smtp_password", "")
    elif form.get("sys_smtp_password"):
        cfg.sys_set(db, "sys_smtp_password", str(form.get("sys_smtp_password")))
    db.commit()
    config.set_tz(tz)
    scheduler.schedule_all()
    flash(request, "Configurações do sistema salvas.")
    return redirect("/admin/system")


@router.post("/system/test")
def system_test(request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    from ..services.senders import system_smtp
    smtp: SmtpConfig | None = system_smtp(db)
    if smtp is None:
        flash(request, "Salve o servidor SMTP e o e-mail do remetente antes de testar.", "err")
        return redirect("/admin/system")
    alert = Alert(subject="Teste do SMTP do sistema", header="Teste de e-mail do sistema", severity="info",
                  intro="O SMTP do sistema (usado na recuperação de senha) está funcionando.",
                  box_title="Tudo certo!", box_sub="Mensagem de teste", rows=[("Destino", admin.email)])
    try:
        smtp_send(smtp, build_email(alert, smtp, [admin.email]), [admin.email])
        flash(request, f"Mensagem de teste enviada para {admin.email}.")
    except Exception as e:  # noqa: BLE001
        flash(request, f"Falha no envio: {type(e).__name__}: {e}"[:300], "err")
    return redirect("/admin/system")
