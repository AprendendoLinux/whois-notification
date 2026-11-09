"""Orquestra a verificação completa de um domínio."""
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..config import LOCAL_TZ
from ..db import SessionLocal
from ..models import Change, Check, Domain, Notification, utcnow
from . import dns_service, http_service, ssl_service, whois_service
from . import settings as cfg
from .notifier import Alert, dispatch, email_ready, telegram_ready

_running: set[int] = set()
_lock = threading.Lock()

# Status EPP que indicam problema sério
DANGER_STATUS = {
    "clienthold", "serverhold", "redemptionperiod", "pendingdelete",
    "pendingrestore", "inactive", "on-hold", "suspended",
}


def is_running(domain_id: int) -> bool:
    return domain_id in _running


def running_ids() -> set[int]:
    return set(_running)


def _parse_dt(s: str | None) -> datetime | None:
    return datetime.fromisoformat(s) if s else None


def _fmt_date(dt: datetime | None) -> str:
    # Datas de registro são publicadas em UTC; converter para o fuso local pode mudar o dia
    return dt.astimezone(timezone.utc).strftime("%d/%m/%Y") if dt else "Indisponível"


def _join(v) -> str:
    if isinstance(v, list):
        return ", ".join(v) if v else "—"
    return "—" if v in (None, "") else str(v)


# ------------------------------------------------------ Detecção de mudanças --
def _detect_changes(domain: Domain, whois: dict | None, dns: dict | None,
                    ssl: dict | None, prev: Check | None) -> list[Change]:
    if prev is None:
        return []  # primeira verificação: nada a comparar
    out: list[Change] = []

    def add(field, old, new, severity):
        if _join(old) != _join(new):
            out.append(Change(domain_id=domain.id, field=field, old_value=_join(old),
                              new_value=_join(new), severity=severity))

    pw = prev.whois or {}
    if whois and pw:
        add("Nameservers (WHOIS)", pw.get("nameservers"), whois.get("nameservers"), "critical")
        add("Registrador", pw.get("registrar"), whois.get("registrar"), "critical")
        # "active"/"ok" aparecem ou somem conforme o servidor WHOIS que respondeu
        generic = {"active", "ok"}
        old_st = {x for x in pw.get("status") or [] if x.lower() not in generic}
        new_st = {x for x in whois.get("status") or [] if x.lower() not in generic}
        if old_st != new_st:
            danger = any(s.lower() in DANGER_STATUS for s in new_st - old_st)
            add("Status do domínio", sorted(old_st), sorted(new_st), "critical" if danger else "info")
        old_exp, new_exp = _parse_dt(pw.get("expiration_date")), _parse_dt(whois.get("expiration_date"))
        if old_exp and new_exp and old_exp.date() != new_exp.date():
            sev = "info" if new_exp > old_exp else "warning"
            add("Data de expiração", _fmt_date(old_exp), _fmt_date(new_exp), sev)

    pd = (prev.dns or {}).get("records") if prev.dns else None
    if dns and pd:
        rec = dns["records"]
        add("Registros MX", pd.get("MX"), rec.get("MX"), "warning")
        add("Registros A", pd.get("A"), rec.get("A"), "info")
        add("Registros AAAA", pd.get("AAAA"), rec.get("AAAA"), "info")
        if (prev.dns or {}).get("dnssec_signed") and not dns.get("dnssec_signed"):
            add("DNSSEC", "Ativo", "Desativado", "warning")
        elif not (prev.dns or {}).get("dnssec_signed") and dns.get("dnssec_signed"):
            add("DNSSEC", "Desativado", "Ativo", "info")

    if ssl and prev.ssl:
        add("Emissor do certificado", prev.ssl.get("issuer"), ssl.get("issuer"), "info")
    return out


CRITICAL_FIELDS = ("nameservers", "registrar")


def _confirm_critical(name: str, whois: dict, prev_whois: dict) -> dict:
    """Servidores WHOIS às vezes respondem com dados divergentes (registro x registrador).
    Antes de aceitar uma mudança crítica, consulta de novo; se a segunda resposta não
    confirmar, mantém os valores anteriores e evita um falso alerta de sequestro."""
    changed = [f for f in CRITICAL_FIELDS
               if prev_whois.get(f) and _join(prev_whois.get(f)) != _join(whois.get(f))]
    if not changed:
        return whois
    time.sleep(3)
    try:
        again, _ = whois_service.lookup(name)
    except Exception:  # noqa: BLE001
        again = None
    for f in changed:
        if again is None or _join(again.get(f)) != _join(whois.get(f)):
            print(f"[~] {name}: mudança em '{f}' não confirmada na segunda consulta; ignorada.")
            whois[f] = prev_whois.get(f)
    return whois


# ---------------------------------------------------- Política de notificação --
def _should_notify(db: Session, domain: Domain, kind: str, days_left: int | None,
                   threshold: int, ref_date: str) -> bool:
    if days_left is None or days_left > threshold:
        return False
    prior = db.scalars(
        select(Notification).where(
            Notification.domain_id == domain.id, Notification.kind == kind,
            Notification.ref_date == ref_date, Notification.success.is_(True),
        )
    ).all()
    if not prior:
        return True  # primeira vez dentro da janela neste ciclo

    today = datetime.now(LOCAL_TZ).date()
    if any(n.created_at.astimezone(LOCAL_TZ).date() == today for n in prior):
        return False  # no máximo um aviso por dia

    if days_left < 0 or days_left <= cfg.get_int(db, "daily_below"):
        return True

    # Marcos: avisa ao cruzar cada marco, mesmo se a verificação do dia exato falhou
    reached = [m for m in cfg.get_int_list(db, "milestones") if m >= days_left]
    if not reached:
        return False
    milestone = min(reached)
    return not any(n.days_left is not None and n.days_left <= milestone for n in prior)


def _recipients(db: Session, domain: Domain) -> tuple[list[str], list[str]]:
    """Destinatários por canal, ignorando canais sem configuração (evita falhas repetidas)."""
    emails = [c.value for c in domain.contacts if c.kind == "email"] if email_ready(db) else []
    chats = [c.value for c in domain.contacts if c.kind == "telegram"] if telegram_ready(db) else []
    return emails, chats


def expiry_alert(domain: Domain, days_left: int) -> Alert:
    rows = [
        ("Status do domínio", _join(domain.whois_status)),
        ("Registrador", domain.registrar or "—"),
        ("Data de registro", _fmt_date(domain.creation_date)),
        ("Data de expiração", _fmt_date(domain.expiration_date)),
    ]
    if days_left < 0:
        n = abs(days_left)
        return Alert(
            subject=f"URGENTE: O domínio {domain.name} EXPIROU há {n} dias!",
            header="Domínio expirado", severity="critical",
            intro=f"O sistema identificou que o domínio **{domain.name}** já expirou em "
                  f"{_fmt_date(domain.expiration_date)} e deve ser renovado IMEDIATAMENTE.",
            box_title=f"Expirado há {n} dias",
            box_sub="Risco altíssimo de perda definitiva e indisponibilidade de serviços",
            rows=rows, footer="Renove imediatamente para evitar a perda definitiva do domínio.",
        )
    return Alert(
        subject=f"AÇÃO NECESSÁRIA: o domínio {domain.name} expira em {days_left} dias",
        header="Alerta de expiração", severity="critical" if days_left <= 7 else "warning",
        intro=f"O sistema identificou que o domínio **{domain.name}** requer sua atenção.",
        box_title=f"{days_left} dias restantes" if days_left != 1 else "1 dia restante",
        box_sub="Até a expiração do registro do domínio",
        rows=rows, footer="Renove o quanto antes para evitar interrupções.",
    )


def ssl_alert(domain: Domain, days_left: int) -> Alert:
    rows = [
        ("Emissor", domain.ssl_issuer or "—"),
        ("Válido até", _fmt_date(domain.ssl_expires_at)),
    ]
    if days_left < 0:
        return Alert(
            subject=f"URGENTE: o certificado SSL de {domain.name} EXPIROU",
            header="Certificado expirado", severity="critical",
            intro=f"O certificado HTTPS de **{domain.name}** expirou. Visitantes estão vendo um aviso de segurança.",
            box_title=f"Expirado há {abs(days_left)} dias", box_sub="O site é exibido como inseguro",
            rows=rows,
        )
    return Alert(
        subject=f"O certificado SSL de {domain.name} expira em {days_left} dias",
        header="Certificado SSL", severity="critical" if days_left <= 3 else "warning",
        intro=f"O certificado HTTPS de **{domain.name}** está perto do vencimento. "
              "Se a renovação é automática, verifique se ela está funcionando.",
        box_title=f"{days_left} dias restantes", box_sub="Até a expiração do certificado",
        rows=rows,
    )


def changes_alert(domain: Domain, changes: list[Change]) -> Alert:
    critical = any(c.severity == "critical" for c in changes)
    rows = []
    for c in changes:
        rows.append((f"{c.field} (antes)", c.old_value or "—"))
        rows.append((f"{c.field} (agora)", c.new_value or "—"))
    return Alert(
        subject=f"Mudança detectada no domínio {domain.name}",
        header="Mudança detectada", severity="critical" if critical else "warning",
        intro=f"Foram detectadas alterações importantes em **{domain.name}**. "
              "Se você não fez essa alteração, pode ser uma tentativa de sequestro do domínio.",
        box_title=f"{len(changes)} alteraç{'ão' if len(changes) == 1 else 'ões'}",
        box_sub="Confirme se a mudança foi autorizada",
        rows=rows,
    )


# ------------------------------------------------------------- Verificação --
def run_check(domain_id: int, notify: bool = True) -> None:
    with _lock:
        if domain_id in _running:
            return
        _running.add(domain_id)
    try:
        _run_check(domain_id, notify)
    finally:
        _running.discard(domain_id)


def _run_check(domain_id: int, notify: bool) -> None:
    db = SessionLocal()
    try:
        domain = db.get(Domain, domain_id)
        if domain is None:
            return
        start = time.perf_counter()
        errors: list[str] = []
        whois = raw = dns = ssl = http = None

        try:
            whois, raw = whois_service.lookup(domain.name)
        except Exception as e:  # noqa: BLE001
            first = next((ln.strip() for ln in str(e).splitlines() if ln.strip()), type(e).__name__)
            errors.append(f"WHOIS: {first[:200]}")

        prev = db.scalars(
            select(Check).where(Check.domain_id == domain.id, Check.success.is_(True))
            .order_by(Check.created_at.desc()).limit(1)
        ).first()
        if whois and prev and prev.whois:
            whois = _confirm_critical(domain.name, whois, prev.whois)
        try:
            dns = dns_service.lookup(domain.name)
        except Exception as e:  # noqa: BLE001
            errors.append(f"DNS: {e}")
        if domain.monitor_ssl:
            try:
                ssl = ssl_service.lookup(domain.name)
            except Exception as e:  # noqa: BLE001
                errors.append(f"SSL: {e}")
        try:
            http = http_service.lookup(domain.name)
        except Exception as e:  # noqa: BLE001
            errors.append(f"HTTP: {e}")

        check = Check(
            domain_id=domain.id, duration_ms=round((time.perf_counter() - start) * 1000),
            success=whois is not None, error="\n".join(errors) or None,
            whois=whois, whois_raw=raw, dns=dns, ssl=ssl, http=http,
        )
        db.add(check)

        changes = _detect_changes(domain, whois, dns, ssl, prev)
        for c in changes:
            db.add(c)

        # Atualiza o resumo do domínio (mantém o valor anterior se a fonte falhou)
        domain.last_checked_at = utcnow()
        domain.last_error = check.error
        if whois:
            domain.expiration_date = _parse_dt(whois["expiration_date"])
            domain.creation_date = _parse_dt(whois["creation_date"])
            domain.registrar = whois["registrar"]
            domain.whois_status = whois["status"]
            domain.nameservers = whois["nameservers"]
        if dns:
            domain.dnssec = "signed" if dns["dnssec_signed"] else "unsigned"
            domain.email_score = dns["email"]["score"]
            if not domain.nameservers:
                domain.nameservers = dns["records"]["NS"]
        if ssl:
            domain.ssl_expires_at = _parse_dt(ssl["not_after"])
            domain.ssl_issuer = ssl["issuer"]
            domain.ssl_valid = ssl["valid"]
        elif domain.monitor_ssl:
            domain.ssl_valid = None
        if http:
            domain.http_status = http.get("status")
            domain.http_ms = http.get("ms")
        db.commit()

        if notify and domain.enabled:
            _notify(db, domain, changes)
    finally:
        db.close()


def _notify(db: Session, domain: Domain, changes: list[Change]) -> None:
    emails, chats = _recipients(db, domain)
    if not emails and not chats:
        return

    d = domain.days_left
    if domain.expiration_date and _should_notify(
        db, domain, "domain_expiry", d, domain.days_threshold, domain.expiration_date.date().isoformat()
    ):
        dispatch(db, domain, expiry_alert(domain, d), "domain_expiry", emails=emails, chats=chats,
                 days_left=d, ref_date=domain.expiration_date.date().isoformat())

    s = domain.ssl_days_left
    if domain.monitor_ssl and domain.ssl_expires_at and _should_notify(
        db, domain, "ssl_expiry", s, domain.ssl_threshold, domain.ssl_expires_at.date().isoformat()
    ):
        dispatch(db, domain, ssl_alert(domain, s), "ssl_expiry", emails=emails, chats=chats,
                 days_left=s, ref_date=domain.ssl_expires_at.date().isoformat())

    important = [c for c in changes if c.severity in ("critical", "warning")]
    if important and cfg.get(db, "alert_on_changes") == "1":
        dispatch(db, domain, changes_alert(domain, important), "change", emails=emails, chats=chats)


def run_all(notify: bool = True, max_workers: int = 4) -> None:
    with SessionLocal() as db:
        ids = list(db.scalars(select(Domain.id).where(Domain.enabled.is_(True))))
    stamp = datetime.now(LOCAL_TZ).strftime("%d/%m/%Y %H:%M:%S")
    print(f"[{stamp}] Verificando {len(ids)} domínio(s)...")
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        list(pool.map(lambda i: run_check(i, notify), ids))
    prune_history()
    print(f"[{datetime.now(LOCAL_TZ).strftime('%d/%m/%Y %H:%M:%S')}] Verificação concluída.")


def prune_history() -> None:
    with SessionLocal() as db:
        days = cfg.get_int(db, "history_days")
        if days <= 0:
            return
        cutoff = utcnow() - timedelta(days=days)
        # Mantém sempre a verificação mais recente de cada domínio
        for (domain_id,) in db.execute(select(Domain.id)):
            latest = db.scalar(
                select(Check.id).where(Check.domain_id == domain_id)
                .order_by(Check.created_at.desc()).limit(1)
            )
            db.execute(
                delete(Check).where(Check.domain_id == domain_id, Check.created_at < cutoff,
                                    Check.id != (latest or 0))
            )
        db.execute(delete(Notification).where(Notification.created_at < cutoff))
        db.commit()
