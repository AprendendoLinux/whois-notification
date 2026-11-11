"""API JSON (autenticada pela mesma sessão da interface)."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Check, Domain, User
from ..web import require_user

router = APIRouter(prefix="/api", tags=["api"])


def _summary(d: Domain) -> dict:
    return {
        "id": d.id, "name": d.name, "health": d.health, "enabled": d.enabled,
        "days_left": d.days_left, "days_threshold": d.days_threshold,
        "expiration_date": d.expiration_date.isoformat() if d.expiration_date else None,
        "ssl_days_left": d.ssl_days_left, "ssl_threshold": d.ssl_threshold,
        "ssl_expires_at": d.ssl_expires_at.isoformat() if d.ssl_expires_at else None,
        "ssl_valid": d.ssl_valid, "registrar": d.registrar, "status": d.whois_status,
        "nameservers": d.nameservers, "dnssec": d.dnssec, "http_status": d.http_status,
        "http_ms": d.http_ms, "email_score": d.email_score,
        "last_checked_at": d.last_checked_at.isoformat() if d.last_checked_at else None,
        "last_error": d.last_error,
    }


def _own(db: Session, domain_id: int, user: User) -> Domain:
    d = db.get(Domain, domain_id)
    if not d or d.user_id != user.id:
        raise HTTPException(404, "Domínio não encontrado")
    return d


@router.get("/domains")
def list_domains(user: User = Depends(require_user), db: Session = Depends(get_db)):
    return [_summary(d) for d in db.scalars(
        select(Domain).where(Domain.user_id == user.id).order_by(Domain.name))]


@router.get("/domains/{domain_id}")
def get_domain(domain_id: int, user: User = Depends(require_user), db: Session = Depends(get_db)):
    d = _own(db, domain_id, user)
    latest = db.scalars(select(Check).where(Check.domain_id == d.id)
                        .order_by(Check.created_at.desc()).limit(1)).first()
    out = _summary(d)
    if latest:
        out["latest_check"] = {
            "created_at": latest.created_at.isoformat(), "success": latest.success,
            "error": latest.error, "whois": latest.whois, "dns": latest.dns,
            "ssl": latest.ssl, "http": latest.http,
        }
    return out


@router.get("/domains/{domain_id}/history")
def domain_history(domain_id: int, limit: int = 90, user: User = Depends(require_user),
                   db: Session = Depends(get_db)):
    _own(db, domain_id, user)
    rows = db.scalars(
        select(Check).where(Check.domain_id == domain_id)
        .order_by(Check.created_at.desc()).limit(min(max(limit, 1), 1000))
    ).all()
    return [{
        "at": c.created_at.isoformat(),
        "success": c.success,
        "http_ms": (c.http or {}).get("ms"),
        "http_status": (c.http or {}).get("status"),
        "check_ms": c.duration_ms,
        "email_score": ((c.dns or {}).get("email") or {}).get("score"),
    } for c in reversed(rows)]
