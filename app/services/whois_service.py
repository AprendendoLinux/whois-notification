"""Consulta WHOIS normalizada."""
import socket
from datetime import date, datetime, timezone

import whois


def _to_dt(v) -> datetime | None:
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    if isinstance(v, date):
        return datetime(v.year, v.month, v.day, tzinfo=timezone.utc)
    return None


def _dates(v) -> list[datetime]:
    items = v if isinstance(v, list) else [v]
    return [d for d in (_to_dt(x) for x in items) if d]


def _first(v):
    if isinstance(v, list):
        return v[0] if v else None
    return v


def _str_list(v) -> list[str]:
    if not v:
        return []
    items = v if isinstance(v, list) else [v]
    return [str(x).strip() for x in items if str(x).strip()]


def _clean_status(v) -> list[str]:
    out = []
    for s in _str_list(v):
        token = s.split()[0]
        # Linhas do .br do tipo "20261108 DSOK" não são status de domínio
        if token.isdigit():
            continue
        if token not in out:
            out.append(token)
    return out


def _clean_ns(v) -> list[str]:
    out = []
    for s in _str_list(v):
        ns = s.split()[0].lower().rstrip(".")
        if ns and ns not in out:
            out.append(ns)
    return sorted(out)


def _raw_query(server: str, query: str, timeout: float = 10.0) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as s:
        s.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
    raw = b"".join(chunks)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _fix_br_text(domain: str, w) -> str | None:
    """O registro.br responde em latin-1; o python-whois às vezes perde acentos."""
    try:
        raw = _raw_query("whois.registro.br", domain)
    except OSError:
        return None
    for line in raw.splitlines():
        if line.lower().startswith("owner:"):
            w["registrant_name"] = line.split(":", 1)[1].strip()
            break
    return raw


def lookup(domain: str) -> tuple[dict, str | None]:
    """Retorna (dados normalizados, texto bruto). Lança exceção em falha."""
    w = whois.whois(domain)
    raw = getattr(w, "text", None) or ""
    if domain.endswith(".br") and "�" in raw:
        raw = _fix_br_text(domain, w) or raw

    exp = _dates(w.get("expiration_date"))
    created = _dates(w.get("creation_date"))
    updated = _dates(w.get("updated_date"))

    registrant = (
        _first(w.get("registrant_name"))
        or _first(w.get("org"))
        or _first(w.get("name"))
    )
    if registrant and "REDACTED" in str(registrant).upper():
        registrant = "Oculto (privacidade)"

    data = {
        "domain": str(_first(w.get("domain_name")) or domain).lower(),
        "registrar": _first(w.get("registrar")) or ("Registro.br" if domain.endswith(".br") else None),
        "registrar_url": _first(w.get("registrar_url")),
        "whois_server": _first(w.get("whois_server")),
        # Se houver mais de uma data de expiração, usamos a mais próxima (conservador)
        "expiration_date": min(exp).isoformat() if exp else None,
        "creation_date": created[0].isoformat() if created else None,
        "updated_date": updated[0].isoformat() if updated else None,
        "status": _clean_status(w.get("status")),
        "nameservers": _clean_ns(w.get("name_servers")),
        "dnssec": str(_first(w.get("dnssec")) or "").strip() or None,
        "registrant": registrant,
        "registrant_id": _first(w.get("registrant_id")),
        "country": _first(w.get("country")),
        "emails": _str_list(w.get("emails") or w.get("email")),
    }
    if not data["expiration_date"] and not data["nameservers"] and not data["status"]:
        raise ValueError("Resposta WHOIS vazia (domínio inexistente ou TLD não suportado)")
    return data, raw
