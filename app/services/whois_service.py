"""Consulta WHOIS normalizada."""
import re
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


def _br_date(v: str | None) -> datetime | None:
    m = re.match(r"(\d{4})(\d{2})(\d{2})", v or "")
    return datetime(int(m[1]), int(m[2]), int(m[3]), tzinfo=timezone.utc) if m else None


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


_BR_ROLES = {"owner-c": "Titular", "admin-c": "Administrativo", "tech-c": "Técnico", "billing-c": "Cobrança"}
_BR_LABELS = {
    "person": "Nome", "e-mail": "E-mail", "country": "País", "created": "Criado em", "changed": "Alterado em",
    "nic-hdl-br": "Handle", "phone": "Telefone", "address": "Endereço", "org": "Organização",
}
_GENERIC_ROLES = {
    "registrant": "Titular", "admin": "Administrativo", "administrative": "Administrativo",
    "tech": "Técnico", "technical": "Técnico", "billing": "Cobrança",
}
_GENERIC_RE = re.compile(
    r"^\s*(Registrant|Administrative|Admin|Technical|Tech|Billing)\s+([A-Za-z][A-Za-z /]*?)\s*:\s*(.*?)\s*$", re.I)
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


def _blocks(raw: str) -> list[list[tuple[str, str]]]:
    out, cur = [], []
    for line in raw.splitlines():
        if not line.strip():
            if cur:
                out.append(cur)
                cur = []
            continue
        if line.startswith(("%", "#")) or ":" not in line:
            continue
        k, v = line.split(":", 1)
        cur.append((k.strip().lower(), v.strip()))
    if cur:
        out.append(cur)
    return out


def _parse_br(domain: str, raw: str) -> dict:
    """Interpreta a resposta do registro.br: titular, responsável e contatos (nic-hdl-br)."""
    blocks = _blocks(raw)
    info: dict = {}
    handles: dict[str, list[tuple[str, str]]] = {}
    for b in blocks:
        keys = [k for k, _ in b]
        if "nic-hdl-br" in keys:
            handles[dict(b)["nic-hdl-br"]] = b
        elif "domain" in keys:
            for k, v in b:
                info.setdefault(k, v)
            info["nservers"] = [v.split()[0] for k, v in b if k == "nserver" and v]
    roles: dict[str, list[str]] = {}
    for k, label in _BR_ROLES.items():
        for b in blocks:
            for kk, v in b:
                if kk == k and v:
                    roles.setdefault(v, []).append(label)
    for h in list(roles)[:6]:
        if h not in handles:
            try:
                extra = _blocks(_raw_query("whois.registro.br", h))
            except OSError:
                continue
            for b in extra:
                if "nic-hdl-br" in [k for k, _ in b]:
                    handles[dict(b)["nic-hdl-br"]] = b
    contacts = []
    for h, b in handles.items():
        fields = [(_BR_LABELS.get(k, k.capitalize()), re.sub(r"^(\d{4})(\d{2})(\d{2})$", r"\3/\2/\1", v))
                  for k, v in b if v and k != "nic-hdl-br"]
        contacts.append({"role": " / ".join(dict.fromkeys(roles.get(h, ["Contato"]))), "handle": h, "fields": fields})
    info["contacts"] = contacts
    return info


def _parse_generic(raw: str) -> list[dict]:
    """Contatos de TLDs genéricos: linhas 'Registrant Name:', 'Admin Email:', 'Tech Phone:'..."""
    groups: dict[str, list[tuple[str, str]]] = {}
    for line in raw.splitlines():
        m = _GENERIC_RE.match(line)
        if not m or not m.group(3):
            continue
        role = _GENERIC_ROLES[m.group(1).lower()]
        item = (m.group(2).strip().title(), m.group(3))
        if item not in groups.setdefault(role, []):
            groups[role].append(item)
    return [{"role": r, "handle": None, "fields": f} for r, f in groups.items()]


def lookup(domain: str) -> tuple[dict, str | None]:
    """Retorna (dados normalizados, texto bruto). Lança exceção em falha."""
    w = whois.whois(domain)
    raw = getattr(w, "text", None) or ""
    is_br = domain.endswith(".br")
    br: dict = {}
    if is_br:
        try:
            raw_br = _raw_query("whois.registro.br", domain)
        except OSError:
            raw_br = ""
        if raw_br.strip():
            raw = raw_br
            br = _parse_br(domain, raw_br)

    exp = _dates(w.get("expiration_date")) or _dates(_br_date(br.get("expires")))
    created = _dates(w.get("creation_date")) or _dates(_br_date(br.get("created")))
    updated = _dates(w.get("updated_date")) or _dates(_br_date(br.get("changed")))

    registrant = (
        br.get("owner")
        or _first(w.get("registrant_name"))
        or _first(w.get("org"))
        or _first(w.get("name"))
    )
    if registrant and "REDACTED" in str(registrant).upper():
        registrant = "Oculto (privacidade)"

    contacts = br.get("contacts") or _parse_generic(raw)
    emails = _str_list(w.get("emails") or w.get("email"))
    for c in contacts:
        for _, v in c["fields"]:
            for e in _EMAIL_RE.findall(v):
                if e.lower() not in {x.lower() for x in emails}:
                    emails.append(e)

    data = {
        "domain": str(_first(w.get("domain_name")) or domain).lower(),
        "registrar": _first(w.get("registrar")) or ("Registro.br" if domain.endswith(".br") else None),
        "registrar_url": _first(w.get("registrar_url")),
        "whois_server": _first(w.get("whois_server")) or ("whois.registro.br" if is_br else None),
        # Se houver mais de uma data de expiração, usamos a mais próxima (conservador)
        "expiration_date": min(exp).isoformat() if exp else None,
        "creation_date": created[0].isoformat() if created else None,
        "updated_date": updated[0].isoformat() if updated else None,
        "status": _clean_status(w.get("status") or br.get("status")),
        "nameservers": _clean_ns(w.get("name_servers") or br.get("nservers")),
        "dnssec": str(_first(w.get("dnssec")) or "").strip() or None,
        "registrant": registrant,
        "registrant_id": br.get("ownerid") or _first(w.get("registrant_id")),
        "responsible": br.get("responsible"),
        "country": br.get("country") or _first(w.get("country")),
        "emails": emails,
        "contacts": contacts,
    }
    if not data["expiration_date"] and not data["nameservers"] and not data["status"]:
        raise ValueError("Resposta WHOIS vazia (domínio inexistente ou TLD não suportado)")
    return data, raw
