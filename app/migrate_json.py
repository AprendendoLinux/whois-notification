"""Importação única do antigo domains.json para o SQLite."""
import json
import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import LEGACY_JSON
from .models import Contact, Domain

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z0-9-]{2,63}$")
EXAMPLE_DOMAINS = {"exemplo.com.br", "outroexemplo.net"}


def normalize_domain(value: str) -> str:
    v = (value or "").strip().lower()
    for prefix in ("https://", "http://"):
        if v.startswith(prefix):
            v = v[len(prefix):]
    v = v.split("/")[0].split(":")[0].rstrip(".")
    if v.startswith("www."):
        v = v[4:]
    return v.encode("idna").decode() if v and not v.isascii() else v


def get_or_create_contact(db: Session, kind: str, value: str, name: str = "") -> Contact:
    value = value.strip()
    c = db.scalar(select(Contact).where(Contact.kind == kind, Contact.value == value))
    if c is None:
        c = Contact(kind=kind, value=value, name=name)
        db.add(c)
        db.flush()
    return c


def import_legacy_json(db: Session) -> int:
    """Importa se o arquivo existir e o banco não tiver domínios. Retorna a quantidade importada."""
    if not LEGACY_JSON.exists():
        return 0
    if db.scalar(select(Domain.id).limit(1)) is not None:
        return 0
    try:
        data = json.loads(LEGACY_JSON.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"[!] Não foi possível ler {LEGACY_JSON} para migração: {e}")
        return 0

    count = 0
    for item in data if isinstance(data, list) else []:
        name = normalize_domain(str(item.get("domain", "")))
        if not name or name in EXAMPLE_DOMAINS or not DOMAIN_RE.match(name):
            if name and name not in EXAMPLE_DOMAINS:
                print(f"[!] Migração: domínio inválido ignorado: {item.get('domain')!r}")
            continue
        if db.scalar(select(Domain).where(Domain.name == name)):
            continue
        d = Domain(name=name, days_threshold=int(item.get("days_threshold", 30) or 30))
        db.add(d)
        for email in item.get("emails") or []:
            if str(email).strip():
                d.contacts.append(get_or_create_contact(db, "email", str(email)))
        for chat in item.get("telegrams") or []:
            if str(chat).strip():
                d.contacts.append(get_or_create_contact(db, "telegram", str(chat)))
        count += 1
    db.commit()

    target = LEGACY_JSON.with_suffix(".json.migrated")
    try:
        LEGACY_JSON.rename(target)
    except OSError as e:
        print(f"[!] Importado, mas não foi possível renomear {LEGACY_JSON}: {e}")
    print(f"[*] Migração: {count} domínio(s) importado(s) de domains.json → SQLite ({target.name}).")
    return count
