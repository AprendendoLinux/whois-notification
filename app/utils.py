"""Validações e normalizações compartilhadas."""
import re

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z0-9-]{2,63}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
CHAT_RE = re.compile(r"^(-?\d{3,20}|@[A-Za-z0-9_]{4,64})$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")


def normalize_domain(value: str) -> str:
    v = (value or "").strip().lower()
    for prefix in ("https://", "http://"):
        if v.startswith(prefix):
            v = v[len(prefix):]
    v = v.split("/")[0].split(":")[0].rstrip(".")
    if v.startswith("www."):
        v = v[4:]
    return v.encode("idna").decode() if v and not v.isascii() else v
