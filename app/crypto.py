"""Criptografia de segredos (senhas SMTP e tokens) com chave gerada no primeiro boot."""
import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from .config import _persisted_key

_fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(_persisted_key(".enc_key").encode()).digest()))


def encrypt(value: str) -> str:
    return _fernet.encrypt(value.encode()).decode() if value else ""


def decrypt(token: str | None) -> str:
    if not token:
        return ""
    try:
        return _fernet.decrypt(token.encode()).decode()
    except InvalidToken:
        return ""
