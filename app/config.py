"""Configuração de caminhos e fuso horário."""
import os
import secrets
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("DATA_DIR", "/app/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "whois.db"
DATABASE_URL = f"sqlite:///{DB_PATH}"
LEGACY_JSON = DATA_DIR / "domains.json"

APP_NAME = "Whois Notification"
APP_VERSION = "2.0.0"


def _load_tz() -> ZoneInfo:
    name = os.getenv("TZ", "America/Sao_Paulo")
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        return ZoneInfo("UTC")


LOCAL_TZ = _load_tz()


def _secret_key() -> str:
    """Chave de sessão: variável de ambiente ou arquivo persistido no volume."""
    env = os.getenv("SECRET_KEY")
    if env:
        return env
    key_file = DATA_DIR / ".secret_key"
    if key_file.exists():
        return key_file.read_text().strip()
    key = secrets.token_urlsafe(48)
    key_file.write_text(key)
    try:
        key_file.chmod(0o600)
    except OSError:
        pass
    return key


SECRET_KEY = _secret_key()
