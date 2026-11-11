"""Configuração de infraestrutura: banco de dados (única parte via ambiente), chaves e fuso."""
import os
import secrets
from pathlib import Path
from urllib.parse import quote_plus
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path("/app/data")
try:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
except OSError:
    DATA_DIR = BASE_DIR.parent / "data"
    DATA_DIR.mkdir(parents=True, exist_ok=True)

APP_NAME = "Whois Notification"
APP_VERSION = "3.0.2"

DB_HOST = os.getenv("DB_HOST", "db")
DB_PORT = os.getenv("DB_PORT", "3306")
DB_NAME = os.getenv("DB_NAME", "whois")
DB_USER = os.getenv("DB_USER", "whois")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")

DATABASE_URL = (
    f"mysql+pymysql://{quote_plus(DB_USER)}:{quote_plus(DB_PASSWORD)}"
    f"@{DB_HOST}:{DB_PORT}/{DB_NAME}?charset=utf8mb4"
)

DEFAULT_TZ = "America/Sao_Paulo"
_tz = ZoneInfo(DEFAULT_TZ)


def valid_tz(name: str) -> bool:
    try:
        ZoneInfo(name)
        return True
    except (ZoneInfoNotFoundError, ValueError):
        return False


def set_tz(name: str) -> None:
    global _tz
    _tz = ZoneInfo(name) if valid_tz(name) else ZoneInfo("UTC")


def local_tz() -> ZoneInfo:
    return _tz


def _persisted_key(filename: str) -> str:
    key_file = DATA_DIR / filename
    if key_file.exists():
        return key_file.read_text().strip()
    key = secrets.token_urlsafe(48)
    key_file.write_text(key)
    try:
        key_file.chmod(0o600)
    except OSError:
        pass
    return key


SECRET_KEY = _persisted_key(".secret_key")
