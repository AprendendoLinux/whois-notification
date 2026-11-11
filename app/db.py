"""Engine MySQL, sessão e criação das tabelas."""
import time
from contextlib import contextmanager

from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import DATABASE_URL

engine = create_engine(
    DATABASE_URL, pool_pre_ping=True, pool_recycle=1800, pool_size=10, max_overflow=20,
)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def init_db(retries: int = 60, delay: float = 2.0) -> None:
    """Aguarda o MySQL ficar disponível e cria todas as tabelas que ainda não existirem."""
    from . import models  # noqa: F401 — registra as tabelas

    last = None
    for attempt in range(1, retries + 1):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            Base.metadata.create_all(engine)
            return
        except Exception as e:  # noqa: BLE001
            last = e
            print(f"[~] Aguardando o banco de dados ({attempt}/{retries}): {type(e).__name__}")
            time.sleep(delay)
    raise RuntimeError(f"Banco de dados indisponível: {last}")


@contextmanager
def session_scope():
    s = SessionLocal()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def get_db():
    """Dependência do FastAPI."""
    s = SessionLocal()
    try:
        yield s
    finally:
        s.close()
