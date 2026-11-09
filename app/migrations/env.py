"""Ambiente do Alembic: usa a mesma engine da aplicação."""
from alembic import context

from app.db import Base, engine
from app import models  # noqa: F401 — registra as tabelas

target_metadata = Base.metadata


def run_migrations_online() -> None:
    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,  # necessário para ALTER TABLE no SQLite
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


run_migrations_online()
