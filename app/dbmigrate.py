"""Aplica as migrações do Alembic na inicialização."""
from alembic import command
from alembic.config import Config

from .config import BASE_DIR


def alembic_config() -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(BASE_DIR / "migrations"))
    return cfg


def upgrade() -> None:
    command.upgrade(alembic_config(), "head")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 2 and sys.argv[1] == "revision":
        command.revision(alembic_config(), message=sys.argv[2], autogenerate=True)
    else:
        upgrade()
