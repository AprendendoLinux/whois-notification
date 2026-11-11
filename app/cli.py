"""Utilitário de linha de comando: docker exec whois_notification python -m app.cli reset-admin"""
import sys

from .auth import reset_admin_password
from .db import SessionLocal, init_db


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] != "reset-admin":
        print("Uso: python -m app.cli reset-admin [usuario]")
        return 1
    init_db()
    username = sys.argv[2] if len(sys.argv) > 2 else "admin"
    with SessionLocal() as db:
        password = reset_admin_password(db, username)
    if password is None:
        print(f"Usuário '{username}' não encontrado.")
        return 1
    print(f"Nova senha temporária de '{username}': {password}\nSerá exigida a troca no próximo login.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
