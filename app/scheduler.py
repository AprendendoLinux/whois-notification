"""Agendador em segundo plano (APScheduler): uma varredura diária por usuário."""
import threading

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy import select

from .config import local_tz
from .db import SessionLocal
from .models import User
from .services import checker
from .services import settings as cfg

scheduler = BackgroundScheduler(job_defaults={"coalesce": True, "max_instances": 1})
_locks: dict[int, threading.Lock] = {}
_locks_guard = threading.Lock()


def _lock(user_id: int) -> threading.Lock:
    with _locks_guard:
        return _locks.setdefault(user_id, threading.Lock())


def run_all_guarded(user_id: int, notify: bool = True) -> bool:
    """Evita duas varreduras completas simultâneas do mesmo usuário."""
    lock = _lock(user_id)
    if not lock.acquire(blocking=False):
        return False
    try:
        checker.run_all(user_id, notify=notify)
    finally:
        lock.release()
    return True


def is_running_all(user_id: int) -> bool:
    queued = scheduler.get_job(f"manual_check_{user_id}") or scheduler.get_job("startup_check")
    return _lock(user_id).locked() or bool(queued)


def _parse_time(value: str) -> tuple[int, int]:
    try:
        h, m = value.strip().split(":")
        h, m = int(h), int(m)
        if 0 <= h < 24 and 0 <= m < 60:
            return h, m
    except ValueError:
        pass
    return 9, 0


def schedule_user(user_id: int) -> None:
    with SessionLocal() as db:
        h, m = _parse_time(cfg.get(db, user_id, "check_time"))
    scheduler.add_job(run_all_guarded, CronTrigger(hour=h, minute=m, timezone=local_tz()),
                      args=[user_id], id=f"daily_{user_id}", replace_existing=True,
                      misfire_grace_time=3600)


def unschedule_user(user_id: int) -> None:
    for job_id in (f"daily_{user_id}", f"manual_check_{user_id}"):
        if scheduler.get_job(job_id):
            scheduler.remove_job(job_id)


def schedule_all() -> None:
    with SessionLocal() as db:
        ids = list(db.scalars(select(User.id).where(User.is_active.is_(True))))
    for uid in ids:
        schedule_user(uid)


def next_run(user_id: int):
    job = scheduler.get_job(f"daily_{user_id}")
    return job.next_run_time if job else None


def _startup_check() -> None:
    with SessionLocal() as db:
        ids = list(db.scalars(select(User.id).where(User.is_active.is_(True))))
    for uid in ids:
        run_all_guarded(uid)


def start(run_now: bool = True) -> None:
    scheduler.configure(timezone=local_tz())
    schedule_all()
    scheduler.start()
    if run_now:
        scheduler.add_job(_startup_check, id="startup_check", replace_existing=True)


def run_all_in_background(user_id: int) -> bool:
    if is_running_all(user_id):
        return False
    scheduler.add_job(run_all_guarded, args=[user_id], id=f"manual_check_{user_id}",
                      replace_existing=True)
    return True


def run_one_in_background(domain_id: int) -> None:
    scheduler.add_job(checker.run_check, args=[domain_id], id=f"check_{domain_id}",
                      replace_existing=True)


def shutdown() -> None:
    if scheduler.running:
        scheduler.shutdown(wait=False)
