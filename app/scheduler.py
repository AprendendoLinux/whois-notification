"""Agendador em segundo plano (APScheduler)."""
import threading

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from .config import LOCAL_TZ
from .db import SessionLocal
from .services import checker
from .services import settings as cfg

scheduler = BackgroundScheduler(timezone=LOCAL_TZ, job_defaults={"coalesce": True, "max_instances": 1})
JOB_ID = "daily_check"
_all_lock = threading.Lock()


def run_all_guarded(notify: bool = True) -> bool:
    """Evita duas varreduras completas simultâneas. Retorna False se já havia uma."""
    if not _all_lock.acquire(blocking=False):
        return False
    try:
        checker.run_all(notify=notify)
    finally:
        _all_lock.release()
    return True


def is_running_all() -> bool:
    queued = any(scheduler.get_job(j) for j in ("startup_check", "manual_check_all"))
    return _all_lock.locked() or queued


def _parse_time(value: str) -> tuple[int, int]:
    try:
        h, m = value.strip().split(":")
        h, m = int(h), int(m)
        if 0 <= h < 24 and 0 <= m < 60:
            return h, m
    except ValueError:
        pass
    return 9, 0


def schedule_daily() -> None:
    with SessionLocal() as db:
        h, m = _parse_time(cfg.get(db, "check_time"))
    scheduler.add_job(run_all_guarded, CronTrigger(hour=h, minute=m, timezone=LOCAL_TZ),
                      id=JOB_ID, replace_existing=True, misfire_grace_time=3600)


def next_run():
    job = scheduler.get_job(JOB_ID)
    return job.next_run_time if job else None


def start(run_now: bool = True) -> None:
    schedule_daily()
    scheduler.start()
    if run_now:
        # Verificação inicial em segundo plano, como no comportamento original
        scheduler.add_job(run_all_guarded, id="startup_check", replace_existing=True)


def run_all_in_background() -> bool:
    if is_running_all():
        return False
    scheduler.add_job(run_all_guarded, id="manual_check_all", replace_existing=True)
    return True


def run_one_in_background(domain_id: int) -> None:
    scheduler.add_job(checker.run_check, args=[domain_id], id=f"check_{domain_id}",
                      replace_existing=True)


def shutdown() -> None:
    if scheduler.running:
        scheduler.shutdown(wait=False)
