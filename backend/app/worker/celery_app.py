from __future__ import annotations

from celery import Celery
from celery.schedules import crontab

from app.settings import settings


celery_app = Celery(
    "supplychain",
    broker=settings.redis_url,
    backend=settings.redis_url,
)

celery_app.conf.update(
    task_track_started=True,
    broker_connection_retry_on_startup=True,
    timezone="UTC",
)

import app.worker.tasks  # noqa: E402,F401

# periodic jobs (run with celery beat)
celery_app.conf.beat_schedule = {
    "waiver-expiry-check-every-minute": {
        "task": "check_waivers",
        "schedule": crontab(minute="*"),
    }
}

