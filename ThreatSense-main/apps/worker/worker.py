from celery import Celery
import os

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

celery_app = Celery(
    "threatsense_worker",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["tasks.scan_task"],
)
