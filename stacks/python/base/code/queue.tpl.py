"""
File: queue.tpl.py
Purpose: Background job processing with Celery
Generated for: {{PROJECT_NAME}}
"""

from celery import Celery
from celery.schedules import crontab
from typing import Any, Callable, Optional
from functools import wraps
import logging

logger = logging.getLogger(__name__)


def create_celery_app(
    name: str,
    broker_url: str = "redis://localhost:6379/0",
    result_backend: str = "redis://localhost:6379/1",
) -> Celery:
    """Create and configure Celery application"""
    
    app = Celery(
        name,
        broker=broker_url,
        backend=result_backend,
    )

    app.conf.update(
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        timezone="UTC",
        enable_utc=True,
        task_track_started=True,
        task_time_limit=30 * 60,  # 30 minutes
        task_soft_time_limit=25 * 60,  # 25 minutes
        worker_prefetch_multiplier=1,
        task_acks_late=True,
        task_reject_on_worker_lost=True,
    )

    return app


# Default app instance
celery_app = create_celery_app("{{PROJECT_NAME}}")


# Task decorators
def task(
    name: Optional[str] = None,
    max_retries: int = 3,
    retry_backoff: bool = True,
    queue: str = "default",
):
    """Custom task decorator with retry logic"""
    def decorator(func: Callable) -> Callable:
        @celery_app.task(
            name=name or func.__name__,
            bind=True,
            max_retries=max_retries,
            default_retry_delay=60,
            queue=queue,
        )
        @wraps(func)
        def wrapper(self, *args, **kwargs) -> Any:
            try:
                return func(*args, **kwargs)
            except Exception as exc:
                logger.error(f"Task {self.name} failed: {exc}")
                if retry_backoff:
                    raise self.retry(exc=exc, countdown=2 ** self.request.retries * 60)
                raise self.retry(exc=exc)

        return wrapper
    return decorator


# Example tasks
@task(name="send_email", queue="notifications")
def send_email(to: str, subject: str, body: str) -> dict:
    """Send an email"""
    logger.info(f"Sending email to {to}: {subject}")
    # Implement email sending logic
    return {"status": "sent", "to": to}


@task(name="process_file", queue="processing")
def process_file(file_path: str) -> dict:
    """Process a file in the background"""
    logger.info(f"Processing file: {file_path}")
    # Implement file processing logic
    return {"status": "processed", "file": file_path}


# Scheduled tasks (beat schedule)
celery_app.conf.beat_schedule = {
    "cleanup-expired-tokens": {
        "task": "cleanup_tokens",
        "schedule": crontab(hour=0, minute=0),  # Daily at midnight
    },
    "send-daily-digest": {
        "task": "send_digest",
        "schedule": crontab(hour=8, minute=0),  # Daily at 8 AM
    },
}


# Usage:
# Start worker: celery -A queue worker -l INFO -Q default,notifications,processing
# Start beat: celery -A queue beat -l INFO
#
# Send task:
# from queue import send_email
# send_email.delay("user@example.com", "Hello", "World")
