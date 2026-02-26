"""
File: background_tasks.tpl.py
Purpose: Background job processing with Celery/Redis
Generated for: {{PROJECT_NAME}}
"""

import os
import logging
from datetime import datetime, timedelta
from typing import Any, Optional, Callable
from functools import wraps
from celery import Celery, Task
from celery.schedules import crontab

logger = logging.getLogger(__name__)

# Celery configuration
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

app = Celery(
    "{{PROJECT_NAME}}",
    broker=REDIS_URL,
    backend=REDIS_URL,
)

app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour
    task_soft_time_limit=3300,  # 55 minutes
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    result_expires=86400,  # 24 hours
)


# Custom base task with error handling
class BaseTask(Task):
    """Base task with automatic error handling and retries"""

    autoretry_for = (Exception,)
    retry_kwargs = {"max_retries": 3}
    retry_backoff = True
    retry_backoff_max = 600
    retry_jitter = True

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        logger.error(f"Task {self.name}[{task_id}] failed: {exc}")
        super().on_failure(exc, task_id, args, kwargs, einfo)

    def on_success(self, retval, task_id, args, kwargs):
        logger.info(f"Task {self.name}[{task_id}] completed successfully")
        super().on_success(retval, task_id, args, kwargs)

    def on_retry(self, exc, task_id, args, kwargs, einfo):
        logger.warning(f"Task {self.name}[{task_id}] retrying: {exc}")
        super().on_retry(exc, task_id, args, kwargs, einfo)


# Task decorator with common options
def task_with_logging(func: Callable) -> Callable:
    """Decorator to add logging to tasks"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = datetime.utcnow()
        logger.info(f"Starting task: {func.__name__}")
        try:
            result = func(*args, **kwargs)
            duration = (datetime.utcnow() - start_time).total_seconds()
            logger.info(f"Task {func.__name__} completed in {duration:.2f}s")
            return result
        except Exception as e:
            logger.error(f"Task {func.__name__} failed: {e}")
            raise
    return wrapper


# Example tasks
@app.task(base=BaseTask, bind=True)
def send_email(self, to: str, subject: str, body: str) -> dict:
    """Send email task"""
    logger.info(f"Sending email to {to}: {subject}")
    # Implement email sending logic here
    return {"status": "sent", "to": to, "subject": subject}


@app.task(base=BaseTask, bind=True)
def process_upload(self, file_id: str, user_id: int) -> dict:
    """Process uploaded file"""
    logger.info(f"Processing file {file_id} for user {user_id}")
    # Update progress
    self.update_state(state="PROGRESS", meta={"current": 0, "total": 100})
    
    # Simulate processing
    import time
    for i in range(10):
        time.sleep(0.1)
        self.update_state(state="PROGRESS", meta={"current": (i + 1) * 10, "total": 100})
    
    return {"status": "processed", "file_id": file_id}


@app.task(base=BaseTask)
def cleanup_expired_sessions() -> dict:
    """Clean up expired user sessions"""
    logger.info("Cleaning up expired sessions")
    # Implement session cleanup
    deleted_count = 0  # Replace with actual logic
    return {"deleted": deleted_count}


@app.task(base=BaseTask)
def generate_report(report_type: str, params: dict) -> dict:
    """Generate a report asynchronously"""
    logger.info(f"Generating {report_type} report with params: {params}")
    # Implement report generation
    return {"status": "generated", "report_type": report_type}


@app.task(base=BaseTask)
def sync_external_data(source: str) -> dict:
    """Sync data from external source"""
    logger.info(f"Syncing data from {source}")
    # Implement data sync
    return {"status": "synced", "source": source}


# Scheduled tasks (Celery Beat)
app.conf.beat_schedule = {
    "cleanup-sessions-daily": {
        "task": "background_tasks.cleanup_expired_sessions",
        "schedule": crontab(hour=2, minute=0),  # 2 AM daily
    },
    "sync-data-hourly": {
        "task": "background_tasks.sync_external_data",
        "schedule": crontab(minute=0),  # Every hour
        "args": ("external_api",),
    },
}


# Task chains and groups
from celery import chain, group, chord

def process_batch(file_ids: list, user_id: int):
    """Process multiple files in parallel"""
    tasks = group(process_upload.s(fid, user_id) for fid in file_ids)
    return tasks.apply_async()


def process_with_callback(file_id: str, user_id: int):
    """Process file and send notification"""
    workflow = chain(
        process_upload.s(file_id, user_id),
        send_email.s(
            to="user@example.com",
            subject="File processed",
            body="Your file has been processed",
        ),
    )
    return workflow.apply_async()


# Task result helper
class TaskResult:
    """Helper for checking task results"""

    def __init__(self, task_id: str):
        self.result = app.AsyncResult(task_id)

    @property
    def status(self) -> str:
        return self.result.status

    @property
    def is_ready(self) -> bool:
        return self.result.ready()

    @property
    def is_successful(self) -> bool:
        return self.result.successful()

    @property
    def data(self) -> Any:
        return self.result.result if self.is_ready else None

    def wait(self, timeout: Optional[float] = None) -> Any:
        return self.result.get(timeout=timeout)


# Usage:
# # Send task
# result = send_email.delay("user@example.com", "Hello", "World")
#
# # Check status
# task = TaskResult(result.id)
# print(task.status)
#
# # Wait for result
# data = task.wait(timeout=30)
