import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


def _trace_path() -> Path:
    return Path(os.getenv("TASK_TRACE_PATH", "artifacts/task-trace.jsonl"))


def _write_event(event: Dict[str, Any]) -> None:
    path = _trace_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    event.setdefault("ts", time.time())
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")


def emit(*, task_id: str, type: str, name: Optional[str] = None, key: Optional[str] = None, table: Optional[str] = None, keys: Optional[List[str]] = None, value: Any = None, fields: Optional[Dict[str, Any]] = None) -> None:
    ev: Dict[str, Any] = {"task_id": task_id, "type": type}
    if name is not None:
        ev["name"] = name
    if key is not None:
        ev["key"] = key
    if table is not None:
        ev["table"] = table
    if keys is not None:
        ev["keys"] = keys
    if value is not None:
        ev["value"] = value
    if fields is not None:
        ev.update(fields)
    _write_event(ev)
