from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict

import yaml


def _load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _dump_yaml(obj: Any) -> str:
    return yaml.safe_dump(obj, sort_keys=False, allow_unicode=True)


def link(*, root: Path, write: bool) -> int:
    idx_path = root / "tasks" / "task-index.yaml"
    data = _load_yaml(idx_path)
    if not isinstance(data, dict):
        raise SystemExit("tasks/task-index.yaml is not a mapping")

    tasks = data.get("tasks")
    if not isinstance(tasks, dict):
        raise SystemExit("tasks/task-index.yaml missing 'tasks' mapping")

    changed = 0
    for task_name, task_data in tasks.items():
        if not isinstance(task_data, dict):
            continue

        expected = f"tasks/invariants/task.{task_name}.invariants.yaml"
        existing = task_data.get("invariant")
        if existing == expected:
            continue

        inv_path = root / expected
        if not inv_path.exists():
            # Don't link if the invariant file doesn't exist.
            continue

        task_data["invariant"] = expected
        changed += 1

    if write and changed:
        idx_path.write_text(_dump_yaml(data), encoding="utf-8")

    return changed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    changed = link(root=root, write=args.write)

    if args.write:
        print(f"UPDATED task-index.yaml invariant links: {changed}")
    else:
        print(f"WOULD update task-index.yaml invariant links: {changed}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
