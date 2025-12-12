from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml


@dataclass
class Result:
    created: List[Path]
    skipped: List[Path]


def _load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _dump_yaml(obj: Any) -> str:
    return yaml.safe_dump(obj, sort_keys=False, allow_unicode=True)


def _task_ids(root: Path) -> List[str]:
    idx_path = root / "tasks" / "task-index.yaml"
    idx = _load_yaml(idx_path)
    tasks = idx.get("tasks") if isinstance(idx, dict) else None
    if not isinstance(tasks, dict):
        raise RuntimeError("tasks/task-index.yaml missing 'tasks' mapping")
    return list(tasks.keys())


def _default_invariant(task_name: str) -> Dict[str, Any]:
    return {
        "version": 1,
        "task_id": f"task.{task_name}",
        "tier": {
            "mvp": {"required": True, "enforcement": "warn"},
            "core": {"required": True, "enforcement": "fail"},
            "enterprise": {"required": True, "enforcement": "fail"},
        },
        "links": {"features": [], "workflows": []},
        "contracts": {
            "must": {"emit_events": [], "write_db": [], "return": []},
            "must_not": {"emit_events": [], "leak_fields": []},
        },
        "properties": {
            "idempotency": "unknown",
            "retry_safe": False,
            "side_effect_level": "medium",
            "security_level": "medium",
            "pii": "possible",
        },
        "observability": {"required_logs": [], "required_metrics": []},
    }


def generate_all(*, root: Path, write: bool) -> Result:
    inv_root = root / "tasks" / "invariants"
    inv_root.mkdir(parents=True, exist_ok=True)

    created: List[Path] = []
    skipped: List[Path] = []

    for task_name in _task_ids(root):
        out_path = inv_root / f"task.{task_name}.invariants.yaml"
        if out_path.exists():
            skipped.append(out_path)
            continue

        if write:
            spec = _default_invariant(task_name)
            out_path.write_text(_dump_yaml(spec), encoding="utf-8")
        created.append(out_path)

    return Result(created=created, skipped=skipped)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    res = generate_all(root=root, write=args.write)

    if args.write:
        for p in res.created:
            print(f"CREATED: {p}")
    else:
        for p in res.created:
            print(f"MISSING (would create): {p}")

    for p in res.skipped:
        print(f"SKIPPED: {p}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
