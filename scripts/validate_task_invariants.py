from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml


def _load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


@dataclass
class ValidationIssue:
    severity: str
    file: str
    message: str


def _is_placeholder_value(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    return "{{" in value or "}}" in value or "[[" in value or "]]" in value


def _canonical_task_id(task_id: str) -> str:
    if task_id.startswith("task."):
        return task_id[len("task.") :]
    return task_id


def _load_known_task_ids(root: Path, issues: List[ValidationIssue]) -> Set[str]:
    task_index = root / "tasks" / "task-index.yaml"
    if not task_index.exists():
        issues.append(ValidationIssue(severity="warning", file=str(task_index), message="tasks/task-index.yaml not found"))
        return set()

    data = _load_yaml(task_index)
    if not isinstance(data, dict):
        return set()

    tasks = data.get("tasks")
    if not isinstance(tasks, dict):
        return set()

    return set(tasks.keys())


def _load_known_feature_ids(root: Path) -> Set[str]:
    idx = root / "features" / "features-index.yaml"
    if not idx.exists():
        return set()
    data = _load_yaml(idx)
    if not isinstance(data, dict):
        return set()
    feats = data.get("features")
    if not isinstance(feats, list):
        return set()
    out: Set[str] = set()
    for it in feats:
        if isinstance(it, dict) and isinstance(it.get("id"), str):
            out.add(it["id"])
    return out


def _load_known_workflow_ids(root: Path) -> Set[str]:
    idx = root / "workflows" / "workflows-index.yaml"
    if not idx.exists():
        return set()
    data = _load_yaml(idx)
    if not isinstance(data, dict):
        return set()
    wfs = data.get("workflows")
    if not isinstance(wfs, list):
        return set()
    out: Set[str] = set()
    for it in wfs:
        if isinstance(it, dict) and isinstance(it.get("id"), str):
            out.add(it["id"])
    return out


def _require_mapping(obj: Any, file: Path, issues: List[ValidationIssue], msg: str) -> Optional[Dict[str, Any]]:
    if not isinstance(obj, dict):
        issues.append(ValidationIssue(severity="error", file=str(file), message=msg))
        return None
    return obj


def _validate_enforcement_value(value: Any, file: Path, issues: List[ValidationIssue], field: str) -> None:
    if value is None:
        return
    if not isinstance(value, str):
        issues.append(ValidationIssue(severity="error", file=str(file), message=f"{field} must be a string"))
        return
    if value not in {"warn", "fail", "off"}:
        issues.append(ValidationIssue(severity="error", file=str(file), message=f"{field} must be one of: warn, fail, off"))


def _validate_tier_block(tier_obj: Any, file: Path, issues: List[ValidationIssue]) -> None:
    if not isinstance(tier_obj, dict):
        issues.append(ValidationIssue(severity="error", file=str(file), message="tier must be a mapping"))
        return
    for tier in ("mvp", "core", "enterprise"):
        ent = tier_obj.get(tier)
        if ent is None:
            continue
        if not isinstance(ent, dict):
            issues.append(ValidationIssue(severity="error", file=str(file), message=f"tier.{tier} must be a mapping"))
            continue
        req = ent.get("required")
        if req is not None and not isinstance(req, bool):
            issues.append(ValidationIssue(severity="error", file=str(file), message=f"tier.{tier}.required must be boolean"))
        _validate_enforcement_value(ent.get("enforcement"), file, issues, f"tier.{tier}.enforcement")


def validate_task_invariants(root: Path) -> Tuple[List[ValidationIssue], List[ValidationIssue]]:
    errors: List[ValidationIssue] = []
    warnings: List[ValidationIssue] = []

    known_tasks = _load_known_task_ids(root, warnings)
    known_features = _load_known_feature_ids(root)
    known_workflows = _load_known_workflow_ids(root)

    inv_root = root / "tasks" / "invariants"
    base_files = list(inv_root.glob("task.*.invariants.yaml")) if inv_root.exists() else []

    if not base_files:
        warnings.append(ValidationIssue(severity="warning", file=str(inv_root), message="No task invariant specs found"))
        return errors, warnings

    for p in base_files:
        try:
            obj = _load_yaml(p)
        except Exception as e:
            errors.append(ValidationIssue(severity="error", file=str(p), message=f"YAML parse error: {e}"))
            continue

        spec = _require_mapping(obj, p, errors, "Invariant spec must be a mapping/object")
        if not spec:
            continue

        version = spec.get("version")
        if not isinstance(version, int):
            errors.append(ValidationIssue(severity="error", file=str(p), message="version must be an integer"))

        task_id = spec.get("task_id")
        if not isinstance(task_id, str) or not task_id:
            errors.append(ValidationIssue(severity="error", file=str(p), message="task_id must be a non-empty string"))
            continue

        canonical = _canonical_task_id(task_id)
        if known_tasks and canonical not in known_tasks and not _is_placeholder_value(task_id):
            warnings.append(ValidationIssue(severity="warning", file=str(p), message=f"Unknown task_id (not in task-index.yaml): {task_id}"))

        tier_obj = spec.get("tier")
        _validate_tier_block(tier_obj, p, errors)

        contracts = spec.get("contracts")
        if not isinstance(contracts, dict):
            errors.append(ValidationIssue(severity="error", file=str(p), message="contracts must be a mapping/object"))

        links = spec.get("links")
        if isinstance(links, dict):
            feats = links.get("features")
            if isinstance(feats, list) and known_features:
                for fid in feats:
                    if not isinstance(fid, str) or not fid:
                        continue
                    if _is_placeholder_value(fid):
                        continue
                    if fid not in known_features:
                        warnings.append(ValidationIssue(severity="warning", file=str(p), message=f"Invariant links unknown feature id: {fid}"))

            wfs = links.get("workflows")
            if isinstance(wfs, list) and known_workflows:
                for wid in wfs:
                    if not isinstance(wid, str) or not wid:
                        continue
                    if _is_placeholder_value(wid):
                        continue
                    if wid not in known_workflows:
                        warnings.append(ValidationIssue(severity="warning", file=str(p), message=f"Invariant links unknown workflow id: {wid}"))

    return errors, warnings


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    errors, warnings = validate_task_invariants(root)

    for w in warnings:
        print(f"WARNING: {w.file}\n  {w.message}")
    for e in errors:
        print(f"ERROR: {e.file}\n  {e.message}")

    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
