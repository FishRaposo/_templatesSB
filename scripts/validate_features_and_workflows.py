from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml


SKIP_DIR_PARTS = {
    "node_modules",
    "__pycache__",
    ".git",
    ".venv",
    "venv",
    "dist",
    "build",
    "reference-projects",
    "_archive",
}

_FEATURE_INDEX_NAMES = {"features-index.yaml"}
_WORKFLOW_INDEX_NAMES = {"workflows-index.yaml"}


@dataclass
class ValidationIssue:
    severity: str
    file: str
    message: str


def _should_skip_path(path: Path) -> bool:
    parts = set(path.parts)
    return any(p in parts for p in SKIP_DIR_PARTS)


def _discover_yaml_files(root: Path) -> Tuple[List[Path], List[Path]]:
    feature_files: List[Path] = []
    workflow_files: List[Path] = []

    for p in root.rglob("*.yaml"):
        if _should_skip_path(p):
            continue

        name_upper = p.name.upper()
        if name_upper in {"FEATURES.YAML", "FEATURES.TPL.YAML"}:
            feature_files.append(p)
        elif name_upper in {"WORKFLOWS.YAML", "WORKFLOWS.TPL.YAML"}:
            workflow_files.append(p)

    return feature_files, workflow_files


def _discover_index_files(root: Path) -> Tuple[List[Path], List[Path]]:
    feature_indexes: List[Path] = []
    workflow_indexes: List[Path] = []

    for p in root.rglob("*.yaml"):
        if _should_skip_path(p):
            continue

        name_lower = p.name.lower()
        if name_lower in _FEATURE_INDEX_NAMES:
            feature_indexes.append(p)
        elif name_lower in _WORKFLOW_INDEX_NAMES:
            workflow_indexes.append(p)

    return feature_indexes, workflow_indexes


def _load_yaml(path: Path, issues: List[ValidationIssue]) -> Optional[Any]:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as e:
        issues.append(ValidationIssue(severity="error", file=str(path), message=f"YAML parse error: {e}"))
        return None


def _canonical_task_id(task_id: str) -> str:
    # Tasks in this repo are keyed by task name in tasks/task-index.yaml.
    # Accept both "task.foo" style and raw keys as best-effort.
    if task_id.startswith("task."):
        return task_id[len("task.") :]
    return task_id


def _load_known_task_ids(root: Path, issues: List[ValidationIssue]) -> Set[str]:
    task_index = root / "tasks" / "task-index.yaml"
    if not task_index.exists():
        issues.append(ValidationIssue(severity="warning", file=str(task_index), message="tasks/task-index.yaml not found"))
        return set()

    data = _load_yaml(task_index, issues)
    if not isinstance(data, dict):
        return set()

    tasks = data.get("tasks")
    if not isinstance(tasks, dict):
        return set()

    return set(tasks.keys())


def _validate_feature_spec(obj: Any, file: Path, issues: List[ValidationIssue]) -> Optional[str]:
    if not isinstance(obj, dict):
        issues.append(ValidationIssue(severity="error", file=str(file), message="Feature spec must be a mapping/object"))
        return None

    feature_id = _require_key(obj, "id", file, issues)
    _require_type(feature_id, str, "id", file, issues)
    if isinstance(feature_id, str) and not _is_placeholder_value(feature_id):
        if not feature_id.startswith("feature."):
            issues.append(ValidationIssue(severity="warning", file=str(file), message=f"Feature id should start with 'feature.': {feature_id}"))

    required_str = ["name", "summary", "user_story"]
    for key in required_str:
        val = _require_key(obj, key, file, issues)
        _require_type(val, str, key, file, issues)

    acceptance = _require_key(obj, "acceptance_criteria", file, issues)
    _require_type(acceptance, list, "acceptance_criteria", file, issues)

    tier_impact = _require_key(obj, "tier_impact", file, issues)
    _require_type(tier_impact, dict, "tier_impact", file, issues)

    stacks = _require_key(obj, "stacks", file, issues)
    _require_type(stacks, dict, "stacks", file, issues)

    tasks = _require_key(obj, "tasks", file, issues)
    _require_type(tasks, list, "tasks", file, issues)

    inputs = _require_key(obj, "inputs", file, issues)
    _require_type(inputs, list, "inputs", file, issues)

    outputs = _require_key(obj, "outputs", file, issues)
    _require_type(outputs, list, "outputs", file, issues)

    if "dependencies" in obj and obj["dependencies"] is not None:
        _require_type(obj["dependencies"], list, "dependencies", file, issues, severity="warning")

    return feature_id if isinstance(feature_id, str) else None


def _validate_workflow_spec(
    obj: Any,
    file: Path,
    issues: List[ValidationIssue],
    *,
    known_feature_ids: Set[str],
    known_task_ids: Set[str],
) -> Optional[str]:
    if not isinstance(obj, dict):
        issues.append(ValidationIssue(severity="error", file=str(file), message="Workflow spec must be a mapping/object"))
        return None

    workflow_id = _require_key(obj, "id", file, issues)
    _require_type(workflow_id, str, "id", file, issues)
    if isinstance(workflow_id, str) and not _is_placeholder_value(workflow_id):
        if not workflow_id.startswith("workflow."):
            issues.append(ValidationIssue(severity="warning", file=str(file), message=f"Workflow id should start with 'workflow.': {workflow_id}"))

    required_str = ["name", "summary", "primary_actor"]
    for key in required_str:
        val = _require_key(obj, key, file, issues)
        _require_type(val, str, key, file, issues)

    pre = _require_key(obj, "preconditions", file, issues)
    _require_type(pre, list, "preconditions", file, issues)

    post = _require_key(obj, "postconditions", file, issues)
    _require_type(post, list, "postconditions", file, issues)

    happy = _require_key(obj, "happy_path", file, issues)
    _require_type(happy, list, "happy_path", file, issues)

    steps = _require_key(obj, "steps", file, issues)
    _require_type(steps, list, "steps", file, issues)

    # Validate step references
    if isinstance(steps, list):
        for st in steps:
            if not isinstance(st, dict):
                issues.append(ValidationIssue(severity="error", file=str(file), message="Each workflow step must be a mapping/object"))
                continue

            step_id = st.get("step_id")
            if not isinstance(step_id, str) or not step_id:
                issues.append(ValidationIssue(severity="error", file=str(file), message="Workflow step missing step_id"))

            feature_id = st.get("feature_id")
            if not isinstance(feature_id, str) or not feature_id:
                issues.append(ValidationIssue(severity="error", file=str(file), message=f"Workflow step '{step_id}' missing feature_id"))
            elif not _is_placeholder_value(feature_id) and known_feature_ids and feature_id not in known_feature_ids:
                issues.append(ValidationIssue(severity="warning", file=str(file), message=f"Workflow references unknown feature id: {feature_id}"))

            sys_tasks = st.get("system_tasks")
            if isinstance(sys_tasks, list) and known_task_ids:
                for t in sys_tasks:
                    if not isinstance(t, str) or not t:
                        continue
                    if _is_placeholder_value(t):
                        continue
                    tid = _canonical_task_id(t)
                    if tid not in known_task_ids:
                        issues.append(ValidationIssue(severity="warning", file=str(file), message=f"Workflow step '{step_id}' references unknown task: {t}"))

    return workflow_id if isinstance(workflow_id, str) else None


def _is_placeholder_value(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    return "{{" in value or "}}" in value or "[[" in value or "]]" in value


def _require_key(
    obj: Dict[str, Any],
    key: str,
    file: Path,
    issues: List[ValidationIssue],
    *,
    severity: str = "error",
) -> Optional[Any]:
    if key not in obj:
        issues.append(ValidationIssue(severity=severity, file=str(file), message=f"Missing required field: {key}"))
        return None
    return obj[key]


def _require_type(
    value: Any,
    expected_type: type,
    field_name: str,
    file: Path,
    issues: List[ValidationIssue],
    *,
    severity: str = "error",
) -> bool:
    if value is None:
        return False
    if not isinstance(value, expected_type):
        issues.append(
            ValidationIssue(
                severity=severity,
                file=str(file),
                message=f"Field '{field_name}' must be {expected_type.__name__}, got {type(value).__name__}",
            )
        )
        return False
    return True


def _validate_feature_item(item: Any, file: Path, issues: List[ValidationIssue]) -> Optional[str]:
    if not isinstance(item, dict):
        issues.append(ValidationIssue(severity="error", file=str(file), message="Each feature must be a mapping/object"))
        return None

    feature_id = _require_key(item, "id", file, issues)
    if _require_type(feature_id, str, "id", file, issues):
        if not _is_placeholder_value(feature_id) and not feature_id.startswith("feature_"):
            issues.append(
                ValidationIssue(
                    severity="warning",
                    file=str(file),
                    message=f"Feature id should start with 'feature_': {feature_id}",
                )
            )

    name = _require_key(item, "name", file, issues)
    _require_type(name, str, "name", file, issues)

    module = _require_key(item, "module", file, issues)
    _require_type(module, str, "module", file, issues)

    description = _require_key(item, "description", file, issues)
    _require_type(description, str, "description", file, issues)

    entry_points = _require_key(item, "entry_points", file, issues)
    if _require_type(entry_points, dict, "entry_points", file, issues):
        if not entry_points:
            issues.append(ValidationIssue(severity="warning", file=str(file), message="entry_points is empty"))

    business_rules = _require_key(item, "business_rules", file, issues)
    _require_type(business_rules, list, "business_rules", file, issues)

    if "main_scenarios" in item and item["main_scenarios"] is not None:
        if _require_type(item["main_scenarios"], list, "main_scenarios", file, issues, severity="warning"):
            for s in item["main_scenarios"]:
                if not isinstance(s, str):
                    issues.append(
                        ValidationIssue(
                            severity="warning",
                            file=str(file),
                            message="main_scenarios entries should be strings",
                        )
                    )

    if "stacks" in item and item["stacks"] is not None:
        _require_type(item["stacks"], list, "stacks", file, issues, severity="warning")

    return feature_id if isinstance(feature_id, str) else None


def _validate_workflow_item(item: Any, file: Path, issues: List[ValidationIssue]) -> Optional[str]:
    if not isinstance(item, dict):
        issues.append(ValidationIssue(severity="error", file=str(file), message="Each workflow must be a mapping/object"))
        return None

    workflow_id = _require_key(item, "id", file, issues)
    if _require_type(workflow_id, str, "id", file, issues):
        if not _is_placeholder_value(workflow_id) and not workflow_id.startswith("wf_"):
            issues.append(
                ValidationIssue(
                    severity="warning",
                    file=str(file),
                    message=f"Workflow id should start with 'wf_': {workflow_id}",
                )
            )

    name = _require_key(item, "name", file, issues)
    _require_type(name, str, "name", file, issues)

    goal = _require_key(item, "goal", file, issues)
    _require_type(goal, str, "goal", file, issues)

    trigger = _require_key(item, "trigger", file, issues)
    if _require_type(trigger, dict, "trigger", file, issues):
        _require_type(trigger.get("type"), str, "trigger.type", file, issues, severity="warning")
        _require_type(trigger.get("description"), str, "trigger.description", file, issues, severity="warning")

    preconditions = _require_key(item, "preconditions", file, issues)
    _require_type(preconditions, list, "preconditions", file, issues)

    success_criteria = _require_key(item, "success_criteria", file, issues)
    _require_type(success_criteria, list, "success_criteria", file, issues)

    path = _require_key(item, "path", file, issues)
    if _require_type(path, dict, "path", file, issues):
        happy_path = path.get("happy_path")
        if happy_path is None:
            issues.append(ValidationIssue(severity="error", file=str(file), message="Missing required field: path.happy_path"))
        else:
            _require_type(happy_path, list, "path.happy_path", file, issues)

    if "critical_failure_cases" in item and item["critical_failure_cases"] is not None:
        if _require_type(item["critical_failure_cases"], list, "critical_failure_cases", file, issues, severity="warning"):
            for s in item["critical_failure_cases"]:
                if not isinstance(s, str):
                    issues.append(
                        ValidationIssue(
                            severity="warning",
                            file=str(file),
                            message="critical_failure_cases entries should be strings",
                        )
                    )

    if "involved_features" in item and item["involved_features"] is not None:
        _require_type(item["involved_features"], list, "involved_features", file, issues, severity="warning")

    return workflow_id if isinstance(workflow_id, str) else None


def _validate_workflow_spec(
    spec_obj: Any,
    file: Path,
    issues: List[ValidationIssue],
    known_feature_ids: Set[str],
    known_task_ids: Set[str],
) -> Optional[str]:
    if not isinstance(spec_obj, dict):
        issues.append(ValidationIssue(severity="error", file=str(file), message="Workflow spec must be a mapping/object"))
        return None

    workflow_id = _require_key(spec_obj, "id", file, issues)
    if _require_type(workflow_id, str, "id", file, issues):
        if not _is_placeholder_value(workflow_id) and not workflow_id.startswith("wf_"):
            issues.append(
                ValidationIssue(
                    severity="warning",
                    file=str(file),
                    message=f"Workflow id should start with 'wf_': {workflow_id}",
                )
            )

    name = _require_key(spec_obj, "name", file, issues)
    _require_type(name, str, "name", file, issues)

    goal = _require_key(spec_obj, "goal", file, issues)
    _require_type(goal, str, "goal", file, issues)

    trigger = _require_key(spec_obj, "trigger", file, issues)
    if _require_type(trigger, dict, "trigger", file, issues):
        _require_type(trigger.get("type"), str, "trigger.type", file, issues, severity="warning")
        _require_type(trigger.get("description"), str, "trigger.description", file, issues, severity="warning")

    preconditions = _require_key(spec_obj, "preconditions", file, issues)
    _require_type(preconditions, list, "preconditions", file, issues)

    success_criteria = _require_key(spec_obj, "success_criteria", file, issues)
    _require_type(success_criteria, list, "success_criteria", file, issues)

    path = _require_key(spec_obj, "path", file, issues)
    if _require_type(path, dict, "path", file, issues):
        happy_path = path.get("happy_path")
        if happy_path is None:
            issues.append(ValidationIssue(severity="error", file=str(file), message="Missing required field: path.happy_path"))
        else:
            _require_type(happy_path, list, "path.happy_path", file, issues)

    if "critical_failure_cases" in spec_obj and spec_obj["critical_failure_cases"] is not None:
        if _require_type(spec_obj["critical_failure_cases"], list, "critical_failure_cases", file, issues, severity="warning"):
            for s in spec_obj["critical_failure_cases"]:
                if not isinstance(s, str):
                    issues.append(
                        ValidationIssue(
                            severity="warning",
                            file=str(file),
                            message="critical_failure_cases entries should be strings",
                        )
                    )

    if "involved_features" in spec_obj and spec_obj["involved_features"] is not None:
        _require_type(spec_obj["involved_features"], list, "involved_features", file, issues, severity="warning")

    steps = _require_key(spec_obj, "steps", file, issues)
    _require_type(steps, list, "steps", file, issues)

    # Validate step references
    if isinstance(steps, list):
        for st in steps:
            if not isinstance(st, dict):
                issues.append(ValidationIssue(severity="error", file=str(file), message="Each workflow step must be a mapping/object"))
                continue

            step_id = st.get("step_id")
            if not isinstance(step_id, str) or not step_id:
                issues.append(ValidationIssue(severity="error", file=str(file), message="Workflow step missing step_id"))

            feature_id = st.get("feature_id")
            if not isinstance(feature_id, str) or not feature_id:
                issues.append(ValidationIssue(severity="error", file=str(file), message=f"Workflow step '{step_id}' missing feature_id"))
            elif not _is_placeholder_value(feature_id) and known_feature_ids and feature_id not in known_feature_ids:
                issues.append(ValidationIssue(severity="warning", file=str(file), message=f"Workflow references unknown feature id: {feature_id}"))

            sys_tasks = st.get("system_tasks")
            if isinstance(sys_tasks, list) and known_task_ids:
                for t in sys_tasks:
                    if not isinstance(t, str) or not t:
                        continue
                    if _is_placeholder_value(t):
                        continue
                    tid = _canonical_task_id(t)
                    if tid not in known_task_ids:
                        issues.append(ValidationIssue(severity="warning", file=str(file), message=f"Workflow step '{step_id}' references unknown task: {t}"))

    return workflow_id if isinstance(workflow_id, str) else None


def validate_features_and_workflows(root: Path) -> Tuple[List[ValidationIssue], List[ValidationIssue]]:

    issues: List[ValidationIssue] = []
    warnings: List[ValidationIssue] = []

    feature_files, workflow_files = _discover_yaml_files(root)
    feature_indexes, workflow_indexes = _discover_index_files(root)

    known_task_ids = _load_known_task_ids(root, issues)

    feature_ids: Set[str] = set()

    for ff in feature_files:
        try:
            data = yaml.safe_load(ff.read_text(encoding="utf-8"))
        except Exception as e:
            issues.append(ValidationIssue(severity="error", file=str(ff), message=f"YAML parse error: {e}"))
            continue

        if data is None:
            issues.append(ValidationIssue(severity="error", file=str(ff), message="File is empty"))
            continue

        if not isinstance(data, list):
            issues.append(ValidationIssue(severity="error", file=str(ff), message="Root must be a list of features"))
            continue

        local_issues: List[ValidationIssue] = []
        for item in data:
            fid = _validate_feature_item(item, ff, local_issues)
            if isinstance(fid, str):
                feature_ids.add(fid)

        for it in local_issues:
            (issues if it.severity == "error" else warnings).append(it)

    workflow_ids: Set[str] = set()

    for wf in workflow_files:
        try:
            data = yaml.safe_load(wf.read_text(encoding="utf-8"))
        except Exception as e:
            issues.append(ValidationIssue(severity="error", file=str(wf), message=f"YAML parse error: {e}"))
            continue

        if data is None:
            issues.append(ValidationIssue(severity="error", file=str(wf), message="File is empty"))
            continue

        if not isinstance(data, list):
            issues.append(ValidationIssue(severity="error", file=str(wf), message="Root must be a list of workflows"))
            continue

        local_issues = []
        for item in data:
            wid = _validate_workflow_item(item, wf, local_issues)
            if isinstance(wid, str):
                workflow_ids.add(wid)

            if isinstance(item, dict) and isinstance(item.get("involved_features"), list):
                for ref in item["involved_features"]:
                    if not isinstance(ref, str):
                        continue
                    if _is_placeholder_value(ref):
                        continue
                    if ref not in feature_ids:
                        warnings.append(
                            ValidationIssue(
                                severity="warning",
                                file=str(wf),
                                message=f"Workflow references unknown feature id: {ref}",
                            )
                        )

        for it in local_issues:
            (issues if it.severity == "error" else warnings).append(it)

    # Index+spec model validation (features/features-index.yaml and workflows/workflows-index.yaml)
    for idx in feature_indexes:
        data = _load_yaml(idx, issues)
        if data is None:
            continue
        if not isinstance(data, dict):
            issues.append(ValidationIssue(severity="error", file=str(idx), message="Feature index must be a mapping/object"))
            continue

        entries = data.get("features")
        if not isinstance(entries, list):
            issues.append(ValidationIssue(severity="error", file=str(idx), message="Feature index must contain 'features' as a list"))
            continue

        for entry in entries:
            if not isinstance(entry, dict):
                issues.append(ValidationIssue(severity="error", file=str(idx), message="Each feature index entry must be a mapping/object"))
                continue
            fid = entry.get("id")
            path = entry.get("path")
            if not isinstance(fid, str) or not fid:
                issues.append(ValidationIssue(severity="error", file=str(idx), message="Feature index entry missing id"))
                continue
            if not isinstance(path, str) or not path:
                issues.append(ValidationIssue(severity="error", file=str(idx), message=f"Feature index entry '{fid}' missing path"))
                continue

            spec_path = (idx.parent / path).resolve()
            if not spec_path.exists():
                issues.append(ValidationIssue(severity="error", file=str(idx), message=f"Feature spec file not found for {fid}: {path}"))
                continue

            spec_obj = _load_yaml(spec_path, issues)
            if spec_obj is None:
                continue

            local_issues: List[ValidationIssue] = []
            spec_id = _validate_feature_spec(spec_obj, spec_path, local_issues)
            for it in local_issues:
                (issues if it.severity == "error" else warnings).append(it)

            if isinstance(spec_id, str) and not _is_placeholder_value(spec_id) and spec_id != fid:
                issues.append(ValidationIssue(severity="error", file=str(spec_path), message=f"Feature spec id '{spec_id}' does not match index id '{fid}'"))

            # dependencies validation (feature -> feature)
            deps = spec_obj.get("dependencies") if isinstance(spec_obj, dict) else None
            if isinstance(deps, list):
                for d in deps:
                    if not isinstance(d, str) or not d:
                        continue
                    if _is_placeholder_value(d):
                        continue
                    # We can only validate against index-collected feature IDs.
                    # Add now for later validation.
            feature_ids.add(fid)

    for idx in workflow_indexes:
        data = _load_yaml(idx, issues)
        if data is None:
            continue
        if not isinstance(data, dict):
            issues.append(ValidationIssue(severity="error", file=str(idx), message="Workflow index must be a mapping/object"))
            continue

        entries = data.get("workflows")
        if not isinstance(entries, list):
            issues.append(ValidationIssue(severity="error", file=str(idx), message="Workflow index must contain 'workflows' as a list"))
            continue

        for entry in entries:
            if not isinstance(entry, dict):
                issues.append(ValidationIssue(severity="error", file=str(idx), message="Each workflow index entry must be a mapping/object"))
                continue
            wid = entry.get("id")
            path = entry.get("path")
            if not isinstance(wid, str) or not wid:
                issues.append(ValidationIssue(severity="error", file=str(idx), message="Workflow index entry missing id"))
                continue
            if not isinstance(path, str) or not path:
                issues.append(ValidationIssue(severity="error", file=str(idx), message=f"Workflow index entry '{wid}' missing path"))
                continue

            spec_path = (idx.parent / path).resolve()
            if not spec_path.exists():
                issues.append(ValidationIssue(severity="error", file=str(idx), message=f"Workflow spec file not found for {wid}: {path}"))
                continue

            spec_obj = _load_yaml(spec_path, issues)
            if spec_obj is None:
                continue

            local_issues: List[ValidationIssue] = []
            spec_id = _validate_workflow_spec(
                spec_obj,
                spec_path,
                local_issues,
                known_feature_ids=feature_ids,
                known_task_ids=known_task_ids,
            )
            for it in local_issues:
                (issues if it.severity == "error" else warnings).append(it)

            if isinstance(spec_id, str) and not _is_placeholder_value(spec_id) and spec_id != wid:
                issues.append(ValidationIssue(severity="error", file=str(spec_path), message=f"Workflow spec id '{spec_id}' does not match index id '{wid}'"))

            workflow_ids.add(wid)

    if not feature_files:
        warnings.append(ValidationIssue(severity="warning", file=str(root), message="No FEATURES(.tpl).yaml files found"))
    if not workflow_files:
        warnings.append(ValidationIssue(severity="warning", file=str(root), message="No WORKFLOWS(.tpl).yaml files found"))

    if not feature_indexes:
        warnings.append(ValidationIssue(severity="warning", file=str(root), message="No features-index.yaml files found"))
    if not workflow_indexes:
        warnings.append(ValidationIssue(severity="warning", file=str(root), message="No workflows-index.yaml files found"))

    return issues, warnings


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Validate FEATURES/WORKFLOWS YAML specs")
    parser.add_argument("--root", default=".", help="Root directory to scan")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    errs, warns = validate_features_and_workflows(root)

    for w in warns:
        print(f"WARNING: {w.file}\n  {w.message}")

    for e in errs:
        print(f"ERROR: {e.file}\n  {e.message}")

    return 1 if errs else 0


if __name__ == "__main__":
    raise SystemExit(main())
