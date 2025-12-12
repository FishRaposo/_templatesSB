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


def validate_features_and_workflows(root: Path) -> Tuple[List[ValidationIssue], List[ValidationIssue]]:

    issues: List[ValidationIssue] = []
    warnings: List[ValidationIssue] = []

    feature_files, workflow_files = _discover_yaml_files(root)

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

    if not feature_files:
        warnings.append(ValidationIssue(severity="warning", file=str(root), message="No FEATURES(.tpl).yaml files found"))
    if not workflow_files:
        warnings.append(ValidationIssue(severity="warning", file=str(root), message="No WORKFLOWS(.tpl).yaml files found"))

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
