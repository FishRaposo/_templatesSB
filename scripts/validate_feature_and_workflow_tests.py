from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml


@dataclass
class ValidationIssue:
    file: str
    message: str


def _load_yaml_list(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(str(path))
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if data is None:
        return []
    if not isinstance(data, list):
        raise ValueError(f"Expected list in {path}")
    out: List[Dict[str, Any]] = []
    for item in data:
        if isinstance(item, dict):
            out.append(item)
    return out


def _iter_test_files(root: Path) -> List[Path]:
    if not root.exists():
        return []

    allowed_ext = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".dart", ".rs", ".R", ".sql", ".md"}
    files: List[Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix in allowed_ext:
            files.append(p)
    return files


def _read_all_text(files: List[Path]) -> str:
    chunks: List[str] = []
    for p in files:
        try:
            chunks.append(p.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
    return "\n".join(chunks)


def _feature_requirements(feature: Dict[str, Any]) -> List[str]:
    fid = str(feature.get("id", ""))
    req: List[str] = []

    req.append(f"{fid}__happy_path")
    req.append(f"{fid}__validation")

    failure_modes = feature.get("failure_modes")
    if isinstance(failure_modes, list) and failure_modes:
        req.append(f"{fid}__failure")

    return req


def _workflow_requirements(workflow: Dict[str, Any]) -> List[str]:
    wid = str(workflow.get("id", ""))
    req: List[str] = []

    req.append(f"{wid}__happy_path")

    path = workflow.get("path")
    if isinstance(path, dict) and isinstance(path.get("alt_paths"), list) and path.get("alt_paths"):
        req.append(f"{wid}__alt_path")

    critical = workflow.get("critical_failure_cases")
    if isinstance(critical, list) and critical:
        req.append(f"{wid}__critical_failure")

    return req


def validate(
    *,
    root: Path,
    features_path: Path,
    workflows_path: Path,
    tests_dir: Path,
) -> Tuple[List[ValidationIssue], List[ValidationIssue]]:
    errors: List[ValidationIssue] = []
    warnings: List[ValidationIssue] = []

    if not features_path.exists() and features_path.name.upper() == "FEATURES.YAML":
        tpl_candidate = features_path.with_name("FEATURES.tpl.yaml")
        if tpl_candidate.exists():
            features_path = tpl_candidate

    if not workflows_path.exists() and workflows_path.name.upper() == "WORKFLOWS.YAML":
        tpl_candidate = workflows_path.with_name("WORKFLOWS.tpl.yaml")
        if tpl_candidate.exists():
            workflows_path = tpl_candidate

    features = _load_yaml_list(features_path)
    workflows = _load_yaml_list(workflows_path)

    test_files = _iter_test_files(tests_dir)
    corpus = _read_all_text(test_files)

    for f in features:
        fid = str(f.get("id", ""))
        if not fid:
            continue

        req = _feature_requirements(f)

        has_happy = req[0] in corpus
        has_validation = req[1] in corpus or f"{fid}__permission" in corpus
        needs_failure = f"{fid}__failure" in req
        has_failure = (f"{fid}__failure" in corpus) if needs_failure else True

        if not has_happy:
            errors.append(ValidationIssue(file=str(tests_dir), message=f"Missing feature happy-path test for {fid} (expected token: {fid}__happy_path)"))
        if not has_validation:
            errors.append(ValidationIssue(file=str(tests_dir), message=f"Missing feature validation/permission test for {fid} (expected token: {fid}__validation or {fid}__permission)"))
        if needs_failure and not has_failure:
            errors.append(ValidationIssue(file=str(tests_dir), message=f"Missing feature failure-mode test for {fid} (expected token: {fid}__failure)"))

    for w in workflows:
        wid = str(w.get("id", ""))
        if not wid:
            continue

        req = _workflow_requirements(w)

        has_happy = f"{wid}__happy_path" in corpus
        if not has_happy:
            errors.append(ValidationIssue(file=str(tests_dir), message=f"Missing workflow happy-path test for {wid} (expected token: {wid}__happy_path)"))

        path = w.get("path")
        if isinstance(path, dict) and isinstance(path.get("alt_paths"), list) and path.get("alt_paths"):
            if f"{wid}__alt_path" not in corpus:
                errors.append(ValidationIssue(file=str(tests_dir), message=f"Missing workflow alt-path test for {wid} (expected token: {wid}__alt_path)"))

        critical = w.get("critical_failure_cases")
        if isinstance(critical, list) and critical:
            if f"{wid}__critical_failure" not in corpus:
                errors.append(ValidationIssue(file=str(tests_dir), message=f"Missing workflow critical-failure test for {wid} (expected token: {wid}__critical_failure)"))

    if not test_files:
        warnings.append(ValidationIssue(file=str(tests_dir), message="No test files found"))

    return errors, warnings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--features", default="docs/FEATURES.yaml")
    parser.add_argument("--workflows", default="docs/WORKFLOWS.yaml")
    parser.add_argument("--tests-dir", default="tests")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    features_path = (root / args.features).resolve()
    workflows_path = (root / args.workflows).resolve()
    tests_dir = (root / args.tests_dir).resolve()

    errors, warnings = validate(root=root, features_path=features_path, workflows_path=workflows_path, tests_dir=tests_dir)

    for w in warnings:
        print(f"WARNING: {w.file}\n  {w.message}")

    for e in errors:
        print(f"ERROR: {e.file}\n  {e.message}")

    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
