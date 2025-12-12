from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import yaml

from stack_config import get_all_stacks


def _load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _render(template_path: Path, substitutions: Dict[str, str]) -> str:
    content = template_path.read_text(encoding="utf-8")
    for k, v in substitutions.items():
        content = content.replace(k, v)
    return content


def _infer_workflow_names(spec: Dict[str, Any]) -> Tuple[str, str]:
    wid = str(spec.get("id", "workflow.unknown.unknown"))
    name = str(spec.get("name", "Workflow"))
    return wid, name


def _discover_stack_templates(root: Path, stack: str) -> Tuple[Optional[Path], Optional[Path]]:
    orch_tpl = root / "workflows" / "stacks" / stack / "workflow-orchestrator.tpl"
    tests_tpl = root / "workflows" / "stacks" / stack / "workflow-tests.tpl"

    orch = next(iter(orch_tpl.parent.glob("workflow-orchestrator.tpl.*")), None)
    tests = next(iter(tests_tpl.parent.glob("workflow-tests.tpl.*")), None)
    return orch, tests


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--spec", required=True, help="Path to workflow spec YAML")
    parser.add_argument("--stack", required=True)
    parser.add_argument("--out-dir", default=".")
    parser.add_argument("--code-path", default="src/workflows")
    parser.add_argument("--tests-path", default="tests/workflows")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    out_dir = Path(args.out_dir).resolve()

    stacks = set(get_all_stacks())
    if args.stack not in stacks:
        raise SystemExit(f"Unknown stack: {args.stack}")

    spec_path = Path(args.spec)
    if not spec_path.is_absolute():
        spec_path = (root / spec_path).resolve()
    if not spec_path.exists():
        raise SystemExit(f"Spec not found: {spec_path}")

    spec_obj = _load_yaml(spec_path)
    if not isinstance(spec_obj, dict):
        raise SystemExit("Workflow spec must be a mapping/object")

    workflow_id, workflow_name = _infer_workflow_names(spec_obj)

    orch_tpl, tests_tpl = _discover_stack_templates(root, args.stack)
    if not orch_tpl or not tests_tpl:
        raise SystemExit(f"Missing workflow templates for stack: {args.stack}")

    substitutions = {
        "[[WORKFLOW_ID]]": workflow_id,
        "[[WORKFLOW_NAME]]": workflow_name,
    }

    orch_ext = orch_tpl.suffix
    orch_out_dir = out_dir / args.code_path
    orch_out_dir.mkdir(parents=True, exist_ok=True)
    orch_out = orch_out_dir / f"{workflow_id.replace('.', '_')}{orch_ext}"
    orch_out.write_text(_render(orch_tpl, substitutions), encoding="utf-8")

    tests_ext = tests_tpl.suffix
    tests_out_dir = out_dir / args.tests_path
    tests_out_dir.mkdir(parents=True, exist_ok=True)
    tests_out = tests_out_dir / f"test_{workflow_id.replace('.', '_')}{tests_ext}"
    tests_out.write_text(_render(tests_tpl, substitutions), encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
