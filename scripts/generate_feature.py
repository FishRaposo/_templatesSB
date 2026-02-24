from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from stack_config import get_all_stacks


def _load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _render(template_path: Path, substitutions: Dict[str, str]) -> str:
    content = template_path.read_text(encoding="utf-8")
    for k, v in substitutions.items():
        content = content.replace(k, v)
    return content


def _infer_feature_names(spec: Dict[str, Any]) -> Tuple[str, str]:
    fid = str(spec.get("id", "feature.unknown.unknown"))
    name = str(spec.get("name", "Feature"))
    return fid, name


def _discover_stack_templates(root: Path, stack: str) -> Tuple[Optional[Path], Optional[Path]]:
    code_tpl = root / "features" / "stacks" / stack / "feature-code.tpl"
    tests_tpl = root / "features" / "stacks" / stack / "feature-tests.tpl"

    # Allow any extension after .tpl
    code = next(iter(code_tpl.parent.glob("feature-code.tpl.*")), None)
    tests = next(iter(tests_tpl.parent.glob("feature-tests.tpl.*")), None)
    return code, tests


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--spec", required=True, help="Path to feature spec YAML")
    parser.add_argument("--stack", required=True)
    parser.add_argument("--out-dir", default=".")
    parser.add_argument("--code-path", default="src/features")
    parser.add_argument("--tests-path", default="tests/features")
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
        raise SystemExit("Feature spec must be a mapping/object")

    feature_id, feature_name = _infer_feature_names(spec_obj)

    code_tpl, tests_tpl = _discover_stack_templates(root, args.stack)
    if not code_tpl or not tests_tpl:
        raise SystemExit(f"Missing feature templates for stack: {args.stack}")

    substitutions = {
        "[[FEATURE_ID]]": feature_id,
        "[[FEATURE_NAME]]": feature_name,
    }

    # write code
    code_ext = code_tpl.suffix
    code_out_dir = out_dir / args.code_path
    code_out_dir.mkdir(parents=True, exist_ok=True)
    code_out = code_out_dir / f"{feature_id.replace('.', '_')}{code_ext}"
    code_out.write_text(_render(code_tpl, substitutions), encoding="utf-8")

    # write tests
    tests_ext = tests_tpl.suffix
    tests_out_dir = out_dir / args.tests_path
    tests_out_dir.mkdir(parents=True, exist_ok=True)
    tests_out = tests_out_dir / f"test_{feature_id.replace('.', '_')}{tests_ext}"
    tests_out.write_text(_render(tests_tpl, substitutions), encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
