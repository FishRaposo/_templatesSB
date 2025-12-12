from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml

from stack_config import get_all_stacks


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


def _resolve_features_workflows_paths(root: Path, features_rel: str, workflows_rel: str) -> Tuple[Path, Path]:
    features_path = (root / features_rel).resolve()
    workflows_path = (root / workflows_rel).resolve()

    if not features_path.exists() and features_path.name.upper() == "FEATURES.YAML":
        tpl_candidate = features_path.with_name("FEATURES.tpl.yaml")
        if tpl_candidate.exists():
            features_path = tpl_candidate

    if not workflows_path.exists() and workflows_path.name.upper() == "WORKFLOWS.YAML":
        tpl_candidate = workflows_path.with_name("WORKFLOWS.tpl.yaml")
        if tpl_candidate.exists():
            workflows_path = tpl_candidate

    return features_path, workflows_path


def _feature_tokens(feature: Dict[str, Any]) -> List[str]:
    fid = str(feature.get("id", ""))
    if not fid:
        return []

    tokens: List[str] = [f"{fid}__happy_path", f"{fid}__validation"]

    failure_modes = feature.get("failure_modes")
    if isinstance(failure_modes, list) and failure_modes:
        tokens.append(f"{fid}__failure")

    return tokens


def _workflow_tokens(workflow: Dict[str, Any]) -> List[str]:
    wid = str(workflow.get("id", ""))
    if not wid:
        return []

    tokens: List[str] = [f"{wid}__happy_path"]

    path = workflow.get("path")
    if isinstance(path, dict) and isinstance(path.get("alt_paths"), list) and path.get("alt_paths"):
        tokens.append(f"{wid}__alt_path")

    critical = workflow.get("critical_failure_cases")
    if isinstance(critical, list) and critical:
        tokens.append(f"{wid}__critical_failure")

    return tokens


def _camelize(value: str) -> str:
    parts: List[str] = []
    buf: List[str] = []
    for ch in value:
        if ch.isalnum():
            buf.append(ch)
        else:
            if buf:
                parts.append("".join(buf))
                buf = []
    if buf:
        parts.append("".join(buf))

    out = "".join(p[:1].upper() + p[1:] for p in parts if p)
    return out or "X"


def _render_feature_tests(stack: str, features: List[Dict[str, Any]]) -> str:
    tokens: List[str] = []
    for f in features:
        tokens.extend(_feature_tokens(f))

    if stack == "python":
        lines = ["import pytest", "", ""]
        for tok in tokens:
            lines.append(f"def test_{tok}():")
            lines.append('    pytest.skip("TODO")')
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    if stack == "go":
        grouped: Dict[str, List[str]] = {}
        for tok in tokens:
            base = tok.split("__", 1)[0]
            grouped.setdefault(base, []).append(tok)

        lines = ["package tests", "", 'import "testing"', ""]
        for fid, toks in grouped.items():
            fn = f"Test{_camelize(fid.replace('feature_', 'Feature_'))}"
            lines.append(f"func {fn}(t *testing.T) {{")
            for tok in toks:
                lines.append(f'\tt.Run("{tok}", func(t *testing.T) {{ t.Skip("TODO") }})')
            lines.append("}")
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    if stack in {"node"}:
        lines = ["const { describe, test } = require('@jest/globals');", "", "describe('Feature Tests', () => {" ]
        for tok in tokens:
            lines.append(f"  test('{tok}', () => {{")
            lines.append("    throw new Error('TODO');")
            lines.append("  });")
            lines.append("")
        if lines and lines[-1] == "":
            lines.pop()
        lines.append("});")
        return "\n".join(lines).rstrip() + "\n"

    if stack in {"react", "react_native", "next"}:
        lines = ["import { describe, test } from '@jest/globals';", "", "describe('Feature Tests', () => {" ]
        for tok in tokens:
            lines.append(f"  test('{tok}', () => {{")
            lines.append("    throw new Error('TODO');")
            lines.append("  });")
            lines.append("")
        if lines and lines[-1] == "":
            lines.pop()
        lines.append("});")
        return "\n".join(lines).rstrip() + "\n"

    if stack == "typescript":
        lines = ["import { describe, it } from '@jest/globals';", "", "describe('Feature Tests', () => {" ]
        for tok in tokens:
            lines.append(f"  it('{tok}', () => {{")
            lines.append("    throw new Error('TODO');")
            lines.append("  });")
            lines.append("")
        if lines and lines[-1] == "":
            lines.pop()
        lines.append("});")
        return "\n".join(lines).rstrip() + "\n"

    if stack == "flutter":
        lines = ["import 'package:flutter_test/flutter_test.dart';", "", "void main() {", "  group('Feature Tests', () {" ]
        for tok in tokens:
            lines.append(f"    test('{tok}', () {{")
            lines.append("      throw UnimplementedError('TODO');")
            lines.append("    });")
            lines.append("")
        if lines and lines[-1] == "":
            lines.pop()
        lines.extend(["  });", "}"])
        return "\n".join(lines).rstrip() + "\n"

    if stack == "r":
        lines: List[str] = []
        for tok in tokens:
            lines.append(f"testthat::test_that('{tok}', {{")
            lines.append("  testthat::skip('TODO')")
            lines.append("})")
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    if stack == "sql":
        lines = []
        for tok in tokens:
            lines.append(f"-- {tok}")
        return "\n".join(lines).rstrip() + "\n"

    if stack == "rust":
        lines = ["#[cfg(test)]", "mod tests {", ""]
        for tok in tokens:
            lines.append("    #[test]")
            lines.append(f"    fn {tok}() {{")
            lines.append("        panic!(\"TODO\");")
            lines.append("    }")
            lines.append("")
        if lines and lines[-1] == "":
            lines.pop()
        lines.append("}")
        return "\n".join(lines).rstrip() + "\n"

    raise ValueError(f"Unsupported stack: {stack}")


def _render_workflow_tests(stack: str, workflows: List[Dict[str, Any]]) -> str:
    tokens: List[str] = []
    for w in workflows:
        tokens.extend(_workflow_tokens(w))

    if stack == "python":
        lines = ["import pytest", "", ""]
        for tok in tokens:
            lines.append(f"def test_{tok}():")
            lines.append('    pytest.skip("TODO")')
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    if stack == "go":
        grouped: Dict[str, List[str]] = {}
        for tok in tokens:
            base = tok.split("__", 1)[0]
            grouped.setdefault(base, []).append(tok)

        lines = ["package tests", "", 'import "testing"', ""]
        for wid, toks in grouped.items():
            fn = f"Test{_camelize(wid.replace('wf_', 'Workflow_'))}"
            lines.append(f"func {fn}(t *testing.T) {{")
            for tok in toks:
                lines.append(f'\tt.Run("{tok}", func(t *testing.T) {{ t.Skip("TODO") }})')
            lines.append("}")
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    if stack in {"node"}:
        lines = ["const { describe, test } = require('@jest/globals');", "", "describe('Workflow Tests', () => {" ]
        for tok in tokens:
            lines.append(f"  test('{tok}', () => {{")
            lines.append("    throw new Error('TODO');")
            lines.append("  });")
            lines.append("")
        if lines and lines[-1] == "":
            lines.pop()
        lines.append("});")
        return "\n".join(lines).rstrip() + "\n"

    if stack in {"react", "react_native", "next"}:
        lines = ["import { describe, test } from '@jest/globals';", "", "describe('Workflow Tests', () => {" ]
        for tok in tokens:
            lines.append(f"  test('{tok}', () => {{")
            lines.append("    throw new Error('TODO');")
            lines.append("  });")
            lines.append("")
        if lines and lines[-1] == "":
            lines.pop()
        lines.append("});")
        return "\n".join(lines).rstrip() + "\n"

    if stack == "typescript":
        lines = ["import { describe, it } from '@jest/globals';", "", "describe('Workflow Tests', () => {" ]
        for tok in tokens:
            lines.append(f"  it('{tok}', () => {{")
            lines.append("    throw new Error('TODO');")
            lines.append("  });")
            lines.append("")
        if lines and lines[-1] == "":
            lines.pop()
        lines.append("});")
        return "\n".join(lines).rstrip() + "\n"

    if stack == "flutter":
        lines = ["import 'package:flutter_test/flutter_test.dart';", "", "void main() {", "  group('Workflow Tests', () {" ]
        for tok in tokens:
            lines.append(f"    test('{tok}', () {{")
            lines.append("      throw UnimplementedError('TODO');")
            lines.append("    });")
            lines.append("")
        if lines and lines[-1] == "":
            lines.pop()
        lines.extend(["  });", "}"])
        return "\n".join(lines).rstrip() + "\n"

    if stack == "r":
        lines: List[str] = []
        for tok in tokens:
            lines.append(f"testthat::test_that('{tok}', {{")
            lines.append("  testthat::skip('TODO')")
            lines.append("})")
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    if stack == "sql":
        lines = []
        for tok in tokens:
            lines.append(f"-- {tok}")
        return "\n".join(lines).rstrip() + "\n"

    if stack == "rust":
        lines = ["#[cfg(test)]", "mod tests {", ""]
        for tok in tokens:
            lines.append("    #[test]")
            lines.append(f"    fn {tok}() {{")
            lines.append("        panic!(\"TODO\");")
            lines.append("    }")
            lines.append("")
        if lines and lines[-1] == "":
            lines.pop()
        lines.append("}")
        return "\n".join(lines).rstrip() + "\n"

    raise ValueError(f"Unsupported stack: {stack}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--stack", required=True)
    parser.add_argument("--features", default="docs/FEATURES.yaml")
    parser.add_argument("--workflows", default="docs/WORKFLOWS.yaml")
    parser.add_argument("--tests-dir", default="tests")
    parser.add_argument("--inplace", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    root = Path(args.root).resolve()

    known_stacks = set(get_all_stacks())
    if args.stack not in known_stacks:
        raise SystemExit(f"Unknown stack: {args.stack}")

    if args.stack == "generic":
        raise SystemExit("generic stack does not have code test generation")

    features_path, workflows_path = _resolve_features_workflows_paths(root, args.features, args.workflows)

    features = _load_yaml_list(features_path)
    workflows = _load_yaml_list(workflows_path)

    tests_dir = (root / args.tests_dir).resolve()
    tests_dir.mkdir(parents=True, exist_ok=True)

    ext_map = {
        "python": "py",
        "node": "js",
        "go": "go",
        "flutter": "dart",
        "react": "jsx",
        "react_native": "jsx",
        "next": "jsx",
        "typescript": "ts",
        "r": "R",
        "sql": "sql",
        "rust": "rs",
    }

    if args.stack not in ext_map:
        raise SystemExit(f"No extension mapping for stack: {args.stack}")

    ext = ext_map[args.stack]

    feature_name = f"feature-tests.{ext}" if args.inplace else f"feature-tests.generated.{ext}"
    workflow_name = f"workflow-tests.{ext}" if args.inplace else f"workflow-tests.generated.{ext}"

    feature_out = tests_dir / feature_name
    workflow_out = tests_dir / workflow_name

    feature_content = _render_feature_tests(args.stack, features)
    workflow_content = _render_workflow_tests(args.stack, workflows)

    if args.dry_run:
        print(str(feature_out))
        print(str(workflow_out))
        return 0

    feature_out.write_text(feature_content, encoding="utf-8")
    workflow_out.write_text(workflow_content, encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
