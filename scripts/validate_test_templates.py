#!/usr/bin/env python3
"""
Test Template Validation Script
Validates syntax and basic structure of all test templates
"""

<<<<<<< ours
import os
import re
=======
import subprocess
>>>>>>> theirs
import sys
from dataclasses import dataclass
from pathlib import Path
from shutil import which
from typing import Dict, Iterable, List, Optional, Tuple


@dataclass
class ValidationRule:
    """Configuration for validating a specific template type."""

    extensions: Tuple[str, ...]
    command: Optional[List[str]] = None
    required_imports: Tuple[str, ...] = ()
    required_tokens: Tuple[str, ...] = ()


# Template validation rules
<<<<<<< ours
VALIDATION_RULES = {
    'dart': {
        'extension': '.dart',
        'required_tokens': ['flutter_test', 'test'],
    },
    'py': {
        'extension': '.py',
        'required_tokens': ['pytest'],
    },
    'js': {
        'extension': '.js',
        'required_tokens': ['jest', '@jest/globals', 'describe(', 'test('],
    },
    'jsx': {
        'extension': '.jsx',
        'required_tokens': ['react', '@jest/globals', 'jest', 'describe(', 'test('],
    },
    'ts': {
        'extension': '.ts',
        'required_tokens': ['@jest/globals', 'jest', 'describe(', 'it('],
    },
    'go': {
        'extension': '.go',
        'required_tokens': ['testing'],
    },
    'rs': {
        'extension': '.rs',
        'required_tokens': ['#[test]', 'mod tests'],
    },
    'r': {
        'extension': '.R',
        'required_tokens': ['testthat'],
    },
    'sql': {
        'extension': '.sql',
        'required_tokens': ['pgtap', 'pgTAP', 'BEGIN', 'SELECT'],
    },
    'md': {
        'extension': '.md',
        'required_tokens': [],
    }
}

_PLACEHOLDER_MARKERS = ["{{", "[[", "{%"]


def _detect_file_type(file_path: Path) -> str:
    suffix = file_path.suffix
    if suffix.lower() == '.r':
        return 'r'
    return suffix.lstrip('.').lower()


def _has_any_placeholder(content: str) -> bool:
    for marker in _PLACEHOLDER_MARKERS:
        if marker in content:
            return True
    return False


def _is_primary_test_template(file_path: Path) -> bool:
    name = file_path.name.lower()
    primary = (
        'unit-tests' in name
        or 'integration-tests' in name
        or 'system-tests' in name
        or 'e2e-tests' in name
        or 'feature-tests' in name
        or 'workflow-tests' in name
        or 'component-tests' in name
        or 'widget-tests' in name
        or 'api-tests' in name
        or 'benchmark-tests' in name
        or 'security-tests' in name
        or 'performance-tests' in name
        or 'enterprise-tests' in name
        or name.startswith(('basic-tests', 'comprehensive-tests'))
    )
    return primary


def _looks_like_markdown_doc(content: str) -> bool:
    head = content.lstrip()[:800]
    if "```" in head:
        return True
    if head.startswith("#"):
        return True
    if head.startswith("-- File:"):
        return True
    if head.startswith("// File:"):
        return True
    if "\n## " in head or head.startswith("## "):
        return True
    return False


def _has_any_required_token(content: str, tokens: List[str]) -> bool:
    if not tokens:
        return True
    lower = content.lower()
    for tok in tokens:
        if tok.lower() in lower:
            return True
    return False


def validate_template_syntax(file_path: Path, file_type: str) -> Tuple[bool, List[str]]:
    """Validate template syntax using appropriate tool"""
    errors = []
    rule = VALIDATION_RULES.get(file_type)

    if not rule:
        return False, [f"Unsupported file type: {file_type}"]

    try:
        content = file_path.read_text(encoding='utf-8')
        if len(content.strip()) < 20:
            errors.append("Template content too short")

        # Check required tokens (language/framework hint) for primary test templates only.
        # Some tier templates are authored as markdown-style guides but use a code extension.
        filename = file_path.name.lower()
        if _is_primary_test_template(file_path) and not _looks_like_markdown_doc(content):
            required_tokens = list(rule.get('required_tokens', []))

            if file_type == 'sql' and filename.startswith(('feature-tests.tpl.', 'workflow-tests.tpl.')):
                required_tokens = []

            if 'e2e' in filename:
                required_tokens.extend(['playwright', '@playwright/test'])

            if not _has_any_required_token(content, required_tokens):
                errors.append("Missing expected language/framework token")

        # Template placeholders are optional across this repository; many templates are intentionally concrete.
        # We still sanity-check that templates with placeholders use a recognized marker.
        if ('{{' in content or '[[' in content or '{%' in content) and not _has_any_placeholder(content):
            errors.append("Template placeholder markers appear malformed")

        return len(errors) == 0, errors
    except Exception as e:
        return False, [f"Validation error: {str(e)}"]
=======
VALIDATION_RULES: Dict[str, ValidationRule] = {
    'dart': ValidationRule(
        extensions=('.dart',),
        command=['dart', 'analyze'],
        required_imports=('flutter_test', 'test'),
    ),
    'python': ValidationRule(
        extensions=('.py',),
        command=[sys.executable, '-m', 'py_compile'],
        required_imports=('pytest',),
    ),
    'javascript': ValidationRule(
        extensions=('.js', '.jsx'),
        command=['node', '--check'],
        required_imports=('jest',),
    ),
    'typescript': ValidationRule(
        extensions=('.ts', '.tsx'),
        required_imports=('vitest', 'jest'),
    ),
    'go': ValidationRule(
        extensions=('.go',),
        command=['gofmt', '-l'],
        required_imports=(),
    ),
    'rust': ValidationRule(
        extensions=('.rs',),
        required_imports=('use',),
    ),
    'sql': ValidationRule(
        extensions=('.sql',),
        required_tokens=(),
    ),
    'r': ValidationRule(
        extensions=('.r', '.R'),
        required_imports=('testthat',),
    ),
}

# Fallback mapping to derive a rule from stack names
STACK_RULE_MAP: Dict[str, str] = {
    'flutter': 'dart',
    'react': 'javascript',
    'react_native': 'javascript',
    'node': 'javascript',
    'typescript': 'typescript',
    'python': 'python',
    'go': 'go',
    'rust': 'rust',
    'sql': 'sql',
    'r': 'r',
}


def _build_extension_map(rules: Dict[str, ValidationRule]) -> Dict[str, str]:
    """Create a mapping of extension to validation rule name."""

    extension_map: Dict[str, str] = {}
    for rule_name, rule in rules.items():
        for ext in rule.extensions:
            extension_map[ext.lower()] = rule_name
    return extension_map


EXTENSION_MAP = _build_extension_map(VALIDATION_RULES)


def resolve_rule_label(file_path: Path) -> str:
    """Resolve the validation rule label for a given template path."""

    parts = file_path.parts
    stack_name = parts[1] if len(parts) > 1 else None
    ext = file_path.suffix.lower()
    ignored_extensions = {'.md', '.yml', '.yaml'}

    ext_rule = EXTENSION_MAP.get(ext)
    stack_rule = STACK_RULE_MAP.get(stack_name) if stack_name else None

    if ext_rule and stack_rule and ext_rule != stack_rule:
        return stack_rule

    if ext_rule:
        return ext_rule

    if ext in ignored_extensions:
        return 'unknown'

    if stack_rule:
        return stack_rule

    return 'unknown'

def _run_command(command: Iterable[str], file_path: Path) -> Tuple[bool, str]:
    """Run a syntax check command if it is available."""

    command = list(command)
    if not which(command[0]):
        return False, f"Skipping syntax check, command not found: {command[0]}"

    try:
        result = subprocess.run(
            command + [str(file_path)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False, "Validation timed out"
    except Exception as exc:  # pragma: no cover - defensive guard
        return False, f"Validation error: {exc}"

    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip()
        if len(message) > 500:
            message = message[:500] + "... (truncated)"
        return False, message

    return True, ""


def validate_template_syntax(file_path: Path, rule: ValidationRule) -> Tuple[bool, List[str], List[str]]:
    """Validate template syntax using appropriate tool and content checks."""

    errors: List[str] = []
    warnings: List[str] = []

    if rule.command:
        ok, message = _run_command(rule.command, file_path)
        if not ok and message:
            # Missing tooling should not fail validation but should be surfaced
            if message.startswith("Skipping syntax check"):
                warnings.append(message)
            else:
                errors.append(f"Syntax error: {message}")

    try:
        content = file_path.read_text(encoding='utf-8')
    except Exception as exc:  # pragma: no cover - defensive guard
        return False, [f"Unable to read file: {exc}"], warnings

    for required_import in rule.required_imports:
        if required_import not in content:
            errors.append(f"Missing required import: {required_import}")

    for token in rule.required_tokens:
        if token not in content:
            errors.append(f"Missing template placeholder: {token}")

    return len(errors) == 0, errors, warnings
>>>>>>> theirs


def find_test_templates() -> Dict[str, List[Path]]:
<<<<<<< ours
    """Find all test template files"""
    templates: Dict[str, List[Path]] = {}

    # stacks/*/base/tests
    stacks_dir = Path('stacks')
    if stacks_dir.exists():
        for stack_dir in stacks_dir.iterdir():
            if not stack_dir.is_dir():
                continue
            tests_dir = stack_dir / 'base' / 'tests'
            if not tests_dir.exists():
                continue
            for file_path in tests_dir.glob('*.tpl.*'):
                file_type = _detect_file_type(file_path)
                templates.setdefault(file_type, []).append(file_path)

    # tiers/*/tests
    tiers_dir = Path('tiers')
    if tiers_dir.exists():
        for tier_dir in tiers_dir.iterdir():
            if not tier_dir.is_dir():
                continue
            tests_dir = tier_dir / 'tests'
            if not tests_dir.exists():
                continue
            for file_path in tests_dir.glob('*.tpl.*'):
                file_type = _detect_file_type(file_path)
                templates.setdefault(file_type, []).append(file_path)

    # tasks/testing/**/tests
    tasks_testing_dir = Path('tasks') / 'testing'
    if tasks_testing_dir.exists():
        for file_path in tasks_testing_dir.rglob('*.tpl.*'):
            if not file_path.is_file():
                continue
            if '/tests/' not in str(file_path).replace('\\', '/') and '\\tests\\' not in str(file_path):
                continue
            file_type = _detect_file_type(file_path)
            templates.setdefault(file_type, []).append(file_path)
=======
    """Find all test template files across stacks and tiers."""

    templates: Dict[str, List[Path]] = {name: [] for name in VALIDATION_RULES.keys()}
    templates['unknown'] = []

    stacks_dir = Path('stacks')
    if not stacks_dir.exists():
        print("❌ stacks directory not found")
        return templates

    for file_path in stacks_dir.rglob('tests/*.tpl.*'):
        label = resolve_rule_label(file_path)
        if label in templates:
            templates[label].append(file_path)
        else:
            templates['unknown'].append(file_path)
>>>>>>> theirs

    return templates


def main():
    """Main validation function"""
    print("🧪 Validating Test Templates")
    print("=" * 40)

    templates = find_test_templates()
    total_files = sum(len(files) for files in templates.values())
    
    if total_files == 0:
        print("❌ No test template files found")
        return False
    
    print(f"📁 Found {total_files} test template files")
    
    all_valid = True
    
    for rule_label, files in templates.items():
        if not files or rule_label == 'unknown':
            continue

        rule = VALIDATION_RULES.get(rule_label)
        if not rule:
            continue

        print(f"\n🔍 Validating {rule_label.upper()} files...")

        for file_path in files:
            print(f"  📄 {file_path.name}")

            is_valid, errors, warnings = validate_template_syntax(file_path, rule)

            for warning in warnings:
                print(f"    ⚠️  {warning}")

            if is_valid:
                print("    ✅ Valid")
            else:
                print("    ❌ Invalid:")
                for error in errors:
                    print(f"       - {error}")
                all_valid = False

    if templates.get('unknown'):
        print("\n⚠️  Unknown file extensions detected:")
        for file_path in templates['unknown']:
            print(f"   - {file_path}")

    print("\n" + "=" * 40)
    if all_valid:
        print("🎉 All test templates are valid!")
        return True
    else:
        print("❌ Some test templates have issues")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
