# Test Infrastructure

This directory contains all testing infrastructure for the universal template system.

## Directory Structure

```
tests/
├── validation/          # Template validation and verification
├── audit/              # System auditing and consistency checks
├── generation/         # Test generation utilities
├── unit/               # Unit tests for core functionality
└── integration/        # Integration tests
```

## Validation Scripts

### Core Validation
- `validate_templates.py` - Comprehensive template validation
- `validate-foundational-templates.py` - Foundational template validation
- `validate-tier-compliance.py` - Tier compliance checking

### Documentation Validation
- `validate_docs.py` - Documentation validation
- `validate_feature_documentation.py` - Feature documentation validation
- `validate_template_versions.py` - Version validation

### Verification
- `verify_templates.py` - Template verification
- `validation_protocol_v2.py` - Validation framework

## Audit Scripts

- `audit_stack_coverage.py` - Stack coverage auditing
- `audit_template_consistency.py` - Template consistency auditing

## Generation Scripts

- `generate_smoke_tests.py` - Smoke test generation
- `generate_tests.py` - Test generation utilities

## Usage

```bash
# Run comprehensive validation
python tests/validation/validate_templates.py --full

# Audit stack coverage
python tests/audit/audit_stack_coverage.py

# Generate smoke tests
python tests/generation/generate_smoke_tests.py
```
