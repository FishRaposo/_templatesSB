# Reference Projects

> Generated reference implementations for the Universal Template System.

## Purpose

This directory contains complete, working reference implementations generated from templates. These serve as:

1. **Validation** - Proof that templates generate working code
2. **Examples** - Complete implementations for developers to learn from
3. **Testing** - Integration tests for the template system

## Structure

```
reference-projects/
├── mvp/           # MVP tier reference implementations
├── core/          # Core tier reference implementations  
└── enterprise/    # Enterprise tier reference implementations
```

## Generating Reference Projects

Use the project generation scripts:

```bash
# Generate reference project
python scripts/generate-reference-projects.py

# Or use setup-project.py for specific stack/tier
python scripts/setup-project.py --manual-stack python --manual-tier mvp
```

## Status

Reference projects are generated on-demand and may not always be present in the repository.
