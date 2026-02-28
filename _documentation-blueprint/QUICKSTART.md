# Quickstart — Documentation Blueprint

Scaffold complete documentation for any project in under 2 minutes.

## For AI Agents

**Start here**: Read `AI-ENTRYPOINT.md` for step-by-step instructions.

```bash
# From AI-ENTRYPOINT.md:
python scaffold.py --name "MyProject" --tier core --stack python
```

## Prerequisites

- Python 3.8+
- Git

## Scaffold a New Project

```bash
# Interactive mode (recommended for humans)
python scaffold.py --interactive

# From config file
cp project.yaml.example project.yaml
# Edit project.yaml, then:
python scaffold.py --config project.yaml

# With CLI flags
python scaffold.py --name "MyProject" --tier core --stack python --output ./my-project
```

## Add Docs to Existing Project

```bash
# Auto-detect best tier
python scaffold.py --detect-tier --output ./my-project

# Add documentation (skips existing files)
python scaffold.py --existing --tier core --stack python --output ./my-project
```

## Validate

```bash
python validate.py ./my-project
python validate.py ./my-project --strict  # Also checks FILL_ME markers
```

## Tiers

| Tier | Files | Use When |
|------|-------|----------|
| MVP | 4 | Solo, prototype, < 1 month |
| Core | 11 | Team, 1–6 months |
| Full | 20+ | Enterprise, multi-agent, > 6 months |

## List Files for a Tier

```bash
python scaffold.py --list-files core
```

## Next Steps

1. Fill any `{{FILL_ME:...}}` markers in generated files
2. Run `python validate.py .`
3. Review AGENTS.md for behavioral rules
4. Commit: `git add . && git commit -m "docs: initialize documentation"`

---

For full specification: `DOCUMENTATION-BLUEPRINT.md`  
For AI agents: `AI-ENTRYPOINT.md`  
Stack profiles: `stacks/` directory
