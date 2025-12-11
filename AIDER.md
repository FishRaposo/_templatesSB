# AIDER.md - Universal Template System Guide for Aider

**Purpose**: Configuration and guidance for Aider AI pair programming in this repository.

**Version**: 1.0  
**Last Updated**: 2025-12-11

---

## 🎯 Project Context

This is the **Universal Template System** - a blueprint-driven template system with:
- 47 production tasks
- 667 template files
- 12 technology stacks
- 3 complexity tiers (MVP, Core, Enterprise)

---

## ⚡ Essential Commands

```bash
# Validate before changes
python scripts/validate-templates.py --full

# Generate project
python scripts/setup-project.py --auto --name "Name" --description "desc"

# Stack validation
python scripts/validate_stacks.py

# Task validation  
python scripts/validate_tasks.py
```

---

## 🏗️ Repository Structure

```
_templates/
├── blueprints/mins/     # Product archetype with overlays
├── tasks/               # 47 task directories + task-index.yaml
├── scripts/             # Validation and build tools
├── stacks/              # 12 technology stacks
├── tiers/               # MVP, Core, Enterprise templates
└── reference-projects/  # Generated examples
```

---

## 📋 Key Conventions

### Template Files
- Naming: `*.tpl.{ext}` (e.g., `config.tpl.py`)
- Must have header comments
- Must include placeholders like `{{PROJECT_NAME}}`

### Task Structure
```
tasks/[task-name]/
├── universal/
│   ├── code/
│   ├── docs/
│   └── tests/
└── stacks/
    ├── python/
    ├── node/
    └── [other stacks]/
```

---

## ✅ Validation Requirements

Always run before commits:
```bash
python scripts/validate-templates.py --full
# Must show: 0 errors, 0 warnings
```

---

## 📚 Documentation Files

| File | Purpose |
|------|---------|
| SYSTEM-MAP.md | Complete architecture |
| task-index.yaml | Task definitions |
| README.md | Main documentation |

---

## 🎯 Aider Tips

1. Use `/add` to include relevant files in context
2. Reference `task-index.yaml` for task patterns
3. Check `stacks/[stack]/README.md` for conventions
4. Run validation after each change session

**Status**: PRODUCTION READY ✅
