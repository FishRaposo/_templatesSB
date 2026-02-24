# AGENTIC-RULES.md - Mandatory Rules for AI Coding Agents

**Purpose**: Enforced rules that all AI coding agents MUST follow when working with this repository.

**Enforcement Level**: MANDATORY - These are not suggestions, they are requirements.

**Version**: 1.0  
**Last Updated**: 2025-12-11

---

## 🚨 CRITICAL RULES (NEVER VIOLATE)

### Rule 1: Always Validate Before Committing

```bash
# MANDATORY - Run this before ANY commit
python scripts/validate-templates.py --full
```

**Expected Output**:
```
Errors: 0
Warnings: 0
All templates validated successfully.
```

**If validation fails**: FIX THE ISSUES BEFORE COMMITTING.

---

### Rule 2: Never Break Existing Templates

Before modifying any template:
1. Check if it's used by other components
2. Understand the template structure
3. Test your changes don't break generation
4. Verify all placeholders still work

---

### Rule 3: Maintain Documentation Parity

When you change code, you MUST update:
- [ ] Related README files
- [ ] Agent-specific guides if affected
- [ ] SYSTEM-MAP.md if architecture changes
- [ ] QUICKSTART.md if commands change

---

### Rule 4: Follow the Task-Based Architecture

**DO**:
- Add new functionality as tasks in `tasks/`
- Use universal templates + stack-specific implementations
- Reference `task-index.yaml` for task definitions

**DON'T**:
- Create ad-hoc file structures
- Bypass the task system
- Ignore existing patterns

---

### Rule 5: Use Blueprint-Driven Development

For new projects:
1. Start with blueprint selection
2. Apply appropriate stack(s)
3. Set tier level (MVP/Core/Enterprise)
4. Let the system generate the structure

---

## 📋 REQUIRED PATTERNS

### Template File Naming
- Code templates: `*.tpl.{ext}` (e.g., `config.tpl.py`)
- Documentation: `*.tpl.md` or `*.md`
- Configuration: `*.yaml` or `*.yml`

### Template Header Comments
Every template file MUST start with a header comment:
- Markdown: `# Title` or `<!-- Comment -->`
- Python: `"""Docstring"""` or `# Comment`
- JavaScript/TypeScript: `// Comment` or `/** JSDoc */`
- Go: `// Comment`
- Dart: `// Comment` or `/// Doc comment`
- Rust: `// Comment` or `/// Doc comment`
- SQL: `-- Comment`
- R: `# Comment`

### Template Placeholders
Use these standard placeholders:
- `{{PROJECT_NAME}}` - Project name
- `{{STACK}}` - Technology stack
- `{{TIER}}` - Complexity tier
- `{{VERSION}}` - Version number
- `{{AUTHOR}}` - Author name
- `{{DATE}}` - Current date

---

## 🔄 WORKFLOW ENFORCEMENT

### Before Starting Work

```bash
# 1. Validate current state
python scripts/validate-templates.py --full

# 2. Check you're on the right branch
git status

# 3. Understand what you're modifying
cat tasks/task-index.yaml  # For task changes
cat blueprints/[blueprint]/blueprint.meta.yaml  # For blueprint changes
```

### During Work

```bash
# Periodically validate
python scripts/validate-templates.py --full

# Check specific areas
python scripts/validate_stacks.py --detailed
python scripts/validate_tasks.py --detailed
python scripts/validate_blueprints.py --detailed
```

### Before Committing

```bash
# MANDATORY validation
python scripts/validate-templates.py --full

# Verify no broken links
grep -r "](\./" *.md | head -20

# Check for consistency
python scripts/validate_stacks.py
python scripts/validate_tasks.py
python scripts/validate_blueprints.py
```

---

## 🛡️ QUALITY GATES

### Gate 1: Template Validation
- All templates must pass validation
- No errors allowed
- Warnings should be addressed

### Gate 2: Documentation Check
- All markdown files must have titles
- Links must be valid
- Tables must be properly formatted

### Gate 3: Code Quality
- Templates must include header comments
- Code patterns must follow stack conventions
- Error handling must be included

### Gate 4: Structure Compliance
- Tasks must follow the universal/stacks pattern
- Blueprints must have BLUEPRINT.md and blueprint.meta.yaml
- Stacks must have README.md

---

## ⚠️ COMMON VIOLATIONS TO AVOID

### Violation 1: Broken Links
```markdown
# WRONG - Link to non-existent file
[See docs](./docs/nonexistent.md)

# CORRECT - Verify file exists first
[See docs](./docs/existing-file.md)
```

### Violation 2: Missing Headers
```python
# WRONG - No header comment
def my_function():
    pass

# CORRECT - Include header
# {{PROJECT_NAME}} - Description
# Purpose: What this file does
def my_function():
    pass
```

### Violation 3: Inconsistent Placeholders
```yaml
# WRONG - Mixed placeholder styles
project: ${PROJECT_NAME}
version: [[VERSION]]
author: {{AUTHOR}}

# CORRECT - Use consistent style
project: {{PROJECT_NAME}}
version: {{VERSION}}
author: {{AUTHOR}}
```

### Violation 4: Skipping Validation
```bash
# WRONG - Commit without validation
git add . && git commit -m "changes"

# CORRECT - Always validate first
python scripts/validate-templates.py --full
# Then commit only if validation passes
```

---

## 📊 METRICS TO MAINTAIN

| Metric | Required Value |
|--------|----------------|
| Validation Errors | 0 |
| Validation Warnings | 0 |
| Broken Links | 0 |
| Missing Headers | 0 |
| Structure Issues | 0 |
| Documentation Coverage | 100% |

---

## 🔧 RECOVERY PROCEDURES

### If Validation Fails

1. **Read the error messages** - They tell you exactly what's wrong
2. **Fix one issue at a time** - Don't try to fix everything at once
3. **Re-validate after each fix** - Ensure you're making progress
4. **Check related files** - Issues often cascade

### If You Break Something

1. **Don't panic** - Git has your history
2. **Identify the breaking commit** - Use git log
3. **Revert if necessary** - Or fix forward
4. **Validate after recovery** - Ensure system is healthy

---

## 🎯 SUCCESS CRITERIA

You are following these rules correctly when:

✅ `python scripts/validate-templates.py --full` shows 0 errors, 0 warnings  
✅ All documentation is current and accurate  
✅ Generated projects work out of the box  
✅ Patterns are consistent across all stacks  
✅ New features integrate with existing structure  

---

**These rules exist to maintain system quality.**

**Follow them consistently. No exceptions.**

**Status**: ENFORCED ✅
