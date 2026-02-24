# Skill Creation Lessons

_Critical patterns for creating skills correctly_

## Lesson: SKILL.md Frontmatter Fields

**Date:** 2026-02-23
**Severity:** Medium

### Problem
Agents were adding curriculum fields to SKILL.md frontmatter (version, tags, category), which should only contain `name` and `description`.

### Root Cause
Confusion about SKILL.md vs curriculum.json structure.

### Solution
Only these fields in SKILL.md frontmatter:
```yaml
---
name: "Skill Name"
description: "What this skill does"
---
```

Version, tags, category go in `config.json`, not SKILL.md.

### Prevention
Always check SKILL.md frontmatter against template.

---

## Lesson: Multi-Language Examples

**Date:** 2026-02-23
**Severity:** Medium

### Problem
Skills had examples in only one language (usually JavaScript).

### Solution
Every skill must have examples in minimum 3 languages:
- JavaScript/TypeScript
- Python
- Go (or another systems language)

### Prevention
Use the multi-language example template.

---
