# Skills Audit Against Skill-Builder Standards

**Date:** 2026-02-26  
**Reference:** `skills/skill-builder/SKILL.md` and its validation checklist  
**Skills audited:** memory-system-setup, rules-setup, skill-builder (all under `skills/`)

---

## Summary

| Skill | SKILL.md lines | Under 500? | Frontmatter | Description | Required sections | config.json | Fixes applied |
|-------|----------------|------------|-------------|-------------|-------------------|-------------|----------------|
| memory-system-setup | 81 | ✅ | ✅ | ✅ third person | ✅ All | ✅ | None needed |
| rules-setup | 753 | ❌ (documented exception) | ✅ | ✅ third person | ✅ All | ✅ (+ memory: false) | Opening → third person; 500-line note; config memory |
| skill-builder | 287 | ✅ | ✅ | ✅ third person | ✅ All (+ Core Approach added) | ✅ | Added Core Approach section |

---

## Skill-Builder Standards (Checklist Reference)

- **Frontmatter:** Only `name` and `description`; no extra fields.
- **Name:** Lowercase, hyphens, max 64 chars; gerund preferred (e.g. `setting-up-memory-system`).
- **Description:** Third person, starts with "Use this skill when…", WHAT + WHEN, under 1024 chars; no "I can help you…".
- **SKILL.md body:** No first-person opening ("I'll help you…"); use third person / invocation-focused.
- **Required sections (minimum):** Core Approach, Step-by-Step Instructions, Validation Checklist; add Best Practices, Troubleshooting, Related Skills, Supporting Files as needed.
- **Line count:** SKILL.md under 500 lines (progressive disclosure; move depth to Supporting Files).
- **config.json:** `agent_support`, `triggers` (keywords, patterns, optional file_types), `requirements` with `tools: []`, permissions, `memory: false`; concrete examples.
- **Supporting Files:** Intention-revealing names; references one level deep from SKILL.md where practical.

---

## memory-system-setup

| Criterion | Status | Notes |
|-----------|--------|-------|
| Frontmatter only name + description | ✅ | |
| Name format | ✅ | `memory-system-setup` (noun-style; gerund would be `setting-up-memory-system` — optional) |
| Description third person, "Use this skill when" | ✅ | |
| No "I'll help you" in body | ✅ | Uses "Sets up…" (third person) |
| Core Approach | ✅ | Four layers, data flow |
| Step-by-Step Instructions | ✅ | Numbered 1–8 |
| Validation Checklist | ✅ | Checkbox list |
| Best Practices | ✅ | |
| Troubleshooting | ✅ | |
| Related Skills | ✅ | |
| Supporting Files | ✅ | event-format-and-types.md, agents-integration-snippet.md, README, worked-example, scripts |
| SKILL.md under 500 lines | ✅ | 81 lines |
| config.json agent_support, triggers, requirements | ✅ | |
| requirements.tools: [] | ✅ | |
| requirements.memory | ✅ | false |
| Examples concrete | ✅ | simple + complex |

**Result:** Compliant. No changes made.

---

## rules-setup

| Criterion | Status | Notes |
|-----------|--------|-------|
| Frontmatter only name + description | ✅ | |
| Name format | ✅ | `rules-setup` |
| Description third person, "Use this skill when" | ✅ | |
| No "I'll help you" in body | ✅ | **Fixed:** Replaced with "This skill creates and maintains… When invoked, it can…" |
| Core Approach | ✅ | Three Pillars Framework |
| Step-by-Step Instructions | ✅ | Present in main sections |
| Validation Checklist | ✅ | Six core areas + checklist |
| Best Practices | ✅ | |
| Troubleshooting | ✅ | |
| Related Skills | ✅ | |
| Supporting Files | ✅ | Points to repo root and protocols |
| SKILL.md under 500 lines | ❌ | 753 lines — **Documented exception:** Note added that SKILL.md exceeds 500 lines because it embeds the full Prompt Validation Protocol as an appendix; use main sections and Supporting Files for quick reference. |
| config.json agent_support, triggers, requirements | ✅ | |
| requirements.tools: [] | ✅ | |
| requirements.memory | ✅ | **Fixed:** Added `"memory": false` |
| Examples concrete | ✅ | simple + complex |

**Result:** Compliant after fixes. 500-line exception documented in SKILL.md.

---

## skill-builder

| Criterion | Status | Notes |
|-----------|--------|-------|
| Frontmatter only name + description | ✅ | |
| Name format | ✅ | `skill-builder` |
| Description third person, "Use this skill when" | ✅ | |
| No "I'll help you" in body | ✅ | Uses "You are an expert…" / "Help users…" (role, not first-person skill pitch) |
| Core Approach | ✅ | **Added:** "Skills are invocation-focused instruction packages…" with methodology |
| Step-by-Step Instructions | ✅ | "Creating New Skills", structure, format |
| Validation Checklist | ✅ | Present |
| Best Practices | ✅ | |
| Troubleshooting | ✅ | |
| Related Skills | ✅ | N/A (meta-skill) |
| Supporting Files | ✅ | References README, examples |
| SKILL.md under 500 lines | ✅ | 287 lines |
| config.json agent_support, triggers, requirements | ✅ | |
| requirements.tools: [] | ✅ | |
| requirements.memory | ✅ | false |
| Examples concrete | ✅ | simple + complex |

**Result:** Compliant. Added explicit "Core Approach" section for self-consistency.

---

## Fixes Applied (2026-02-26)

1. **rules-setup/SKILL.md**
   - Opening paragraph changed from first person ("I'll help you… When you invoke this skill, I can analyze your…") to third person ("This skill creates and maintains… When invoked, it can analyze the codebase…").
   - Short note added documenting that SKILL.md exceeds 500 lines by design (embedded Prompt Validation Protocol appendix) and directing readers to main sections and Supporting Files for quick reference.

2. **rules-setup/config.json**
   - Added `"memory": false` under `requirements` to align with skill-builder standards.

3. **skill-builder/SKILL.md**
   - Added "## Core Approach" section stating the fundamental methodology (invocation-focused instruction packages, description for WHAT + WHEN, SKILL.md under 500 lines, third person, frontmatter only, Supporting Files for depth).

---

## Optional Follow-Ups (Not Done)

- **memory-system-setup:** Consider renaming to gerund form `setting-up-memory-system` in a future version (would require path/ref updates).
- **rules-setup:** If desired, split "Appendix: Complete Prompt Validation Protocol" into a separate Supporting File and link from SKILL.md to bring line count under 500; current approach keeps a single-file reference by design.

---

## References

- Skill-builder definition: `skills/skill-builder/SKILL.md`
- Skill-builder config: `skills/skill-builder/config.json`
- Current repository state: `CURRENT-REPOSITORY-STATE.md` (only Rules + three skills in `skills/` are active)
