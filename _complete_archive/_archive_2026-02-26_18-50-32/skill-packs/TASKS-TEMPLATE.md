# {{PACK_NAME}} — Skill Verification Tasks

> **Pack**: {{PACK_ID}}
> **Skills Count**: {{SKILL_COUNT}}
> **Generated from**: `skill-packs/TASKS-TEMPLATE.md`

These tasks are used to generate the reference files in `reference-files/`. Each task names the **primary skill** and the **related skills** the agent should invoke. Use these tasks to verify skills produce correct, useful guidance.

**Pack location**: `skill-packs/{{PACK_ID}}/`

---

## How to Use This Template

1. Copy this file into `skill-packs/{{PACK_ID}}/reference-files/TASKS.md`
2. Replace all `{{PLACEHOLDERS}}` with pack-specific values
3. Write one individual task per skill (Section A)
4. Write 4–7 combined tasks that pair skills together (Section B)
5. Write a full-stack capstone task that invokes all skills (Section C)
6. Run each task and save raw outputs to `reference-files/task-outputs/`
7. Convert each output into a standalone reference file in `reference-files/`
8. Create `reference-files/INDEX.md` listing all reference files

### Placeholder Reference

| Placeholder | Description | Example |
|-------------|-------------|----------|
| `{{PACK_NAME}}` | Human-readable pack name | Programming Core |
| `{{PACK_ID}}` | Pack directory name | 1-programming-core |
| `{{SKILL_COUNT}}` | Number of skills in the pack | 12 |

### Task Design Guidelines

- **Each individual task** should test the primary skill's core concepts
- **Invoke lists** must include the primary skill + its Related Skills from SKILL.md
- **Prompts** should be specific enough to produce verifiable output, not vague
- **Combined tasks** should target realistic workflows that naturally use multiple skills
- **Output filenames** follow `task-NN-short-name.md` (zero-padded, lowercase, hyphenated)
- **Reference filenames** are descriptive standalone names (e.g., `sorting-algorithms.md`, not `task-01-algorithms.md`)
- **All tasks should require multi-language output** if the pack supports it

---

## A. Individual Skill Tasks

<!-- One section per skill. Copy this block for each skill in the pack. -->

### Task {{N}} — {{SKILL_NAME}}

**Invoke**: `{{SKILL_NAME}}`, `{{RELATED_SKILL_1}}`, `{{RELATED_SKILL_2}}`, ...

**Prompt**:
> {{A specific, concrete prompt that exercises the skill's core concepts.
> Should require the agent to demonstrate understanding, not just recite.
> Include enough detail that the output is verifiable.
> Reference related skills explicitly in the instructions where they apply.}}

**Output**: `task-{{NN}}-{{SKILL_NAME}}.md`

**Evaluation criteria**:
- [ ] Correctly applies the primary skill's core approach
- [ ] References and uses related skills where appropriate
- [ ] Produces working code (if applicable)
- [ ] Follows the skill's validation checklist (from SKILL.md)

---

<!-- Repeat the above block for each skill in the pack -->

## B. Combined Skill Tasks

<!-- 4–7 tasks that pair skills for realistic workflows. -->

### Task {{N}} — {{WORKFLOW_NAME}}

**Invoke**: `{{SKILL_A}}` + `{{SKILL_B}}` + `{{SKILL_C}}` + ...

**Prompt**:
> {{A realistic project or problem that naturally requires multiple skills.
> Structure the prompt so each numbered step maps to a specific skill:}}
> 1. **{{SKILL_A}}**: {{What this skill should contribute}}
> 2. **{{SKILL_B}}**: {{What this skill should contribute}}
> 3. **{{SKILL_C}}**: {{What this skill should contribute}}

**Output**: `task-{{NN}}-{{SHORT_NAME}}.md`

**Evaluation criteria**:
- [ ] Each invoked skill is visibly applied in the output
- [ ] Skills are integrated (not just listed side by side)
- [ ] The combined output is more useful than individual skill outputs would be

---

<!-- Repeat for each combined task -->

## C. Capstone Task

### Task {{N}} — Full Stack (All {{SKILL_COUNT}} Skills)

**Invoke**: `{{ALL_SKILLS_COMMA_SEPARATED}}`

**Prompt**:
> {{A larger project that exercises every skill in the pack.
> Number each sub-requirement and map it to a specific skill.
> This should be a design + implementation exercise.}}
> 1. **{{SKILL_1}}**: ...
> 2. **{{SKILL_2}}**: ...
> ...

**Output**: `task-{{NN}}-full-stack.md`

---

## D. Execution Notes

- **Run each task as a fresh conversation** with the agent, explicitly invoking the named skills
- **Save the agent's full response** as a raw output file in `reference-files/task-outputs/`
- **Evaluate** whether the agent correctly applied each skill's principles (check against the SKILL.md validation checklists)
- **Estimated time**: Individual tasks 5–15 min; combined tasks 15–30 min; capstone ~1 hour
- **Do not skip the capstone** — it validates that all skills integrate correctly

## E. Reference File Generation

After running all tasks, convert raw outputs into standalone reference files. This is a two-phase process:

### Phase 1: Run tasks and save raw outputs

Save every raw agent response to `reference-files/task-outputs/`:

```
reference-files/
└── task-outputs/
    ├── task-01-{{SKILL_1}}.md
    ├── task-02-{{SKILL_2}}.md
    ├── ...
    ├── task-{{N}}-{{COMBINED}}.md
    └── task-{{N}}-full-stack.md     ← capstone
```

**Keep raw outputs permanently** — they serve as history and can be re-processed.

### Phase 2: Convert each output into a standalone reference file

For **every** task output, create a corresponding reference file at the `reference-files/` level:

1. **Copy** the task output content
2. **Remove** all "task", "prompt", and "exercise" language
3. **Rename** to a descriptive standalone filename (e.g., `sorting-algorithms.md`)
4. **Rewrite the title and intro** so it reads as a self-contained guide, not a task response
5. **Preserve** all code snippets, examples, and technical content
6. **Add** a header comment: `<!-- Generated from task-outputs/task-NN-name.md -->`
7. **Save** to `reference-files/` (alongside TASKS.md and INDEX.md)

Result:

```
reference-files/
├── INDEX.md                          ← categorized index
├── TASKS.md                          ← this file
├── sorting-algorithms.md             ← standalone reference
├── hashmap-implementation.md         ← standalone reference
├── ...                               ← one per task
├── {{capstone-name}}.md              ← capstone reference
└── task-outputs/                     ← raw outputs (kept for history)
    ├── task-01-algorithms.md
    ├── task-02-data-structures.md
    └── ...
```

### Phase 3: Create INDEX.md and cross-link

1. **Create `INDEX.md`** in `reference-files/` with:
   - Table of all reference files organized by category
   - Quick reference by topic section
   - Usage guidance

2. **Update pack files** to cross-reference:
   - Add Reference Files table to `PACK.md`
   - Add Reference links to scenarios in `QUICK_REFERENCE.md`

### Reference File Naming Convention

| Task Output | Reference File |
|-------------|----------------|
| `task-01-algorithms.md` | `sorting-algorithms.md` |
| `task-02-data-structures.md` | `hashmap-implementation.md` |
| `task-NN-{{SHORT_NAME}}.md` | `{{descriptive-standalone-name}}.md` |

### Expected Reference Files

Fill in this mapping table before running tasks. It ensures every task has a planned reference file name:

| Task Output | Expected Reference File | Primary Skill(s) |
|-------------|------------------------|-------------------|
| `task-01-{{SKILL_1}}.md` | `{{descriptive-name-1}}.md` | {{SKILL_1}} |
| `task-02-{{SKILL_2}}.md` | `{{descriptive-name-2}}.md` | {{SKILL_2}} |
| ... | ... | ... |
| `task-{{N}}-full-stack.md` | `{{capstone-name}}.md` | all {{SKILL_COUNT}} skills |

## F. Results Summary

After running all tasks, fill in this table:

| Task | Primary Skill(s) | Pass/Fail | Reference File | Notes |
|------|-------------------|-----------|----------------|-------|
| 1 | {{SKILL}} | | {{ref-file}}.md | |
| 2 | {{SKILL}} | | {{ref-file}}.md | |
| ... | ... | | | |

## G. Task Count Guide

| Section | Count | Formula |
|---------|-------|---------|
| A. Individual tasks | {{SKILL_COUNT}} | One per skill |
| B. Combined tasks | 4–7 | Pair skills for realistic workflows |
| C. Capstone task | 1 | Required: uses all skills |
| **Total** | **{{SKILL_COUNT}} + 6 to {{SKILL_COUNT}} + 8** | |
