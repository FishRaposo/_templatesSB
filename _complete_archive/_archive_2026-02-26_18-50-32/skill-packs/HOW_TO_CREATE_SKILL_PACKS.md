# How to Create Skill Packs

This guide provides step-by-step instructions for creating skill packs, using completed packs as reference templates:
- **`1-programming-core/`** — 12 skills, 19 reference files, multi-language examples (JS/Python/Go/Rust)
- **`2-code-quality/`** — 12 skills, 18 verification tasks, multi-language examples (JS/Python/Go)

## Overview

A skill pack is a curated collection of related agent skills that work together to address a specific domain or capability area. Each pack should contain skills that are:
- Practically useful and invocable
- Related but not overlapping
- Action-oriented (what the agent can DO)
- Free of curriculum/educational content

## Pack Structure

```
skill-packs/{pack-id}/
├── PACK.md                          # Pack overview, structure tree, reference files table
├── QUICK_REFERENCE.md              # Decision tree, scenario lookup, reference file links
├── skills/                         # All skills in this subfolder
│   └── {skill}/                    # One directory per skill
│       ├── SKILL.md                # Skill definition with multi-language examples
│       ├── config.json             # Cross-platform config (language-agnostic)
│       ├── README.md               # Quick start guide
│       └── _examples/              # Examples showing this skill in use
│           ├── basic-examples.md   # Fundamental implementations
│           └── advanced-examples.md # Complex scenarios (optional)
├── _examples/                      # Pack-level integration examples
│   └── skill-integrations.md      # Examples showing skills working together
└── _reference-files/               # Worked reference implementations
    ├── INDEX.md                    # Full index of all reference files
    ├── TASKS.md                    # Verification tasks used to generate references
    ├── *.md                        # Standalone reference guides
    └── task-outputs/               # Raw task outputs (historical)
```

### Operational Files

Each skill contains only operational files:
- **SKILL.md** - Main skill definition with comprehensive guidance and multi-language examples
- **config.json** - Cross-platform configuration with triggers (language-agnostic: `"tools": []`)
- **README.md** - Quick start guide with usage examples
- **_examples/** - Practical usage examples (markdown files only)

### Reference Files

Each pack includes an `_examples/` directory at pack level (with `skill-integrations.md`) and an `_reference-files/` directory containing:
- **Standalone reference guides** — reworked from task outputs into self-contained documents
- **INDEX.md** — categorized index of all reference files with quick-lookup sections
- **TASKS.md** — the verification prompts used to generate the references
- **task-outputs/** — raw agent outputs (kept for history, not published)

Reference files are cross-linked from `PACK.md` (by skill area table) and `QUICK_REFERENCE.md` (by scenario).

No generation scripts, utility files, or templates are included in the operational pack.

## Step 1: Define the Pack

### 1.1 Create PACK.md

Start by creating the PACK.md file with this structure:

```markdown
# {Pack Name}

**Pack ID**: {unique-pack-id}  
**Category**: {category}  
**Skills Count**: {number}  

## Overview
{Brief description of what this pack provides and its purpose}

## Skills Included

1. **skill-name** - {action-oriented description}
2. **skill-name** - {action-oriented description}
...

## When to Use This Pack

Invoke skills from this pack when you need to:
- {specific use case 1}
- {specific use case 2}
...

## Skill Relationships & Workflows

### Progression:
- **skill-a** → **skill-b** → **skill-c**

### By Task:

| Task | Primary Skills | Supporting Skills |
|------|----------------|-------------------|
| **{workflow 1}** | skill-a, skill-b | skill-c |
| **{workflow 2}** | skill-d, skill-e | skill-f |

### Cross-Pack References:
- → **{other-pack-id}**: {skill-name}

## Pack Structure

```
{pack-id}/
├── PACK.md                  ← You are here
├── QUICK_REFERENCE.md       ← Decision tree and scenario lookup
├── skills/<skill>/           ← {N} skill directories
│   ├── SKILL.md             ← Skill definition, instructions, multi-language examples
│   ├── config.json          ← Cross-platform config and trigger keywords
│   ├── README.md            ← Quick start guide
│   └── _examples/           ← Practical code examples
├── _examples/               ← Pack-level integration examples
│   └── skill-integrations.md← Cross-skill integration examples
└── _reference-files/        ← Worked reference implementations
    ├── INDEX.md             ← Full index of all reference files
    ├── TASKS.md             ← Verification prompts
    └── *.md                 ← Standalone reference guides
```

## Reference Files

The `_reference-files/` directory contains standalone implementation guides demonstrating each skill in practice.

### By Skill Area

| Skill(s) | Reference File | What It Covers |
|----------|----------------|----------------|
| {skill-a} | `{descriptive-name}.md` | {brief description} |
| {skill-b + skill-c} | `{descriptive-name}.md` | {brief description} |
| **all skills** | `{capstone-name}.md` | {comprehensive system} |

> **See also**: [`QUICK_REFERENCE.md`](QUICK_REFERENCE.md) for scenario-based skill lookup and [`_reference-files/INDEX.md`](_reference-files/INDEX.md) for the full reference file index.
```

### 1.3 Create skill-integrations.md

Create `_examples/skill-integrations.md` to show how pack skills work together:

```markdown
# {Pack Name} — Skill Integrations

Practical examples showing how multiple skills from this pack work together on real tasks.

---

## 1. {Integration Title} ({skill-a} + {skill-b} + {skill-c})

**Scenario**: {Brief description of real-world problem}

**Before** — showing problematic code:

```{language}
// {skill-a}: {technique applied}
// {skill-b}: {technique applied}

// Code example...
```

**Skills used**: {skill-a} ({technique}), {skill-b} ({technique})

---

## Quick Reference: Skill Combinations by Task

| Task | Primary Skills | Supporting Skills |
|------|----------------|-------------------|
| **{Task 1}** | {skill-a}, {skill-b} | {skill-c} |
| **{Task 2}** | {skill-d}, {skill-e} | {skill-f} |
```

### Guidelines for skill-integrations.md:

1. **Show 3-5 Real Integrations**:
   - Each demonstrating 2-4 skills working together
   - Before/after code where applicable
   - Clear explanation of which skill contributes what

2. **Practical Scenarios**:
   - Use realistic tasks (refactoring, hardening, migration)
   - Multi-language examples matching the pack's focus
   - Production-ready code patterns

3. **Quick Reference Table**:
   - End with skill combinations by task
   - Guide users on when to use which combination
   - Cross-reference to individual skill documentation

---

### Key Principles for PACK.md:

1. **No Curriculum Elements**:
   - ❌ No prerequisites, estimated time, learning paths
   - ❌ No phases, weeks, or schedules
   - ❌ No projects, assessments, or resources
   - ❌ No "after completing this pack" sections

2. **Focus on Utility**:
   - ✅ Emphasize what the agent can DO
   - ✅ Provide practical invocation examples
   - ✅ Show how skills complement each other

3. **Clear Relationships**:
   - Explain how skills work together
   - Guide users on when to use each skill
   - Show synergies between skills

### 1.2 Create QUICK_REFERENCE.md

Provide a decision tree and scenario lookup for skill selection:

```markdown
# {Pack Name} - Quick Reference Guide

This guide helps you quickly find the right skill for your {domain} needs.

> **Navigation**: [`PACK.md`](PACK.md) for full pack overview | `<skill>/SKILL.md` for skill details | [`_reference-files/INDEX.md`](_reference-files/INDEX.md) for all reference implementations

## Decision Tree

```
Need to {domain action}?
├─ Is it about {category A}?
│  ├─ {sub-problem 1} → skill-a
│  └─ {sub-problem 2} → skill-b
├─ Is it about {category B}?
│  ├─ {sub-problem 3} → skill-c
│  └─ {sub-problem 4} → skill-d
└─ Is it about {category C}?
   └─ {sub-problem 5} → skill-e
```

## Common Scenarios

### "{User says this}"
1. **Primary**: skill-a (for {reason})
2. **Supporting**: skill-b (for {reason})
3. **Optimization**: skill-c (for {reason})
- **Reference**: [`{ref-file}.md`](_reference-files/{ref-file}.md)

### "{User says this}"
1. **Primary**: skill-d (for {reason})
2. **Supporting**: skill-e (for {reason})
- **Reference**: [`{ref-file}.md`](_reference-files/{ref-file}.md)

## Skill Relationships

| Skill | Best Paired With | Use Case |
|-------|-----------------|----------|
| skill-a | skill-b | {when to pair} |
| skill-c | skill-d | {when to pair} |

## Quick Tips

- **{Tip category}**: {actionable advice}
- **{Tip category}**: {actionable advice}
```

### Key Principles for QUICK_REFERENCE.md:

- **Decision tree** covers the most common "I need to..." prompts
- **Scenarios** link to reference files (added after task execution)
- **Relationships** show which skills pair well together
- Scenarios use numbered steps: Primary → Supporting → Optimization

### 1.4 Create _examples/skill-integrations.md

Show how multiple skills from the pack work together on real tasks:

```markdown
# {Pack Name} — Skill Integration Examples

## Example 1: {Realistic Workflow Name}

**Skills used**: `skill-a` + `skill-b` + `skill-c`

### Step 1: {skill-a action}

```{language}
// Code showing skill-a applied
```

### Step 2: {skill-b action}

```{language}
// Code showing skill-b applied, building on Step 1
```

### Step 3: {skill-c action}

```{language}
// Code showing skill-c applied, integrating all steps
```

## Example 2: {Another Workflow Name}

...
```

### Key Principles for skill-integrations.md:

- Show **3–5 integration examples** covering different skill combinations
- Each example should be a **realistic workflow**, not contrived
- Code should build on previous steps (not isolated snippets)
- Include examples in **multiple languages** where applicable
- Show the **value of combining skills** — the result should be better than using skills individually

## Step 2: Design Individual Skills

### 2.1 Skill Naming Convention

- Use lowercase with hyphens: `data-structures`, `problem-solving`
- Be descriptive but concise
- Avoid generic names: prefer `api-design` over `design`

### 2.2 Create SKILL.md Template

Each skill follows this structure:

```markdown
---
name: {skill-name}
description: Use this skill when {specific scenarios where this skill helps}.
---

# {Skill Title}

I'll help you {primary benefit}. When you invoke this skill, I can guide you through the entire {process/topic}.

# Core Approach

My approach focuses on:
1. {First principle/step}
2. {Second principle/step}
3. {Third principle/step}
4. {Fourth principle/step}

# Step-by-Step Instructions

## 1. {First Major Step}

First, I'll help you {action}:

- {Specific action item 1}
- {Specific action item 2}
- {Specific action item 3}

**Examples** (show in multiple languages where applicable):

```python
# Python implementation
def example():
    pass
```

```javascript
// JavaScript implementation
const example = () => {};
```

## 2. {Second Major Step}

Next, I'll help you {action}:

- {Specific action item 1}
- {Specific action item 2}

**Common Issues:**
- **{Issue name}**: {Symptom and solution}

# Best Practices

- {Practice 1 with rationale}
- {Practice 2 with rationale}
- {Practice 3 with rationale}

# Validation Checklist

When {doing this}, verify:
- [ ] {Validation item 1}
- [ ] {Validation item 2}
- [ ] {Validation item 3}
- [ ] {Validation item 4}

# Troubleshooting

## Issue: {Common Problem 1}

**Symptoms**: {What user sees}

**Solution**:
- {Step 1}
- {Step 2}
- {Step 3}

## Issue: {Common Problem 2}

**Symptoms**: {What user sees}

**Solution**:
- {Step 1}
- {Step 2}

# Supporting Files

- See `./_examples/basic-examples.md` for {fundamental usage patterns}
- See `./README.md` for quick start and invocation examples

## Related Skills

- **{related-skill-1}** - {how it relates to this skill}
- **{related-skill-2}** - {how it relates to this skill}
- → **{pack-id}**: {skill-name} (for {specific use case})

Remember: {Key insight or principle}!
```

### Key Principles for SKILL.md:

1. **Minimal YAML Frontmatter**:
   ```yaml
   ---
   name: skill-name
   description: Use this skill when {scenarios}. I can help with {capabilities}.
   ---
   ```
   - No version, tags, or category fields (these are curriculum artifacts)

2. **Action-Oriented Content**:
   - Start with "I'll help you..."
   - Focus on what the agent DOES
   - Use active voice throughout

3. **Clear Invocation Examples**:
   - Provide 3-5 concrete examples
   - Use quotes to show exact phrases
   - Cover different use cases

4. **No Educational Content**:
   - ❌ No theory explanations
   - ❌ No history or background
   - ❌ No practice problems
   - ❌ No resources or references
   - ❌ No code examples unless essential to capability

### 2.3 Create config.json

Each skill needs a cross-platform configuration file:

```json
{
  "agent_support": {
    "claude": {"min_version": "3.0"},
    "roo": {"min_version": "1.0"},
    "cascade": {"min_version": "1.0"},
    "generic": {"requirements": ["file_access", "code_execution"]}
  },
  "triggers": {
    "keywords": [
      "{keyword-1}",
      "{keyword-2}",
      "{keyword-3}"
    ],
    "patterns": [
      "{regex-pattern-1}",
      "{regex-pattern-2}",
      "{regex-pattern-3}"
    ]
  },
  "requirements": {
    "tools": [],
    "permissions": ["file_read", "file_write"],
    "notes": "Language-agnostic skill. Works with any programming language."
  },
  "examples": {
    "simple": [
      "{Simple invocation example 1}",
      "{Simple invocation example 2}",
      "{Simple invocation example 3}"
    ],
    "complex": [
      "{Complex invocation example 1}",
      "{Complex invocation example 2}",
      "{Complex invocation example 3}"
    ]
  }
}
```

### Key Principles for config.json:

- **`tools`**: Always `[]` — skills are language-agnostic, no runtime required
- **`permissions`**: Use `["file_read", "file_write"]` as default; add `"execute"` only for skills that run CLI commands (e.g., metrics, standards)
- **`keywords`**: 8–10 trigger words that match natural user prompts
- **`patterns`**: 6–7 regex patterns for phrase matching (e.g., `"refactor.*code"`)
- **`examples`**: 3 simple + 3 complex invocation examples
- **`notes`**: Brief note about runtime requirements

### 2.4 Create README.md

Each skill needs a quick-start guide:

```markdown
# {Skill Title} Skill

This skill helps you {primary benefit in one sentence}.

## Quick Start

Invoke this skill when you need to:
- {Use case 1}
- {Use case 2}
- {Use case 3}

## Example Usage

### Basic Example
```
User: {realistic user prompt}

Agent: I'll help you {action}. {Brief description of what the agent does}...
```

### Advanced Example
```
User: {complex user prompt}

Agent: Let's {action}. I'll help you {multi-step description}...
```

## {Key Reference Table Title}

| {Column A} | {Column B} | {Column C} |
|------------|------------|------------|
| {item-1} | {value} | {description} |
| {item-2} | {value} | {description} |

## Related Skills

- **{skill-a}** - {how it relates}
- **{skill-b}** - {how it relates}
- → **{pack-id}**: {skill-name} (for {specific use case})
```

### Key Principles for README.md:

- **Quick Start** lists 3–5 concrete use cases
- **Example Usage** shows realistic user↔agent dialogue (Basic + Advanced)
- **Key reference table** varies by skill (e.g., algorithm categories, tool stack, metrics, patterns)
- Keep it under 80 lines — this is a quick-start, not the full skill definition
- Link to `./_examples/basic-examples.md` for more code

### 2.5 Create _examples/basic-examples.md

Each skill needs runnable code examples:

```markdown
# {Skill Title} — Basic Examples

## {Technique/Pattern 1 Name}

**JavaScript:**
```javascript
// ❌ Before (problem)
{code showing the problem}

// ✅ After (solution)
{code showing the skill applied}
```

**Python:**
```python
# ❌ Before
{code showing the problem}

# ✅ After
{code showing the skill applied}
```

**Go:**
```go
// ❌ Before
{code showing the problem}

// ✅ After
{code showing the skill applied}
```

## {Technique/Pattern 2 Name}

{Same before/after structure in multiple languages}

## When to Use
- "{Trigger phrase 1}"
- "{Trigger phrase 2}"
- "{Trigger phrase 3}"
```

### Key Principles for basic-examples.md:

- **Before/after format** (❌/✅) for each technique — show the transformation
- **Multi-language**: JavaScript, Python, and Go minimum; add others if relevant
- **3–5 technique sections** covering the skill's core concepts
- **"When to Use"** section at the end with trigger phrases matching config.json keywords
- Code must be **runnable** — no pseudocode or incomplete snippets
- Keep examples **focused and short** — 5–15 lines per code block

## Step 3: Create Reference Files

Reference files are worked implementation guides that demonstrate skills in practice. They are generated from verification tasks.

### 3.1 Write Verification Tasks

Use the `skill-packs/TASKS-TEMPLATE.md` to create tasks:
- One individual task per skill (tests the primary skill's core concepts)
- 4–7 combined tasks pairing skills for realistic workflows
- One capstone task using all skills (required — validates full integration)

See `skill-packs/1-programming-core/_reference-files/TASKS.md` for a complete example with 19 tasks (12 individual + 6 combined + 1 capstone). All packs use `_reference-files/` per AGENTS.md conventions.

### 3.2 Run Tasks and Save Raw Outputs

1. Run each task as a fresh agent conversation, explicitly invoking the named skills
2. Save raw outputs to `_reference-files/task-outputs/` (e.g., `task-01-algorithms.md`)
3. Keep raw outputs permanently — they serve as history and can be re-processed

### 3.3 Convert Outputs to Standalone Reference Files

For **every** task output, create a standalone reference file at the `_reference-files/` level:

1. **Copy** the task output content
2. **Remove** all "task", "prompt", and "exercise" language
3. **Rename** to a descriptive standalone filename (e.g., `sorting-algorithms.md`)
4. **Rewrite the title and intro** so it reads as a self-contained guide
5. **Preserve** all code snippets, examples, and technical content
6. **Add** a header comment: `<!-- Generated from task-outputs/task-NN-name.md -->`
7. **Save** to `_reference-files/` (alongside TASKS.md and INDEX.md)

Result structure (see `1-programming-core/reference-files/` for a complete example; new packs use `_reference-files/` per AGENTS.md):

```
_reference-files/
├── INDEX.md                          ← categorized index
├── TASKS.md                          ← verification tasks
├── sorting-algorithms.md             ← standalone reference (from task-01)
├── hashmap-implementation.md         ← standalone reference (from task-02)
├── ...                               ← one reference file per task
├── in-memory-database-engine.md      ← capstone reference (from task-19)
└── task-outputs/                     ← raw outputs (kept for history)
    ├── task-01-algorithms.md
    ├── task-02-data-structures.md
    ├── ...
    └── task-19-full-stack.md
```

### 3.4 Create _reference-files/INDEX.md

```markdown
# {Pack Name} — Reference Files Index

> **Pack**: {pack-id}
> **Reference Files**: {count}
> **Generated from**: [`TASKS.md`](TASKS.md)

## Individual Skill References

| Skill(s) | Reference File | What It Covers |
|----------|----------------|----------------|
| skill-a | [`{descriptive-name}.md`]({descriptive-name}.md) | {brief description} |
| skill-b | [`{descriptive-name}.md`]({descriptive-name}.md) | {brief description} |

## Combined Skill References

| Skills Combined | Reference File | What It Covers |
|----------------|----------------|----------------|
| skill-a + skill-b + skill-c | [`{descriptive-name}.md`]({descriptive-name}.md) | {brief description} |

## Capstone Reference

| Skills | Reference File | What It Covers |
|--------|----------------|----------------|
| **all {N} skills** | [`{capstone-name}.md`]({capstone-name}.md) | {comprehensive system description} |

## Quick Reference by Topic

- **{Topic A}**: [`{file}.md`]({file}.md), [`{file}.md`]({file}.md)
- **{Topic B}**: [`{file}.md`]({file}.md)
```

### 3.5 Cross-Link Reference Files

After reference files are generated, update pack files:

- Add **Reference Files** table to `PACK.md` mapping skills → reference files
- Add **Reference** links to scenarios in `QUICK_REFERENCE.md`
- Add **Reference Files by Skill** table to `QUICK_REFERENCE.md`

## Step 4: Ensure Quality and Consistency

### 4.1 Review Checklist

For each pack:
- [ ] PACK.md has no curriculum elements
- [ ] PACK.md includes Pack Structure tree
- [ ] PACK.md includes Reference Files table
- [ ] QUICK_REFERENCE.md provides skill selection guidance
- [ ] QUICK_REFERENCE.md links scenarios to reference files
- [ ] All skill descriptions are action-oriented
- [ ] Skills are related but not overlapping
- [ ] Each skill has clear invocation examples
- [ ] Skill relationships are explained
- [ ] _examples/skill-integrations.md shows skill combinations
- [ ] _reference-files/INDEX.md indexes all reference files
- [ ] _reference-files/ contains standalone guides (no task language)

For each skill:
- [ ] YAML frontmatter is minimal (name, description only)
- [ ] SKILL.md has Related Skills section with cross-references
- [ ] README.md provides quick start guide
- [ ] config.json is language-agnostic (`"tools": []`, has `"notes"` field)
- [ ] `_examples/basic-examples.md` exists with runnable code snippets
- [ ] Content focuses on capabilities
- [ ] No educational content
- [ ] Clear, concise language
- [ ] Practical examples provided

### 4.2 Common Pitfalls to Avoid

1. **Curriculum Creep**:
   - Don't add learning objectives
   - Don't include prerequisites
   - Don't suggest learning paths

2. **Overlapping Skills**:
   - `computational-thinking` vs `problem-solving` - too similar
   - Merge or clearly differentiate

3. **Too Abstract**:
   - Skills should be directly invocable
   - Avoid purely theoretical concepts
   - Focus on practical capabilities

4. **Too Broad**:
   - Each skill should have a clear focus
   - Break broad topics into specific skills

## Step 5: Validation

### 5.1 Test Invocation

For each skill, ask:
- Can a user clearly understand when to invoke this?
- Are the examples realistic and useful?
- Is the scope well-defined?

### 5.2 Cross-Skill Analysis

Review the pack to ensure:
- Skills complement rather than duplicate
- Coverage is comprehensive for the domain
- No critical capabilities are missing

## Example: Creating a New Pack

Let's say we're creating a "web-development" pack:

### PACK.md Structure:
```markdown
# Web Development Pack

**Pack ID**: 2-web-development  
**Category**: Web Development  
**Skills Count**: 8  

## Overview
This pack provides essential capabilities for building and maintaining web applications...

## Skills Included

1. **api-design** - Design RESTful APIs and GraphQL schemas
2. **frontend-styling** - Create responsive CSS and implement design systems
3. **database-schema** - Design efficient database schemas and relationships
4. **authentication** - Implement secure authentication and authorization
...
```

### Individual Skill Example (api-design):
```markdown
---
name: api-design
description: Use this skill when designing APIs, planning endpoints, or architecting service communication.
---

# API Design

I'll help you design clean, scalable APIs. When you invoke this skill, I can guide you through the entire API design process.

# Core Approach

My approach focuses on:
1. Understanding requirements and constraints
2. Selecting the right architectural style
3. Designing clear, consistent interfaces
4. Planning for scalability and maintainability

# Step-by-Step Instructions

## 1. Requirements Analysis

First, I'll help you understand what your API needs to do:

- Identify the resources and operations needed
- Determine client requirements and constraints
- Plan for authentication and security
- Consider rate limiting and caching needs

**Examples** (multi-language):

```python
# Python - Define API resource structure
api_resources = {
    "users": {
        "endpoints": ["/users", "/users/<id>"],
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "fields": ["id", "name", "email"]
    }
}
```

```javascript
// JavaScript - Define API resource structure
const apiResources = {
  users: {
    endpoints: ['/users', '/users/:id'],
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    fields: ['id', 'name', 'email']
  }
};
```

## 2. Architecture Design

Next, I'll help you choose and design the API architecture:

- Select REST or GraphQL based on use case
- Design endpoint structure and naming
- Plan request/response formats
- Document error handling patterns

**Common Issues:**
- **Inconsistent naming**: Use plural nouns for resources
- **Deep nesting**: Keep URL depth to 2-3 levels maximum

# Best Practices

- Use plural resource names (`/users` not `/user`)
- Implement proper HTTP status codes
- Version your API from the start
- Design for idempotency in state-changing operations

# Validation Checklist

When designing an API, verify:
- [ ] All endpoints follow consistent naming conventions
- [ ] HTTP methods are used appropriately
- [ ] Error responses have consistent format
- [ ] Rate limiting is considered
- [ ] Documentation is complete
- [ ] Security measures are implemented

# Troubleshooting

## Issue: API Consumers Confused by Endpoints

**Symptoms**: Clients report difficulty understanding the API structure

**Solution**:
- Add comprehensive documentation
- Use descriptive endpoint names
- Provide clear examples
- Implement OpenAPI/Swagger specs

## Issue: Poor Performance Under Load

**Symptoms**: Response times degrade with increased traffic

**Solution**:
- Implement caching strategies
- Add database indexing
- Use pagination for large collections
- Consider GraphQL for complex queries

# Supporting Files

- See `./_examples/basic-examples.md` for common API design patterns
- See `./README.md` for quick start and invocation examples

## Related Skills

- **database-schema** - Design underlying data structures
- **authentication** - Secure API endpoints
- **frontend-styling** - Build interfaces that consume the API
- → **5-architecture-fundamentals**: architecture-patterns (for API architecture)

Remember: A good API is like a good waiter - it anticipates needs, handles requests efficiently, and never spills the soup!
```

## Best Practices Summary

1. **Always be practical**: Focus on what users need help with
2. **Be specific, not general**: Clear scope for each skill
3. **Avoid teaching**: These are skills, not lessons
4. **Show, don't tell**: Use examples instead of explanations
5. **Stay focused**: Each skill does one thing well
6. **Think synergy**: Skills should work together naturally

## Next Steps

1. Define your pack's domain and purpose
2. Brainstorm related skills (aim for 5-12)
3. Create PACK.md following the template (include Pack Structure tree)
4. Create QUICK_REFERENCE.md for skill selection
5. Create `_examples/skill-integrations.md` showing skill combinations
6. For each skill:
   - Create SKILL.md with multi-language examples
   - Create config.json (language-agnostic: `"tools": []`)
   - Create README.md for quick start
   - Create `_examples/basic-examples.md` with runnable code snippets (required)
7. Write verification tasks using `skill-packs/TASKS-TEMPLATE.md` (individual + combined + capstone)
8. Run all tasks, save raw outputs to `_reference-files/task-outputs/`
9. Convert each output into a standalone reference file in `_reference-files/`
10. Create `_reference-files/INDEX.md`
11. Cross-link reference files from PACK.md and QUICK_REFERENCE.md
12. Review for curriculum content and remove
13. Validate invocation scenarios
14. Refine based on practical usage

Remember: The goal is to create practical, invocable skills that help users accomplish real tasks, not to teach them concepts.
