# Creating Skills from Scratch: End-to-End Walkthrough

This guide walks you through creating a complete skill from zero, step by step. We'll build a real skill called "reviewing-pull-requests" as our running example.

## Overview

Creating a skill takes 6 steps:

1. **Define** — What problem does this skill solve?
2. **Name** — Choose a gerund-form name
3. **Describe** — Write the trigger-focused description
4. **Structure** — Create files and directories
5. **Write** — Fill in SKILL.md content
6. **Validate** — Check everything works

---

## Step 1: Define the Problem

Before writing anything, answer these questions:

- **What task does this skill handle?**
  → Reviewing pull requests for code quality, security, and best practices

- **When should an agent invoke this skill?**
  → When a user asks to review a PR, check code quality, or audit changes

- **What's the scope?**
  → Focused on PR review workflow — not general code review of entire codebases

- **Who uses this?**
  → Developers who want thorough, structured PR feedback

## Step 2: Choose the Name

**Rules:**
- Gerund form (verb + -ing)
- Lowercase, hyphens only
- Max 64 characters
- Specific enough to avoid collisions

**Process:**

```
❌ pr-reviewer          → Not gerund form
❌ code-review          → Not gerund form
❌ reviewing             → Too vague
✅ reviewing-pull-requests → Gerund, specific, clear
```

## Step 3: Write the Description

This is the **most critical step**. The description determines when the agent invokes the skill.

**Formula:**
```
"Use this skill when [specific triggers]. This includes [concrete use cases]."
```

**Drafting process:**

```
Draft 1: "Reviews pull requests"
→ ❌ Explains WHAT, not WHEN. Too short.

Draft 2: "Use this skill when reviewing pull requests"
→ ❌ Better, but no trigger keywords or use cases

Draft 3: "Use this skill when reviewing pull requests for code quality,
security vulnerabilities, performance issues, or best practices.
This includes analyzing PR diffs, providing structured feedback,
checking for common bugs, and suggesting improvements."
→ ✅ Trigger-focused, includes keywords, lists use cases
```

**Check:** Does this description contain words a user might actually say?
- "review this PR" ✅
- "check this pull request" ✅
- "security vulnerabilities" ✅
- "code quality" ✅

## Step 4: Create the File Structure

```bash
# Choose your platform location (this repo uses _examples/; elsewhere you may use examples/)
mkdir -p ~/.claude/skills/reviewing-pull-requests/_examples

# Create all required files
touch ~/.claude/skills/reviewing-pull-requests/SKILL.md
touch ~/.claude/skills/reviewing-pull-requests/README.md
touch ~/.claude/skills/reviewing-pull-requests/config.json
touch ~/.claude/skills/reviewing-pull-requests/_examples/basic-examples.md
```

## Step 5: Write the SKILL.md

### 5a. Start with Frontmatter

```yaml
---
name: reviewing-pull-requests
description: Use this skill when reviewing pull requests for code quality, security vulnerabilities, performance issues, or best practices. This includes analyzing PR diffs, providing structured feedback, checking for common bugs, and suggesting improvements.
---
```

### 5b. Write the Introduction and Core Approach

```markdown
# Pull Request Review

I'll help you conduct thorough, structured pull request reviews that cover quality, security, performance, and best practices.

# Core Approach

My approach focuses on:
1. Understanding the PR's purpose and scope from the description
2. Analyzing changes systematically (structure → logic → security → style)
3. Providing prioritized, actionable feedback
4. Suggesting specific improvements with code examples
```

### 5c. Write Step-by-Step Instructions

This is the meat of the skill. Be specific and actionable:

```markdown
# Step-by-Step Instructions

## 1. Understand the PR Context

First, I'll gather context about the changes:

- Read the PR title and description
- Check which files are modified and how many lines changed
- Identify the type of change (feature, bugfix, refactor, config)

**CLI Tools:**
- `gh pr view <number>` - Read PR details
- `gh pr diff <number>` - See the actual changes
- `gh pr checks <number>` - Check CI status

## 2. Review for Code Quality

Next, I'll examine the code changes:

- Readability: Are names clear? Is logic easy to follow?
- Structure: Does the code follow existing patterns?
- Complexity: Are functions/methods too long or nested?
- DRY: Is there unnecessary duplication?

## 3. Review for Security

Check for common security issues:

- Input validation and sanitization
- Authentication and authorization checks
- SQL injection, XSS, or CSRF vulnerabilities
- Hardcoded secrets or credentials
- Dependency vulnerabilities

## 4. Review for Performance

Identify potential performance issues:

- N+1 query patterns
- Missing database indexes
- Unnecessary API calls or data fetching
- Large memory allocations
- Missing pagination

## 5. Generate Structured Feedback

Organize findings by severity:

**Critical** — Must fix before merge (security, data loss, crashes)
**Major** — Should fix (bugs, performance, significant quality issues)
**Minor** — Nice to fix (style, naming, small improvements)
**Praise** — What's done well (reinforce good patterns)
```

### 5d. Add Best Practices

```markdown
# Best Practices

- Review the PR description before the code — understand intent first
- Limit reviews to under 400 lines of changes when possible
- Be specific: "rename `x` to `userCount`" not "use better names"
- Suggest, don't demand: "Consider using..." not "You must..."
- Acknowledge good work — positive feedback reinforces good patterns
- Focus on the code, not the author
- If unsure about a pattern, ask rather than assume it's wrong
```

### 5e. Add Validation Checklist

```markdown
# Validation Checklist

When reviewing a PR, verify:
- [ ] PR description explains the purpose of the changes
- [ ] All modified files have been reviewed
- [ ] No security vulnerabilities introduced
- [ ] Tests cover the new/changed behavior
- [ ] No hardcoded values that should be configurable
- [ ] Error handling is appropriate
- [ ] Performance impact is acceptable
```

### 5f. Add Troubleshooting

```markdown
# Troubleshooting

## Issue: PR is too large to review effectively

**Symptoms**: Over 500 lines changed, touching many unrelated files

**Solution**:
- Ask the author to split into smaller, focused PRs
- If not possible, review file by file in logical order
- Focus on the most critical files first (business logic > config > tests)

## Issue: Missing test coverage

**Symptoms**: New behavior has no corresponding tests

**Solution**:
- Flag as a major issue
- Suggest specific test cases that should be added
- Offer example test structure if helpful
```

### 5g. Add Related Skills

```markdown
# Supporting Files

- See `./_examples/basic-examples.md` for simple PR review examples
- See `./_examples/advanced-examples.md` for complex multi-file reviews

## Related Skills

- **algorithms** - Evaluating algorithmic choices in PRs
- **complexity-analysis** - Assessing performance implications of changes
- → **2-code-quality**: code-organization (for structural review feedback)
- → **5-error-handling**: exception-handling (for error handling review)

Remember: A good PR review is a conversation, not a verdict!
```

### 5h. Write the README.md

```markdown
# Reviewing Pull Requests

Conduct thorough, structured PR reviews covering quality, security, and performance.

## Quick Start

1. Get PR context: `gh pr view <number>`
2. Review the diff: `gh pr diff <number>`
3. Check by category: quality → security → performance → style
4. Provide prioritized, actionable feedback

## When This Skill Activates

- "Review this pull request"
- "Check PR #42 for issues"
- "Is this code safe to merge?"
- "Review the security of these changes"

## Key Commands

| Command | Purpose |
|---------|---------|
| `gh pr view <n>` | Read PR details |
| `gh pr diff <n>` | See code changes |
| `gh pr checks <n>` | Check CI status |
| `gh pr review <n>` | Submit review |

## Files in This Skill

| File | Purpose |
|------|---------|
| `SKILL.md` | Main review instructions |
| `README.md` | This quick reference |
| `config.json` | Triggers and configuration |
| `_examples/basic-examples.md` | Simple review examples |
```

### 5i. Write the config.json

```json
{
  "agent_support": {
    "claude": true,
    "roo": true,
    "generic": true
  },
  "triggers": {
    "keywords": [
      "pull request",
      "PR",
      "code review",
      "review changes",
      "merge request"
    ],
    "patterns": [
      "review this PR",
      "check this pull request",
      "is this safe to merge",
      "review PR #"
    ],
    "file_types": []
  },
  "requirements": {
    "tools": [],
    "permissions": [
      "file_read"
    ],
    "memory": false
  },
  "examples": {
    "simple": [
      {
        "query": "Review PR #42",
        "description": "Standard pull request review"
      }
    ],
    "complex": [
      {
        "query": "Review PR #42 with focus on security — this touches our auth system",
        "context": "Authentication-related changes",
        "expected_behavior": "Security-focused review with auth-specific checks"
      }
    ]
  }
}
```

## Step 6: Validate

Run through this final checklist:

### Structure
- [ ] Directory exists at correct platform path
- [ ] `SKILL.md` present with valid YAML frontmatter
- [ ] `README.md` present with quick reference
- [ ] `config.json` present with triggers
- [ ] `_examples/` directory has at least one file

### Content
- [ ] Name is gerund form, lowercase, hyphens, max 64 chars
- [ ] Description starts with "Use this skill when..."
- [ ] Description includes trigger keywords users would say
- [ ] Description is under 1024 characters
- [ ] YAML has only `name` and `description` (no model, tools, etc.)
- [ ] Has all 6 required sections: Core Approach, Step-by-Step, Best Practices, Validation, Troubleshooting, Related Skills
- [ ] Examples use real code (no TODOs or placeholders)
- [ ] Under 500 lines total
- [ ] Supporting file names are intention-revealing

### Invocation Test
Try these queries mentally — would the description match?
- "Review this PR" → ✅ matches "reviewing pull requests"
- "Check code quality" → ✅ matches "code quality"
- "Is this safe to merge?" → ✅ matches "security vulnerabilities"
- "Deploy to production" → ❌ correctly doesn't match

---

## Common Mistakes to Avoid

| Mistake | Why It's Bad | Fix |
|---------|-------------|-----|
| Description says WHAT not WHEN | Agent won't know when to invoke | Start with "Use this skill when..." |
| Noun-form name (`code-reviewer`) | Doesn't follow convention | Use gerund form (`reviewing-code`) |
| TODOs in examples | Not production-ready | Write real, working code |
| Over 500 lines | Too much context loaded | Move details to supporting files |
| Generic file names (`helpers.md`) | Not intention-revealing | Use `pr-review-checklist.md` |
| Missing Related Skills section | No cross-referencing | Add related skills within and across packs |
| Hardcoded API keys in examples | Security risk | Use environment variables |

---

## Quick Reference: Section Purposes

| Section | Purpose | Required? |
|---------|---------|-----------|
| **Core Approach** | High-level methodology (4-5 bullet points) | Yes |
| **Step-by-Step Instructions** | Detailed actionable steps | Yes |
| **Examples** | Inline usage examples (CLI-focused skills) | Optional |
| **CLI Tools to Leverage** | CLI commands relevant to the skill | Optional |
| **Node.js Patterns** | Script patterns for complex operations | Optional |
| **Best Practices** | Do's and don'ts | Yes |
| **Validation Checklist** | Verify task completion | Yes |
| **Troubleshooting** | Common issues and solutions | Yes |
| **Supporting Files** | References to other files in the skill | Optional |
| **Related Skills** | Cross-references to related skills | Yes |
| **Remember** | Key closing insight | Optional |
