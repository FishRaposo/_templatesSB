# Prompt Validation Protocol

**All agents MUST validate user prompts before execution** to ensure clarity, completeness, security, and effectiveness. Validation is mandatory — no exceptions.

This protocol is designed to be placed in `docs/protocols/PROMPT-VALIDATION-PROTOCOL.md` by the **prompt-validation-setup** skill and referenced by agents and Rules (e.g. AGENTS.md) before executing any task.

---

## Table of Contents

1. [Validation Levels](#validation-levels)
2. [Quick Validation (2 minutes)](#quick-validation-2-minutes--must-pass-for-all-prompts)
3. [Security Patterns — BLOCKED](#security-patterns--blocked)
4. [Standard Validation (10 minutes)](#standard-validation-10-minutes--for-standard-and-strict-levels)
5. [Three-Dimension Validation Checklist](#three-dimension-validation-checklist)
6. [Type-Specific Checks](#type-specific-checks)
7. [4-Step Validation Process](#4-step-validation-process-for-strict-level)
8. [Common Validation Failures & Fixes](#common-validation-failures--fixes)
9. [Validation Log Template](#validation-log-template)
10. [Quick Emergency Validation (5-Minute Version)](#quick-validation-5-minute-emergency-version)
11. [Validation Priority Tiers](#validation-priority-tiers)
12. [Security Quick Scan](#security-quick-scan-for-any-sensitive-task)
13. [When to Escalate](#when-to-escalate)
14. [Adaptation by Project Type](#adaptation-by-project-type)
15. [Integration with Three Pillars](#integration-with-three-pillars)

---

## Validation Levels

| Level | When to Use | What It Checks |
|-------|-------------|----------------|
| **PERMISSIVE** | Simple queries, low-risk tasks | Basic syntax, obvious security issues, purpose clarity |
| **STANDARD** | Default for all tasks | Full 4-check validation, 5-dimension scoring, type-specific checks |
| **STRICT** | Security-sensitive, shared prompts, production code | Everything in Standard + adversarial testing, peer-review simulation, edge case analysis |

---

## Quick Validation (2 minutes) — MUST PASS FOR ALL PROMPTS

If ANY of these fail, stop and ask for clarification:

| Check | How to Verify | Fail If |
|-------|-------------|---------|
| **1. Purpose in first line** | Can you state what the prompt wants in one sentence? | No clear objective, multiple competing goals |
| **2. All variables defined** | Search for `{{`, `[`, `{` — is every placeholder defined or defaulted? | Undefined variables, ambiguous references |
| **3. No dangerous patterns** | Scan for injection vectors (see Security Patterns below) | Any blocked pattern found |
| **4. Output format specified** | Does the prompt say what the output should look like? | Format undefined, multiple conflicting formats |

---

## Security Patterns — BLOCKED

These 27 patterns must be flagged and rejected:

**Script Injection (7):**
- `<script>`, `</script>`, `javascript:`
- `onerror=`, `onload=`, `onclick=`, event handlers

**Command Injection (7):**
- `eval(`, `exec(`, `subprocess`, `os.system`, `os.popen`
- Backticks `` ` ``, `${...}`, `$()`

**Path Traversal (3):**
- `../`, `..\`, `/etc/passwd`, `.env`, `.git/`

**SQL Injection (3):**
- `DROP TABLE`, `UNION SELECT`, `DELETE FROM`

**System Commands (4):**
- `rm -rf /`, `sudo`, `chmod`, `chown`, `cmd.exe`, `powershell`, `registry`

**Secrets (3):**
- Hardcoded passwords, API keys, `AWS_SECRET`, `PRIVATE_KEY`

---

## Standard Validation (10 minutes) — FOR STANDARD AND STRICT LEVELS

### Step 1: Classify the Prompt Type

| Type | Signals |
|------|---------|
| **Code Generation** | "generate", "create", "implement", "write code" |
| **Code Refactoring** | "refactor", "improve", "optimize", "clean up" |
| **Documentation** | "document", "explain", "write docs", "describe" |
| **Analysis** | "analyze", "review", "audit", "find issues" |
| **Conversion** | "convert", "migrate", "transform", "translate" |
| **Testing** | "test", "verify", "validate", "check" |
| **Configuration** | "configure", "set up", "install", "deploy" |
| **General** | None of the above |

### Step 2: Score 5 Dimensions (0-1 Scale)

| Dimension | Weight | Checks |
|-----------|--------|--------|
| **Clarity** | 25% | Single interpretation? No vague words? Imperative instructions? Scope bounded? |
| **Completeness** | 25% | All variables defined? Sufficient context? Output format? Constraints? Error handling? |
| **Structure** | 15% | Logical sections? Numbered steps? No wall of text? |
| **Security** | 20% | No injection vectors? No secrets? No dangerous ops? Output boundaries set? |
| **Effectiveness** | 15% | Tested with real input? Edge cases covered? Consistent output? |

### Step 3: Calculate Grade

```
Final Score = (Clarity × 0.25) + (Completeness × 0.25) + (Structure × 0.15) + (Security × 0.20) + (Effectiveness × 0.15)

A: 0.90-1.00  → Proceed
B: 0.75-0.89  → Fix warnings, then proceed
C: 0.60-0.74  → Fix all issues before proceeding
D: 0.40-0.59  → Major rewrite needed
F: 0.00-0.39  → Do not proceed
```

**Automatic Failures** (forces at least a D):
- Any Security check scores 0
- Clarity "single interpretation" scores 0
- Completeness "all variables defined" scores 0
- 3+ zeros in any single dimension

---

## Three-Dimension Validation Checklist

Every prompt must pass these three dimensions:

**Content Validation:**
- [ ] Prompt clearly states its purpose in the first line
- [ ] All required variables are defined (no undefined placeholders)
- [ ] Context is sufficient for the task
- [ ] Output format is specified (markdown, JSON, code, etc.)
- [ ] Edge cases are considered

**Structure Validation:**
- [ ] Follows established prompt template structure
- [ ] Sections are properly organized and labeled
- [ ] Examples are provided where needed
- [ ] Instructions are sequential and logical
- [ ] Error conditions are handled

**Technical Validation:**
- [ ] All placeholders use consistent format (`{{VAR}}` not mixed `[VAR]` and `{VAR}`)
- [ ] Tool calls are properly specified (if applicable)
- [ ] File paths are correct and safe (no traversal)
- [ ] Dependencies are declared
- [ ] Security considerations are included

---

## Type-Specific Checks

After universal validation, apply these:

**Code Generation:**
- Language/framework version specified?
- Input/output types defined?
- Error handling strategy specified?
- Test expectations stated?

**Code Refactoring:**
- Behavior preservation required?
- Scope bounded (which files/modules)?
- Test requirements stated (must pass existing tests)?

**Documentation:**
- Target audience specified?
- Format specified (README, API docs, inline comments)?
- Accuracy verification method?

**Analysis:**
- Scope bounded (time range, file set, criteria)?
- Output structure defined (report format, priority levels)?
- Criteria for findings specified?
- Prioritization method defined?

**Conversion:**
- Source/target formats defined?
- Data loss policy specified?
- Edge case handling (encoding, special characters)?

**Testing:**
- Framework specified?
- Coverage expectations stated?
- Test categories defined (unit, integration, e2e)?

**Configuration:**
- Target environment specified?
- Environment variables listed?
- Secrets handling strategy defined?

---

## 4-Step Validation Process (For Strict Level)

| Step | Action | Details |
|------|--------|---------|
| **1. Initial Review** | Review prompt against all checklists | Identify missing elements, note areas for improvement |
| **2. Testing** | Test with sample inputs | Verify output format, check error handling, try edge cases |
| **3. Peer Review Simulation** | Critique as if another developer | Question ambiguous terms, challenge assumptions |
| **4. Documentation** | Document validation results | Note limitations, record test cases, log grade |

---

## Common Validation Failures & Fixes

| Failure | Problem | Fix Pattern |
|---------|---------|-------------|
| **Missing Context** | Not enough background | Add context section with all necessary information |
| **Ambiguous Instructions** | Can be interpreted multiple ways | Be specific: "IN SCOPE: X, Y. OUT OF SCOPE: Z" |
| **No Error Handling** | Doesn't specify what to do on errors | Add: "On error: log to stderr, return empty array, do not throw" |
| **Undefined Variables** | References variables that aren't defined | Define all variables in context section with examples |
| **Vague Output Format** | "Create a good README" | "Create README.md with: H1 title, one-paragraph description, installation, usage, license" |
| **Security Blind Spots** | "Set up the database" | "Set up PostgreSQL using DATABASE_URL env var. Never hardcode credentials. Use parameterized queries" |

---

## Validation Log Template

When issues are found, log them in your response:

```
[Prompt Validation: Quick/Standard/Strict]
- Level: [permissive/standard/strict]
- Type: [code-gen/refactoring/documentation/analysis/conversion/testing/configuration/general]
- Issues found: X critical, Y high, Z medium
- Grade: [A/B/C/D/F] (0.XX)
- Failed checks: [list specific checks that failed]
- Actions taken: [what you fixed or asked for clarification on]
- Status: [proceeding after fix / awaiting clarification / rejected]
```

---

## Quick Validation (5-Minute Emergency Version)

For urgent prompts when you cannot do full validation:

**2-Minute Must-Have Check:**
- [ ] Purpose is clear in first line
- [ ] All variables are defined
- [ ] Error handling mentioned
- [ ] Output format specified
- [ ] Sections are labeled
- [ ] Instructions are numbered

**Red Flags — Stop Immediately:**
- ❌ No clear purpose statement
- ❌ Undefined variables or references
- ❌ No error handling instructions
- ❌ Ambiguous or vague instructions
- ❌ Security patterns present (eval, exec, rm -rf, etc.)

**3-Minute Quick Test:**
1. Test with simple input
2. Test edge case
3. Verify output format matches expectations

---

## Validation Priority Tiers

| Priority | Requirements | Examples |
|----------|-------------|----------|
| **High (Must Pass)** | Blocking — cannot proceed without these | Clarity and specificity, complete context, proper error handling, security considerations |
| **Medium (Should Pass)** | Important but not blocking | Examples provided, consistent formatting, adequate testing, documentation complete |
| **Low (Nice to Have)** | Improvement opportunities | Optimization opportunities, alternative approaches, performance considerations |

---

## Security Quick Scan (For Any Sensitive Task)

For prompts touching user input, databases, files, or authentication:

1. **Secrets**: Are credentials from env vars only?
2. **Dangerous ops**: Are `eval`, `exec`, `rm`, `DROP` guarded or absent?
3. **User input flow**: Is input sanitized before databases/shells/templates?
4. **Output boundaries**: Could secrets or system info leak?
5. **Path safety**: Are file paths validated against a base directory?

If any fail → upgrade to Strict validation or ask for clarification.

---

## When to Escalate

Escalate to user (do not proceed) when:
- Grade is D or F after attempting fixes
- Security dimension scores 0
- Prompt contains dangerous patterns that cannot be sanitized
- Purpose is fundamentally unclear even after clarification attempt
- Multiple critical issues across dimensions

---

## Adaptation by Project Type

Customize the validation emphasis based on the project:

**API projects** — emphasize security checks:
- SQL injection vectors, credential handling, path traversal
- Input validation, authentication flows, rate limiting
- Secrets management, environment variable handling

**Library projects** — emphasize completeness:
- Input/output types, error handling strategy, edge cases
- API compatibility, versioning, breaking changes
- Documentation coverage, examples for all public methods

**Documentation projects** — emphasize clarity:
- Target audience, format, accuracy verification method
- Structure, navigation, cross-references
- Code example correctness, runnable snippets

**Configuration projects** — emphasize security:
- Environment variables, secrets handling, target environment
- Network access, firewall rules, access controls
- Audit trails, change management, rollback procedures

**Web/Frontend projects** — emphasize structure:
- Component boundaries, state management patterns
- Accessibility, responsive design, browser compatibility
- Performance budgets, bundle size, lazy loading

**Data/ML projects** — emphasize validation:
- Data quality checks, schema validation, missing values
- Model versioning, reproducibility, experiment tracking
- Bias detection, privacy preservation, ethical guidelines

---

## Integration with Three Pillars

Prompt validation is the **pre-task gate** that bookends the Three Pillars:

```
┌─────────────────────────────────────────────────────────────────┐
│                        TASK LIFECYCLE                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   PROMPT VALIDATION          EXECUTION          THREE PILLARS   │
│   ─────────────────          ─────────          ─────────────   │
│   "Is input valid?"  ──▶  DO WORK  ──▶  "Is output complete?"  │
│                                                                  │
│   • 4 must-pass checks          • Code changes    • AUTOMATING  │
│   • 27 security patterns                        • TESTING        │
│   • 5-dimension scoring                         • DOCUMENTING  │
│   • Grade A-F before proceeding                                  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

The Three Pillars verify **output quality**. Prompt validation verifies **input quality**. Together they ensure quality at both ends of every task.

---

## Maintenance

- **Review frequency**: Monthly — audit your validation habits
- **Update triggers**: When new failure patterns emerge, update Common Failures table
- **Log retention**: Keep last 10 validation logs in CHANGELOG.md for pattern analysis

---

## Archive Reference

For the original Python implementation (8 scripts, 4 specs, 3 reports):
- `_complete_archive/PROMPT-VALIDATION-SYSTEM-REFERENCE.md`

This includes the original tier compliance system, self-healing protocols, diff inspection, and template validation infrastructure that preceded this markdown-only protocol.
