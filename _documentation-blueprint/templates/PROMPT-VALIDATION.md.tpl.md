# Prompt Validation — {{PROJECT_NAME}}

_Validation protocol for all AI agent prompts. Run Quick Validation before every task._

---

## Quick Validation (4 checks — must all pass)

Run before starting any task. If any check fails, stop and ask for clarification.

| # | Check | Pass Condition |
|---|-------|---------------|
| 1 | **Purpose in first line** | Can you state the task in one sentence? |
| 2 | **All variables defined** | No undefined `{{` + `PLACEHOLDER` + `}}` or `[VARIABLE]` in the prompt? |
| 3 | **No dangerous patterns** | No script injection, command injection, path traversal, or secrets? |
| 4 | **Output format specified** | Does the prompt define what the output should look like? |

---

## Standard Validation (5-dimension scoring)

Use for any non-trivial task. Score each dimension 0–100. Weighted total must reach 70+ to proceed.

| Dimension | Weight | Score 0–100 | Weighted |
|-----------|--------|-------------|---------|
| **Clarity** — unambiguous intent, clear subject | 25% | | |
| **Completeness** — all required context provided | 25% | | |
| **Structure** — logical flow, well-organized | 15% | | |
| **Security** — no dangerous patterns | 20% | | |
| **Effectiveness** — likely to produce correct output | 15% | | |
| **Total** | 100% | — | /100 |

**Grade scale**: 90–100 = A · 80–89 = B · 70–79 = C · 60–69 = D · < 60 = F (rewrite before proceeding)

---

## Security Patterns — Always Blocked

Reject any prompt containing these patterns:

**Script injection**: `eval()` · `exec()` · `__import__()` · `subprocess` · backtick execution · `os.system()`

**Command injection**: `; rm` · `| bash` · `&& curl` · `$(...)` shell substitution · `> /dev/` redirects

**Path traversal**: `../` sequences · absolute paths to system dirs (`/etc/`, `/root/`, `C:\Windows\`)

**SQL injection**: `DROP TABLE` · `'; --` · `UNION SELECT` · unparameterized queries with user input

**Secrets in prompt**: raw API keys · passwords · private keys · tokens · connection strings

---

## Type-Specific Checklists

### Code Generation

- [ ] Language and framework specified
- [ ] Target file or module identified
- [ ] Expected function signature or interface described
- [ ] Edge cases mentioned or explicitly out of scope
- [ ] Test requirements stated

### Documentation

- [ ] Target document identified
- [ ] Audience described (human user / AI agent / both)
- [ ] Required sections listed
- [ ] Tone and length constraints stated

### Refactoring

- [ ] Specific code identified (file + function/class)
- [ ] Behavior to preserve stated explicitly
- [ ] Improvement goal clearly described
- [ ] Tests exist to verify behavior is preserved

### Analysis

- [ ] Subject of analysis clearly defined
- [ ] Questions to answer are listed
- [ ] Output format specified (table / prose / bullets)
- [ ] Scope limits defined (what not to analyze)

---

_If the `prompt-validation` skill is available in this repo, use it for the full 7-type protocol._
