# Quickstart — {{PROJECT_NAME}}

_Get up and running in minutes._

---

## Prerequisites

| Requirement | Version | Check | Install |
|-------------|---------|-------|---------|
| {{PREREQ_1}} | {{PREREQ_1_VERSION}} | `{{PREREQ_1_CHECK_COMMAND}}` | [Download]({{PREREQ_1_INSTALL_URL}}) |
| {{PREREQ_2}} | {{PREREQ_2_VERSION}} | `{{PREREQ_2_CHECK_COMMAND}}` | [Download]({{PREREQ_2_INSTALL_URL}}) |

---

## Installation

```bash
# Clone the repository
git clone {{REPO_URL}}
cd {{PROJECT_NAME}}

# Install dependencies
{{INSTALL_COMMAND}}
```

---

## First Run

```bash
# Start the application
{{RUN_COMMAND}}
```

You should see the application running at {{LOCAL_URL}}.

**Success looks like:**
- Server starts without errors
- {{LOCAL_URL}} responds with expected output
- No console warnings or errors

---

## Verify Setup

```bash
# Run tests to verify everything works
{{TEST_COMMAND}}
```

---

## Common Errors

### Module not found / Dependency errors
**Cause**: Dependencies not installed or outdated  
**Fix**: Run `{{INSTALL_COMMAND}}` to install/update dependencies

### Port already in use
**Cause**: Another process using the port  
**Fix**: Kill the existing process or change the port in configuration

### Permission denied
**Cause**: Missing execute permissions or ownership  
**Fix**: Check file permissions, run with appropriate privileges if needed

---

## Next Steps

1. Read [AGENTS.md](AGENTS.md) for project conventions
2. Check [TODO.md](TODO.md) for current tasks
3. Review [docs/SYSTEM-MAP.md](docs/SYSTEM-MAP.md) for architecture

---

_Having issues? Check [CONTRIBUTING.md](CONTRIBUTING.md) or open an issue._
