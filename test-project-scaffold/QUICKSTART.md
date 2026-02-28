# Quickstart — TestProject

_Get up and running in minutes._

---

## Prerequisites

| Requirement | Version | Check | Install |
|-------------|---------|-------|---------|
| Python | 3.11+ | `python --version` | [Download](https://python.org/downloads/) |
| pip | 23+ | `pip --version` | [Download](https://pip.pypa.io/en/stable/installation/) |

---

## Installation

```bash
# Clone the repository
git clone {{FILL_ME:REPO_URL}}
cd TestProject

# Install dependencies
pip install -r requirements.txt
```

---

## First Run

```bash
# Start the application
python main.py
```

You should see the application running at http://localhost:8000.

**Success looks like:**
- Server starts without errors
- http://localhost:8000 responds with expected output
- No console warnings or errors

---

## Verify Setup

```bash
# Run tests to verify everything works
pytest
```

---

## Common Errors

### Module not found / Dependency errors
**Cause**: Dependencies not installed or outdated  
**Fix**: Run `pip install -r requirements.txt` to install/update dependencies

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
