# Quickstart — {{PROJECT_NAME}}

Get from zero to running in under 5 minutes.

---

## Prerequisites

| Requirement | Version | Install |
|-------------|---------|---------|
| {{PREREQ_1}} | {{PREREQ_1_VERSION}} | {{PREREQ_1_INSTALL_URL}} |
| {{PREREQ_2}} | {{PREREQ_2_VERSION}} | {{PREREQ_2_INSTALL_URL}} |
| {{PREREQ_3}} | {{PREREQ_3_VERSION}} | {{PREREQ_3_INSTALL_URL}} |

Verify your environment:

```bash
{{PREREQ_1_CHECK_COMMAND}}
{{PREREQ_2_CHECK_COMMAND}}
```

---

## Installation

```bash
# 1. Clone the repository
git clone {{REPO_URL}}
cd {{PROJECT_NAME}}

# 2. Install dependencies
{{INSTALL_COMMAND}}

# 3. Configure environment (remove this block if the project has no .env file)
cp {{ENV_EXAMPLE_FILE}} {{ENV_FILE}}
# Edit {{ENV_FILE}} — set required values:
#   {{ENV_VAR_1}}
#   {{ENV_VAR_2}}

# 4. Initialize (database migrations, build steps, etc. — remove if not applicable)
{{INIT_COMMAND}}
```

---

## First Run

```bash
{{RUN_COMMAND}}
```

You should see:

```
{{EXPECTED_OUTPUT}}
```

Open {{LOCAL_URL}} in your browser (or use `{{CLI_VERIFY_COMMAND}}`).

---

## Running Tests

```bash
# Run all tests
{{TEST_COMMAND}}

# Run a specific test file
{{TEST_SINGLE_COMMAND}}
```

Expected: all tests pass with no errors.

---

## Common Errors

### `{{ERROR_1}}`

**Cause**: {{ERROR_1_CAUSE}}  
**Fix**: `{{ERROR_1_FIX}}`

### `{{ERROR_2}}`

**Cause**: {{ERROR_2_CAUSE}}  
**Fix**: `{{ERROR_2_FIX}}`

### Something else?

Check the [issue tracker]({{ISSUES_URL}}) or open a new issue using the bug report template.

---

## Next Steps

- Read [CONTRIBUTING.md](CONTRIBUTING.md) to start contributing
- Explore [docs/SYSTEM-MAP.md](docs/SYSTEM-MAP.md) for architecture overview
- See [CHANGELOG.md](CHANGELOG.md) for recent changes
