# Security Policy — _templatesSB

## Supported Versions

| Scope | Supported |
|-------|-----------|
| Current docs and skills | ✅ Active (Rules, Protocols, nine skills in `.agents/skills/`) |
| Archived content (`_complete_archive/`) | ⚠️ Read-only reference; no security fixes guaranteed |
| Memory system (`.memory/`, `docs/protocols/`) | ✅ Active when in use |

This repository is primarily documentation and template/skill definitions. No runtime services or credentials are executed from this repo; security-sensitive use is in projects that adopt these templates.

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Report privately:

- **GitHub**: Use the repository's **Security** tab → "Report a vulnerability" (if enabled).
- **Otherwise**: Contact the repository owner or maintainers through a private channel (e.g. email or private message) listed in the repo profile or CONTRIBUTING.md.

### What to Include

- Description of the vulnerability and its potential impact (e.g. unsafe prompt patterns, script injection in a template).
- Affected files or template types (e.g. a skill, a protocol, a blueprint template).
- Step-by-step reproduction if applicable.
- Suggested fix (optional but appreciated).

## Response Timeline

| Stage | Timeline |
|-------|----------|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 5 business days |
| Fix or documentation update | Within 30 days for critical; 90 days for moderate |
| Public disclosure | After fix is released and a reasonable delay has passed |

## Security Best Practices for Users

- When using skills or protocols in other projects, install protocol files via the official skills (e.g. prompt-validation-setup, memory-system-setup) rather than copying ad hoc.
- Follow the **Prompt Validation Protocol** (`docs/protocols/PROMPT-VALIDATION-PROTOCOL.md`) before executing user or external prompts.
- Do not commit secrets, API keys, or credentials; use environment variables or secret managers in projects that consume these templates.

---

_Security-related events in `CHANGELOG.md` use tag `security` and type `fix`._
