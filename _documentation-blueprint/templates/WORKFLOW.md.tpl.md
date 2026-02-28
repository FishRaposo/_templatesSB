# Development Workflow — {{PROJECT_NAME}}

_Branching strategy, release process, and team conventions_

---

## Branching Strategy

```
main          ← stable, always deployable, protected
feature/name  ← new features (branch from main)
fix/name      ← bug fixes (branch from main)
docs/name     ← documentation-only changes
release/x.y   ← release preparation
```

**Rules**:
- Never commit directly to `main`
- All work goes through a PR with at least one approval
- Squash and merge to keep `main` history linear
- Tag releases on `main` with `vMAJOR.MINOR.PATCH`

---

## Development Cycle

### Starting Work

```bash
# Always branch from the latest main
git checkout main
git pull origin main
git checkout -b feature/your-feature-name
```

### During Development

- Commit early and often with conventional commit messages
- Run tests before each commit: `{{TEST_COMMAND}}`
- Append decisions to `CHANGELOG.md` as you work

### Opening a Pull Request

1. Push your branch: `git push origin feature/your-feature-name`
2. Open PR against `main` using the PR template
3. Complete the Three Pillars checklist before marking ready
4. Request review from relevant team members

### Merging

- At least one approval required
- All CI checks must pass
- Resolve all review comments before merging
- Squash and merge — delete branch after merge

---

## Release Process

### Creating a Release

```bash
git checkout main && git pull
git checkout -b release/x.y.z
# Update version references, run final checks
git push origin release/x.y.z
# Open PR: release/x.y.z → main
```

### Release Checklist

- [ ] All features for this release merged to `main`
- [ ] Version bumped in version file
- [ ] CHANGELOG.md updated with `milestone` event
- [ ] All tests pass: `{{TEST_COMMAND}}`
- [ ] Documentation reflects this version
- [ ] PR approved and merged to `main`
- [ ] Tag created: `git tag vx.y.z && git push --tags`

---

## Commit Message Convention

```
type(scope): short description (≤72 chars)

[optional body]

[optional footer: Closes #NNN, CHANGELOG evt-NNN]
```

**Types**: `feat` · `fix` · `docs` · `style` · `refactor` · `test` · `chore` · `ci`

---

## CI / Automation

| Check | Trigger | Command |
|-------|---------|---------|
| Tests | PR, push to main | `{{TEST_COMMAND}}` |
| Lint | PR, push to main | `{{LINT_COMMAND}}` |
| Build | Push to main | `{{BUILD_COMMAND}}` |

---

_For contribution guidelines: [CONTRIBUTING.md](CONTRIBUTING.md)_  
_For architecture: [docs/SYSTEM-MAP.md](docs/SYSTEM-MAP.md)_
