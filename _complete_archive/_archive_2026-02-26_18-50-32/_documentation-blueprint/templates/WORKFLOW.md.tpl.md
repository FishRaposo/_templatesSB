# Development Workflow — {{PROJECT_NAME}}

_Branching strategy, release process, and team conventions_

---

## Branching Strategy

```
main          ← stable, always deployable, protected
dev           ← integration branch — PRs merge here first
feature/name  ← new features (branch from dev)
fix/name      ← bug fixes (branch from dev or main for hotfixes)
docs/name     ← documentation-only changes
release/x.y   ← release preparation (branch from dev)
hotfix/name   ← critical production fixes (branch from main)
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
# Always branch from the latest dev
git checkout dev
git pull origin dev
git checkout -b feature/{{FEATURE_NAME}}
```

### During Development

- Commit early and often with conventional commit messages
- Run tests before each commit: `{{TEST_COMMAND}}`
- Append decisions to `CHANGELOG.md` as you work

### Opening a Pull Request

1. Push your branch: `git push origin feature/{{FEATURE_NAME}}`
2. Open PR against `dev` using the PR template
3. Complete the Three Pillars checklist before marking ready
4. Request review from `{{DEFAULT_REVIEWERS}}`

### Merging

- At least **{{REQUIRED_APPROVALS}}** approval(s) required
- All CI checks must pass
- Resolve all review comments before merging
- Squash and merge — delete branch after merge

---

## Release Process

### Creating a Release

```bash
git checkout dev && git pull
git checkout -b release/{{VERSION}}
# Update version references, run final checks
git push origin release/{{VERSION}}
# Open PR: release/{{VERSION}} → main
```

### Release Checklist

- [ ] All features for this release merged to `dev`
- [ ] Version bumped in `{{VERSION_FILE}}`
- [ ] CHANGELOG.md updated with `milestone` event
- [ ] All tests pass: `{{TEST_COMMAND}}`
- [ ] Documentation reflects this version
- [ ] PR approved and merged to `main`
- [ ] Tag created: `git tag v{{VERSION}} && git push --tags`

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
| Tests | PR, push to dev/main | `{{TEST_COMMAND}}` |
| Lint | PR, push to dev/main | `{{LINT_COMMAND}}` |
| Build | Push to main | `{{BUILD_COMMAND}}` |
| Deploy | Tag on main | `{{DEPLOY_COMMAND}}` |

---

_For contribution guidelines: [CONTRIBUTING.md](CONTRIBUTING.md)_  
_For architecture: [docs/SYSTEM-MAP.md](docs/SYSTEM-MAP.md)_
