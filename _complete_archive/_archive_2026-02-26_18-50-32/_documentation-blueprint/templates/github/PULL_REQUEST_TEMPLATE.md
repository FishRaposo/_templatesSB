## Summary

<!-- One paragraph: what this PR does and why -->

## Changes

- <!-- change 1 -->
- <!-- change 2 -->
- <!-- change 3 -->

## Related Issues / Events

- Closes #{{ISSUE_NUMBER}}
- CHANGELOG event: evt-NNN

## Three Pillars Checklist

Before marking this PR ready for review, all three must pass:

**AUTOMATING**
- [ ] Structure validator run — 0 errors
- [ ] Placeholder scanner run — 0 `{{PLACEHOLDER}}` strings remaining (`grep -r '{{' .`)
- [ ] Link checker run — 0 broken links
- [ ] Linter run — 0 style errors (`{{TEST_COMMAND}}`)

**TESTING**
- [ ] All tests pass (`{{TEST_COMMAND}}`)
- [ ] New code has test coverage
- [ ] Code examples in docs are runnable

**DOCUMENTING**
- [ ] `CHANGELOG.md` has an event for this change
- [ ] README.md updated if user-facing behavior changed
- [ ] `docs/SYSTEM-MAP.md` updated if architecture changed
- [ ] `.memory/graph.md` and `.memory/context.md` regenerated

## Screenshots / Output (if applicable)

<!-- Add screenshots or terminal output to demonstrate the change -->

## Notes for Reviewer

<!-- Anything the reviewer should know: tricky parts, known limitations, follow-up tasks -->
