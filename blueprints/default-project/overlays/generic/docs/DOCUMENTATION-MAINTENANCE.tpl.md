# Documentation Maintenance Guide

> ⚠️ **MANDATORY**: Code changes require documentation updates in {{PROJECT_NAME}}

## Critical Rule

**CODE CHANGES WITHOUT DOCUMENTATION UPDATES = INCOMPLETE WORK**

Every code change MUST include:
- CHANGELOG update
- Relevant doc updates
- Relevant examples updated

## Minimum Checklist (Every Change)

- [ ] Update `CHANGELOG.md`
- [ ] Update `README.md` if usage changed
- [ ] Update `WORKFLOW.md` if user flow changed
- [ ] Update `CONTEXT.md` if architecture changed
- [ ] Update `EVALS.md` if tests/evals changed

## Keeping Links Healthy

- Use relative links
- Avoid linking to template system internals
- Run link checks as part of CI if possible

---

**Last Updated**: {{LAST_UPDATED_DATE}}  
**Next Review**: {{NEXT_REVIEW_DATE}}  
**Maintainer**: {{MAINTAINER_NAME}}
