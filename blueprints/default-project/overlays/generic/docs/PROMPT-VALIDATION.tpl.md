# Prompt Validation System

> ⚠️ **MANDATORY**: Validate all AI prompts before use in {{PROJECT_NAME}}

## Purpose

This system validates that all AI prompts used in {{PROJECT_NAME}} are:
- Clear and unambiguous
- Contain all necessary context
- Specify output format
- Include error handling and edge cases
- Safe to run and aligned with project constraints

## Validation Checklist

### Content

- [ ] Purpose is explicit
- [ ] Scope is explicit
- [ ] Assumptions are listed
- [ ] Success criteria are listed
- [ ] Constraints are listed

### Context

- [ ] Relevant files/paths are provided
- [ ] Relevant stack/tier info is provided
- [ ] Dependencies and tools are listed

### Execution Plan

- [ ] Steps are numbered and ordered
- [ ] Risks and fallbacks are stated
- [ ] Tests are planned (unit/integration/e2e as relevant)
- [ ] Documentation updates are planned

### Output Format

- [ ] Output format is specified (files changed, commands, etc.)
- [ ] Non-goals are specified

## Quick Gate

- Proceed only if confidence is **≥ 7/10** on:
  - task understanding
  - codebase understanding
  - testing plan
  - rollout plan

## Related

- [PROMPT-VALIDATION-QUICK.md](PROMPT-VALIDATION-QUICK.md)
- [DOCUMENTATION-MAINTENANCE.md](DOCUMENTATION-MAINTENANCE.md)

---

**Last Updated**: {{LAST_UPDATED_DATE}}  
**Next Review**: {{NEXT_REVIEW_DATE}}
