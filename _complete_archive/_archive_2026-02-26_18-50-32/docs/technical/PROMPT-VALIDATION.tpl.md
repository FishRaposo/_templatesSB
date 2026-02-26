# Prompt Validation System

> ⚠️ **MANDATORY**: This file ensures all AI prompts are validated before use in {{PROJECT_NAME}}

## 🎯 Purpose

This system validates that all AI prompts used in {{PROJECT_NAME}} are:
- Clear and unambiguous
- Contain all necessary context
- Include proper error handling
- Follow established patterns
- Are tested and verified

## 📋 Validation Checklist

### Before Using Any Prompt

#### ✅ Content Validation
- [ ] Prompt clearly states its purpose
- [ ] All required variables are defined
- [ ] Context is sufficient for the task
- [ ] Output format is specified
- [ ] Edge cases are considered

#### ✅ Structure Validation
- [ ] Follows established prompt template
- [ ] Sections are properly organized
- [ ] Examples are provided where needed
- [ ] Instructions are sequential and logical
- [ ] Error conditions are handled

#### ✅ Technical Validation
- [ ] All placeholders are valid
- [ ] Tool calls are properly specified
- [ ] File paths are correct
- [ ] Dependencies are declared
- [ ] Security considerations are included

### Prompt Template Structure

```markdown
# [Prompt Title]

## Purpose
[Clear statement of what the prompt does]

## Context
[All necessary background information]

## Instructions
[Step-by-step instructions]

## Expected Output
[Format and content expectations]

## Examples
[Example inputs and outputs]

## Error Handling
[How to handle errors or edge cases]

## Dependencies
[Tools, files, or resources needed]
```

## 🔍 Validation Process

### 1. Initial Review
- Review prompt against checklist
- Identify missing elements
- Note areas for improvement

### 2. Testing
- Test with sample inputs
- Verify output format
- Check error handling

### 3. Peer Review
- Have another developer review
- Get feedback on clarity
- Incorporate suggestions

### 4. Documentation
- Document validation results
- Note any limitations
- Record test cases

## 📊 Validation Categories

### High Priority (Must Pass)
- Clarity and specificity
- Complete context
- Proper error handling
- Security considerations

### Medium Priority (Should Pass)
- Examples provided
- Consistent formatting
- Adequate testing
- Documentation complete

### Low Priority (Nice to Have)
- Optimization opportunities
- Alternative approaches
- Performance considerations
- Future enhancements

## 🚨 Common Validation Failures

### Missing Context
**Problem**: Prompt doesn't provide enough background
**Solution**: Add context section with all necessary information

### Ambiguous Instructions
**Problem**: Instructions can be interpreted multiple ways
**Solution**: Be specific and use unambiguous language

### No Error Handling
**Problem**: Prompt doesn't specify what to do on errors
**Solution**: Add error handling section with clear instructions

### Undefined Variables
**Problem**: References variables that aren't defined
**Solution**: Define all variables in context section

## 📝 Validation Log

| Prompt Name | Validator | Date | Status | Notes |
|-------------|-----------|------|--------|-------|
| [Prompt 1] | [Name] | [Date] | ✅ Pass | [Notes] |
| [Prompt 2] | [Name] | [Date] | ❌ Fail | [Issues] |
| [Prompt 3] | [Name] | [Date] | ✅ Pass | [Notes] |

## 🔧 Tools for Validation

### Automated Checks
- Template validation script
- Placeholder verification
- Syntax checking
- Security scanning

### Manual Reviews
- Peer review process
- User testing
- Expert consultation
- Documentation audit

## 📚 Related Documentation

- [PROMPT-VALIDATION-QUICK.md](PROMPT-VALIDATION-QUICK.md) - 5-minute quick validation
- [DOCUMENTATION-MAINTENANCE.md](DOCUMENTATION-MAINTENANCE.md) - Documentation maintenance guide
- [AGENTS.md](../../blueprints/default-project/overlays/generic/AGENTS.tpl.md) - Developer implementation guide

---

## 🔄 Maintenance

**Review Frequency**: Monthly  
**Last Updated**: {{LAST_UPDATED_DATE}}  
**Next Review**: {{NEXT_REVIEW_DATE}}

### Update Checklist
- [ ] Review validation checklist
- [ ] Update common failures section
- [ ] Add new validation categories
- [ ] Refresh validation log
- [ ] Update tools and processes

---

*This validation system is mandatory for all AI prompts used in {{PROJECT_NAME}}. All prompts must pass validation before being used in production.*
