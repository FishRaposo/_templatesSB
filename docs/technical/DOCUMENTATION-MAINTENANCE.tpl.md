# Documentation Maintenance Guide

> ⚠️ **MANDATORY**: Automatic documentation updates are required for every code change in {{PROJECT_NAME}}

## 🚨 Critical Rule

**CODE CHANGES WITHOUT DOCUMENTATION UPDATES = INCOMPLETE WORK**

Every code change MUST include:
1. **Automatic documentation update** (using checklists below)
2. **CHANGELOG.md update** (REQUIRED - no exceptions)
3. **Related documentation updates** (based on change type)

## 📋 Automatic Update Checklists

### For All Code Changes

#### ✅ Immediate Actions (During Implementation)
- [ ] Update CHANGELOG.md with change description
- [ ] Update affected API documentation
- [ ] Update relevant examples
- [ ] Update configuration documentation if needed

#### ✅ Post-Implementation Actions
- [ ] Review all updated documentation for accuracy
- [ ] Test documentation examples
- [ ] Update relevant sections in CONTEXT.md if architecture changed
- [ ] Update TODO.md if tasks were completed

### By Change Type

#### 🐛 Bug Fixes
- [ ] Document bug symptoms and resolution
- [ ] Update troubleshooting guide
- [ ] Add to known issues if applicable
- [ ] Update test documentation

#### ✨ New Features
- [ ] Document feature purpose and usage
- [ ] Add examples to README.md
- [ ] Update API documentation
- [ ] Add to WORKFLOW.md if user-facing
- [ ] Update EVALS.md with test cases

#### 🔧 Refactoring
- [ ] Document architectural changes
- [ ] Update CONTEXT.md
- [ ] Update developer guides
- [ ] Update performance documentation
- [ ] Update migration guides if needed

#### 🗑️ Deprecations/Removals
- [ ] Document deprecation timeline
- [ ] Update migration guides
- [ ] Remove from current documentation
- [ ] Add to deprecation notice

#### 🔒 Security Changes
- [ ] Document security implications
- [ ] Update security guide
- [ ] Update configuration documentation
- [ ] Document required user actions

## 🔄 Documentation Update Workflow

### 1. Before Code Change
```bash
# Identify affected documentation
grep -r "affected_function" docs/
grep -r "affected_class" docs/
```

### 2. During Implementation
- Keep documentation open alongside code
- Update as you implement, not after
- Use placeholder comments for complex sections

### 3. After Code Change
```bash
# Validate documentation
./scripts/validate-docs.sh
# Test examples
./scripts/test-examples.sh
# Check links
./scripts/check-links.sh
```

### 4. Review Process
- Self-review all changes
- Peer review for significant changes
- Automated validation where possible

## 📊 Maintenance Schedule

### Daily (For Active Developers)
- Review and update CHANGELOG.md
- Update in-progress documentation
- Fix documentation bugs found during development

### Weekly
- Review TODO.md progress
- Update API documentation for recent changes
- Check for outdated examples

### Monthly
- Full documentation audit
- Update architecture documentation
- Review and update all guides
- Check for broken links

### Quarterly
- Major documentation restructuring
- Update project philosophy in CONTEXT.md
- Review and update templates
- User feedback incorporation

## 🛠️ Maintenance Tools

### Automated Scripts
```bash
# Validate all documentation
./scripts/validate-documentation.sh

# Check for broken links
./scripts/check-links.sh

# Generate API docs
./scripts/generate-api-docs.sh

# Update table of contents
./scripts/update-toc.sh
```

### Manual Checks
- Read through recent changes
- Test all examples
- Verify all commands work
- Check formatting consistency

## 📝 Documentation Standards

### Formatting Rules
- Use consistent markdown
- Follow established templates
- Include code examples
- Add visual aids when helpful

### Content Guidelines
- Be clear and concise
- Include prerequisites
- Provide step-by-step instructions
- Add troubleshooting sections

### Version Control
- Commit documentation with code
- Use descriptive commit messages
- Tag documentation releases
- Maintain change history

## 🚨 Common Maintenance Issues

### Outdated Examples
**Problem**: Examples don't work with current code
**Solution**: Test examples regularly, update with code changes

### Missing Updates
**Problem**: Code changed but documentation didn't
**Solution**: Use checklists, automate where possible

### Inconsistent Formatting
**Problem**: Different styles across documents
**Solution**: Use templates, establish style guide

### Broken Links
**Problem**: References to non-existent sections
**Solution**: Regular link checking, use relative paths

## 📋 Maintenance Log

| Date | Action | Documents Updated | Reviewer |
|------|--------|-------------------|----------|
| [Date] | [Change type] | [List] | [Name] |
| [Date] | [Change type] | [List] | [Name] |

## 🎯 Quality Metrics

### Documentation Coverage
- API documentation: {{API_COVERAGE}}%
- Code examples: {{EXAMPLE_COVERAGE}}%
- Test coverage: {{TEST_COVERAGE}}%

### User Feedback
- Documentation helpfulness: {{HELPFULNESS_SCORE}}/5
- Completeness rating: {{COMPLETENESS_SCORE}}/5
- Clarity rating: {{CLARITY_SCORE}}/5

## 📚 Related Documentation

- [PROMPT-VALIDATION.md](PROMPT-VALIDATION.md) - Prompt validation system
- [DOCUMENTATION.md](../../blueprints/default-project/overlays/generic/DOCUMENTATION.tpl.md) - Documentation navigation
- [AGENTS.md](../../blueprints/default-project/overlays/generic/AGENTS.tpl.md) - Developer guidelines

---

## 🔄 Review Process

**Monthly Review Required**
- [ ] Review all documentation for accuracy
- [ ] Update metrics and statistics
- [ ] Check maintenance log completeness
- [ ] Update this guide as needed

**Last Updated**: {{LAST_UPDATED_DATE}}  
**Next Review**: {{NEXT_REVIEW_DATE}}  
**Maintainer**: {{MAINTAINER_NAME}}

---

*This maintenance guide is mandatory for all developers working on {{PROJECT_NAME}}. Documentation updates are not optional - they are part of the implementation process.*
