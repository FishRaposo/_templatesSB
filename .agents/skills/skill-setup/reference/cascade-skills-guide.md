# Cascade (Windsurf) Skills Guide

This guide covers the specific implementation and best practices for creating skills in Cascade (Windsurf).

**Official Documentation**: https://docs.windsurf.com/windsurf/cascade/skills

## Overview

Cascade skills help handle complex, multi-step tasks by bundling instructions, templates, checklists, and supporting files. Cascade uses **progressive disclosure** to intelligently invoke skills only when relevant to the task.

## Key Features

### Progressive Disclosure
Cascade automatically determines which skills are relevant based on:
- The skill's description in the frontmatter
- The current task context
- Available resources

### Manual Invocation
Skills can be manually invoked using `@skill-name` syntax.

### Resource Bundling
All files in the skill directory become available when the skill is invoked.

## Directory Structure

### Workspace Skills (Project-Specific)
```
.windsurf/skills/
└── skill-name/
    ├── SKILL.md              # Required: Main skill definition
    ├── deployment-checklist.md
    ├── rollback-procedure.md
    └── config-template.yaml
```

### Global Skills (Available Everywhere)
```
~/.codeium/windsurf/skills/
└── skill-name/
    ├── SKILL.md
    └── [supporting files]
```

## Creating Skills

### Method 1: Using the UI (Recommended)
1. Open the Cascade panel
2. Click the three dots (⋮) to open customizations
3. Click on the `Skills` section
4. Click `+ Workspace` for project skills or `+ Global` for global skills
5. Name the skill (lowercase letters, numbers, and hyphens only)

### Method 2: Manual Creation
```bash
# Create workspace skill
mkdir -p .windsurf/skills/my-skill
touch .windsurf/skills/my-skill/SKILL.md

# Create global skill
mkdir -p ~/.codeium/windsurf/skills/my-skill
touch ~/.codeium/windsurf/skills/my-skill/SKILL.md
```

## SKILL.md Format

### Required Frontmatter
```yaml
---
name: deploy-to-production
description: Guides the deployment process to production with safety checks
---
```

### Frontmatter Fields
- **name** (required): Unique identifier (lowercase, numbers, hyphens only)
- **description** (required): Helps Cascade decide when to invoke the skill

### Example Skill
```markdown
---
name: deploy-to-production
description: Use this skill when deploying applications to production environment, including pre-deployment checks, deployment steps, and rollback procedures
---

## Pre-deployment Checklist
1. Run all tests and ensure they pass
2. Check for uncommitted changes in git
3. Verify environment variables are set
4. Backup current production version
5. Notify stakeholders of upcoming deployment

## Deployment Steps
1. **Prepare Environment**
   ```bash
   # Set production environment
   export NODE_ENV=production
   
   # Verify configuration
   npm run config:verify
   ```

2. **Build Application**
   ```bash
   # Clean previous build
   rm -rf dist/
   
   # Build for production
   npm run build
   ```

3. **Deploy**
   ```bash
   # Deploy to production
   npm run deploy:prod
   
   # Verify deployment
   npm run health-check
   ```

## Rollback Procedure
If deployment fails:
1. See `./rollback-procedure.md`
2. Use `./config-template.yaml` for configuration reference
3. Contact the on-call engineer

## Post-deployment
1. Monitor application logs for 15 minutes
2. Run smoke tests
3. Update deployment documentation
4. Send deployment success notification
```

## Skill Naming Conventions

### Good Names
- `deploy-to-staging`
- `code-review-guidelines`
- `setup-dev-environment`
- `run-performance-tests`

### Poor Names
- `deploy1` (not descriptive)
- `Deploy` (uppercase)
- `deploy skill` (contains space)
- `deploy_to_production` (underscores not allowed)

## Best Practices for Cascade Skills

### 1. Write Clear Descriptions
The description is crucial for progressive disclosure:

```yaml
# Good
description: Use this skill when you need to deploy applications to production, including safety checks, backup procedures, and rollback plans

# Poor
description: Deploys stuff
```

### 2. Include Supporting Resources
Bundle relevant files that help with the task:
- Templates
- Checklists
- Configuration files
- Example scripts
- Documentation

### 3. Use Relative Paths
When referencing files in the skill:
```markdown
See the deployment checklist in `./deployment-checklist.md`
Use the configuration template at `./config-template.yaml`
```

### 4. Structure for Progressive Disclosure
Organize content from general to specific:
1. Quick overview
2. Requirements (what the agent or user needs before starting)
3. Step-by-step instructions
4. Troubleshooting
5. References

## Skill Invocation

### Automatic Invocation
Cascade automatically invokes skills when:
- The user's request matches the skill description
- The skill is relevant to the current context
- Required resources are available

### Manual Invocation
Use `@skill-name` to explicitly invoke a skill:
```
@deploy-to-production deploy the latest changes
```

## Example Use Cases

### 1. Deployment Workflow
```
.windsurf/skills/deploy-staging/
├── SKILL.md
├── pre-deploy-checks.sh
├── environment-template.env
└── rollback-steps.md
```

### 2. Code Review Guidelines
```
.windsurf/skills/code-review/
├── SKILL.md
├── style-guide.md
├── security-checklist.md
└── review-template.md
```

### 3. Testing Procedures
```
.windsurf/skills/run-tests/
├── SKILL.md
├── test-template.py
├── coverage-config.json
└── ci-workflow.yaml
```

## Cascade-Specific Features

### Real-time Awareness
Skills have access to:
- Current workspace files
- Git status
- Environment context
- Recent conversation history

### UI Integration
- Skills appear in the Cascade UI
- Can be managed through the skills panel
- Visual indicators for skill status

### No Config.json Required
Unlike other platforms, Cascade skills don't need a separate config.json file. All configuration is in the SKILL.md frontmatter.

## Migration from Other Platforms

### From Claude
1. Copy skill directory to `.windsurf/skills/` or `~/.codeium/windsurf/skills/`
2. Remove config.json (not needed)
3. Enhance description for better progressive disclosure
4. Test manual invocation with `@skill-name`

### From Roo Code
1. Update path location
2. Remove mode-specific configurations
3. Add supporting files if needed
4. Simplify structure

## Troubleshooting

### Skill Not Invoking Automatically
1. Check if description is specific enough
2. Verify skill is in correct directory
3. Test manual invocation with `@skill-name`
4. Check for syntax errors in SKILL.md

### Supporting Files Not Accessible
1. Ensure files are in the same skill directory
2. Use relative paths in references
3. Check file permissions

### Manual Invocation Not Working
1. Verify skill name matches directory name
2. Use correct syntax: `@skill-name`
3. Check for typos in skill name

## Advanced Patterns

### Conditional Logic
```markdown
## Environment-Specific Steps

### For Production
1. Run full test suite
2. Get approval from team lead
3. Schedule maintenance window

### For Staging
1. Run smoke tests
2. Deploy immediately
3. Notify QA team
```

### Interactive Prompts
```markdown
## Configuration
Before proceeding, you'll need:
1. [ ] API key (check environment variables)
2. [ ] Database credentials
3. [ ] Target server address

Have these ready before continuing.
```

### Error Recovery
```markdown
## Common Issues

### Build Fails
If the build fails:
1. Check `./build-logs/` for error details
2. Verify all dependencies are installed
3. Clean and rebuild: `npm run clean && npm run build`

### Tests Fail
If tests fail:
1. Review test output
2. Check for flaky tests
3. Run tests individually: `npm test -- --grep "test-name"`
```

## Integration with Other Cascade Features

### Workflows
Skills can be referenced from workflows:
```markdown
# In a workflow file
Deploy to staging using @deploy-to-staging skill
```

### Rules
Skills complement rules by providing:
- Structured procedures (skills)
- Behavioral guidelines (rules)

### AGENTS.md
Skills can work alongside AGENTS.md for:
- Directory-specific instructions (AGENTS.md)
- Complex workflows (skills)

## Performance Considerations

- Keep skills focused on specific tasks
- Avoid overly large supporting files
- Use efficient file organization
- Test skill loading time

## Security Considerations

- Don't include sensitive data in skills
- Use environment variables for secrets
- Validate all inputs in scripts
- Follow principle of least privilege

This guide helps you create effective Cascade skills that leverage the platform's unique features while maintaining compatibility with universal skill standards.
