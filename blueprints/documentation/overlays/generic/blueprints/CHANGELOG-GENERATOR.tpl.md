# CHANGELOG-GENERATOR.md - Automated Changelog Creation Module

**Purpose**: Automatically create clean, semantically structured changelogs from diffs, refactors, migrations, and agent operations.  
**Design**: LLM-native changelog generation with standardized format and comprehensive change tracking.  
**Integration**: Required audit trail component for all changes, integrates with CI/CD and PR workflows.

---

## 📝 Changelog Generator — v1.0

**This ensures every change stays human-readable and audit-friendly.**

---

## Changelog Format

The generator must output entries in this format:

```markdown
## [Version or Date]

### Added
- ...

### Changed
- ...

### Fixed
- ...

### Removed
- ...

### Security
- ...

### Migration Notes
- ...
```

---

## Generation Rules

### 1. Every diff produces a human-readable explanation
- Translate technical changes into business impact
- Explain "what" and "why" for each change
- Use clear, accessible language

### 2. Group changes by module or feature
- Organize entries logically
- Group related changes together
- Maintain coherent narrative flow

### 3. Describe behavior changes explicitly
- Detail how user experience changes
- Explain API contract modifications
- Document performance implications

### 4. Include migration steps if needed
- Provide step-by-step migration instructions
- Include rollback procedures
- Document breaking changes clearly

### 5. Document breaking changes separately
- Highlight breaking changes prominently
- Explain impact on existing users
- Provide upgrade paths

### 6. Reference related tickets, roadmap items, or TODOs
- Link to issue trackers
- Reference roadmap milestones
- Connect to strategic initiatives

### 7. Use clear, non-technical language where possible
- Avoid jargon when possible
- Explain technical concepts simply
- Focus on user impact

### 8. Ensure changelog matches refactor phases
- Align with migration phases
- Track multi-step refactors
- Document intermediate states

---

## Changelog Engine (Reasoning Steps)

### STEP 1 — Parse all diffs
```bash
# Input: Unified diff files
# Process: Extract changed files, functions, and patterns
# Output: Structured change data

python3 scripts/diff_parser.py \
  --diffs patches/*.diff \
  --output parsed_changes.json
```

### STEP 2 — Categorize changes (Added/Changed/Fixed/Removed/Security)
```python
# Change categorization logic
def categorize_change(change):
    if change.is_new_feature():
        return "Added"
    elif change.is_modification():
        return "Changed"
    elif change.is_bug_fix():
        return "Fixed"
    elif change.is_removal():
        return "Removed"
    elif change.is_security_change():
        return "Security"
```

### STEP 3 — Identify migrations or breaking changes
```python
# Breaking change detection
def detect_breaking_changes(changes):
    breaking_changes = []
    for change in changes:
        if change.affects_public_api() or change.changes_behavior():
            breaking_changes.append(change)
    return breaking_changes
```

### STEP 4 — Summarize each change
```markdown
Template for each change:
- **What changed**: [Technical description]
- **Why**: [Business/technical justification]
- **Impact**: [User/system impact]
- **Required follow-up**: [Additional actions needed]
```

### STEP 5 — Format into standard template
```python
# Changelog formatting
def format_changelog(changes, version):
    changelog = f"## {version}\n\n"
    
    for category in ["Added", "Changed", "Fixed", "Removed", "Security", "Migration Notes"]:
        category_changes = [c for c in changes if c.category == category]
        if category_changes:
            changelog += f"### {category}\n"
            for change in category_changes:
                changelog += f"- {change.description}\n"
            changelog += "\n"
    
    return changelog
```

### STEP 6 — Append to CHANGELOG.md
```bash
# Update changelog file
python3 scripts/changelog_updater.py \
  --new_entry "$(cat new_changelog_entry.md)" \
  --changelog_file CHANGELOG.md \
  --backup CHANGELOG.md.backup
```

### STEP 7 — Validate alignment with documentation and roadmap
```bash
# Cross-reference validation
python3 scripts/changelog_validator.py \
  --changelog CHANGELOG.md \
  --roadmap ROADMAP.md \
  --architecture ARCHITECTURE.md \
  --api_docs API-DOCUMENTATION.md
```

---

## PR Integration

### Automated PR Workflow
```bash
# Agents should automatically run:
echo "🤖 Running automated changelog generation"

# 1. Generate changelog from current changes
python3 scripts/changelog_generator.py \
  --pr_number $PR_NUMBER \
  --diffs $(git diff main...HEAD) \
  --context current_context.json \
  --output pr_changelog.md

# 2. Run Diff Validator
python3 scripts/diff_validator.py --strict

# 3. Run Merge Safety Checklist
python3 scripts/merge_safety_checklist.py

# 4. Validate changelog completeness
python3 scripts/changelog_validator.py --file pr_changelog.md

echo "✅ Changelog generation and validation completed"
```

### GitHub Actions Integration
```yaml
name: Changelog Generation
on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  generate-changelog:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Generate Changelog
        run: |
          python3 scripts/changelog_generator.py \
            --pr_number ${{ github.event.number }} \
            --diffs "$(git diff origin/main...HEAD)" \
            --output pr_changelog.md
      
      - name: Comment PR with Changelog
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const changelog = fs.readFileSync('pr_changelog.md', 'utf8');
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `## 📝 Automated Changelog\n\n${changelog}`
            });
```

---

## 🔧 Integration with Agentic Platform Engineering System

### Component Dependencies:
| Component | Integration Point | Role |
|-----------|-------------------|------|
| **CODE-DIFF-REASONER.md** | STEP 1 | Provides diff input for changelog generation |
| **MIGRATION-ENGINE.md** | STEP 3 | Identifies migration phases and breaking changes |
| **DIFF-VALIDATOR.md** | STEP 7 | Validates changelog completeness and accuracy |
| **REFACTOR-SAFETY-DASHBOARD.md** | STEP 4 | Provides context and impact information |
| **MERGE-SAFETY-CHECKLIST.md** | PR Integration | Ensures changelog is complete before merge |
| **docs/platform-engineering/VALIDATION-PROTOCOL-v2.md** | STEP 7 | Validates documentation alignment |

### Data Flow Integration:
```
Code Changes → Diff Generation → Changelog Generation → Validation → Merge → Audit Trail
     ↓              ↓                 ↓               ↓        ↓         ↓
CODE-DIFF-   DIFF-VALIDATOR   CHANGELOG-GENERATOR   VALIDATION  MERGE   CHANGELOG.md
REASONER.md      .md               .md            PROTOCOL   SAFETY   (Final
                                                   v2.md    CHECKLIST  Audit
                                                            .md        Trail)
```

### Agent Workflow Integration:
```bash
#!/bin/bash
# Complete agent workflow with changelog generation
echo "🤖 Starting agent workflow with changelog generation"

# 1. Run refactor playbook
source scripts/agent_refactor_playbook.sh "$@"

# 2. Generate changelog from completed changes
python3 scripts/changelog_generator.py \
  --context refactor_context.json \
  --diffs patches/*.diff \
  --dashboard REFACTOR-SAFETY-DASHBOARD.md \
  --output CHANGELOG-ENTRY.md

# 3. Validate changelog completeness
python3 scripts/changelog_validator.py \
  --changelog CHANGELOG-ENTRY.md \
  --documentation docs/ \
  --roadmap ROADMAP.md

# 4. Update master changelog
python3 scripts/changelog_updater.py \
  --new_entry CHANGELOG-ENTRY.md \
  --master_changelog CHANGELOG.md

# 5. Run final safety checks
python3 scripts/merge_safety_checklist.py

echo "✅ Agent workflow completed with changelog generation"
```

---

## 📋 Changelog Templates

### Feature Addition Template:
```markdown
### Added
- **[Feature Name]**: Added new functionality for [user benefit]
  - **What**: [Technical description of new feature]
  - **Why**: [Business justification and user value]
  - **Impact**: [How this changes user experience]
  - **Follow-up**: [Any additional work needed]
```

### Bug Fix Template:
```markdown
### Fixed
- **[Issue Description]**: Fixed bug causing [problem description]
  - **What**: [Technical fix implemented]
  - **Why**: [Root cause and impact of bug]
  - **Impact**: [How this fixes the user experience]
  - **Testing**: [How the fix was validated]
```

### Breaking Change Template:
```markdown
### Changed
- **BREAKING**: [Component/Feature] behavior has changed
  - **What**: [Detailed description of change]
  - **Why**: [Reason for breaking change]
  - **Impact**: [Effect on existing users]
  - **Migration**: [Steps to upgrade/migrate]
  - **Timeline**: [When change takes effect]
```

### Migration Template:
```markdown
### Migration Notes
- **[Migration Name]**: System migration from [old] to [new]
  - **Overview**: [High-level description of migration]
  - **Steps**: [Step-by-step migration instructions]
  - **Rollback**: [How to revert if needed]
  - **Timeline**: [Migration schedule and phases]
  - **Impact**: [Expected downtime or effects]
```

---

## 🎯 Usage Examples

### Simple Feature PR:
```markdown
## v2.1.0 - 2024-01-15

### Added
- **User Profile Enhancement**: Added avatar upload functionality
  - **What**: New image upload endpoint and UI components
  - **Why**: Users requested ability to customize profile images
  - **Impact**: Users can now upload and display profile avatars
  - **Follow-up**: Image resizing and optimization planned for v2.2.0

### Changed
- **API Rate Limiting**: Adjusted rate limits for profile endpoints
  - **What**: Increased rate limit from 100 to 200 requests per hour
  - **Why**: Accommodate additional avatar upload requests
  - **Impact**: Reduced likelihood of rate limit errors for active users
```

### Architecture Migration PR:
```markdown
## v3.0.0 - 2024-02-01

### Changed
- **BREAKING**: Authentication system migrated from JWT to OAuth 2.0
  - **What**: Complete replacement of JWT authentication with OAuth 2.0
  - **Why**: Improved security and third-party integration capabilities
  - **Impact**: All clients must update authentication flow
  - **Migration**: See Migration Notes below for upgrade steps
  - **Timeline**: Migration must be completed by 2024-03-01

### Removed
- **JWT Authentication**: Removed legacy JWT authentication system
  - **What**: Deleted JWT token generation and validation code
  - **Why**: OAuth 2.0 provides better security and features
  - **Impact**: JWT tokens will no longer be accepted
  - **Replacement**: Use OAuth 2.0 authentication flow

### Migration Notes
- **OAuth 2.0 Migration**: Migrate from JWT to OAuth 2.0 authentication
  - **Overview**: System-wide upgrade to OAuth 2.0 for improved security
  - **Steps**:
    1. Register your application in the developer console
    2. Update client libraries to support OAuth 2.0
    3. Replace JWT authentication with OAuth 2.0 flow
    4. Test authentication with existing user accounts
    5. Deploy updated authentication by 2024-03-01
  - **Rollback**: Revert to previous deployment if OAuth 2.0 issues arise
  - **Timeline**: Migration window: 2024-02-01 to 2024-03-01
  - **Impact**: Brief authentication downtime during deployment
```

---

## 🛠️ Implementation Notes

### Configuration:
```yaml
changelog_config:
  version_format: "v{major}.{minor}.{patch}"
  date_format: "%Y-%m-%d"
  categories:
    - Added
    - Changed
    - Fixed
    - Removed
    - Security
    - Migration Notes
  
  breaking_change_thresholds:
    api_changes: true
    behavior_changes: true
    database_schema_changes: true
  
  auto_linking:
    issue_tracker: "https://github.com/org/repo/issues/"
    roadmap: "ROADMAP.md"
    documentation: "docs/"
```

### Validation Rules:
```python
def validate_changelog_entry(entry):
    validations = [
        has_version_number(entry),
        has_date(entry),
        has_required_categories(entry),
        changes_are_human_readable(entry),
        breaking_changes_documented(entry),
        migrations_have_steps(entry),
        references_are_valid(entry),
        follows_style_guide(entry)
    ]
    return all(validations)
```

### Quality Metrics:
- **Readability Score**: Ensure changelog is accessible to non-technical users
- **Completeness**: All changes properly documented
- **Accuracy**: Changelog matches actual changes
- **Consistency**: Follows established format and style
- **Timeliness**: Generated promptly after changes

---

**This changelog generator provides enterprise-grade auditing with zero friction, ensuring every change is tracked, documented, and human-readable while maintaining complete audit trails for compliance and governance.**
