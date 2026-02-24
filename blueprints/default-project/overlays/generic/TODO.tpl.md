# {{PROJECT_NAME}} - TODO List

> Pending features, improvements, and tasks for {{PROJECT_NAME}}

## 🎯 Current Sprint (Sprint {{CURRENT_SPRINT}})

### In Progress
{{#each IN_PROGRESS}}
- [ ] {{title}} - {{assignee}} - {{priority}} - {{due_date}}
  - {{description}}
{{/each}}

### Ready for Review
{{#each READY_FOR_REVIEW}}
- [ ] {{title}} - {{assignee}} - {{priority}}
  - {{description}}
{{/each}}

## 📋 Backlog

### High Priority
{{#each HIGH_PRIORITY}}
- [ ] {{title}} - {{priority}} - {{estimated_effort}}
  - {{description}}
  - **Dependencies**: {{dependencies}}
{{/each}}

### Medium Priority
{{#each MEDIUM_PRIORITY}}
- [ ] {{title}} - {{priority}} - {{estimated_effort}}
  - {{description}}
  - **Dependencies**: {{dependencies}}
{{/each}}

### Low Priority
{{#each LOW_PRIORITY}}
- [ ] {{title}} - {{priority}} - {{estimated_effort}}
  - {{description}}
  - **Dependencies**: {{dependencies}}
{{/each}}

## 🐛 Bug Fixes

### Critical Bugs
{{#each CRITICAL_BUGS}}
- [ ] {{title}} - {{severity}} - {{reported_by}}
  - {{description}}
  - **Steps to Reproduce**: {{reproduction_steps}}
{{/each}}

### Major Bugs
{{#each MAJOR_BUGS}}
- [ ] {{title}} - {{severity}} - {{reported_by}}
  - {{description}}
  - **Steps to Reproduce**: {{reproduction_steps}}
{{/each}}

### Minor Bugs
{{#each MINOR_BUGS}}
- [ ] {{title}} - {{severity}} - {{reported_by}}
  - {{description}}
  - **Steps to Reproduce**: {{reproduction_steps}}
{{/each}}

## 🔧 Technical Debt

### Code Improvements
{{#each CODE_IMPROVEMENTS}}
- [ ] Refactor {{module}} - {{priority}}
  - {{reason}}
  - **Impact**: {{impact}}
{{/each}}

### Performance Optimizations
{{#each PERFORMANCE_OPTIMIZATIONS}}
- [ ] Optimize {{component}} - {{priority}}
  - {{description}}
  - **Expected Improvement**: {{improvement}}
{{/each}}

### Security Improvements
{{#each SECURITY_IMPROVEMENTS}}
- [ ] {{title}} - {{priority}}
  - {{description}}
  - **Risk Level**: {{risk_level}}
{{/each}}

## 📚 Documentation Tasks

### Pending Documentation
{{#each PENDING_DOCUMENTATION}}
- [ ] Document {{feature}} - {{priority}}
  - {{description}}
  - **Assignee**: {{assignee}}
{{/each}}

### Documentation Updates
{{#each DOCUMENTATION_UPDATES}}
- [ ] Update {{doc_name}} - {{priority}}
  - {{description}}
  - **Reason**: {{reason}}
{{/each}}

## 🚀 Future Features

### Next Release ({{NEXT_VERSION}})
{{#each NEXT_RELEASE_FEATURES}}
- [ ] {{title}} - {{feature_type}}
  - {{description}}
  - **User Story**: {{user_story}}
{{/each}}

### Future Roadmap
{{#each FUTURE_ROADMAP}}
#### {{version}} ({{estimated_date}})
- [ ] {{feature_1}}
- [ ] {{feature_2}}
- [ ] {{feature_3}}
{{/each}}

## 🔄 Recurring Tasks

### Weekly
- [ ] Review and update sprint backlog
- [ ] Update documentation for completed features
- [ ] Review bug reports and prioritize
- [ ] Check performance metrics

### Monthly
- [ ] Technical debt assessment
- [ ] Security audit
- [ ] User feedback review
- [ ] Roadmap planning

### Quarterly
- [ ] Architecture review
- [ ] Performance optimization planning
- [ ] Major feature planning
- [ ] Team skill assessment

## 📊 Task Statistics

### Completion Rates
| Period | Completed | In Progress | Blocked |
|--------|-----------|-------------|---------|
| This Week | {{WEEKLY_COMPLETED}} | {{WEEKLY_IN_PROGRESS}} | {{WEEKLY_BLOCKED}} |
| This Month | {{MONTHLY_COMPLETED}} | {{MONTHLY_IN_PROGRESS}} | {{MONTHLY_BLOCKED}} |
| This Quarter | {{QUARTERLY_COMPLETED}} | {{QUARTERLY_IN_PROGRESS}} | {{QUARTERLY_BLOCKED}} |

### Bug Metrics
- Open Critical: {{OPEN_CRITICAL}}
- Open Major: {{OPEN_MAJOR}}
- Open Minor: {{OPEN_MINOR}}
- Average Resolution Time: {{AVG_RESOLUTION_TIME}} days

### Technical Debt
- Identified Items: {{TECH_DEBT_COUNT}}
- Addressed This Quarter: {{TECH_DEBT_ADDRESSED}}
- Remaining Effort: {{TECH_DEBT_EFFORT}} story points

## 🏷️ Labels and Tags

### Priority Labels
- `critical` - Must be done immediately
- `high` - Should be done this sprint
- `medium` - Can be done next sprint
- `low` - Nice to have when time permits

### Type Labels
- `feature` - New functionality
- `bug` - Bug fix
- `enhancement` - Improvement to existing feature
- `tech-debt` - Code quality or refactoring
- `documentation` - Documentation related

### Status Labels
- `in-progress` - Currently being worked on
- `review` - Ready for code review
- `blocked` - Waiting on dependencies
- `backlog` - Not yet scheduled

## 📝 Task Templates

### Feature Task Template
```markdown
- [ ] [Feature Name] - priority - estimated effort
  - Description: Clear description of what needs to be done
  - Acceptance Criteria:
    - [ ] Criteria 1
    - [ ] Criteria 2
  - Dependencies: List any dependencies
  - Assignee: Person responsible
```

### Bug Task Template
```markdown
- [ ] [Bug Description] - severity - reporter
  - Description: What the bug is
  - Steps to Reproduce:
    1. Step 1
    2. Step 2
    3. Step 3
  - Expected Behavior: What should happen
  - Actual Behavior: What actually happens
  - Priority: How important this is to fix
```

## 🔗 Related Resources

- [Project Board]({{PROJECT_BOARD_URL}})
- [Issue Tracker]({{ISSUE_TRACKER_URL}})
- [Release Notes](CHANGELOG.md)
- [Roadmap Document]({{ROADMAP_URL}})

---

## 📋 Task Management Guidelines

### Adding New Tasks
1. Check if task already exists
2. Use appropriate template
3. Include all required information
4. Assign appropriate priority
5. Link to related issues

### Updating Tasks
1. Mark completed tasks
2. Update progress notes
3. Move to appropriate section
4. Update statistics
5. Notify stakeholders

### Review Process
1. Weekly backlog grooming
2. Monthly priority review
3. Quarterly roadmap planning
4. Annual strategy review

---

**Last Updated**: {{LAST_UPDATED_DATE}}  
**Maintainer**: {{MAINTAINER_NAME}}  
**Review Frequency**: Weekly

---

*This TODO list helps track all work items for {{PROJECT_NAME}}. Keep it updated to ensure transparency and proper prioritization.*
