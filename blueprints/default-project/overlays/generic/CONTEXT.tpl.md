# {{PROJECT_NAME}} - Project Context

> Understanding the philosophy, design decisions, and context behind {{PROJECT_NAME}}

## 🎯 Project Purpose

{{PROJECT_DESCRIPTION}}

### Core Problem Statement
{{CORE_PROBLEM_STATEMENT}}

### Solution Overview
{{SOLUTION_OVERVIEW}}

## 🏗️ Architecture Philosophy

### Design Principles
{{#each DESIGN_PRINCIPLES}}
- {{this}}
{{/each}}

### Key Architectural Decisions
{{#each ARCHITECTURAL_DECISIONS}}
- **{{title}}**: {{description}} (Rationale: {{rationale}})
{{/each}}

### Technology Stack Choices
{{#each TECH_STACK_CHOICES}}
- **{{technology}}**: {{reason}} (Alternatives considered: {{alternatives}})
{{/each}}

## 🎨 Design Patterns Used

{{#each DESIGN_PATTERNS}}
### {{name}}
- **Purpose**: {{purpose}}
- **Implementation**: {{implementation}}
- **Benefits**: {{benefits}}
{{/each}}

## 📋 Project Requirements

### Functional Requirements
{{#each FUNCTIONAL_REQUIREMENTS}}
- {{this}}
{{/each}}

### Non-Functional Requirements
{{#each NON_FUNCTIONAL_REQUIREMENTS}}
- {{this}}
{{/each}}

### Constraints and Limitations
{{#each CONSTRAINTS}}
- {{this}}
{{/each}}

## 🔄 Evolution History

### Initial Concept ({{INITIAL_CONCEPT_DATE}})
{{INITIAL_CONCEPT_DESCRIPTION}}

### Major Iterations
{{#each MAJOR_ITERATIONS}}
- **{{date}}**: {{description}}
{{/each}}

### Current State ({{CURRENT_STATE_DATE}})
{{CURRENT_STATE_DESCRIPTION}}

## 🎯 Success Metrics

### Technical Metrics
{{#each TECHNICAL_METRICS}}
- {{this}}
{{/each}}

### Business Metrics
{{#each BUSINESS_METRICS}}
- {{this}}
{{/each}}

## 🔮 Future Considerations

### Planned Enhancements
{{#each PLANNED_ENHANCEMENTS}}
- {{this}}
{{/each}}

### Potential Risks
{{#each POTENTIAL_RISKS}}
- {{this}}
{{/each}}

### Scalability Considerations
{{SCALABILITY_CONSIDERATIONS}}

## 📚 Related Documentation

- [README.md](README.md) - Project overview and getting started
- [AGENTS.md](AGENTS.md) - Developer implementation guide
- [WORKFLOW.md](WORKFLOW.md) - User workflows and processes
- [CHANGELOG.md](CHANGELOG.md) - Version history and changes

---

## 📝 Context Maintenance

**Last Updated**: {{LAST_UPDATED_DATE}}  
**Maintainer**: {{MAINTAINER_NAME}}

### When to Update This Document
- When architectural decisions are made
- When project scope or goals change
- When new design patterns are introduced
- When significant technical debt is incurred

### Update Checklist
- [ ] Review and update design principles
- [ ] Document new architectural decisions
- [ ] Update technology stack rationale
- [ ] Add new design patterns
- [ ] Update success metrics
- [ ] Review future considerations

---

*This document serves as the living context for {{PROJECT_NAME}}. It should be referenced when making architectural decisions and updated whenever the project's context evolves.*
