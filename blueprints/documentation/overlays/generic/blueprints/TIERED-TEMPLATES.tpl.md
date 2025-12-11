# TIERED-TEMPLATES.md - Skeleton Templates for Agent Instantiation

**Purpose**: Structural templates that agents fill using blueprint → index mapping.  
**Generation Order**: README.md (1) → ARCHITECTURE.md (2) → TODO.md (3) → WORKFLOWS.md (4) → TESTING.md (5)

---

## 🟩 MVP TIER TEMPLATES (Lean / Fast / Minimal)

### README.md (MVP)
```markdown
# {PROJECT_NAME}

## Overview
{1–2 sentence summary of what the app does.}

## Key Features
- {Feature 1}
- {Feature 2}
- {Feature 3}

## Tech Stack
- Framework: {Flutter/React/Node/etc}
- State/Data: {pattern}
- Build Tools: {tools}

## Quickstart

Current Status (MVP)
Architecture not final.
Minimal tests.
Focus on validating concept.
```

### ARCHITECTURE.md (MVP)
```markdown
# Architecture (MVP)

## Folder Structure
<simple tree, 5–8 folders max>

## Data Flow
Input → Core Logic → Output

## Key Decisions (Draft)
- Navigation: {pattern}
- Storage: {local/sqlite/etc}
- API: {yes/no}

## Next Steps
- Stabilize structure
- Expand tests
```

### TESTING.md (MVP)
```markdown
# Testing (MVP)

## Strategy
Smoke tests only.
One test per core feature.

## Future Layers
- Unit tests for core logic
- UI/Integration tests (Core tier)
```

### TODO.md (MVP)
```markdown
# TODO (MVP)

## MVP Checklist
- [ ] Feature 1
- [ ] Feature 2
- [ ] Feature 3

## Next Milestones
- Architecture stabilization
- Basic analytics
```

### WORKFLOWS.md (MVP)
```markdown
# Workflows (MVP)

## Development
<commands>

## Testing
<smoke test command>

## Build
<build command>
```

---

## 🟦 CORE TIER TEMPLATES (Stable / Maintainable / Complete)

### README.md (Core)
```markdown
# {PROJECT_NAME}

## Summary
{clear explanation}

## Features
{list with 1–2 sentences per feature}

## Architecture
See ARCHITECTURE.md.

## Testing
See TESTING.md + TESTING-EXAMPLES.md.

## Documentation Overview
- Architecture
- Testing strategy
- Framework patterns
- Roadmap

## Status
This project is in the Core tier: stable architecture, maintainable code, growing tests.
```

### ARCHITECTURE.md (Core)
```markdown
# Architecture (Core)

## Goals
- Maintainability
- Testability
- Agent-friendly structure

## Folder Structure
<expanded tree, 10–15 folders>

## Data Flow
(Detailed diagram-like description)

## Layers / Modules
- UI
- State
- Domain
- Infrastructure

## Key Invariants
- Follow FRAMEWORK-PATTERNS.md
- Use dependency rules
- All public interfaces documented

## Risks / Tradeoffs
{analysis}
```

### TESTING.md (Core)
```markdown
# Testing (Core)

## Layers
1. Unit Tests
2. Integration Tests
3. UI Tests
4. End-to-End Flows

## Requirements
- All critical logic covered
- All screens tested at least minimally
- Tests must follow TESTING-EXAMPLES.md

## Commands
<test commands>
```

### PROJECT-ROADMAP.md (Core)
```markdown
# Roadmap (Core)

## Phase 1 — MVP
<done list>

## Phase 2 — Production
- {Feature X}
- {Feature Y}

## Phase 3 — Growth (Optional)
- {Stretch goals}
```

### AGENTS.md (Core)
```markdown
# Agents

## Roles
- Architect
- Builder
- Refactorer
- Documentation Manager
- Tester

## Responsibilities
- Follow tier rules
- Maintain doc-code parity
- Use validation protocol
```

---

## 🟧 FULL TIER TEMPLATES (Enterprise / Long-Term / Multi-Agent)

### README.md (Full)
```markdown
# {PROJECT_NAME}

{elevator pitch}

## Architecture
See ARCHITECTURE.md and DATA-MODEL.md.

## Testing
Complete: all layers covered.

## Deployment
See DEPLOYMENT.md.

## Security
See SECURITY.md.

## Documentation Table of Contents
- Architecture
- Data Model
- API Documentation
- Migration Guide
- Analytics
- Integration Guide
- CI/CD
```

### ARCHITECTURE.md (Full)
```markdown
# Architecture (Full)

## Principles
- Scalability
- Modularity
- Multi-agent operability
- Test-first design

## Folder Structure
<full structured tree with modules, layers, boundaries>

## Component Boundaries
- Public/Private APIs
- Inter-module rules
- Dependency constraints

## Sequence Flows
- Feature flow
- Request cycle
- Error handling cycles

## Performance Considerations
<details>
```

### TESTING-STRATEGY.md (Full)
```markdown
# Testing Strategy (Full)

## Test Matrix
- Unit → Integration → UI → E2E → Regression

## Coverage
- Critical logic: 100%
- Screens: 100%
- Integrations: 80%
- Error states: required

## Testing Automation
- CI pipeline
- Snapshot testing (if UI)
```

### MIGRATION-GUIDE.md (Full)
```markdown
# Migration Guide

## When to Migrate
{criteria}

## Migration Plan Template
1. Assess impact
2. Create branch
3. Update architecture
4. Update all docs
5. Run validation
6. Testing pass
7. Merge + release
```

### CI-CD.md (Full)
```markdown
# CI/CD

## Pipelines
- build
- test
- lint
- integration checks

## Rules
- No merge without passing validation
- Docs regenerated on changes
```

---

## 🔧 Template Usage Instructions

### For AI Agents
1. **Select tier** using docs/TIER-SELECTION.md algorithm
2. **Load appropriate templates** from this file
3. **Fill placeholders** using blueprint mapping from BLUEPRINT-MAPPING.md
4. **Generate in dependency order** (README.md last, references other files)
5. **Validate output** using docs/platform-engineering/VALIDATION-PROTOCOL-v2.md

### Placeholder System
Use consistent placeholders across all templates:
- `{PROJECT_NAME}` - Project name
- `{PROJECT_DESCRIPTION}` - Brief description
- `{FRAMEWORK}` - Tech framework
- `{FEATURES}` - Feature list
- `{ARCHITECTURE}` - Architecture details
- `{DATA_MODELS}` - Data structures
- `{ENDPOINTS}` - API endpoints
- `{TIMELINE}` - Project timeline
- `{TEAM_SIZE}` - Team size

### Integration Points
- **docs/TIER-SELECTION.md**: Determines which template set to use
- **BLUEPRINT-MAPPING.md**: Provides placeholder values and generation logic
- **docs/platform-engineering/VALIDATION-PROTOCOL-v2.md**: Ensures generated content meets tier requirements
- **tier-index.yaml**: Source of truth for file requirements per tier
