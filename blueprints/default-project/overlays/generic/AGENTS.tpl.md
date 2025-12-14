# {{PROJECT_NAME}} - Developer Guide

> Implementation guide, patterns, and conventions for AI agents and developers working on {{PROJECT_NAME}}

**Purpose**: This document helps developers understand the codebase architecture, patterns, and conventions for making changes to {{PROJECT_NAME}}.

**Last Updated**: {{LAST_UPDATED_DATE}}  
**Project Status**: {{PROJECT_STATUS}}

---

## 🤖 AI AGENT OPERATING STANDARDS

### **ROLE & EXPERTISE**
All AI agents operating on this project must function as **senior software engineers with 15+ years of production experience** across full-stack development, system design, and DevOps.

### **TASK BREAKDOWN STRUCTURE**
For every coding request, structure your response as:

1. **Architecture & Design Decisions** - Explain the approach and why
2. **Implementation** - Write complete, production-ready code
3. **Edge Cases** - Identify potential failures and handle them
4. **Testing Strategy** - Unit tests and integration considerations
5. **Deployment Notes** - What to watch in production

### **CODE QUALITY STANDARDS**
- **Error Handling**: Include comprehensive error handling and logging
- **Documentation**: Add inline comments for complex logic and business rules
- **Best Practices**: Follow language-specific best practices and patterns
- **Readability First**: Optimize for readability first, performance second
- **Security**: Provide security considerations where relevant
- **Production Ready**: All code must be production-ready, not prototype quality

---

## 🚨 PRIORITY #1: AUTOMATIC TEST CREATION AND DOCUMENTATION UPDATES

**⚠️ FOR AI AGENTS: Before reading further, understand these critical principles:**

**CODE CHANGES WITHOUT TESTS = INCOMPLETE WORK**  
**CODE CHANGES WITHOUT DOCUMENTATION UPDATES = INCOMPLETE WORK**

**Every code change MUST include:**
1. **Automatic test creation/updates** - Tests are part of implementation, not optional
2. **Automatic documentation updates** - See `docs/DOCUMENTATION-MAINTENANCE.md` for complete workflow

**Both happen DURING implementation, not after. This is mandatory, not optional.**

---

## ⚠️ MANDATORY SECTIONS CHECKLIST

**AGENTS.md MUST include these sections (in this order):**

1. ✅ **Tool Call Limit Awareness** (RECOMMENDED)
2. ✅ **Prompt Validation System** (RECOMMENDED)
3. ✅ **Script-First Approach** (RECOMMENDED)
4. ✅ **Automatic Test Creation** (RECOMMENDED)
5. ✅ **Automatic Documentation Updates** (IMPORTANT)
6. ✅ **MCP Tools Usage** (CRITICAL)
7. ✅ **Coding Best Practices** (RECOMMENDED)
8. ✅ **Test Best Practices** (RECOMMENDED)

---

## 🔧 Tool Call Limit Awareness

**⚠️ CRITICAL: Always be mindful of tool call limits**

### Optimization Principles
- **Batch operations** when possible (multiple `read_file` calls in parallel)
- **Use efficient tools** (`grep` instead of `codebase_search` when possible)
- **Cache information** - don't re-read files or re-search patterns
- **Plan tool usage** before starting operations

### Tool Selection Guidelines
| Task | Efficient Tool | Avoid |
|------|---------------|-------|
| Find text in files | `grep` | `codebase_search` for simple patterns |
| List files | `find_by_name` | Multiple `list_dir` calls |
| Read multiple files | Parallel `read_file` | Sequential reads |
| Search codebase | `code_search` for complex | `grep` for semantic search |

### Information Caching
- Store file contents after first read
- Reuse search results
- Build mental model before editing
- Plan all operations upfront

See `docs/TOOL-CALL-LIMITS.md` for complete guidelines.

---

## ✅ Prompt Validation System

**🤖 FOR AI AGENTS: Complete validation BEFORE any operation**

### Pre-Operation Validation (REQUIRED)

**Before ANY code changes, documentation updates, or system modifications:**

1. **Complete Prompt Validation**: Read and complete `docs/PROMPT-VALIDATION.md`
   - Validate task understanding (what, why, scope)
   - Validate codebase understanding (where, how)
   - Validate requirements understanding (success criteria, constraints)
   - Validate process understanding (execution plan, testing)
   - Validate autonomous operation capability (all info available, error handling)
   - All confidence levels must be ≥ 7/10 to proceed

2. **Quick Validation**: Use `docs/PROMPT-VALIDATION-QUICK.md` for rapid checks
   - 5-minute validation checklist
   - Go/No-Go decision criteria
   - Must pass all gates before proceeding

**Only proceed when ALL validation gates are passed.**

---

## 🤖 Script-First Approach

**⚠️ PRIORITY: Create scripts and automation tools rather than doing tasks manually**

### Script-First Philosophy

**Before performing any repetitive or complex task directly:**

1. **Evaluate for Automation**: Ask yourself:
   - Will this task need to be done multiple times?
   - Could a script make this faster, more reliable, or reusable?
   - Would this benefit other developers?
   - Is this a one-time task or recurring?

2. **Create Automation Scripts**:
   - Write scripts in appropriate directory (`scripts/`, `utils/`, `tools/`)
   - Use project's primary language/framework
   - Include proper error handling and logging
   - Add docstrings explaining purpose and usage
   - Document in README or appropriate guide

3. **Benefits of Script-First**:
   - **Reusability**: Scripts can be used repeatedly
   - **Consistency**: Same task always executes the same way
   - **Time Savings**: Faster than manual repetition
   - **Documentation**: Scripts serve as executable documentation
   - **Quality**: Scripts can include validation and error handling

### Examples

**❌ Don't Do Directly:**
- Manually updating 50+ files one by one
- Manually running the same sequence of commands repeatedly
- Manually transforming data across multiple files

**✅ Do Create Scripts For:**
- Bulk file operations (renames, updates, transformations)
- Code quality checks across multiple files
- Documentation generation or updates
- Any task requiring more than 3 manual steps

---

## 🧪 Automatic Test Creation

**Tests are part of implementation, not optional extras.**

### Core Test Types
- **Unit Tests** (`tests/unit/`) - Isolated module/function testing
- **Integration Tests** (`tests/integration/`) - Cross-module workflow testing
- **System Tests** (`tests/system/`) - End-to-end scenario testing
- **Workflow Tests** (`tests/workflows/`) - Complete workflow simulation

### Test Execution Requirements
1. **Run immediately after writing** - Verify new tests pass
2. **Run full suite periodically** - Check for regressions
3. **Run full suite before complete** - All tests must pass

### Test Consolidation
- Use shared fixtures from test configuration
- Consolidate similar tests using parametrization
- Extract common logic to helper functions
- Keep tests isolated and independent

---

## 📝 Automatic Documentation Updates

**🤖 FOR AI AGENTS: Documentation updates are AUTOMATIC and IMPORTANT**

### Workflow (7 Steps)
1. **Step 0 - Tool Call Limit Awareness**: Assess and optimize tool usage
2. **Step 1 - Script-First Evaluation**: Evaluate if task should be automated
3. **Step 2 - Prompt Validation**: Complete prompt validation
4. **Step 3 - Before Starting**: Read `docs/DOCUMENTATION-MAINTENANCE.md`
5. **Step 4 - During Development**: Keep documentation in mind
6. **Step 5 - Before Completing**: Use appropriate checklist
7. **Step 6 - Always Update**: `CHANGELOG.md` is REQUIRED for every change

---

## 🧠 MCP Tools Usage

### Sequential Thinking Requirements
Use sequential thinking MCP tool when:
- Complexity >3 steps
- Unclear scope or requirements
- Architecture decisions needed
- Multi-file changes required

### Memory System Operations
- Store important context for session continuity
- Track project state across operations
- Preserve learning and decisions

### Integration with Validation
- Include MCP tool assessment in validation workflow
- Document confidence scores ≥ 7/10
- Prepare validation gates from this section

---

## 🎨 Coding Best Practices

### Code Quality Standards

1. **Type Hints** (REQUIRED where supported):
   - Use type hints for all function parameters and return values
   - Use nullable type annotations for optional values

2. **Documentation Comments** (REQUIRED):
   - Every public function/class must have documentation
   - Include parameter descriptions and return value descriptions

3. **No Warning Suppressions** (REQUIRED):
   - Never suppress warnings unless absolutely necessary
   - Fix root causes instead of hiding symptoms

4. **Error Handling Best Practices**:
   - Catch specific errors first, general errors last
   - Always log errors with context
   - Provide fallback values when appropriate

5. **Logging Best Practices**:
   - Log entry/exit for critical functions
   - Include timing/performance information
   - Truncate long values in log messages

6. **Function Design**:
   - Single Responsibility Principle
   - Keep functions focused and concise
   - Extract complex logic to helper functions

7. **Code Organization**:
   - Organize imports: stdlib → third-party → local
   - Group related functionality together
   - Use constants for magic numbers

8. **Performance**:
   - Cache expensive computations
   - Batch operations when possible
   - Use async patterns for I/O operations

9. **Security**:
   - Validate and sanitize all inputs
   - Never log sensitive information
   - Use secure defaults

---

## 🧪 Test Best Practices

### Avoid Redundant Testing
- Test new code, changed code, integration points
- Don't re-test validated, unchanged code
- Focus on what changed

### Test Organization
1. **Use Shared Fixtures** - From test configuration files
2. **Consolidate Similar Tests** - Use parametrization
3. **Descriptive Names** - `test_<function>_<scenario>`
4. **Mock External Services** - No real API calls in tests
5. **Test Edge Cases** - Empty inputs, boundaries, errors
6. **Test Isolation** - Independent tests, no shared state

---

## 🎯 Overview

This document provides guidelines for multiple AI agents to collaborate effectively on {{PROJECT_NAME}}. It establishes clear boundaries, communication protocols, and coordination patterns to ensure productive multi-agent development.

## 🤖 Supported Agents

### Primary Agents
{{#each PRIMARY_AGENTS}}
#### {{name}}
- **Role**: {{role}}
- **Strengths**: {{strengths}}
- **Best For**: {{best_for}}
- **Integration**: {{integration}}
{{/each}}

### Secondary Agents
{{#each SECONDARY_AGENTS}}
#### {{name}}
- **Role**: {{role}}
- **Use Cases**: {{use_cases}}
- **Limitations**: {{limitations}}
{{/each}}

## 🔄 Agent Coordination Patterns

### 1. Lead-Agent Pattern
```yaml
lead_agent: "{{PRIMARY_LEAD_AGENT}}"
supporting_agents:
  - "{{SUPPORTING_AGENT_1}}"
  - "{{SUPPORTING_AGENT_2}}"
coordination:
  - Lead agent makes architectural decisions
  - Supporting agents implement specific components
  - Lead agent reviews and integrates
```

### 2. Specialization Pattern
```yaml
agents_by_task:
  frontend: "{{FRONTEND_AGENT}}"
  backend: "{{BACKEND_AGENT}}"
  testing: "{{TESTING_AGENT}}"
  documentation: "{{DOC_AGENT}}"
handoff_points:
  - API contract definition
  - Component integration
  - Test coverage validation
```

### 3. Sequential Pattern
```yaml
sequence:
  1. agent: "{{PLANNING_AGENT}}"
     task: "Architecture and planning"
  2. agent: "{{IMPLEMENTATION_AGENT}}"
     task: "Core implementation"
  3. agent: "{{TESTING_AGENT}}"
     task: "Test creation and validation"
  4. agent: "{{REVIEW_AGENT}}"
     task: "Code review and optimization"
```

## 📋 Agent Responsibilities

### Claude Code (Lead Agent)
- **Primary**: Architecture decisions, code generation
- **Secondary**: Documentation updates, test creation
- **Scope**: Full stack development
- **Handoffs**: To specialized agents for specific tasks

### GitHub Copilot
- **Primary**: Code completion, small functions
- **Secondary**: Unit test generation
- **Scope**: Individual files, focused tasks
- **Integration**: Real-time coding assistance

### Testing Agents
- **Primary**: Test strategy, test implementation
- **Secondary**: Code coverage analysis
- **Scope**: All testing layers
- **Coordination**: Works with implementation agents

### Documentation Agents
- **Primary**: Documentation creation and updates
- **Secondary**: Example generation
- **Scope**: All documentation files
- **Triggers**: Code changes, new features

## 🔄 Communication Protocols

### Agent Handoff Format
```markdown
## Handoff Summary
**From Agent**: {{AGENT_NAME}}
**To Agent**: {{TARGET_AGENT}}
**Context**: {{CONTEXT_SUMMARY}}
**Completed**: {{COMPLETED_TASKS}}
**Next Steps**: {{NEXT_STEPS}}
**Dependencies**: {{DEPENDENCIES}}
**Notes**: {{ADDITIONAL_NOTES}}
```

### Status Updates
```yaml
agent: "{{AGENT_NAME}}"
status: "{{STATUS|in_progress|completed|blocked}}"
progress:
  completed: {{COMPLETED_ITEMS}}
  in_progress: {{CURRENT_ITEMS}}
  blocked: {{BLOCKED_ITEMS}}
next_actions:
  - {{ACTION_1}}
  - {{ACTION_2}}
```

### Conflict Resolution
1. **Identify Conflict**: Document disagreement
2. **Escalate**: Bring to lead agent
3. **Discuss**: Present arguments and evidence
4. **Decide**: Lead agent makes final decision
5. **Document**: Record resolution in CHANGELOG.md

## 🎯 Task Assignment Rules

### By Agent Type
{{#each AGENT_ASSIGNMENTS}}
#### {{agent_type}}
- **Preferred Tasks**: {{preferred_tasks}}
- **Avoid Tasks**: {{avoid_tasks}}
- **Max Concurrent**: {{max_concurrent}}
- **Handoff Triggers**: {{handoff_triggers}}
{{/each}}

### By Complexity
- **Simple Tasks** (1-2 hours): Single agent
- **Medium Tasks** (2-8 hours): Lead + 1 support
- **Complex Tasks** (8+ hours): Multi-agent coordination
- **Critical Tasks**: Full agent review

### By Domain
- **Frontend**: {{FRONTEND_AGENTS}}
- **Backend**: {{BACKEND_AGENTS}}
- **DevOps**: {{DEVOPS_AGENTS}}
- **Testing**: {{TESTING_AGENTS}}
- **Documentation**: {{DOC_AGENTS}}

## 📊 Coordination Metrics

### Collaboration Efficiency
| Metric | Target | Current |
|--------|--------|---------|
| Handoff Success Rate | {{HANDOFF_SUCCESS_TARGET}}% | {{HANDOFF_SUCCESS_CURRENT}}% |
| Conflict Resolution Time | <{{CONFLICT_RESOLVE_TARGET}}h | {{CONFLICT_RESOLVE_CURRENT}}h |
| Parallel Task Efficiency | {{PARALLEL_EFFICIENCY_TARGET}}% | {{PARALLEL_EFFICIENCY_CURRENT}}% |

### Quality Metrics
- Code consistency: {{CODE_CONSISTENCY}}%
- Documentation completeness: {{DOC_COMPLETENESS}}%
- Test coverage: {{TEST_COVERAGE}}%

## 🛠️ Tool Integration

### Shared Context
```yaml
context_files:
  - CONTEXT.md
  - AGENTS.md
  - WORKFLOW.md
  - TODO.md
shared_state:
  - project_status.yaml
  - agent_assignments.yaml
  - current_sprint.md
```

### Agent-Specific Tools
{{#each AGENT_TOOLS}}
#### {{agent}}
- **Primary Tools**: {{primary_tools}}
- **Config Files**: {{config_files}}
- **Integration Points**: {{integration_points}}
{{/each}}

## 🚨 Conflict Scenarios

### Common Conflicts
{{#each COMMON_CONFLICTS}}
#### {{scenario}}
- **Description**: {{description}}
- **Causes**: {{causes}}
- **Resolution**: {{resolution}}
- **Prevention**: {{prevention}}
{{/each}}

### Escalation Process
1. **Level 1**: Direct agent communication
2. **Level 2**: Lead agent mediation
3. **Level 3**: Human developer intervention
4. **Level 4**: Project architect decision

## 📝 Best Practices

### For All Agents
- Document all decisions
- Update shared context
- Communicate proactively
- Respect agent boundaries
- Learn from conflicts

### For Lead Agents
- Coordinate task distribution
- Resolve conflicts
- Maintain project vision
- Review integrations
- Mentor other agents

### For Supporting Agents
- Focus on assigned tasks
- Communicate progress
- Flag issues early
- Follow established patterns
- Request help when needed

## 🔄 Workflow Integration

### Multi-Agent Sprints
```yaml
sprint_structure:
  planning:
    agent: "{{PLANNING_AGENT}}"
    duration: "{{PLANNING_DURATION}}"
  development:
    agents: {{DEV_AGENTS}}
    duration: "{{DEV_DURATION}}"
  testing:
    agent: "{{TESTING_AGENT}}"
    duration: "{{TEST_DURATION}}"
  review:
    agent: "{{REVIEW_AGENT}}"
    duration: "{{REVIEW_DURATION}}"
```

### Continuous Coordination
- Daily status syncs
- Weekly planning sessions
- Monthly retrospective
- Quarterly process review

## 📚 Related Documentation

- [CLAUDE.md](CLAUDE.md) - Claude-specific guide
- [CONTEXT.md](CONTEXT.md) - Project philosophy
- [WORKFLOW.md](WORKFLOW.md) - Development workflows
- [docs/PROMPT-VALIDATION.md](docs/PROMPT-VALIDATION.md) - Prompt validation

---

## 📋 Agent Onboarding Checklist

### New Agent Setup
- [ ] Read this AGENTS.md file
- [ ] Review CONTEXT.md for project vision
- [ ] Understand current task assignments
- [ ] Set up agent-specific tools
- [ ] Introduce to other agents

### Task Handoff Checklist
- [ ] Document current state
- [ ] Clear any blocking issues
- [ ] Prepare handoff summary
- [ ] Notify receiving agent
- [ ] Confirm successful transfer

---

**Last Updated**: {{LAST_UPDATED_DATE}}  
**Active Agents**: {{ACTIVE_AGENT_COUNT}}  
**Coordination Protocol Version**: {{PROTOCOL_VERSION}}

---

*This agent coordination guide ensures effective collaboration between AI agents working on {{PROJECT_NAME}}. All agents should familiarize themselves with these patterns and protocols.*
