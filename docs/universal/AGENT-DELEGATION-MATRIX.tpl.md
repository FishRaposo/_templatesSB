# AGENT-DELEGATION-MATRIX.md - Who Calls Whom, When, and How

**Purpose**: Define delegation rules and trigger conditions for multi-agent coordination.
**Version**: 1.0
**Design**: Role-based delegation with strict boundaries and escalation paths

---

## 📋 DELEGATION MATRIX

| Situation / Trigger | Primary Agent | Delegates To | Trigger Conditions |
|---------------------|---------------|--------------|-------------------|
| **New feature request** | Architect | Builder → Tester | After architecture defined |
| **Minor code change** | Builder | Tester | Code modification complete |
| **Behavior bug** | Tester | Builder | If implementation incorrect |
| **Architecture bug** | Tester | Architect | If boundaries violated |
| **Large refactor** | Architect | Refactorer → Tester | Structural impact detected |
| **Migration** | Architect | Migration Engine + Refactorer | Multi-phase changes needed |
| **Docs outdated** | Doc Manager | Architect (if structural) | If mismatch detected |
| **Test coverage gap** | Tester | Builder | Missing tests |
| **API drift** | Architect | Doc Manager | Update API + docs |
| **Pattern violations** | Validator | Refactorer | Violates FRAMEWORK-PATTERNS |
| **Diff unsafe** | Validator | Refactorer | If patch is dangerous |
| **Merge conflict** | Validator | Architect | If architectural resolution needed |
| **Performance issue** | Tester | Builder | If implementation optimization needed |
| **Security vulnerability** | Validator | Architect | If architectural changes required |
| **Documentation inconsistency** | Doc Manager | Architect | If structural changes implied |

---

## 🎯 DELEGATION RULES

### Role Authority Boundaries
- **Only Architect** may update architecture or invariants
- **Only Builder** may generate core code
- **Only Refactorer** may modify existing code structure
- **Only Tester** may declare code valid or invalid
- **Only Doc Manager** may update documentation
- **Validator** sits above all and checks compliance

### Delegation Protocol
1. **Primary Agent** assesses situation
2. **Identifies** appropriate delegate based on matrix
3. **Creates handoff artifact** with context
4. **Transfers control** with clear expectations
5. **Monitors** delegate progress
6. **Validates** output before acceptance

### Escalation Paths
```
Level 1: Agent self-correction
Level 2: Peer agent delegation  
Level 3: Architect intervention
Level 4: Human oversight required
```

---

## 🔄 DELEGATION SCENARIOS

### Scenario 1: Feature Development
```
User Request → Architect (define) → Builder (implement) → Tester (verify) → Doc Manager (update) → Validator (check) → Merge
```

### Scenario 2: Bug Fix
```
Bug Report → Tester (analyze) → Builder (fix) → Tester (verify) → Doc Manager (update docs) → Validator (check) → Merge
```

### Scenario 3: Large Refactor
```
Refactor Request → Architect (plan) → Refactorer (execute) → Tester (verify) → Doc Manager (update) → Validator (check) → Merge
```

### Scenario 4: Migration
```
Migration Need → Architect (design) → Migration Engine (plan) → Refactorer (implement) → Tester (verify) → Doc Manager (update) → Validator (check) → Merge
```

---

## ⚡ TRIGGER CONDITIONS

### Automatic Triggers
- **Test failure** → Builder delegation
- **Architecture violation** → Architect escalation  
- **Documentation drift** → Doc Manager activation
- **Pattern violation** → Refactorer delegation
- **Safety filter trigger** → Immediate halt + Architect review

### Manual Triggers
- **Human request** → Direct agent assignment
- **Priority change** → Architect re-prioritization
- **Scope change** → Architect re-planning
- **Emergency fix** → Direct Builder/Refactorer assignment

### Conditional Triggers
- **If test coverage < threshold** → Tester → Builder
- **If diff size > limit** → Validator → Refactorer
- **If architecture impacted** → Any → Architect
- **If docs inconsistent** → Any → Doc Manager

---

## 🛡️ SAFETY CONSTRAINTS

### Delegation Limits
- **Max delegation depth**: 3 levels
- **Max handoff attempts**: 3 per agent
- **Max time per delegation**: 30 minutes
- **Max concurrent delegations**: 5 per work item

### Forbidden Delegations
- **Builder → Architect** (cannot delegate upward)
- **Tester → Doc Manager** (cannot skip validation)
- **Doc Manager → Builder** (cannot delegate code changes)
- **Validator → Any** (only escalates, doesn't delegate)

### Override Conditions
- **Human override** can bypass any delegation rule
- **Emergency override** allows direct agent assignment
- **Architect override** can restructure delegation chain
- **System override** can halt all delegations

---

## 📊 DELEGATION METRICS

### Success Indicators
- **Delegation accuracy rate**: % of correct agent assignments
- **Handoff success rate**: % of successful handoffs
- **Escalation frequency**: How often escalation is needed
- **Resolution time**: Average time per delegation

### Failure Modes
- **Wrong agent assigned**: Restart delegation chain
- **Handoff artifact incomplete**: Return to source agent
- **Delegate cannot complete**: Escalate to next level
- **Circular delegation**: System intervention required

---

## 🔄 DELEGATION WORKFLOW

### Standard Delegation Flow
```yaml
delegation_event:
  trigger: [situation_type]
  primary_agent: [agent_name]
  delegate_agent: [agent_name]
  handoff_artifact: [artifact_data]
  expected_outcome: [success_criteria]
  timeout: [time_limit]
  escalation_path: [next_level]
```

### Delegation Acceptance
1. **Receive handoff artifact**
2. **Validate entry conditions**
3. **Confirm role appropriateness**
4. **Acknowledge delegation**
5. **Begin work**

### Delegation Completion
1. **Complete assigned tasks**
2. **Generate completion artifact**
3. **Validate exit conditions**
4. **Hand off to next agent or return to primary**
5. **Log delegation outcome**

---

## 🚀 ADVANCED DELEGATION

### Parallel Delegation
- **Multiple Builders** under one Architect
- **Parallel Testers** for large test suites
- **Coordinated Refactorers** for complex changes

### Conditional Delegation
- **If-then delegation** based on analysis results
- **Fallback delegation** if primary fails
- **Adaptive delegation** based on agent performance

### Learning Delegation
- **Historical success rates** inform future assignments
- **Agent specialization** tracking
- **Pattern recognition** for optimal delegation

---

**This delegation matrix ensures clear, deterministic agent coordination with strict role boundaries and comprehensive escalation protocols.**
