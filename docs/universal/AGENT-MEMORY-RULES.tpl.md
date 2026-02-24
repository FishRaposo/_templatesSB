# AGENT-MEMORY-RULES.md - Role-Based Memory Model

**Purpose**: Define how each agent carries and transfers internal state across the multi-agent pipeline.
**Version**: 1.0
**Design**: Ephemeral memory with clean handoff tokens, preventing cross-role contamination

---

## 🧠 MEMORY TYPES

### 1. Local Memory
Information relevant only to the current task:
- Selected files
- Architectural context  
- Invariants
- No-go zones
- Patch sets
- Temporary calculations

**Scope**: Agent-specific, task duration only
**Persistence**: Purged on handoff
**Access**: Read/write within agent only

### 2. Handoff Memory
Information explicitly packaged for next agent:

#### Architect → Builder:
```yaml
handoff_memory:
  from: "Architect"
  to: "Builder"
  invariants: [list_of_constraints]
  module_boundaries: [defined_boundaries]
  allowed_dependencies: [permitted_imports]
  folder_structure: [directory_layout]
  no_go_zones: [restricted_areas]
  tier_constraints: [mvp/core/full_rules]
```

#### Builder → Tester:
```yaml
handoff_memory:
  from: "Builder" 
  to: "Tester"
  new_functions: [implemented_functions]
  expected_behavior: [behavior_specifications]
  modified_flows: [changed_workflows]
  test_skeletons: [generated_test_templates]
  implementation_notes: [technical_decisions]
```

#### Tester → Doc Manager:
```yaml
handoff_memory:
  from: "Tester"
  to: "Doc Manager"
  behavior_changes: [detected_modifications]
  new_test_cases: [created_tests]
  uncovered_paths: [missing_coverage]
  validation_results: [test_outcomes]
  regression_notes: [compatibility_issues]
```

#### Doc Manager → Validator:
```yaml
handoff_memory:
  from: "Doc Manager"
  to: "Validator"
  documentation_updates: [changed_docs]
  api_changes: [interface_modifications]
  migration_entries: [migration_records]
  roadmap_adjustments: [plan_updates]
  parity_status: [doc_code_sync]
```

**Scope**: Forward-only transfer
**Persistence**: Consumed by target agent
**Access**: Read-only for target agent

### 3. Forbidden Memory
Agents may NOT carry:
- Personal preferences
- Lingering architectural opinions
- Accidental interpretations
- Partial code from previous tasks
- Undocumented assumptions
- Cross-agent role knowledge
- Implementation biases

**Enforcement**: System-level validation prevents transfer

### 4. Global Memory (Documented State)
This is the only persistent memory across agents:
- Blueprint
- Architecture  
- Documentation
- Patterns
- Roadmap
- Tests
- Configuration

**Scope**: System-wide, persistent
**Persistence**: Stored in files, version controlled
**Access**: Read-only for agents, write-only through designated processes

---

## 🔄 MEMORY TRANSFER PROTOCOL

### Handoff Generation
```python
def generate_handoff_memory(source_agent, target_agent, task_context):
    """Generate clean handoff memory token"""
    memory_token = {
        'metadata': {
            'source': source_agent.name,
            'target': target_agent.name,
            'timestamp': iso_timestamp(),
            'task_id': task_context.id,
            'phase': task_context.phase
        },
        'context': extract_relevant_context(source_agent, target_agent),
        'constraints': extract_constraints(source_agent),
        'artifacts': collect_outputs(source_agent),
        'validation': validate_handoff_completeness()
    }
    return memory_token
```

### Memory Validation
```python
def validate_handoff_memory(memory_token, target_agent):
    """Validate memory token is complete and appropriate"""
    required_fields = get_required_fields(target_agent)
    forbidden_content = scan_forbidden_memory(memory_token)
    
    if not all(field in memory_token for field in required_fields):
        return False, "Missing required fields"
    
    if forbidden_content:
        return False, f"Forbidden memory detected: {forbidden_content}"
    
    return True, "Memory token valid"
```

### Memory Consumption
```python
def consume_handoff_memory(memory_token, consuming_agent):
    """Load handoff memory into agent's local context"""
    # Validate token is for this agent
    if memory_token['metadata']['target'] != consuming_agent.name:
        raise MemoryError("Invalid handoff target")
    
    # Load into local memory
    consuming_agent.load_context(memory_token['context'])
    consuming_agent.apply_constraints(memory_token['constraints'])
    consuming_agent.receive_artifacts(memory_token['artifacts'])
    
    # Clear source agent's local memory
    clear_agent_memory(memory_token['metadata']['source'])
```

---

## 🛡️ MEMORY SAFETY RULES

### Isolation Requirements
1. **No backward memory transfer** - agents cannot send memory back to previous agents
2. **No cross-agent memory sharing** - agents cannot access other agents' memory directly
3. **No persistent local memory** - all local memory purged on handoff
4. **No undocumented state** - all memory must be in structured format

### Contamination Prevention
```yaml
memory_safety_check:
  - no_role_bleeding: true
  - no_preferences: true  
  - no_undocumented_assumptions: true
  - no_cross_agent_references: true
  - no_persistent_biases: true
  - clean_handoff: true
```

### Memory Sanitization
```python
def sanitize_memory(agent_memory):
    """Remove forbidden content before handoff"""
    sanitized = {
        'task_context': filter_task_context(agent_memory),
        'technical_decisions': extract_decisions(agent_memory),
        'outputs': collect_artifacts(agent_memory),
        'constraints': extract_constraints(agent_memory)
    }
    
    # Remove forbidden elements
    remove_personal_preferences(sanitized)
    remove_implementation_biases(sanitized)
    remove_undocumented_assumptions(sanitized)
    
    return sanitized
```

---

## 📋 AGENT-SPECIFIC MEMORY RULES

### Architect Agent Memory
**Allowed**: Blueprint interpretations, architectural decisions, invariants
**Forbidden**: Implementation preferences, code style opinions, tool choices
**Handoff Focus**: Constraints and boundaries only

### Builder Agent Memory  
**Allowed**: Implementation details, code patterns, technical decisions
**Forbidden**: Architectural opinions, design preferences, future plans
**Handoff Focus**: Code changes and behavior specifications

### Tester Agent Memory
**Allowed**: Test results, behavior analysis, coverage gaps
**Forbidden**: Implementation opinions, architectural judgments
**Handoff Focus**: Validation outcomes and quality metrics

### Doc Manager Agent Memory
**Allowed**: Documentation changes, API updates, migration notes
**Forbidden**: Code implementation details, architectural preferences
**Handoff Focus**: Documentation status and updates

### Refactorer Agent Memory
**Allowed**: Refactoring plans, structural changes, migration steps
**Forbidden**: New feature ideas, architectural redesigns
**Handoff Focus**: Structural modifications and impact analysis

---

## 🔄 MEMORY LIFECYCLE

### Memory Creation
1. **Agent initializes** with empty local memory
2. **Task context loaded** from global memory
3. **Working memory built** during task execution
4. **Handoff memory prepared** at completion

### Memory Transfer
1. **Source agent** generates handoff token
2. **System validates** token completeness
3. **Target agent** receives and validates token
4. **Memory consumed** and local memory updated
5. **Source memory** purged

### Memory Cleanup
```python
def cleanup_agent_memory(agent_name):
    """Complete memory cleanup for agent"""
    clear_local_memory(agent_name)
    clear_handoff_buffers(agent_name)
    clear_temporary_state(agent_name)
    log_memory_cleanup(agent_name, timestamp())
```

---

## 📊 MEMORY MONITORING

### Memory Metrics
- **Local memory size**: KB per agent
- **Handoff token size**: KB per transfer
- **Memory validation success rate**: % of clean transfers
- **Memory contamination incidents**: Count per day
- **Memory cleanup efficiency**: % of successful cleanups

### Memory Auditing
```yaml
memory_audit:
  agent: [agent_name]
  timestamp: [audit_time]
  local_memory_size: [size_kb]
  handoff_tokens_created: [count]
  memory_violations: [count]
  cleanup_success_rate: [percentage]
```

---

## 🚨 MEMORY VIOLATION RECOVERY

### Violation Detection
```python
def detect_memory_violations(agent_memory):
    """Scan for forbidden memory content"""
    violations = []
    
    if has_role_bleeding(agent_memory):
        violations.append("Role bleeding detected")
    
    if has_undocumented_assumptions(agent_memory):
        violations.append("Undocumented assumptions found")
    
    if has_persistent_biases(agent_memory):
        violations.append("Persistent biases detected")
    
    return violations
```

### Recovery Protocol
1. **Halt agent execution** immediately
2. **Isolate contaminated memory**
3. **Reset agent to clean state**
4. **Regenerate handoff from approved sources**
5. **Resume with sanitized memory**

---

## 🔧 MEMORY OPTIMIZATION

### Efficient Memory Usage
- **Lazy loading** of global memory
- **Compression** of handoff tokens
- **Caching** of frequently accessed patterns
- **Garbage collection** of unused memory

### Performance Tuning
```python
def optimize_memory_usage():
    """Optimize memory system performance"""
    compress_handoff_tokens()
    cache_common_patterns()
    implement_lazy_loading()
    tune_garbage_collection()
    monitor_memory_metrics()
```

---

**This memory model ensures clean, deterministic agent behavior with strict isolation and comprehensive contamination prevention.**
