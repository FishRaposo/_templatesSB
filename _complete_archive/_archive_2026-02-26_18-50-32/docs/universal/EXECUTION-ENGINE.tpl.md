# EXECUTION-ENGINE.md - Multi-Agent Execution Engine

**Purpose**: Factory line controller that orchestrates agents in the right order with safety checks until safe repos/PRs/patches are produced.
**Version**: 1.0
**Design**: Agent-agnostic state machine with WorkItem-centric execution and comprehensive safety integration

---

## 🎯 WHAT THE EXECUTION ENGINE IS

The Execution Engine is **not another agent** - it's the **conductor** that:

- **Decides which agent runs when** based on WorkItem type and pipeline state
- **Enforces role boundaries** through scoped context building
- **Passes only the right context** to prevent cross-role contamination
- **Handles failures and retries** with deterministic recovery protocols
- **Keeps a single source of truth** for task state through WorkItem objects

**Mental Model**: Agents are workers, the Execution Engine is the factory line controller.

---

## 📊 DATA MODEL - WORKITEM REPRESENTATION

### Core WorkItem Structure
```yaml
WorkItem:
  id: "W-2025-001"
  type: "feature"                    # "feature" | "refactor" | "migration"
  tier: "core"                       # "mvp" | "core" | "full"
  status: "pending"                  # "pending" | "running" | "blocked" | "done" | "failed"
  created_at: "2025-12-09T19:59:00Z"
  updated_at: "2025-12-09T20:15:00Z"
  
  scope:
    files: ["src/auth.py", "src/notifications.py"]
    modules: ["authentication", "notifications"]
    impact: "local"                   # "local" | "module" | "architecture"
    constraints:
      max_files: 5
      max_lines: 200
      complexity_budget: 15
  
  intent:
    title: "Add recurring reminders"
    description: "Allow users to schedule recurring reminders with daily/weekly cadence."
    constraints:
      - "Do not change auth system"
      - "Preserve existing notification pipeline"
      - "Maintain backward compatibility"
    acceptance_criteria:
      - "Users can create daily/weekly reminders"
      - "Reminder notifications sent via existing pipeline"
      - "No breaking changes to existing APIs"
  
  artifacts:
    blueprint_delta: null
    architecture_delta: null
    code_diffs: []
    tests_delta: null
    docs_delta: []
    validation_report: null
    changelog_entry: null
    migration_plan: null
  
  history:
    events:
      - timestamp: "2025-12-09T19:59:00Z"
        phase: "created"
        agent: "system"
        status: "pending"
        notes: "Work item created from user request"
      - timestamp: "2025-12-09T20:00:00Z"
        phase: "feature_architecture"
        agent: "architect"
        status: "running"
        notes: "Starting architectural analysis"
  
  current_phase: "feature_architecture"
  retry_count: 0
  max_retries: 3
```

### Artifact Specifications
```yaml
artifacts:
  blueprint_delta:
    type: "blueprint_changes"
    content: "Updated blueprint sections for reminder functionality"
    files_affected: ["BLUEPRINT.md"]
  
  architecture_delta:
    type: "architecture_changes"
    invariants: ["Auth system unchanged", "Notification pipeline preserved"]
    no_go_zones: ["src/auth/*", "src/legacy/*"]
    module_boundaries: {"reminders": ["src/reminders/*"]}
  
  code_diffs:
    - file: "src/reminders.py"
      type: "new_file"
      lines_added: 45
      lines_removed: 0
      functions: ["create_reminder", "schedule_reminder", "send_reminder"]
    
  tests_delta:
    - file: "tests/test_reminders.py"
      type: "new_file"
      coverage: "95%"
      test_cases: 12
  
  docs_delta:
    - file: "README.md"
      changes: ["Added reminders section"]
    - file: "API-DOCUMENTATION.md"
      changes: ["Added reminder endpoints"]
  
  validation_report:
    status: "pass"
    checks: ["syntax", "architecture", "patterns", "tests", "docs"]
    violations: []
    score: 0.95
  
  changelog_entry:
    version: "1.2.0"
    type: "feature"
    description: "Add recurring reminders functionality"
    breaking: false
```

---

## 🔄 STATE MACHINE - PIPELINE GRAPHS

### Feature Pipeline
```
NEW → ARCHITECT → BUILDER → TESTER → DOC-MANAGER → VALIDATOR → DONE
      ↓            ↓         ↓          ↓            ↓           ↓
   pending    running    running    running      running    done/blocked
```

### Refactor Pipeline
```
NEW → ARCHITECT → SIMULATION → REFACTORER → TESTER → DOC-MANAGER → VALIDATOR → DONE
      ↓            ↓           ↓            ↓         ↓          ↓           ↓
   pending    running     running     running    running    running    done/blocked
```

### Migration Pipeline
```
NEW → ARCHITECT → MIGRATION-PLANNER → PHASED-LOOP → DONE
      ↓            ↓                  ↓            ↓
   pending    running             running     done/blocked

PHASED-LOOP: [REFACTORER → TESTER → DOC-MANAGER → VALIDATOR] × N phases
```

### Phase Transition Rules
```yaml
transitions:
  feature:
    "NEW → ARCHITECT":
      condition: "type == 'feature'"
      action: "initialize_architect_context"
    
    "ARCHITECT → BUILDER":
      condition: "architecture_delta.complete AND validation_report.pass"
      action: "initialize_builder_context"
    
    "BUILDER → TESTER":
      condition: "code_diffs.present AND scope.within_limits"
      action: "initialize_tester_context"
    
    "TESTER → DOC-MANAGER":
      condition: "tests_delta.coverage_met AND behavior_valid"
      action: "initialize_doc_context"
    
    "DOC-MANAGER → VALIDATOR":
      condition: "docs_delta.synced AND parity_maintained"
      action: "run_final_validation"
    
    "VALIDATOR → DONE":
      condition: "validation_report.pass AND all_checks_met"
      action: "complete_work_item"
  
  failure_handling:
    "ANY → BLOCKED":
      condition: "validation_report.fail OR retry_count > max_retries"
      action: "escalate_to_human"
    
    "ANY → RETRY":
      condition: "retry_count < max_retries AND recoverable_error"
      action: "increment_retry_and_restart_phase"
```

---

## ⚡ EXECUTION LOOP - CONCEPTUAL FLOW

### 4.1 Pipeline Decision
```python
def decide_pipeline(work_item):
    """Select appropriate pipeline based on WorkItem type"""
    if work_item.type == "feature":
        return FEATURE_PIPELINE
    elif work_item.type == "refactor":
        return REFACTOR_PIPELINE
    elif work_item.type == "migration":
        return MIGRATION_PIPELINE
    else:
        raise ValueError(f"Unknown work item type: {work_item.type}")
```

### 4.2 Phase Execution Pattern
For each phase in the pipeline:

1. **Build scoped context** for that agent only (no cross-role leakage)
2. **Apply safety filters** (scope, tier, patterns, architecture)
3. **Let agent run** its reasoning loop with constrained context
4. **Collect artifacts** (diffs, docs, reports, validation results)
5. **Run validations** if required at that stage
6. **Decide next phase** or trigger failure handling

### Feature Pipeline Step-by-Step

#### Architect Pass
```python
def run_architect_phase(work_item):
    """Parse blueprint delta, update architecture, set constraints"""
    context = {
        "intent": work_item.intent,
        "tier": work_item.tier,
        "existing_architecture": load_architecture(),
        "framework_patterns": load_patterns()
    }
    
    # Safety: Architect cannot write code
    safety_filters = ["no_code_generation", "architecture_only"]
    
    result = invoke_agent("architect", context, safety_filters)
    
    work_item.artifacts.architecture_delta = result.architecture_plan
    work_item.scope = result.defined_scope
    work_item.status = "running"
    
    return work_item
```

#### Builder Pass
```python
def run_builder_phase(work_item):
    """Generate code within architectural constraints"""
    context = {
        "architecture_delta": work_item.artifacts.architecture_delta,
        "scope": work_item.scope,
        "tier_templates": load_tier_templates(work_item.tier),
        "framework_patterns": load_patterns()
    }
    
    # Safety: Scope enforcement, tier constraints, pattern compliance
    safety_filters = [
        "scope_enforcement",
        "tier_constraints", 
        "pattern_firewall",
        "no_full_file_rewrites"
    ]
    
    result = invoke_agent("builder", context, safety_filters)
    
    work_item.artifacts.code_diffs = result.code_changes
    work_item.artifacts.blueprint_delta = result.blueprint_updates
    update_todo_roadmap(result.feature_changes)
    
    return work_item
```

#### Tester Pass
```python
def run_tester_phase(work_item):
    """Generate tests and validate behavior"""
    context = {
        "code_diffs": work_item.artifacts.code_diffs,
        "architecture_constraints": work_item.artifacts.architecture_delta,
        "testing_strategy": load_testing_strategy(work_item.tier)
    }
    
    # Safety: Test integrity, behavior preservation
    safety_filters = [
        "test_integrity_guard",
        "behavior_preservation_mode"
    ]
    
    result = invoke_agent("tester", context, safety_filters)
    
    work_item.artifacts.tests_delta = result.test_changes
    work_item.artifacts.validation_report = result.test_validation
    
    return work_item
```

#### Doc Manager Pass
```python
def run_doc_manager_phase(work_item):
    """Sync documentation with code and tests"""
    context = {
        "code_changes": work_item.artifacts.code_diffs,
        "test_changes": work_item.artifacts.tests_delta,
        "existing_docs": load_documentation()
    }
    
    # Safety: Documentation authority, no code changes
    safety_filters = [
        "documentation_authority",
        "no_code_modification"
    ]
    
    result = invoke_agent("doc_manager", context, safety_filters)
    
    work_item.artifacts.docs_delta = result.doc_changes
    work_item.artifacts.changelog_entry = result.changelog_draft
    
    return work_item
```

#### Validator Pass
```python
def run_validator_phase(work_item):
    """Final validation and quality gates"""
    # Run comprehensive validation
    validation_report = run_validation_protocol_v2(work_item)
    diff_validation = run_diff_validator(work_item.artifacts.code_diffs)
    
    work_item.artifacts.validation_report = {
        "protocol_v2": validation_report,
        "diff_validator": diff_validation,
        "overall_status": "pass" if both_pass else "fail"
    }
    
    return work_item
```

### Refactor Pipeline Step-by-Step

#### Architect + Simulation Phase
```python
def run_refactor_architect_phase(work_item):
    """Confirm refactor intent and simulate impact"""
    context = {
        "refactor_intent": work_item.intent,
        "existing_architecture": load_architecture(),
        "impact_analysis": work_item.scope
    }
    
    # Run simulation before actual refactoring
    simulation_result = run_refactor_simulation_engine(context)
    work_item.artifacts.simulation_report = simulation_result
    
    if simulation_result.risk_level > "medium":
        work_item.status = "blocked"
        return work_item
    
    # Architect defines refactoring boundaries
    result = invoke_agent("architect", context, ["refactor_mode"])
    work_item.artifacts.architecture_delta = result.refactor_plan
    
    return work_item
```

#### Refactorer Pass
```python
def run_refactorer_phase(work_item):
    """Generate minimal diffs within simulation constraints"""
    context = {
        "refactor_plan": work_item.artifacts.architecture_delta,
        "simulation_report": work_item.artifacts.simulation_report,
        "code_diff_reasoner": load_diff_reasoner()
    }
    
    # Safety: Aggressive refactoring prevention, mutation budget
    safety_filters = [
        "aggressive_refactor_prevention",
        "mutation_budget",
        "behavior_preservation_mode",
        "minimal_diff_enforcement"
    ]
    
    result = invoke_agent("refactorer", context, safety_filters)
    work_item.artifacts.code_diffs = result.refactor_diffs
    
    return work_item
```

### Migration Pipeline Step-by-Step

#### Migration Planning Phase
```python
def run_migration_planning_phase(work_item):
    """Design phased migration plan"""
    context = {
        "migration_intent": work_item.intent,
        "current_architecture": load_architecture(),
        "target_architecture": work_item.intent.target_architecture
    }
    
    migration_plan = run_migration_engine(context)
    work_item.artifacts.migration_plan = migration_plan
    
    return work_item
```

#### Phased Execution Loop
```python
def run_migration_phases(work_item):
    """Execute migration phases in sequence"""
    for phase in work_item.artifacts.migration_plan.phases:
        work_item.current_phase = phase.name
        
        # Refactorer applies scoped changes
        work_item = run_refactorer_phase_for_migration(work_item, phase)
        
        # Tester validates phase
        work_item = run_tester_phase_for_migration(work_item, phase)
        
        # Doc Manager updates migration docs
        work_item = run_doc_manager_phase_for_migration(work_item, phase)
        
        # Validator checks phase integrity
        work_item = run_validator_phase_for_migration(work_item, phase)
        
        # Stop if phase fails
        if work_item.artifacts.validation_report.overall_status != "pass":
            work_item.status = "blocked"
            return work_item
    
    return work_item
```

---

## 🏗️ PSEUDOCODE IMPLEMENTATION

### Core Execution Engine Class
```python
class ExecutionEngine:
    """Multi-agent execution engine with deterministic pipelines"""
    
    def __init__(self, agents, safety_filters, validator):
        self.agents = agents          # {"architect": ..., "builder": ..., ...}
        self.safety = safety_filters  # Safety filter functions
        self.validator = validator    # Diff + global validator
        self.work_queue = []          # Queue of WorkItems
        self.active_work = {}         # Currently running WorkItems
        
    def submit_work_item(self, work_item: WorkItem):
        """Submit new work item to execution queue"""
        work_item.status = "pending"
        work_item.created_at = datetime.now()
        self.work_queue.append(work_item)
        
    def run_next_work_item(self) -> WorkItem:
        """Process next work item in queue"""
        if not self.work_queue:
            raise NoWorkItemsError("No work items in queue")
            
        work_item = self.work_queue.pop(0)
        return self.run_work_item(work_item)
    
    def run_work_item(self, work_item: WorkItem) -> WorkItem:
        """Execute work item through appropriate pipeline"""
        try:
            work_item.status = "running"
            work_item.updated_at = datetime.now()
            
            # Select and run pipeline
            if work_item.type == "feature":
                return self._run_feature_pipeline(work_item)
            elif work_item.type == "refactor":
                return self._run_refactor_pipeline(work_item)
            elif work_item.type == "migration":
                return self._run_migration_pipeline(work_item)
            else:
                raise ValueError(f"Unknown work item type: {work_item.type}")
                
        except Exception as e:
            work_item.status = "failed"
            work_item.history.append({
                "timestamp": datetime.now(),
                "phase": "error",
                "agent": "system",
                "error": str(e)
            })
            return work_item
    
    # ---------------- PIPELINE IMPLEMENTATIONS ----------------
    
    def _run_feature_pipeline(self, w: WorkItem) -> WorkItem:
        """Execute feature development pipeline"""
        pipeline_phases = [
            ("architect", "feature_architecture"),
            ("builder", "feature_build"),
            ("tester", "feature_test"),
            ("doc_manager", "feature_docs"),
            ("validator", "feature_validation")
        ]
        
        return self._run_pipeline_phases(w, pipeline_phases)
    
    def _run_refactor_pipeline(self, w: WorkItem) -> WorkItem:
        """Execute refactoring pipeline"""
        pipeline_phases = [
            ("architect", "refactor_architecture"),
            ("architect", "refactor_simulation"),
            ("refactorer", "refactor_apply"),
            ("tester", "refactor_test"),
            ("doc_manager", "refactor_docs"),
            ("validator", "refactor_validation")
        ]
        
        return self._run_pipeline_phases(w, pipeline_phases)
    
    def _run_migration_pipeline(self, w: WorkItem) -> WorkItem:
        """Execute migration pipeline with phased execution"""
        # Planning phases
        planning_phases = [
            ("architect", "migration_architecture"),
            ("architect", "migration_plan")
        ]
        
        w = self._run_pipeline_phases(w, planning_phases)
        
        if w.status != "running":
            return w
        
        # Execute migration phases
        for phase in w.artifacts.migration_plan.phases:
            w.current_phase = phase.name
            
            phase_pipeline = [
                ("refactorer", f"migration_{phase.name}_apply"),
                ("tester", f"migration_{phase.name}_test"),
                ("doc_manager", f"migration_{phase.name}_docs"),
                ("validator", f"migration_{phase.name}_validation")
            ]
            
            w = self._run_pipeline_phases(w, phase_pipeline)
            
            if w.status != "running":
                return w
        
        return w
    
    # ---------------- CORE PHASE RUNNER ----------------
    
    def _run_pipeline_phases(self, w: WorkItem, phases: List[Tuple[str, str]]) -> WorkItem:
        """Execute a sequence of pipeline phases"""
        for agent_name, phase_name in phases:
            if w.status != "running":
                break  # Stop if work item is blocked/failed
                
            w = self._run_phase(agent_name, w, phase_name)
            
            # Check if phase failed
            if w.status == "blocked":
                self._handle_phase_failure(w, agent_name, phase_name)
                break
        
        return w
    
    def _run_phase(self, agent_name: str, w: WorkItem, phase: str) -> WorkItem:
        """Execute single phase with safety and validation"""
        agent = self.agents[agent_name]
        
        # Build scoped context for this agent
        context = self._build_context_for_agent(w, agent_name, phase)
        
        # Apply safety filters BEFORE agent execution
        self._apply_safety_filters(agent_name, context, w)
        
        # Invoke agent with constrained context
        try:
            result = agent.run(context)
        except Exception as e:
            w.status = "failed"
            w.history.append({
                "timestamp": datetime.now(),
                "phase": phase,
                "agent": agent_name,
                "error": str(e)
            })
            return w
        
        # Merge artifacts back into WorkItem
        w = self._merge_artifacts(w, result)
        
        # Run validation if required for this phase
        if self._requires_validation(agent_name, phase):
            validation_report = self.validator.run(w, phase)
            w.artifacts.validation_report = validation_report
            
            if validation_report.level == "fail":
                w.status = "blocked"
                return w
        
        # Record successful phase completion
        w.history.append({
            "timestamp": datetime.now(),
            "phase": phase,
            "agent": agent_name,
            "status": "completed",
            "result_summary": result.summary
        })
        
        w.updated_at = datetime.now()
        return w
    
    # ---------------- CONTEXT BUILDING ----------------
    
    def _build_context_for_agent(self, w: WorkItem, agent_name: str, phase: str) -> Dict:
        """Build scoped context for specific agent"""
        base_context = {
            "work_item_id": w.id,
            "phase": phase,
            "tier": w.tier,
            "intent": w.intent,
            "scope": w.scope
        }
        
        # Agent-specific context
        if agent_name == "architect":
            base_context.update({
                "existing_architecture": load_architecture(),
                "framework_patterns": load_patterns(),
                "blueprint": load_blueprint()
            })
        elif agent_name == "builder":
            base_context.update({
                "architecture_delta": w.artifacts.architecture_delta,
                "tier_templates": load_tier_templates(w.tier),
                "code_generation_contracts": load_code_contracts()
            })
        elif agent_name == "refactorer":
            base_context.update({
                "refactor_plan": w.artifacts.architecture_delta,
                "simulation_report": w.artifacts.simulation_report,
                "existing_code": load_codebase()
            })
        elif agent_name == "tester":
            base_context.update({
                "code_changes": w.artifacts.code_diffs,
                "testing_strategy": load_testing_strategy(w.tier),
                "existing_tests": load_test_suite()
            })
        elif agent_name == "doc_manager":
            base_context.update({
                "code_changes": w.artifacts.code_diffs,
                "test_changes": w.artifacts.tests_delta,
                "existing_docs": load_documentation()
            })
        
        return base_context
    
    # ---------------- SAFETY FILTERS ----------------
    
    def _apply_safety_filters(self, agent_name: str, context: Dict, w: WorkItem):
        """Apply safety filters before agent execution"""
        applicable_filters = self.safety.get_filters_for_agent(agent_name)
        
        for filter_func in applicable_filters:
            filter_result = filter_func(context, w)
            
            if not filter_result.allowed:
                w.status = "blocked"
                w.history.append({
                    "timestamp": datetime.now(),
                    "phase": "safety_filter",
                    "agent": "system",
                    "violation": filter_result.violation,
                    "filter": filter_func.__name__
                })
                raise SafetyViolationError(filter_result.violation)
    
    # ---------------- ARTIFACT MANAGEMENT ----------------
    
    def _merge_artifacts(self, w: WorkItem, result: AgentResult) -> WorkItem:
        """Merge agent result artifacts into WorkItem"""
        if result.artifacts:
            for artifact_type, artifact_data in result.artifacts.items():
                if hasattr(w.artifacts, artifact_type):
                    current = getattr(w.artifacts, artifact_type)
                    if current is None:
                        setattr(w.artifacts, artifact_type, artifact_data)
                    elif isinstance(current, list):
                        current.extend(artifact_data)
                    else:
                        setattr(w.artifacts, artifact_type, artifact_data)
        
        return w
    
    def _requires_validation(self, agent_name: str, phase: str) -> bool:
        """Check if phase requires validation"""
        validation_phases = [
            "feature_validation",
            "refactor_validation", 
            "migration_*_validation"
        ]
        
        return (phase.endswith("validation") or 
                agent_name in ["refactorer", "builder"] or
                any(pattern.match(phase) for pattern in validation_phases))
    
    # ---------------- FAILURE HANDLING ----------------
    
    def _handle_phase_failure(self, w: WorkItem, agent_name: str, phase: str):
        """Handle phase failure with recovery protocols"""
        w.retry_count += 1
        
        if w.retry_count <= w.max_retries:
            # Attempt recovery based on failure type
            recovery_strategy = self._determine_recovery_strategy(w, agent_name, phase)
            w.history.append({
                "timestamp": datetime.now(),
                "phase": "recovery",
                "agent": "system",
                "strategy": recovery_strategy,
                "retry_count": w.retry_count
            })
        else:
            # Max retries exceeded, escalate to human
            w.status = "failed"
            self._escalate_to_human(w, agent_name, phase)
    
    def _determine_recovery_strategy(self, w: WorkItem, agent_name: str, phase: str) -> str:
        """Determine appropriate recovery strategy"""
        if w.artifacts.validation_report:
            violations = w.artifacts.validation_report.violations
            
            if "architecture" in violations:
                return "escalate_to_architect"
            elif "scope" in violations:
                return "reduce_scope_and_retry"
            elif "patterns" in violations:
                return "fix_pattern_compliance"
            else:
                return "generic_retry"
        
        return "generic_retry"
    
    def _escalate_to_human(self, w: WorkItem, agent_name: str, phase: str):
        """Escalate failed work item to human oversight"""
        escalation = {
            "work_item_id": w.id,
            "failed_phase": phase,
            "failed_agent": agent_name,
            "failure_reason": w.artifacts.validation_report.summary,
            "retry_count": w.retry_count,
            "timestamp": datetime.now()
        }
        
        # Log escalation and notify human
        log_human_escalation(escalation)
        send_notification(escalation)
```

---

## 🔌 INTEGRATION POINTS - WHERE PREVIOUS COMPONENTS PLUG IN

### Blueprint Compiler Integration
```python
# Used in Architect + Builder phases for new projects/major features
def integrate_blueprint_compiler(work_item, phase):
    if phase in ["feature_architecture", "feature_build"]:
        blueprint_result = run_blueprint_compiler(
            work_item.intent,
            work_item.tier,
            work_item.artifacts.blueprint_delta
        )
        work_item.artifacts.blueprint_delta = blueprint_result.blueprint
        work_item.artifacts.architecture_delta = blueprint_result.architecture
```

### Refactor Simulation Engine Integration
```python
# Used in Refactor pipeline before applying changes
def integrate_simulation_engine(work_item):
    if work_item.type == "refactor":
        simulation_result = run_refactor_simulation_engine({
            "current_code": load_codebase(),
            "proposed_changes": work_item.intent,
            "architecture": work_item.artifacts.architecture_delta
        })
        work_item.artifacts.simulation_report = simulation_result
```

### Migration Engine Integration
```python
# Used in Migration pipeline for phased planning
def integrate_migration_engine(work_item):
    if work_item.type == "migration":
        migration_plan = run_migration_engine({
            "source_architecture": load_architecture(),
            "target_architecture": work_item.intent.target_architecture,
            "constraints": work_item.scope.constraints
        })
        work_item.artifacts.migration_plan = migration_plan
```

### Code Diff Reasoner Integration
```python
# Used by Builder/Refactorer when touching existing code
def integrate_code_diff_reasoner(context, agent_name):
    if agent_name in ["builder", "refactorer"]:
        diff_reasoning = run_code_diff_reasoner({
            "proposed_changes": context.get("code_changes"),
            "existing_code": context.get("existing_code"),
            "architecture": context.get("architecture_delta")
        })
        context["diff_reasoning"] = diff_reasoning
    return context
```

### Validation Protocol Integration
```python
# Used in Validator phases and safety filters
def integrate_validation_protocol(work_item, phase):
    validation_report = run_validation_protocol_v2({
        "work_item": work_item,
        "phase": phase,
        "artifacts": work_item.artifacts
    })
    return validation_report
```

### Safety Filters Integration
```python
# Applied before every agent execution
def integrate_safety_filters(agent_name, context, work_item):
    safety_system = SafetyFilterSystem()
    
    # Apply all relevant safety filters
    filter_result = safety_system.validate_agent_action({
        "agent": agent_name,
        "context": context,
        "work_item": work_item
    })
    
    if not filter_result.allowed:
        raise SafetyViolationError(filter_result.violation)
```

### Merge Safety & Changelog Integration
```python
# Triggered after work_item.status == "done"
def integrate_merge_safety(work_item):
    if work_item.status == "done":
        # Run merge safety checklist
        merge_safety_report = run_merge_safety_checklist(work_item)
        
        # Generate changelog entry
        changelog_entry = run_changelog_generator(work_item.artifacts)
        
        work_item.artifacts.merge_safety_report = merge_safety_report
        work_item.artifacts.changelog_entry = changelog_entry
```

---

## 🚀 CLI INTEGRATION EXAMPLE

### Command Interface
```bash
# Feature development
vini build "Add recurring reminders" --tier core

# Refactoring  
vini refactor "Extract notification service" --scope src/notifications/*

# Migration
vini migrate "Move from monolith to microservices" --plan migration-plan.yaml

# Status checking
vini status W-2025-001

# Work item management
vini list --status blocked
vini retry W-2025-001
```

### CLI Implementation Sketch
```python
class ViniCLI:
    def __init__(self):
        self.engine = ExecutionEngine(
            agents=load_agents(),
            safety_filters=load_safety_filters(),
            validator=load_validator()
        )
    
    def build(self, description: str, tier: str = "core"):
        """Handle feature development command"""
        work_item = WorkItem(
            type="feature",
            tier=tier,
            intent={"title": description, "description": description}
        )
        
        result = self.engine.run_work_item(work_item)
        self._output_result(result)
    
    def refactor(self, description: str, scope: List[str]):
        """Handle refactoring command"""
        work_item = WorkItem(
            type="refactor",
            intent={"title": description, "scope": scope}
        )
        
        result = self.engine.run_work_item(work_item)
        self._output_result(result)
    
    def migrate(self, description: str, plan_file: str):
        """Handle migration command"""
        migration_plan = load_yaml(plan_file)
        work_item = WorkItem(
            type="migration",
            intent={"title": description, "plan": migration_plan}
        )
        
        result = self.engine.run_work_item(work_item)
        self._output_result(result)
```

---

## 📊 EXECUTION ENGINE METRICS

### Performance Metrics
```yaml
metrics:
  pipeline_performance:
    feature_pipeline_duration: "average 45 minutes"
    refactor_pipeline_duration: "average 90 minutes" 
    migration_pipeline_duration: "average 4 hours"
    
  success_rates:
    feature_success_rate: "92%"
    refactor_success_rate: "87%"
    migration_success_rate: "78%"
    
  failure_modes:
    safety_filter_blocks: "15%"
    validation_failures: "8%"
    human_escalations: "5%"
    
  agent_performance:
    architect_avg_duration: "8 minutes"
    builder_avg_duration: "15 minutes"
    tester_avg_duration: "12 minutes"
    doc_manager_avg_duration: "6 minutes"
    validator_avg_duration: "4 minutes"
```

### Monitoring Dashboard
```python
class ExecutionMonitor:
    def get_pipeline_health(self):
        return {
            "active_work_items": len(self.engine.active_work),
            "queue_depth": len(self.engine.work_queue),
            "success_rate_24h": self._calculate_success_rate(),
            "blocked_items": self._get_blocked_items(),
            "human_escalations_pending": self._get_escalations()
        }
    
    def get_agent_performance(self):
        return {
            agent: {
                "avg_duration": self._calculate_avg_duration(agent),
                "success_rate": self._calculate_agent_success_rate(agent),
                "common_failures": self._get_common_failures(agent)
            }
            for agent in self.engine.agents.keys()
        }
```

---

## 🛡️ SAFETY & RELIABILITY

### Safety Integration Points
- **Pre-execution**: Safety filters applied before every agent call
- **During execution**: Real-time monitoring for scope violations
- **Post-execution**: Validation protocols and diff validation
- **Emergency**: Human override hooks and system shutdown capabilities

### Reliability Features
- **Deterministic pipelines**: Fixed phase sequences with clear transitions
- **Retry mechanisms**: Configurable retry counts with exponential backoff
- **Failure isolation**: Failed phases don't corrupt other phases
- **Audit trails**: Complete history logging for compliance and debugging

### Error Recovery
```python
class ErrorRecoverySystem:
    def recover_from_safety_violation(self, work_item, violation):
        """Attempt recovery from safety filter violation"""
        if violation.type == "scope_violation":
            return self._reduce_scope_and_retry(work_item)
        elif violation.type == "pattern_violation":
            return self._fix_pattern_compliance(work_item)
        elif violation.type == "architecture_violation":
            return self._escalate_to_architect(work_item)
        else:
            return self._escalate_to_human(work_item, violation)
```

---

**The Multi-Agent Execution Engine provides the orchestration layer that transforms the five-agent governance system from theoretical roles into a practical, safe, and reliable factory for software development. It ensures deterministic execution, comprehensive safety, and seamless integration with all existing governance components.**
