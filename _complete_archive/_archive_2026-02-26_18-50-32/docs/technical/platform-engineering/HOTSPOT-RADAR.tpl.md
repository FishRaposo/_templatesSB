# HOTSPOT-RADAR.md - Pre-Refactor Risk Detection Template

**Purpose**: Identify modules/files/functions at high risk of causing breakages, instability, or architectural violations when refactored.  
**Design**: Pre-flight safety scan with 6 hotspot categories and automated risk scoring.  
**Integration**: Required analysis before any refactoring or migration begins.

---

## 🎯 Hotspot Radar — v1.0

**The goal is to detect danger zones in the codebase before refactoring begins.**

---

## 1. Structural Hotspots

### Risk Indicators:
- [ ] **Large files (> X lines)**
  - Files exceeding complexity thresholds
  - Monolithic files hard to understand and modify

- [ ] **God objects / giant classes**
  - Classes with too many responsibilities
  - Objects that know too much about the system

- [ ] **Modules with too many responsibilities**
  - Violation of single responsibility principle
  - Modules handling multiple concerns

- [ ] **Cyclical dependencies**
  - Circular import relationships
  - Dependency graph violations

- [ ] **Deeply nested folder structures**
  - Excessive nesting levels
  - Complex module hierarchies

- [ ] **Deprecated patterns still present**
  - Legacy code patterns still in use
  - Outdated architectural approaches

### Detection Rules:
```yaml
structural_thresholds:
  max_file_lines: 500
  max_class_methods: 20
  max_module_responsibilities: 3
  max_nesting_depth: 5
  deprecated_patterns:
    - direct_database_access_from_ui
    - global_state_usage
    - tight_coupling_patterns
```

---

## 2. Behavioral Hotspots

### Risk Indicators:
- [ ] **Functions with complex branching (N > threshold)**
  - High cyclomatic complexity
  - Too many conditional paths

- [ ] **Critical business paths (e.g., payment, auth)**
  - Core business logic
  - Revenue or security-critical functions

- [ ] **High I/O frequency modules (DB, storage, network)**
  - Heavy external resource usage
  - Performance bottleneck potential

- [ ] **Shared global state or singletons**
  - Global mutable state
  - Hidden dependencies

- [ ] **Error-prone async flows**
  - Complex asynchronous operations
  - Race condition potential

### Detection Rules:
```yaml
behavioral_thresholds:
  max_complexity: 10
  critical_paths:
    - authentication
    - payment_processing
    - user_data_management
    - audit_logging
  io_heavy_modules:
    - database_access
    - file_storage
    - network_communication
    - cache_operations
```

---

## 3. Volatility Hotspots

### Risk Indicators:
- [ ] **Files frequently changed in PR history**
  - High frequency of modifications
  - Unstable or evolving code

- [ ] **Modules with conflicting contributors**
  - Multiple developers making conflicting changes
  - Coordination challenges

- [ ] **Known unstable APIs**
  - APIs with frequent breaking changes
  - External dependencies with volatility

- [ ] **Core dependencies updated recently**
  - Recent major version updates
  - Potential compatibility issues

### Detection Rules:
```yaml
volatility_metrics:
  change_frequency_threshold: 5_changes_per_month
  contributor_conflict_threshold: 3_contributors_same_file
  unstable_api_indicators:
    - frequent_major_version_updates
    - deprecated_warnings
    - breaking_change_notifications
```

---

## 4. Test Coverage Hotspots

### Risk Indicators:
- [ ] **Modules with < 50% coverage**
  - Insufficient test coverage
  - High risk of undetected regressions

- [ ] **Missing integration tests for high-risk modules**
  - No end-to-end testing
  - Integration blind spots

- [ ] **Missing UI tests for navigation flows**
  - Critical user paths untested
  - UI regression risk

- [ ] **Legacy tests referencing removed code**
  - Broken test suites
  - False confidence in coverage

### Detection Rules:
```yaml
testing_thresholds:
  min_coverage_percentage: 50
  critical_modules_min_coverage: 80
  required_test_types:
    - unit_tests
    - integration_tests
    - ui_tests_for_user_flows
  test_health_indicators:
    - test_pass_rate > 95%
    - no_flaky_tests
    - recent_test_execution
```

---

## 5. Documentation Hotspots

### Risk Indicators:
- [ ] **ARCHITECTURE.md out of sync**
  - Documentation doesn't match actual structure
  - Missing architectural decisions

- [ ] **FRAMEWORK-PATTERNS.md violated frequently**
  - Pattern violations in codebase
  - Inconsistent implementation approaches

- [ ] **MIGRATION-GUIDE.md missing required details**
  - Incomplete migration documentation
  - Missing rollback procedures

- [ ] **API-DOCUMENTATION.md outdated vs code**
  - API docs don't match implementation
  - Missing endpoint documentation

### Detection Rules:
```yaml
documentation_health:
  architecture_sync:
    - documented_modules_match_actual
    - dependencies_currently_documented
    - boundaries_properly_described
  pattern_compliance:
    - framework_patterns_followed
    - violations_documented_with_justification
  api_documentation:
    - all_public_endpoints_documented
    - request_response_formats_current
    - error_codes_documented
```

---

## 6. Risk Score (Auto + Manual)

### Automated Risk Assessment:
```yaml
risk_scoring:
  structural_risk:
    low: 0-2_issues
    medium: 3-5_issues
    high: 6-8_issues
    critical: 9+_issues
  
  behavior_risk:
    low: no_critical_paths_affected
    medium: 1-2_critical_paths_affected
    high: 3-4_critical_paths_affected
    critical: 5+_critical_paths_affected
  
  test_risk:
    low: coverage_80%+_and_all_tests_passing
    medium: coverage_50-80%_or_some_failing_tests
    high: coverage_30-50%_or_many_failing_tests
    critical: coverage_<30%_or_test_suite_broken
  
  doc_risk:
    low: all_docs_current_and_synced
    medium: minor_doc_drift_detected
    high: significant_doc_drift_or_missing_docs
    critical: docs_completely_outdated_or_missing
```

### Manual Risk Adjustment:
- **Domain Knowledge**: Consider business criticality
- **Team Expertise**: Adjust based on team familiarity
- **Timeline Pressure**: Increase risk for urgent changes
- **Dependencies**: Consider external system dependencies

### Overall Hotspot Score:
```
{LOW / MEDIUM / HIGH / CRITICAL}

Scoring Formula:
Overall Score = max(Structural, Behavior, Test, Doc) + Volatility Adjustment

LOW: All categories low, minimal volatility
MEDIUM: One category medium or multiple low
HIGH: One category high or multiple medium
CRITICAL: Any category critical or multiple high
```

---

## 7. Recommended Actions

### Risk-Based Recommendations:

**LOW Risk Areas:**
- Refactor with standard precautions
- Follow normal development workflow
- Basic testing requirements

**MEDIUM Risk Areas:**
- Add targeted tests before refactoring
- Create detailed refactor plan
- Peer review required
- Consider feature flags for gradual rollout

**HIGH Risk Areas:**
- Comprehensive test coverage required
- Detailed impact analysis needed
- Multiple approvals required
- Consider canary deployment strategy
- Rollback plan mandatory

**CRITICAL Risk Areas:**
- Full regression testing required
- Architecture review mandatory
- Staged rollout with monitoring
- Real-time monitoring during deployment
- Immediate rollback capability

### Action Templates:
```markdown
## Risk Mitigation Plan for [Module/Area]

### Pre-Refactor Requirements:
- [ ] Add missing test coverage to [X]%
- [ ] Update documentation for [specific areas]
- [ ] Create detailed impact analysis
- [ ] Design rollback strategy

### During Refactor:
- [ ] Work in small, reversible steps
- [ ] Maintain test coverage throughout
- [ ] Update documentation incrementally
- [ ] Monitor system behavior

### Post-Refactor:
- [ ] Full regression testing
- [ ] Performance validation
- [ ] Documentation review
- [ ] Team knowledge transfer
```

---

## 🔧 Integration with Agentic Platform Engineering System

### Component Integration:
| Component | Radar Section | Role |
|-----------|---------------|------|
| **tier-index.yaml** | 6 | Tier-based risk thresholds |
| **ARCHITECTURE.md** | 1, 5 | Structural analysis, documentation sync |
| **FRAMEWORK-PATTERNS.md** | 1, 5 | Pattern compliance validation |
| **TESTING.md** | 4 | Coverage requirements and gaps |
| **docs/platform-engineering/VALIDATION-PROTOCOL-v2.md** | 5 | Documentation health verification |
| **docs/platform-engineering/REFACTOR-SIMULATION-ENGINE.md** | All | Pre-flight risk assessment input |

### Automated Radar Execution:
```bash
#!/bin/bash
# Hotspot radar analysis script
echo "🎯 Running Hotspot Radar Analysis"

# Structural analysis
python3 scripts/structural_analyzer.py \
  --codebase src/ \
  --thresholds config/structural_thresholds.yaml \
  --output analysis/structural_hotspots.json

# Behavioral analysis
python3 scripts/behavioral_analyzer.py \
  --codebase src/ \
  --critical_paths config/critical_paths.yaml \
  --output analysis/behavioral_hotspots.json

# Test coverage analysis
python3 scripts/coverage_analyzer.py \
  --test_results test_results/ \
  --coverage_report coverage.xml \
  --output analysis/test_hotspots.json

# Documentation analysis
python3 scripts/documentation_analyzer.py \
  --docs docs/ \
  --codebase src/ \
  --output analysis/documentation_hotspots.json

# Generate consolidated risk report
python3 scripts/risk_scorer.py \
  --structural analysis/structural_hotspots.json \
  --behavioral analysis/behavioral_hotspots.json \
  --test analysis/test_hotspots.json \
  --documentation analysis/documentation_hotspots.json \
  --output HOTSPOT-RADAR-REPORT.md

echo "✅ Hotspot radar analysis completed"
```

### Integration with Refactor Workflow:
```bash
# Pre-refactor safety check
echo "🔍 Running pre-refactor hotspot analysis"
python3 scripts/hotspot_radar.py --target "$TARGET_MODULE"

# Check if safe to proceed
if [[ "$(cat hotspot_radar_report.json | jq -r '.overall_risk')" == "CRITICAL" ]]; then
  echo "❌ Critical risk detected - refactor blocked"
  echo "Required actions:"
  cat hotspot_radar_report.json | jq -r '.recommended_actions[]'
  exit 1
elif [[ "$(cat hotspot_radar_report.json | jq -r '.overall_risk')" == "HIGH" ]]; then
  echo "⚠️ High risk detected - additional safeguards required"
  echo "Implementing safety measures..."
  # Apply additional safety measures
fi

echo "✅ Hotspot analysis passed - proceeding with refactor"
```

---

## 📊 Usage Examples

### Web Application Analysis:
```
Structural Risk: MEDIUM (3 large files, 1 god object)
Behavior Risk: HIGH (payment processing in complex module)
Test Risk: MEDIUM (70% coverage, some integration tests missing)
Doc Risk: LOW (documentation current and synced)
Volatility: LOW (stable codebase)

Overall Hotspot Score: HIGH

Recommended Actions:
- Add comprehensive tests for payment module before refactoring
- Break down god object into smaller components
- Create detailed refactor plan with rollback strategy
- Peer review and architecture approval required
```

### API Service Analysis:
```
Structural Risk: LOW (clean module structure)
Behavior Risk: MEDIUM (some complex async flows)
Test Risk: CRITICAL (30% coverage, broken integration tests)
Doc Risk: MEDIUM (API docs slightly outdated)
Volatility: MEDIUM (frequent recent changes)

Overall Hotspot Score: CRITICAL

Recommended Actions:
- CRITICAL: Fix broken test suite before any changes
- Add comprehensive test coverage to >80%
- Update API documentation to match implementation
- Staged rollout with extensive monitoring
- Full regression testing required
```

---

## 🛠️ Implementation Notes

### Configuration:
- Customize thresholds based on project characteristics
- Define project-specific critical paths
- Set coverage targets appropriate to domain
- Configure documentation standards

### Automation:
- Integrate with CI/CD pipeline for continuous monitoring
- Schedule periodic hotspot analysis
- Alert on risk level changes
- Track risk trends over time

### Reporting:
- Generate risk reports for stakeholders
- Create risk mitigation plans
- Track risk reduction progress
- Maintain risk history for audit purposes

---

**This hotspot radar provides the essential pre-flight safety analysis that prevents agents and humans from stepping on landmines during refactoring operations.**
