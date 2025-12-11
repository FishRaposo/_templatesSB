# VALIDATION-PROTOCOL-v2.md - Self-Healing Auto-Repair Reasoning Loop

**Purpose**: Operational protocol for any AI agent or CLI tool to maintain repo consistency with tier requirements.  
**Design**: Closed-loop, self-consistent, deterministic, auto-repairing.  
**Execution**: Run on every repo update/generation.

---

## VALIDATION PROTOCOL v2.0

**Goal**: Ensure repo is consistent with selected tier AND automatically repair missing/outdated documents.

**Inputs**:
- tier-index.yaml
- project repo
- blueprint (universal + specific)
- tier
- file tree

---

## STEP 1 — LOAD INDEX + TIER

Load from tier-index.yaml:
- required docs
- recommended docs  
- ignored docs
- file descriptors
- tier-specific rules

```python
def load_tier_index(tier):
    with open("tier-index.yaml") as f:
        index = yaml.safe_load(f)
    return index["tiers"][tier.lower()]
```

---

## STEP 2 — SCAN REPO

List all files in `/docs` and top-level.

Identify:
- missing files
- outdated files (timestamp heuristic or doc-code mismatch)
- incomplete files (missing required sections)

```python
def scan_repo():
    docs_files = glob("docs/*.md") + glob("*.md")
    return {f: get_file_metadata(f) for f in docs_files}
```

---

## STEP 3 — VALIDATE STRUCTURE

For each required file:
```python
if missing → add to REPAIR_LIST
if exists but empty/fragmentary → add to REWRITE_LIST
```

For each recommended file:
```python
if missing → add to SUGGEST_LIST
```

Validation rules:
- File size > tier minimum
- Contains required sections
- Follows tier template structure

---

## STEP 4 — DOCUMENT PARITY CHECK

Compare blueprint vs documentation:

- features in blueprint vs TODO.md
- architecture decisions vs ARCHITECTURE.md
- endpoints vs API-DOCUMENTATION.md
- modules/folders vs documentation references

If mismatch → add to UPDATE_LIST

```python
def check_parity(blueprint, docs):
    mismatches = []
    if blueprint["features"] != parse_todo_features(docs["TODO.md"]):
        mismatches.append("TODO.md")
    if blueprint["endpoints"] != parse_api_endpoints(docs["API-DOCUMENTATION.md"]):
        mismatches.append("API-DOCUMENTATION.md")
    return mismatches
```

---

## STEP 5 — AUTO-REPAIR LOOP

For each file in REPAIR_LIST:
- Generate file using template from TIERED-TEMPLATES.md
- Fill in project-specific details from blueprint

For each file in REWRITE_LIST:
- Rebuild using appropriate tier template
- Preserve existing content where possible

For each file in UPDATE_LIST:
- Apply diffs, preserving existing content where reasonable
- Update placeholders with current blueprint data

```python
def repair_file(file_name, blueprint, tier):
    template = load_template(file_name, tier)
    content = fill_placeholders(template, blueprint)
    write_file(file_name, content)
```

---

## STEP 6 — TESTING PARITY CHECK

Cross-reference tests and documentation:

If tests reference modules not documented → update docs.
If docs reference modules not in code → suggest code generation or doc update.

```python
def check_testing_parity():
    test_modules = extract_test_modules()
    doc_modules = extract_doc_modules()
    
    missing_docs = test_modules - doc_modules
    missing_tests = doc_modules - test_modules
    
    return missing_docs, missing_tests
```

---

## STEP 7 — OUTPUT REPORT

Summarize actions taken:

```python
report = {
    "missing_docs_created": len(REPAIR_LIST),
    "outdated_docs_fixed": len(REWRITE_LIST), 
    "inconsistencies_resolved": len(UPDATE_LIST),
    "recommended_docs_suggested": len(SUGGEST_LIST),
    "next_steps": generate_next_steps()
}
```

Format: Human-readable + JSON for agents.

---

## STEP 8 — CONFIRMATION PASS

Re-run Steps 1–4 to ensure consistency.

```python
def confirmation_pass():
    # Re-validate after repairs
    validation_result = run_validation_steps_1_to_4()
    
    if validation_result["status"] == "PASS":
        return {"status": "SUCCESS", "report": report}
    else:
        # If still failing, escalate to human
        return {"status": "REQUIRES_HUMAN", "issues": validation_result["errors"]}
```

---

## 🤖 Agent Implementation

### Complete Protocol Function
```python
def run_validation_protocol_v2(blueprint, tier, repo_path="."):
    """Execute complete validation protocol."""
    
    # Step 1: Load tier requirements
    tier_config = load_tier_index(tier)
    
    # Step 2: Scan repository
    repo_files = scan_repo()
    
    # Step 3: Validate structure
    repair_list, rewrite_list, suggest_list = validate_structure(tier_config, repo_files)
    
    # Step 4: Document parity check
    update_list = check_parity(blueprint, repo_files)
    
    # Step 5: Auto-repair loop
    for file_name in repair_list:
        repair_file(file_name, blueprint, tier)
    
    for file_name in rewrite_list:
        rebuild_file(file_name, blueprint, tier)
    
    for file_name in update_list:
        update_file(file_name, blueprint)
    
    # Step 6: Testing parity check
    missing_docs, missing_tests = check_testing_parity()
    
    # Step 7: Output report
    report = generate_report(repair_list, rewrite_list, update_list, suggest_list)
    
    # Step 8: Confirmation pass
    final_result = confirmation_pass()
    
    return final_result
```

### CLI Integration
```bash
#!/bin/bash
# validation-agent.sh - CLI wrapper for protocol

echo "[AI] Running Validation Protocol v2..."
python3 -c "
from validation_protocol_v2 import run_validation_protocol_v2
import yaml

# Load blueprint
with open('blueprint.yaml') as f:
    blueprint = yaml.safe_load(f)

# Detect tier (or use explicit)
tier = '$1' or detect_tier(blueprint)

# Run protocol
result = run_validation_protocol_v2(blueprint, tier)
print(yaml.dump(result))
"

if [ $? -eq 0 ]; then
    echo "[AI] ✅ Validation complete - repo is consistent"
else
    echo "[AI] ❌ Validation failed - manual intervention required"
    exit 1
fi
```

---

## 🔧 Integration Points

### With TIERED-TEMPLATES.md
- Uses appropriate tier templates for repairs
- Maintains placeholder consistency
- Respects generation order dependencies

### With BLUEPRINT-MAPPING.md
- Sources blueprint data for placeholder filling
- Uses mapping table for file generation
- Maintains bidirectional consistency

### With tier-index.yaml
- Validates against tier requirements
- Ensures compliance with file counts and rules
- Uses tier-specific validation thresholds

### With VALIDATION.md
- Extends basic validation with auto-repair
- Uses same compliance reporting format
- Integrates with CLI validation script

---

## 📊 Success Metrics

- **Compliance Score**: 100% required files present and valid
- **Parity Score**: 0 mismatches between blueprint and docs
- **Repair Success**: All auto-repairs completed without errors
- **Confirmation Pass**: Second validation run passes

---

## 🚀 Usage

### For AI Agents
```python
# Run after any repo changes
result = run_validation_protocol_v2(blueprint, tier)
if result["status"] == "REQUIRES_HUMAN":
    escalate_to_human(result["issues"])
```

### For CLI Tools
```bash
# Run validation manually
./validation-agent.sh core

# Run in CI/CD pipeline
./validation-agent.sh --json --fail-on-error
```

### For IDE Integration
```json
{
  "validation": {
    "command": "./validation-agent.sh",
    "args": ["--tier", "auto"],
    "trigger": "on_file_save"
  }
}
```

---

**Result**: Closed-loop, self-healing documentation system that maintains perfect consistency with tier requirements while minimizing human intervention.
