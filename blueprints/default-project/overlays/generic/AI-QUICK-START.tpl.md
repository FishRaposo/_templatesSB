# AI Quick Start - {{PROJECT_NAME}}

> Zero-config setup sequence for AI assistants working on {{PROJECT_NAME}}

**Purpose**: Automated project setup and documentation initialization for AI agents  
**Version**: {{VERSION}}  
**Three Pillars**: Scripting, Testing, Documenting  
**AI Command**: `Run the quickstart`  
**Setup Time**: 5-10 minutes  
**Human Input Required**: Project name and type (if not auto-detected)

---

## 🎯 AI Execution Command

```
Run the quickstart with context detection. 
Analyze this project structure and set up comprehensive documentation:
1. Execute AI-QUICK-START.md step-by-step
2. Verify AI assistant files exist (AGENTS.md, CLAUDE.md)
3. Detect project context (web/mobile/API/library)
4. Detect tech stack from configuration files
5. Replace all [PLACEHOLDERS] with detected values
6. Create complete documentation structure
7. Verify all files created successfully
8. Report setup completion with summary
```

---

## 🚀 Automated Setup Sequence

### **PHASE 0: Context Detection**

**Purpose**: Detect project characteristics and determine appropriate configuration.

```bash
#!/bin/bash
echo "=========================================="
echo "[AI] {{PROJECT_NAME}} Quickstart"
echo "[AI] Phase 0: Context Detection"
echo "=========================================="

# Detect project type
PROJECT_TYPE="{{PROJECT_TYPE}}"  # web, mobile, api, library, cli
TECH_STACK="{{TECH_STACK}}"      # react, flutter, node, python, go, etc.
TEAM_SIZE="{{TEAM_SIZE}}"        # 1-2, 3-5, 5+

echo "[AI] Project Characteristics Detected:"
echo "  Project Type: $PROJECT_TYPE"
echo "  Tech Stack: $TECH_STACK"
echo "  Team Size: $TEAM_SIZE developers"
```

### **PHASE 1: Validation System Setup**

**Purpose**: Create prompt validation and documentation maintenance files.

**Required Files:**
1. `docs/PROMPT-VALIDATION.md` - ⚠️ MANDATORY
2. `docs/PROMPT-VALIDATION-QUICK.md` - Quick validation
3. `docs/DOCUMENTATION-MAINTENANCE.md` - ⚠️ MANDATORY

**Verification:**
```bash
# Check validation files exist
[ -f "docs/PROMPT-VALIDATION.md" ] && echo "✅ PROMPT-VALIDATION.md" || echo "❌ Missing"
[ -f "docs/PROMPT-VALIDATION-QUICK.md" ] && echo "✅ PROMPT-VALIDATION-QUICK.md" || echo "❌ Missing"
[ -f "docs/DOCUMENTATION-MAINTENANCE.md" ] && echo "✅ DOCUMENTATION-MAINTENANCE.md" || echo "❌ Missing"
```

### **PHASE 2: Core Documentation Setup**

**Purpose**: Create essential documentation files.

**File Creation Order:**
1. `README.md` - Project overview
2. `CONTEXT.md` - Philosophy and decisions
3. `CHANGELOG.md` - Version history (start immediately)
4. `TODO.md` - Task tracking
5. `AGENTS.md` - Developer implementation guide
6. `CLAUDE.md` - Quick reference

**Verification:**
```bash
# Check core files exist
for file in README.md CONTEXT.md CHANGELOG.md TODO.md AGENTS.md CLAUDE.md; do
    [ -f "$file" ] && echo "✅ $file" || echo "❌ Missing: $file"
done
```

### **PHASE 3: Extended Documentation**

**Purpose**: Create additional documentation based on project needs.

**Conditional Files:**
- `WORKFLOW.md` - When user workflows exist
- `EVALS.md` - When testing is important
- `INDEX.md` - When project has 20+ files
- `DOCUMENTATION.md` - When many docs exist

### **PHASE 4: Test Infrastructure**

**Purpose**: Set up test organization and structure.

**Test Directory Structure:**
```
tests/
├── unit/           # Unit tests
├── integration/    # Integration tests
├── system/         # System tests
├── workflows/      # Workflow tests
├── fixtures/       # Test data and fixtures
└── INDEX.md        # Test directory index (when 5+ files)
```

**Test Configuration:**
- Create test configuration file (e.g., `conftest.py`, `setup.js`)
- Set up shared fixtures
- Configure test markers/categories

### **PHASE 5: Final Verification**

**Purpose**: Verify complete setup and report status.

**Checklist:**
- [ ] All mandatory files created
- [ ] All placeholders replaced
- [ ] Links validated
- [ ] Test structure ready
- [ ] Documentation consistent

**Completion Report:**
```bash
echo "=========================================="
echo "[AI] Setup Complete"
echo "=========================================="
echo "✅ Mandatory Files: Created"
echo "✅ Validation System: Ready"
echo "✅ Test Structure: Configured"
echo "✅ Documentation: Complete"
echo ""
echo "Next Steps:"
echo "1. Review generated documentation"
echo "2. Run: {{TEST_COMMAND}}"
echo "3. Start development with AGENTS.md"
```

---

## 📋 Pre-Operation Checklist

Before any code change, AI agents must:

1. **Tool Call Limit Awareness** ⚠️
   - Plan all tool calls needed
   - Batch operations when possible
   - Use efficient tools
   - Cache information

2. **Script-First Evaluation**
   - Evaluate if task should be automated
   - Create scripts for repetitive tasks
   - Place scripts in `scripts/` or `utils/`

3. **Prompt Validation**
   - Complete `docs/PROMPT-VALIDATION.md`
   - All confidence levels ≥ 7/10
   - All validation gates passed

4. **Test Planning**
   - Identify test requirements
   - Plan test type (unit/integration/system/workflow)
   - Review existing tests

5. **Documentation Planning**
   - Read `docs/DOCUMENTATION-MAINTENANCE.md`
   - Copy appropriate checklist
   - Plan documentation updates

---

## 🔄 Validation Checkpoints

### Checkpoint 1: Understanding
- [ ] Task purpose clear
- [ ] Scope defined
- [ ] Success criteria known

### Checkpoint 2: Codebase
- [ ] File locations known
- [ ] Patterns understood
- [ ] Dependencies identified

### Checkpoint 3: Requirements
- [ ] Constraints identified
- [ ] Quality standards known
- [ ] Testing requirements clear

### Checkpoint 4: Process
- [ ] Execution plan ready
- [ ] Tool usage optimized
- [ ] Error handling planned

### Checkpoint 5: Autonomous Operation
- [ ] All information available
- [ ] No blocking questions
- [ ] Confidence ≥ 7/10

---

## 🚨 Critical Rules

1. **CHANGELOG.md is REQUIRED** for every code change
2. **Tests are REQUIRED** alongside code changes
3. **Documentation updates are AUTOMATIC**, not optional
4. **Prompt validation BEFORE** any operation
5. **Tool call efficiency** is critical

---

## 📚 Related Documentation

- [AGENTS.md](AGENTS.md) - Developer implementation guide
- [CLAUDE.md](CLAUDE.md) - Quick reference
- [docs/PROMPT-VALIDATION.md](docs/PROMPT-VALIDATION.md) - Validation system
- [docs/DOCUMENTATION-MAINTENANCE.md](docs/DOCUMENTATION-MAINTENANCE.md) - Maintenance guide

---

**Last Updated**: {{LAST_UPDATED_DATE}}  
**Setup Version**: {{SETUP_VERSION}}

---

*This quickstart guide enables rapid project setup for AI assistants working on {{PROJECT_NAME}}. Follow the phases sequentially for complete setup.*
