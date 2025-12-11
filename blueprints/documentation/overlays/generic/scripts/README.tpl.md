# Validation Scripts

**Purpose**: Automated validation and quality assurance tools for the documentation template system.

---

## 📋 File Inventory

| File | Size | Purpose | Dependencies |
|------|------|---------|--------------|
| **validate_docs.py** | 12KB | ✅ Comprehensive documentation validation | tier-index.yaml, docs/ files |
| **validation_protocol_v2.py** | 17KB | 🔄 Self-healing validation protocol implementation | docs/platform-engineering/VALIDATION-PROTOCOL-v2.md |

---

## 🎯 Script Overview

### **validate_docs.py**
**Purpose**: Validates project documentation against tier requirements and ensures completeness.

**Features**:
- **Tier compliance checking** (MVP/CORE/FULL requirements)
- **File existence validation** based on tier-index.yaml
- **Cross-reference verification** between documentation files
- **Coverage requirement validation** for testing tiers
- **Template customization validation** (placeholder replacement)

**Usage**:
```bash
# Basic validation
python3 scripts/validate_docs.py

# Tier-specific validation
python3 scripts/validate_docs.py --tier core

# With blueprint file
python3 scripts/validate_docs.py --tier core --blueprint project.yaml

# Verbose output
python3 scripts/validate_docs.py --verbose
```

**Integration**:
- Called by QUICKSTART-AI.md after template generation
- Used in CI/CD pipelines for documentation quality gates
- Integrated with docs/platform-engineering/VALIDATION-PROTOCOL-v2.md

### **validation_protocol_v2.py**
**Purpose**: Implements the 8-step self-healing validation protocol from docs/platform-engineering/VALIDATION-PROTOCOL-v2.md.

**Features**:
- **Auto-repair reasoning loop** for common documentation issues
- **Documentation synchronization** between code and docs
- **Tier-aware validation** with automatic fixes
- **Comprehensive reporting** with actionable recommendations
- **Integration with platform engineering workflow**

**Usage**:
```bash
# Standard validation with auto-repair
python3 scripts/validation_protocol_v2.py --tier core

# Sync mode (documentation alignment)
python3 scripts/validation_protocol_v2.py --mode sync --docs *.md

# Validation only (no repairs)
python3 scripts/validation_protocol_v2.py --mode validate --no-repair

# Blueprint integration
python3 scripts/validation_protocol_v2.py --tier core --blueprint blueprint.yaml
```

**Integration**:
- Core component of platform engineering refactoring pipeline
- Used by docs/platform-engineering/AGENTIC-REFACTOR-PLAYBOOK.md
- Integrates with docs/platform-engineering/DIFF-VALIDATOR.md

---

## 🔗 Integration Points

### **With Documentation System**
- **docs/TIER-GUIDE.md** - Tier requirements and validation criteria
- **docs/TIER-MAPPING.md** - File requirements per tier
- **QUICKSTART-AI.md** - Automated setup validation
- **tier-index.yaml** - Source of truth for validation rules

### **With Platform Engineering**
- **docs/platform-engineering/VALIDATION-PROTOCOL-v2.md** - Protocol specification
- **docs/platform-engineering/DIFF-VALIDATOR.md** - Change validation
- **docs/platform-engineering/MERGE-SAFETY-CHECKLIST.md** - Pre-merge validation
- **docs/platform-engineering/REFACTOR-SAFETY-DASHBOARD.md** - Status tracking

### **With AI Agents**
- **QUICKSTART-AI.md** calls validate_docs.py after setup
- **docs/platform-engineering/AGENTIC-REFACTOR-PLAYBOOK.md** integrates validation steps
- **universal/AGENTS.md** defines validation responsibilities

---

## 🚀 Usage Scenarios

### **New Project Setup**
```bash
# After running QUICKSTART-AI.md
echo "[AI] Validating documentation setup..."
python3 scripts/validate_docs.py --tier $SELECTED_TIER

# Expected output
✅ All required files present
✅ Cross-references valid
✅ Placeholders replaced
✅ Tier compliance confirmed
```

### **Pre-Merge Validation**
```bash
# Before merging changes
python3 scripts/validation_protocol_v2.py --mode validate --no-repair

# Integration with MERGE-SAFETY-CHECKLIST.md
if validation_passed; then
    echo "✅ Ready for merge"
else
    echo "❌ Fix validation issues before merge"
fi
```

### **Documentation Sync**
```bash
# After code changes
python3 scripts/validation_protocol_v2.py --mode sync --docs *.md

# Auto-repair common issues
- Update API documentation
- Sync testing examples
- Fix cross-references
- Update version numbers
```

### **CI/CD Integration**
```yaml
# GitHub Actions example
- name: Validate Documentation
  run: |
    python3 scripts/validate_docs.py --tier ${{ matrix.tier }}
    python3 scripts/validation_protocol_v2.py --mode validate
```

---

## 📋 Validation Criteria

### **Tier Requirements**
- **MVP**: 4-7 files, basic structure, smoke tests
- **CORE**: 15-25 files, 85%+ coverage, complete documentation
- **FULL**: 30-50 files, 95%+ coverage, enterprise features

### **Quality Checks**
- **File Existence**: All required files present
- **Cross-References**: All internal links valid
- **Placeholders**: All [PLACEHOLDERS] replaced
- **Structure**: Proper section organization
- **Content**: Minimum content requirements met

### **Auto-Repair Capabilities**
- **Cross-Reference Updates**: Fix broken internal links
- **Template Sync**: Update outdated examples
- **Placeholder Replacement**: Fill common patterns
- **Format Standardization**: Ensure consistent styling

---

## 🔧 Configuration

### **Environment Variables**
```bash
# Optional configuration
export DOCS_TIER="core"                    # Default tier
export DOCS_BLUEPRINT="project.yaml"       # Blueprint file
export DOCS_VERBOSE="true"                 # Verbose output
export DOCS_AUTO_REPAIR="true"             # Enable auto-repair
```

### **Configuration Files**
- **tier-index.yaml** - Tier definitions and requirements
- **project.yaml** - Project-specific blueprint (optional)
- **.docs-config** - Local script configuration (optional)

---

## 🛠️ Development

### **Adding New Validation Rules**
1. Update `validate_docs.py` with new rule logic
2. Add rule to tier-index.yaml if tier-specific
3. Update documentation in relevant .md files
4. Test with sample projects

### **Extending Auto-Repair**
1. Add repair logic to `validation_protocol_v2.py`
2. Update docs/platform-engineering/VALIDATION-PROTOCOL-v2.md
3. Test repair effectiveness
4. Document new capabilities

---

## 📊 Reporting

### **Validation Report Format**
```json
{
  "tier": "core",
  "status": "pass",
  "files_validated": 18,
  "issues_found": 0,
  "issues_fixed": 2,
  "recommendations": [],
  "validation_time": "2.3s"
}
```

### **Exit Codes**
- **0**: Success - all validations passed
- **1**: Warning - minor issues, auto-repaired
- **2**: Error - critical issues require manual fix

---

**Last Updated**: 2025-12-09  
**Script Version**: 2.0  
**Status**: Production Ready 🎊
