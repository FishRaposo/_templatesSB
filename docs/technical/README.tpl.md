# Documentation Templates

**Purpose**: User-facing documentation templates organized by the Three Tiers Framework (MVP → CORE → FULL).

---

## 📋 File Inventory

| File | Size | Purpose |
|------|------|---------|
| **TIER-GUIDE.md** | 23KB | 📚 Complete framework documentation for MVP/CORE/FULL tiers |
| **TIER-MAPPING.md** | 21KB | 🗺️ Template inventory and file mappings by tier |
| **TIER-SELECTION.md** | 10KB | 🎯 Deterministic algorithm for automatic tier selection |
| **platform-engineering/** | 10 files | 🏗️ Advanced refactoring and validation components |

---

## 🎯 Three Tiers Framework

### **MVP Tier** (Prototype/Exploration)
- **Setup Time**: 15-30 minutes
- **Files**: 4-7 documents
- **Coverage**: 0-20% (smoke tests)
- **Use Cases**: Hackathons, experiments, solo projects

### **CORE Tier** ⭐ (Production Baseline - Default)
- **Setup Time**: 2-4 hours  
- **Files**: 15-25 documents
- **Coverage**: 85%+ (unit, component, integration)
- **Use Cases**: 90% of real projects, SaaS, client work

### **FULL Tier** (Enterprise/Long-term)
- **Setup Time**: 1-2 days
- **Files**: 30-50 documents
- **Coverage**: 95%+ (complete testing matrix)
- **Use Cases**: Enterprise platforms, team projects, compliance

---

## 🚀 Quick Start

### For New Projects
```bash
# AI Command
"Set tier to CORE for [PROJECT_DESCRIPTION]"

# Manual Setup
1. Read TIER-GUIDE.md to understand framework
2. Reference TIER-MAPPING.md for template details  
3. Execute QUICKSTART-AI.md for automated setup
4. Validate with scripts/validate_docs.py
```

### For AI Agents
1. **Analyze project context** using TIER-SELECTION.md algorithm
2. **Select appropriate tier** based on analysis
3. **Execute tier-appropriate setup** using QUICKSTART-AI.md
4. **Validate completeness** using tier-index.yaml

---

## 🔗 Integration Points

### Cross-Reference Structure
- **TIER-GUIDE.md** ← Decision framework and migration guidelines
- **TIER-MAPPING.md** ← Template mappings and file requirements
- **TIER-SELECTION.md** ← Deterministic tier selection algorithm
- **QUICKSTART-AI.md** ← Automated setup with Phase 0 tier detection

### Dependencies
- **tier-index.yaml** (root) - Source of truth for tier requirements
- **universal/** - Base templates that apply across all tiers
- **examples/** - Tech-specific templates for customization
- **platform-engineering/** - Advanced refactoring and validation tools

---

## 📚 Usage Guidelines

### When to Use Each Tier
- **MVP**: Personal projects, experiments, learning new tech
- **CORE**: ⭐ Default choice for production software
- **FULL**: Enterprise requirements, team collaboration, compliance

### AI Agent Integration
- All files support AI-driven automation
- Tier selection is deterministic and reproducible
- Cross-references are fully updated for new directory structure
- Validation protocols ensure consistency

---

**Last Updated**: 2025-12-09  
**Framework Version**: 2.0  
**Status**: Production Ready 🎊
