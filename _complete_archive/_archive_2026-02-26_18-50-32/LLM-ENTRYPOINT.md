# 🤖 LLM Entry Point - Universal Template System

> **PRIMARY STARTING POINT FOR AI AGENTS** - Read this file first to understand and use the template system

**Purpose**: This is the definitive entry point for LLMs to generate projects using the Universal Template System.  
**Last Updated**: {{LAST_UPDATED_DATE}}  
**Total Templates**: 66 (in default-project blueprint generic overlay) / 746 (system-wide)  
**System Version**: {{SYSTEM_VERSION}}

---

## 🎯 Quick Start for LLMs

### Step 1: Understand the System (30 seconds)
```yaml
# Read these 3 files in order:
1. blueprint.meta.yaml     # Master configuration (7KB)
2. tier-index.yaml         # Tier selection rules (16KB)  
3. AI-QUICK-START.md       # Automated setup guide (42KB)
```

### Step 2: Generate Project (5 minutes)
```bash
# Single command to generate any project:
"Generate a {{PROJECT_TYPE}} project using the Universal Template System:
- Read blueprint.meta.yaml for available templates
- Always apply the 'default-project' blueprint first (this is the mandatory documentation + repo hygiene baseline)
- Detect tier as {{TIER}} from project requirements
- Apply {{STACK}} stack overlay
- Generate FEATURES.md and docs/FEATURES.md by extracting ALL features from the requirements
- Follow AI-QUICK-START.md for automated setup"
```

---

## 📁 System Architecture

```
Universal Template System/
├── 🎯 LLM-ENTRYPOINT.md          # YOU ARE HERE - Primary starting point
├── 📋 blueprint.meta.yaml        # MASTER CONFIG - All template definitions
├── 📊 tier-index.yaml            # TIER SELECTION - MVP/Core/Enterprise rules
├── 🚀 AI-QUICK-START.md          # AUTOMATED SETUP - 5-phase generation
├── 🤖 AI Agent Guides (System Docs)
│   ├── AGENTS.md                 # Multi-agent coordination
│   ├── CLAUDE.md                 # Claude quick reference
│   ├── AIDER.md                  # Aider CLI guide
│   ├── CODEX.md                  # Codex API guide
│   ├── CODY.md                   # Sourcegraph Cody guide
│   ├── COPILOT.md                # GitHub Copilot guide
│   ├── CURSOR.md                 # Cursor IDE guide
│   ├── GEMINI.md                 # Google Gemini guide
│   ├── WARP.md                   # Warp terminal guide
│   └── WINDSURF.md               # Windsurf assistant guide
├── 📚 blueprints/default-project/  # DEFAULT PROJECT BLUEPRINT (project templates)
│   ├── overlays/generic/         # Universal project templates
│   │   ├── (root templates)      # Default project docs + repo hygiene (31 templates)
│   │   ├── agents/               # 9 AI agent TEMPLATES (.tpl.md)
│   │   ├── docs/                 # Comprehensive project documentation set (20 templates)
│   │   └── .github/              # Workflows + PR/issue templates (6 templates)
│   └── overlays/[stack]/         # Stack-specific (python, node, etc.)
└── 📖 TEMPLATE-MANIFEST.md       # Complete inventory
```

---

## 🔧 Template Categories

| Category | Location | Count | Use When |
|----------|----------|-------|----------|
| **Core Files** | `blueprints/default-project/overlays/generic/` | 31 | Default project docs + repo hygiene |
| **AI Guides** | `blueprints/default-project/overlays/generic/agents/` | 9 | Specific AI assistant setup |
| **Docs Governance** | `blueprints/default-project/overlays/generic/docs/` | 20 | Full project documentation set |
| **GitHub Templates** | `blueprints/default-project/overlays/generic/.github/` | 6 | Workflows + PR/issue templates |

---

## 🚀 Project Generation Workflow

### Phase 0: Context Detection
```yaml
# LLM automatically detects:
project_type: "{{web|mobile|api|library|cli}}"
tech_stack: "{{python|node|flutter|react|go|etc}}"
team_size: "{{1-2|3-5|5+}}"
complexity: "{{mvp|core|enterprise}}"
```

### Phase 1: Template Selection
```yaml
# Read blueprint.meta.yaml to find:
- Required templates for project type
- Stack-specific overlays to apply
- Tier-appropriate complexity
```

### Phase 2: Generation
```bash
# Process:
1. Copy templates from blueprints/default-project/overlays/generic/ (mandatory baseline)
2. Apply stack-specific overlays (and any additional blueprints selected)
3. Replace {{PLACEHOLDERS}} with project values
4. Generate tier-appropriate file count
```

### Phase 3: Validation
```bash
# Run validation:
python scripts/validate-templates.py --full
```

---

## 📋 Essential Files for LLMs

| Priority | File | Purpose | Size |
|----------|------|---------|------|
| 1 | `blueprint.meta.yaml` | **MASTER CONFIG** - All templates | 7KB |
| 2 | `tier-index.yaml` | **TIER SELECTION** - Auto-detect complexity | 16KB |
| 3 | `AI-QUICK-START.md` | **AUTOMATED SETUP** - 5-phase guide | 42KB |
| 4 | `AGENTS.md` | **DEVELOPER GUIDE** - AI standards | 18KB |
| 5 | `TEMPLATE-MANIFEST.md` | **INVENTORY** - Complete list | 8KB |

---

## 🎯 Example Prompts

### Generate Web API
```
"Generate a Python FastAPI web API using Universal Template System:
1. Read blueprint.meta.yaml
2. Detect tier as 'core' (REST API with database)
3. Apply python stack overlay
4. Generate all core templates
5. Replace {{PROJECT_NAME}} with 'MyAPI'
6. Follow AI-QUICK-START.md setup"
```

### Generate Mobile App
```
"Generate a Flutter mobile app using Universal Template System:
1. Read blueprint.meta.yaml
2. Detect tier as 'mvp' (simple mobile app)
3. Apply flutter stack overlay
4. Generate mobile-specific templates
5. Replace {{PROJECT_NAME}} with 'MyApp'
6. Follow AI-QUICK-START.md setup"
```

---

## 🔍 Navigation Tips

### For Project Generation
1. **Start here** - LLM-ENTRYPOINT.md
2. **Read config** - blueprint.meta.yaml
3. **Select tier** - tier-index.yaml
4. **Generate** - AI-QUICK-START.md

### For Development
1. **Standards** - AGENTS.md
2. **Quick ref** - CLAUDE.md
3. **Navigation** - INDEX.md
4. **All files** - TEMPLATE-MANIFEST.md

---

## ⚡ Optimization Tips

### Tool Call Efficiency
- **Batch reads** - Read multiple files in parallel
- **Use grep** - For pattern searching, not codebase_search
- **Cache info** - Don't re-read files
- **Plan ahead** - Know what you need before starting

### Template Selection
- **Tier first** - Determines complexity
- **Stack second** - Language/framework
- **Type third** - Web/mobile/API/etc.
- **Size last** - Based on team/requirements

---

## 🎯 Success Checklist

Before completing project generation:

- [ ] Read blueprint.meta.yaml
- [ ] Determined tier from tier-index.yaml
- [ ] Applied appropriate stack overlay
- [ ] Replaced all {{PLACEHOLDERS}}
- [ ] Generated correct number of files
- [ ] FEATURES.md and docs/FEATURES.md fully reflect the project requirements (no missing features)
- [ ] Followed AI-QUICK-START.md
- [ ] Ran validation script
- [ ] All tests pass

---

## 📚 Quick Reference

| Need | File | Command |
|------|------|---------|
| Generate project | AI-QUICK-START.md | "Run the quickstart" |
| Understand system | blueprint.meta.yaml | Read metadata |
| Select tier | tier-index.yaml | Auto-detect |
| Development rules | AGENTS.md | Read standards |
| Find template | TEMPLATE-MANIFEST.md | Search manifest |
| Validate all | scripts/validate-templates.py | Run validation |

---

**Last Updated**: {{LAST_UPDATED_DATE}}  
**System Version**: {{SYSTEM_VERSION}}  
**Total Templates**: 746

---

*🤖 This is the primary entry point for AI agents. Start here, follow the workflow, and generate projects efficiently.*
