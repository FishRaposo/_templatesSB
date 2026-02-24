# Platform Comparison Matrix

This document provides a detailed comparison of skills implementation across Claude, Roo Code, and Cascade (Windsurf).

**Platform Documentation:**
- Claude: https://docs.claude.com/en/docs/agents-and-tools/agent-skills/overview.md
- Roo Code: https://docs.roocode.com/features/skills
- Cascade: https://docs.windsurf.com/windsurf/cascade/skills

## Overview Table

| Feature | Claude | Roo Code | Cascade (Windsurf) |
|---------|--------|----------|-------------------|
| **Skill Discovery** | Automatic | Automatic | Progressive Disclosure |
| **Global Skills Path** | `~/.claude/skills/` | `~/.roo/skills/` | `~/.codeium/windsurf/skills/` |
| **Project Skills Path** | `.claude/skills/` | `.roo/skills/` | `.windsurf/skills/` |
| **Config File** | `config.json` (optional) | `config.json` (optional) | Not required |
| **Manual Invocation** | No | No | Yes (@skill-name) |
| **UI Management** | No | No | Yes |
| **Mode Support** | Yes (Code/Write) | Yes (Code/Architect) | N/A |
| **Override System** | No | Yes (Project > Global) | No |
| **Resource Bundling** | Yes | Yes | Yes (Automatic) |
| **Real-time Context** | Limited | Limited | Yes |
| **Progressive Loading** | No | Yes | Yes |

## Detailed Comparison

### 1. Skill Structure

#### Claude
```
skill-name/
├── SKILL.md              # Required
├── config.json           # Optional
└── [supporting files]    # Optional
```

#### Roo Code
```
skill-name/
├── SKILL.md              # Required
├── config.json           # Optional
└── [supporting files]    # Optional
```

#### Cascade
```
skill-name/
├── SKILL.md              # Required
└── [supporting files]    # Optional (no config.json)
```

### 2. Frontmatter Requirements

#### Claude Frontmatter
```yaml
---
name: skill-name
description: Use this skill when...
version: "1.0.0"
agent_support:
  claude:
    min_version: "3.0"
    model_preference: "sonnet"
    tools: ["file_read", "file_write", "execute"]
    modes: ["code", "write"]
---
```

#### Roo Code Frontmatter
```yaml
---
name: skill-name
description: Use this skill when...
version: "1.0.0"
agent_support:
  roo:
    min_version: "1.0"
    mode: "code"
    auto_approve: false
    tools: ["read_file", "write_file", "bash"]
---
```

#### Cascade Frontmatter
```yaml
---
name: skill-name
description: Use this skill when...
version: "1.0.0"
# No agent_support needed
tags: ["tag1", "tag2"]
---
```

### 3. Configuration Options

#### Claude Config.json
```json
{
  "agent_specific": {
    "claude": {
      "temperature": 0.7,
      "max_tokens": 4000,
      "tools": ["file_read", "file_write", "execute"],
      "model": "claude-3-sonnet"
    }
  },
  "permissions": {
    "file_system": true,
    "network": false,
    "execute_code": true
  }
}
```

#### Roo Code Config.json
```json
{
  "agent_specific": {
    "roo": {
      "mode": "code",
      "auto_approve": false,
      "tools": ["read_file", "write_file", "bash"],
      "timeout": 30
    }
  },
  "permissions": {
    "file_system": true,
    "network": false,
    "execute_code": true
  }
}
```

#### Cascade Configuration
All configuration is in SKILL.md frontmatter. No config.json file.

### 4. Invocation Methods

#### Claude
- **Automatic**: Based on description matching
- **No manual invocation**

#### Roo Code
- **Automatic**: Based on description matching
- **No manual invocation**
- **Project overrides**: Project skills take precedence

#### Cascade
- **Automatic**: Progressive disclosure based on description
- **Manual**: `@skill-name` syntax
- **UI**: Can select skills from the UI

### 5. Platform-Specific Features

#### Claude Unique Features
- **Native File Tools**: Direct file system access
- **Mode-Specific Skills**: Skills limited to Code/Write modes
- **Strong Markdown Processing**: Advanced markdown features
- **Context Preservation**: Maintains context across invocations

#### Roo Code Unique Features
- **Project Override System**: Project skills override global
- **Mode Integration**: Strong integration with Code/Architect modes
- **Custom Tool Implementation**: Unique tool set
- **Progressive Loading**: Efficient skill loading

#### Cascade Unique Features
- **Progressive Disclosure**: Enhanced automatic invocation
- **Manual Invocation**: @skill-name syntax
- **UI Integration**: Create/manage through UI
- **Real-time Awareness**: Workspace context awareness
- **No Config.json**: Simplified configuration

### 6. Skill Creation Methods

#### Claude
```bash
# Manual only
mkdir -p ~/.claude/skills/skill-name
# Create SKILL.md manually
```

#### Roo Code
```bash
# Manual only
mkdir -p ~/.roo/skills/skill-name
# Create SKILL.md manually
```

#### Cascade
```bash
# Method 1: UI (Recommended)
# Use Cascade UI to create skills

# Method 2: Manual
mkdir -p ~/.codeium/windsurf/skills/skill-name
# Create SKILL.md manually
```

### 7. Best Practices by Platform

#### Claude Best Practices
- Leverage native file tools
- Use mode-specific skills for specialized tasks
- Include Claude-specific tool configurations
- Test with different Claude models

#### Roo Code Best Practices
- Understand the override priority system
- Leverage mode-specific skills
- Include Roo-specific tool configurations
- Test project-level overrides

#### Cascade Best Practices
- Write clear, specific descriptions for automatic invocation
- Include relevant supporting files
- Use descriptive names
- Test both automatic and manual invocation

### 8. Migration Paths

#### To Claude
```bash
# From any platform
cp -r source/skills/skill-name ~/.claude/skills/skill-name
# Add config.json if needed
# Update frontmatter for Claude
```

#### To Roo Code
```bash
# From any platform
cp -r source/skills/skill-name ~/.roo/skills/skill-name
# Add config.json if needed
# Update frontmatter for Roo Code
```

#### To Cascade
```bash
# From any platform
cp -r source/skills/skill-name ~/.codeium/windsurf/skills/skill-name
# Remove config.json (not needed)
# Update description for progressive disclosure
```

### 9. Limitations and Workarounds

#### Claude Limitations
- No UI management
- No manual invocation
- Mode restrictions

**Workarounds**:
- Create multiple skills for different modes
- Use clear descriptions for better matching
- Document mode requirements

#### Roo Code Limitations
- Complex override system
- Mode dependencies
- Custom tool requirements

**Workarounds**:
- Document override behavior clearly
- Provide mode-specific instructions
- Include tool requirement checks

#### Cascade Limitations
- No config.json support
- Dependent on description quality
- Some features UI-only

**Workarounds**:
- Write excellent, specific descriptions
- Use frontmatter for all configuration
- Document manual creation process

### 10. Testing Strategies

#### Claude Testing
```bash
# Test automatic invocation
claude "Use skill-name to [task]"

# Verify mode-specific behavior
claude --mode code "Use skill-name"
```

#### Roo Code Testing
```bash
# Test automatic invocation
roo code "Use skill-name to [task]"

# Test project overrides
cd project-directory
roo code "Use skill-name to [task]"
```

#### Cascade Testing
```bash
# Test automatic invocation
# In Cascade: "Use skill-name to [task]"

# Test manual invocation
# In Cascade: "@skill-name [task]"

# Test UI creation
# Use Cascade UI to create/manage skills
```

## Decision Matrix

### Choose Claude When:
- You need native file tool integration
- Mode-specific skills are important
- Strong markdown processing is required
- Context preservation across invocations

### Choose Roo Code When:
- Project override system is needed
- Mode integration is critical
- Custom tool implementations are required
- Progressive loading is beneficial

### Choose Cascade When:
- UI management is preferred
- Manual invocation is needed
- Real-time workspace awareness is important
- Simplified configuration (no config.json) is desired

### Choose Universal Approach When:
- Skills need to work across platforms
- Maximum compatibility is required
- Platform-specific features are secondary
- Future platform support is anticipated

This comparison helps you choose the right platform for your needs and understand how to create skills that work effectively across different AI agent platforms.
