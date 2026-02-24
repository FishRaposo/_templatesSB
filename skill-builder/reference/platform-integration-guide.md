# Platform Integration Guide

This guide provides a comprehensive overview of how skills work across Claude, Roo Code, and Cascade (Windsurf), ensuring seamless integration and compatibility.

**Platform Documentation:**
- Claude: https://docs.claude.com/en/docs/agents-and-tools/agent-skills/overview.md
- Roo Code: https://docs.roocode.com/features/skills
- Cascade: https://docs.windsurf.com/windsurf/cascade/skills

## Quick Reference

| Feature | Claude | Roo Code | Cascade (Windsurf) |
|---------|--------|----------|-------------------|
| **Global Path** | `~/.claude/skills/` | `~/.roo/skills/` | `~/.codeium/windsurf/skills/` |
| **Project Path** | `.claude/skills/` | `.roo/skills/` | `.windsurf/skills/` |
| **Config File** | `config.json` (optional) | `config.json` (optional) | Not required |
| **Invocation** | Automatic | Automatic | Automatic + Manual (@skill) |
| **UI Management** | No | No | Yes |
| **Mode Support** | Yes | Yes | N/A |
| **Progressive Disclosure** | Yes | Yes | Yes (Enhanced) |

## Universal Skill Structure

All platforms follow this basic structure:
```
skill-name/
├── SKILL.md              # Required
├── config.json           # Optional (Claude/Roo)
├── scripts/              # Optional
├── templates/            # Optional
├── _examples/            # Optional (this repo; elsewhere: examples/)
└── tests/                # Optional
```

## Platform-Specific Implementation

### Claude Skills

#### Key Characteristics
- **Native File Tools**: Direct access to file system
- **Mode-Specific Skills**: Can be limited to Code/Write modes
- **Strong Markdown Processing**: Advanced markdown features
- **Context Preservation**: Maintains context across invocations

#### Frontmatter Example
```yaml
---
name: claude-skill
description: Use this skill when you need Claude-specific file processing with markdown support
version: "1.0.0"
agent_support:
  claude:
    min_version: "3.0"
    model_preference: "sonnet"
    tools: ["file_read", "file_write", "execute"]
    modes: ["code", "write"]
---
```

#### Unique Features
```yaml
# Claude-specific configurations
agent_support:
  claude:
    temperature: 0.7
    max_tokens: 4000
    tools: ["file_read", "file_write", "execute"]
```

### Roo Code Skills

#### Key Characteristics
- **Project Override System**: Project skills override global
- **Mode Integration**: Strong integration with Code/Architect modes
- **Custom Tool Set**: Unique tool implementations
- **Progressive Loading**: Efficient skill loading

#### Frontmatter Example
```yaml
---
name: roo-skill
description: Use this skill when you need Roo Code mode-specific operations with project overrides
version: "1.0.0"
agent_support:
  roo:
    min_version: "1.0"
    mode: "code"
    auto_approve: false
    tools: ["read_file", "write_file", "bash"]
---
```

#### Unique Features
```yaml
# Roo-specific configurations
agent_support:
  roo:
    mode: "code"
    auto_approve: false
    priority: 1
    shortcut: "skill"
```

### Cascade (Windsurf) Skills

#### Key Characteristics
- **Progressive Disclosure**: Enhanced automatic invocation
- **Manual Invocation**: @skill-name syntax
- **UI Integration**: Create/manage through UI
- **No Config.json**: All config in frontmatter
- **Real-time Awareness**: Workspace context

#### Frontmatter Example
```yaml
---
name: cascade-skill
description: Use this skill when you need real-time workspace-aware processing with manual invocation support
version: "1.0.0"
# No agent_support needed - Cascade handles automatically
---
```

#### Unique Features
- Manual invocation: `@cascade-skill`
- UI creation and management
- Automatic resource bundling
- No separate config file

## Creating Cross-Platform Skills

### Step 1: Universal Frontmatter
```yaml
---
name: universal-skill
description: Use this skill when you need cross-platform compatibility with automatic and manual invocation
version: "1.0.0"
tags: ["cross-platform", "universal"]
category: "utility"

# Universal agent support
agent_support:
  claude:
    min_version: "3.0"
    tools: ["file_read", "file_write"]
  roo:
    min_version: "1.0"
    mode: "code"
  cascade:
    auto_invoke: true
    manual_invoke: true
  generic:
    required_features: ["file_access"]
---
```

### Step 2: Universal Instructions
```markdown
# Universal Skill

This skill works across Claude, Roo Code, and Cascade.

## Platform-Specific Instructions

### Claude Users
- Leverage native file tools
- Use mode-specific features if available

### Roo Code Users
- Check project override status
- Use mode-appropriate tools

### Cascade Users
- Use @universal-skill for manual invocation
- All supporting files are automatically available

## Universal Workflow
1. [Step that works everywhere]
2. [Platform-specific adaptation if needed]
3. [Universal completion step]
```

### Step 3: Platform-Specific Adaptations
```javascript
// scripts/platform-detector.js
export function detectPlatform() {
  if (process.env.CLAUDE_ENV) return 'claude';
  if (process.env.ROO_CODE_ENV) return 'roo';
  if (process.env.WINDSURF_ENV) return 'cascade';
  return 'generic';
}

export function adaptToPlatform(platform) {
  switch(platform) {
    case 'claude':
      return { useNativeTools: true, modeSupport: true };
    case 'roo':
      return { checkOverrides: true, useModeTools: true };
    case 'cascade':
      return { manualInvoke: true, autoBundle: true };
    default:
      return { fallback: true };
  }
}
```

## Migration Between Platforms

### From Claude to Roo Code
```bash
# 1. Copy skill
cp -r ~/.claude/skills/my-skill ~/.roo/skills/my-skill

# 2. Update config.json
cat > ~/.roo/skills/my-skill/config.json << EOF
{
  "agent_specific": {
    "roo": {
      "mode": "code",
      "auto_approve": false
    }
  }
}
EOF

# 3. Update SKILL.md frontmatter
# Add roo-specific configurations
```

### From Roo Code to Cascade
```bash
# 1. Copy skill
cp -r ~/.roo/skills/my-skill ~/.codeium/windsurf/skills/my-skill

# 2. Remove config.json (not needed)
rm ~/.codeium/windsurf/skills/my-skill/config.json

# 3. Update description for progressive disclosure
# Make it more specific for automatic invocation
```

### From Cascade to Others
```bash
# 1. Copy skill
cp -r ~/.codeium/windsurf/skills/my-skill ~/.claude/skills/my-skill

# 2. Add config.json if needed
cat > ~/.claude/skills/my-skill/config.json << EOF
{
  "agent_specific": {
    "claude": {
      "temperature": 0.7,
      "max_tokens": 4000
    }
  }
}
EOF
```

## Testing Across Platforms

### Universal Test Script
```javascript
// scripts/test-universal.js
import { detectPlatform } from './platform-detector.js';

async function testSkill() {
  const platform = detectPlatform();
  console.log(`Testing on ${platform}...`);
  
  // Test basic functionality
  await testBasicFeatures();
  
  // Test platform-specific features
  switch(platform) {
    case 'claude':
      await testClaudeFeatures();
      break;
    case 'roo':
      await testRooFeatures();
      break;
    case 'cascade':
      await testCascadeFeatures();
      break;
  }
}

async function testBasicFeatures() {
  // Tests that work on all platforms
  console.log('✓ Basic file operations');
  console.log('✓ Markdown processing');
  console.log('✓ Resource loading');
}

async function testClaudeFeatures() {
  console.log('✓ Mode-specific skills');
  console.log('✓ Native tool access');
}

async function testRooFeatures() {
  console.log('✓ Project overrides');
  console.log('✓ Mode integration');
}

async function testCascadeFeatures() {
  console.log('✓ Manual invocation (@skill)');
  console.log('✓ UI integration');
  console.log('✓ Progressive disclosure');
}
```

## Best Practices for Universal Skills

### 1. Frontmatter Design
- Include all platform configurations
- Use universal descriptions
- Specify platform-specific requirements

### 2. Content Organization
```markdown
## Universal Instructions
[Content that works everywhere]

## Platform-Specific Notes
### Claude
[ Claude-specific notes ]

### Roo Code
[ Roo-specific notes ]

### Cascade
[ Cascade-specific notes ]
```

### 3. Resource Management
- Use relative paths
- Provide platform alternatives when needed
- Document platform-specific requirements

### 4. Error Handling
```javascript
// Universal error handling
try {
  // Try platform-specific approach
  if (platform === 'claude') {
    await claudeSpecificOperation();
  } else if (platform === 'roo') {
    await rooSpecificOperation();
  } else {
    await genericOperation();
  }
} catch (error) {
  // Fallback to universal approach
  await fallbackOperation();
}
```

## Platform Limitations and Workarounds

### Claude Limitations
- No UI management
- Manual file placement only
- Mode restrictions

**Workarounds**:
- Use mode-specific frontmatter
- Provide clear installation instructions
- Create multiple skills for different modes

### Roo Code Limitations
- Complex override system
- Mode dependencies
- Custom tool requirements

**Workarounds**:
- Document override behavior
- Provide mode-specific instructions
- Include tool requirement checks

### Cascade Limitations
- No config.json support
- Dependent on description quality
- UI-only for some features

**Workarounds**:
- Write excellent descriptions
- Use frontmatter for all config
- Document manual creation process

## Integration Checklist

### Before Publishing
- [ ] Test on all target platforms
- [ ] Verify paths are correct
- [ ] Check platform-specific features
- [ ] Document limitations
- [ ] Include fallback mechanisms

### For Claude
- [ ] Mode-specific configurations
- [ ] Native tool references
- [ ] Context preservation notes

### For Roo Code
- [ ] Override system documentation
- [ ] Mode integration notes
- [ ] Custom tool references

### For Cascade
- [ ] Progressive disclosure testing
- [ ] Manual invocation examples
- [ ] UI instructions included

## Advanced Integration Patterns

### 1. Conditional Logic Based on Platform
```markdown
## Platform Detection

This skill automatically adapts to your platform:

- **Claude**: Uses native file tools and mode features
- **Roo Code**: Respects project overrides and mode settings
- **Cascade**: Supports @skill-name manual invocation

## Adaptive Workflow

### If using Claude:
1. Claude-specific step
2. Universal step

### If using Roo Code:
1. Check project overrides
2. Roo-specific step
3. Universal step

### If using Cascade:
1. Automatic or manual invocation
2. Universal step with workspace awareness
```

### 2. Universal Configuration Pattern
```yaml
---
name: adaptive-skill
description: Use this skill when you need adaptive behavior across Claude, Roo Code, and Cascade

# Platform capabilities
capabilities:
  file_access: true
  code_execution: true
  network_access: false

# Platform-specific settings
platform_settings:
  claude:
    temperature: 0.7
    modes: ["code", "write"]
  roo:
    mode: "code"
    auto_approve: false
  cascade:
    auto_invoke: true
    manual_invoke: true
---
```

### 3. Resource Abstraction
```javascript
// scripts/universal-resource-loader.js
export class UniversalResourceLoader {
  constructor(platform) {
    this.platform = platform;
  }
  
  async loadResource(path) {
    switch(this.platform) {
      case 'claude':
        return await this.loadWithNativeTools(path);
      case 'roo':
        return await this.loadWithRooTools(path);
      case 'cascade':
        return await this.loadWithBundledResources(path);
      default:
        return await this.loadGenerically(path);
    }
  }
}
```

This integration guide ensures your skills work seamlessly across Claude, Roo Code, and Cascade while leveraging each platform's unique features.
