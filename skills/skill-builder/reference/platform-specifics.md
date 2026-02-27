# Platform-Specific Implementation Guide

This document details the differences and specific requirements for various AI agent platforms.

## Platform Comparison Matrix

| Feature | Claude | Roo Code | Cascade (Windsurf) | Generic Agents | Custom Implementation |
|---------|--------|----------|-------------------|---------------|----------------------|
| **Global Skills Path** | `~/.claude/skills/` | `~/.roo/skills/` | `~/.codeium/windsurf/skills/` | `~/.agent/skills/` | Implementation-dependent |
| **Project Skills Path** | `.claude/skills/` | `.roo/skills/` | `.windsurf/skills/` | `.agent/skills/` | Implementation-dependent |
| **Config Format** | JSON | JSON | Optional | JSON | Variable |
| **File Tools** | Native | Custom | Native | Variable | Implementation-dependent |
| **Mode Support** | ✓ | ✓ | ✓ | Variable | Optional |
| **Symlink Support** | ✓ | ✓ | ✓ | Variable | File system dependent |
| **Version Constraints** | ✓ | ✓ | Optional | Optional | Optional |
| **Permission System** | ✓ | ✓ | Optional | Variable | Implementation-dependent |

## Claude

### Directory Structure
```bash
# Global skills
~/.claude/skills/
└── skill-name/
    └── SKILL.md

# Project skills
<project>/.claude/skills/
└── skill-name/
    └── SKILL.md

# Mode-specific skills
~/.claude/skills-code/     # Code mode only
~/.claude/skills-write/    # Write mode only
```

### Configuration
```json
{
  "agent_specific": {
    "claude": {
      "temperature": 0.7,
      "max_tokens": 4000,
      "tools": ["file_read", "file_write", "execute"],
      "model": "claude-3-sonnet"
    }
  }
}
```

### Special Features
- **Native File Tools**: Direct file system access
- **Mode-Specific Skills**: Skills can be limited to specific modes
- **Strong Markdown Support**: Advanced markdown processing
- **Context Preservation**: Maintains context across skill invocations

### Best Practices
- Leverage native file tools for efficiency
- Use mode-specific skills for specialized tasks
- Include Claude-specific tool configurations
- Test with different Claude models

## Roo Code

### Directory Structure
```bash
# Global skills
~/.roo/skills/
└── skill-name/
    └── SKILL.md

# Project skills
<project>/.roo/skills/
└── skill-name/
    └── SKILL.md

# Mode-specific skills
~/.roo/skills-code/       # Code mode only
~/.roo/skills-architect/  # Architect mode only
```

### Configuration
```json
{
  "agent_specific": {
    "roo": {
      "mode": "code",
      "auto_approve": false,
      "tools": ["read_file", "write_file", "bash"],
      "timeout": 30
    }
  }
}
```

### Special Features
- **Project Override System**: Project skills override global skills
- **Mode-Based Organization**: Strong integration with mode system
- **Custom Tool Implementation**: Unique tool set
- **Progressive Loading**: Efficient skill loading system

### Best Practices
- Understand the override priority system
- Leverage mode-specific skills
- Include Roo-specific tool configurations
- Test project-level overrides

## Cascade (Windsurf)

**Official Documentation**: https://docs.windsurf.com/windsurf/cascade/skills

### Directory Structure
```bash
# Global skills
~/.codeium/windsurf/skills/
└── skill-name/
    ├── SKILL.md
    └── [supporting files]

# Project/Workspace skills
.windsurf/skills/
└── skill-name/
    ├── SKILL.md
    └── [supporting files]
```

### Configuration
Cascade skills typically don't require a separate config.json file. All configuration is done through the SKILL.md frontmatter.

### Special Features
- **Progressive Disclosure**: Intelligent automatic skill invocation
- **UI Integration**: Skills can be created and managed through the UI
- **Manual Invocation**: Use @skill-name to manually invoke skills
- **Resource Bundling**: Supporting files are automatically available
- **Real-time Awareness**: Skills have access to current workspace context

### Skill Creation Methods

#### Using the UI (Easiest)
1. Open the Cascade panel
2. Click the three dots to open customizations
3. Click on the `Skills` section
4. Click `+ Workspace` for project skills or `+ Global` for global skills
5. Name the skill (lowercase, numbers, and hyphens only)

#### Manual Creation
```bash
# Workspace skill
mkdir -p .windsurf/skills/skill-name
echo "---\nname: skill-name\ndescription: Skill description\n---\n" > .windsurf/skills/skill-name/SKILL.md

# Global skill
mkdir -p ~/.codeium/windsurf/skills/skill-name
echo "---\nname: skill-name\ndescription: Skill description\n---\n" > ~/.codeium/windsurf/skills/skill-name/SKILL.md
```

### Best Practices
- Write clear, specific descriptions for automatic invocation
- Include relevant supporting files (templates, checklists, scripts)
- Use descriptive names (e.g., `deploy-to-staging` not `deploy1`)
- Leverage the progressive disclosure system
- Test both automatic and manual invocation

## Generic Agents

### Directory Structure
```bash
# Standard paths
~/.agent/skills/
└── skill-name/
    └── SKILL.md

<project>/.agent/skills/
└── skill-name/
    └── SKILL.md
```

### Configuration
```json
{
  "agent_specific": {
    "generic": {
      "api_version": "1.0",
      "capabilities": ["file_access", "code_execution"],
      "endpoint": "/v1/skills"
    }
  }
}
```

### Special Features
- **Flexible Implementation**: Adaptable to various agents
- **Standard Compliance**: Follows Agent Skills standard
- **Minimal Dependencies**: Works with basic agent capabilities
- **Extensible**: Easy to add new features

### Best Practices
- Follow the Agent Skills standard strictly
- Include fallback mechanisms
- Document required capabilities
- Test with multiple implementations

## Custom Agent Implementation

### Directory Structure
```bash
# Implementation-dependent
/custom/path/skills/
└── skill-name/
    └── SKILL.md
```

### Configuration
```json
{
  "agent_specific": {
    "custom": {
      "api_key_env": "CUSTOM_API_KEY",
      "endpoint": "https://api.example.com/v1/skills",
      "auth_method": "bearer_token",
      "custom_features": ["feature1", "feature2"]
    }
  }
}
```

### Implementation Requirements
1. **Skill Discovery**: Must scan directories for SKILL.md files
2. **Frontmatter Parsing**: Must parse YAML frontmatter
3. **Matching Logic**: Must match user requests to descriptions
4. **Resource Loading**: Must load bundled resources on demand
5. **Execution Context**: Must provide execution environment

### Best Practices
- Document all custom requirements
- Provide clear migration guides
- Include compatibility information
- Maintain backward compatibility

## Cross-Platform Compatibility Strategies

### Universal Path Handling
```python
# Python example
from pathlib import Path
import os

def get_skills_path(agent_type="generic"):
    """Get skills path based on agent type"""
    home = Path.home()
    
    paths = {
        "claude": home / ".claude" / "skills",
        "roo": home / ".roo" / "skills",
        "cascade": home / ".codeium" / "windsurf" / "skills",
        "generic": home / ".agent" / "skills"
    }
    
    return paths.get(agent_type, paths["generic"])
```

### Configuration Abstraction
```javascript
// Node.js example
class AgentConfig {
    constructor(agentType) {
        this.agentType = agentType;
        this.config = this.loadConfig();
    }
    
    loadConfig() {
        const baseConfig = {
            timeout: 30,
            retryCount: 3
        };
        
        const agentConfigs = {
            claude: { temperature: 0.7, maxTokens: 4000 },
            roo: { mode: "code", autoApprove: false },
            cascade: { autoInvoke: true, manualInvoke: true },
            generic: { apiVersion: "1.0" }
        };
        
        return {
            ...baseConfig,
            ...agentConfigs[this.agentType]
        };
    }
}
```

### Feature Detection
```python
def detect_agent_capabilities():
    """Detect available agent capabilities"""
    capabilities = {
        "file_read": False,
        "file_write": False,
        "execute_code": False,
        "network_access": False,
        "progressive_disclosure": False,
        "ui_integration": False
    }
    
    # Test for capabilities
    try:
        test_file_read()
        capabilities["file_read"] = True
    except:
        pass
    
    return capabilities
```

## Migration Guide

### From Claude to Cascade
1. Update paths from `~/.claude/skills/` to `~/.codeium/windsurf/skills/`
2. Remove Claude-specific configurations
3. Add clear descriptions for progressive disclosure
4. Test manual invocation with @skill-name

### From Roo Code to Cascade
1. Update paths from `~/.roo/skills/` to `~/.codeium/windsurf/skills/`
2. Remove mode-specific references
3. Simplify override logic
4. Add supporting files as needed

### From Cascade to Other Platforms
1. Copy skill directory to target location
2. Add platform-specific config.json if needed
3. Adjust frontmatter for platform requirements
4. Test on target platform

## Testing Across Platforms

### Unit Testing
```python
def test_skill_compatibility():
    """Test skill across different platforms"""
    platforms = ["claude", "roo", "cascade", "generic"]
    
    for platform in platforms:
        config = load_platform_config(platform)
        assert validate_skill_structure(config)
        assert check_dependencies(platform)
```

### Integration Testing
```yaml
# test-scenarios.yml
scenarios:
  - name: "Basic PDF Processing"
    platforms: ["claude", "roo", "cascade", "generic"]
    input: "Extract text from this PDF"
    expected: "Text extracted successfully"
  
  - name: "Manual Skill Invocation"
    platforms: ["cascade"]
    input: "@pdf-extractor process this file"
    expected: "Skill invoked manually"
```

## Platform-Specific Gotchas

### Claude
- Model-specific limitations
- Token limits affecting large skills
- Tool availability varies by model

### Roo Code
- Project override complexity
- Mode-specific behavior
- Custom tool implementations

### Cascade (Windsurf)
- Progressive disclosure depends on description quality
- Manual invocation uses @ syntax
- UI-based skill management
- No separate config.json needed

### Generic Agents
- Variable feature support
- Inconsistent configurations
- Limited debugging capabilities

### Custom Agents
- Non-standard implementations
- Unique requirements
- Documentation gaps

This guide helps ensure your skills work effectively across different AI agent platforms while leveraging platform-specific features when available.
