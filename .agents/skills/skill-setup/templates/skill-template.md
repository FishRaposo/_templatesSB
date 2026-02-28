<!-- TEMPLATE GUIDE:
  Required sections: Core Approach, Step-by-Step, Best Practices, Validation Checklist, Troubleshooting, Related Skills
  Minimum for small skills: Core Approach, Step-by-Step, Validation Checklist
  Optional sections: Examples, CLI Tools to Leverage, Language Patterns (for implementation-focused skills)
  Show concepts in at least 2 languages (JavaScript + Python minimum). Add Go/Rust/TypeScript where they illustrate a different paradigm.
  Include an "Adapting to Other Languages" note so users of C#, Java, Kotlin, Swift, etc. can map concepts to their stack.
  Use examples/ or _examples/ and reference folders per project convention.
  Remove this comment block when using the template.
-->
---
name: your-skill-name
description: Use this skill when [describe specific situations when this skill should be invoked]. This includes [list concrete use cases and trigger keywords that should activate this skill].
---

# [Skill Name]

I'll help you [primary benefit]. When you invoke this skill, I can guide you through the entire [process/topic].

# Core Approach

My approach focuses on:
1. [First principle/step]
2. [Second principle/step]
3. [Third principle/step]
4. [Fourth principle/step]

# Step-by-Step Instructions

## 1. [First Major Step]

First, I'll help you [action]:

- [Specific action item 1]
- [Specific action item 2]
- [Validation step]

**CLI Tools:**
- `command-name` - What it does
- `another-command` - What it does

## 2. [Second Major Step]

Next, I'll help you [action]:

- [Specific action item 1]
- [Specific action item 2]

**JavaScript:**
```javascript
import { readFile } from 'fs/promises';
const data = await readFile('input.txt', 'utf-8');
console.log(data);
```

**Python:**
```python
with open('input.txt') as f:
    data = f.read()
print(data)
```

## 3. [Third Major Step]

[Clear, actionable instructions with complete, runnable commands]

```bash
gh repo view --json name,description
npm install -g useful-package
aws s3 ls s3://bucket-name/
```

# Examples (Optional — for CLI-focused skills)

## Example 1: [Use Case Name]

**User Query**: "[Example of what user might say]"

**Approach**:
1. Use `cli-tool` to gather information
2. Process with script (JS/Python/etc.)
3. Validate output with another CLI command

**Complete Commands:**
```bash
# Step 1
gh api repos/owner/repo

# Step 2 - Node.js processing
node process-data.js

# Step 3 - Validation
npm test
```

**Expected Outcome**: [What should result]

## Example 2: [Another Use Case]

**User Query**: "[Another example query]"

**Approach**:
1. [Step using CLI tools]
2. [Step using Node.js]
3. [Verification step]

# CLI Tools to Leverage (Optional — omit for conceptual skills)

**Essential tools for this skill:**
- `git` - Version control operations
- `jq` - JSON processing
- [Other relevant CLI tools]

**Language-Specific Tools:**
- **JavaScript**: `npm install -g package-name` - [Purpose]
- **Python**: `pip install package-name` - [Purpose]
- **Go**: `go install tool@latest` - [Purpose]
- **Rust**: `cargo install tool` - [Purpose]

# Language Patterns (Optional — omit for conceptual skills)

**JavaScript (Node.js):**
```javascript
import { readFile, writeFile } from 'fs/promises';
const data = JSON.parse(await readFile('data.json', 'utf-8'));
const filtered = data.filter(item => item.active);
await writeFile('output.json', JSON.stringify(filtered, null, 2));
```

**Python:**
```python
import json
from pathlib import Path

data = json.loads(Path('data.json').read_text())
filtered = [item for item in data if item['active']]
Path('output.json').write_text(json.dumps(filtered, indent=2))
```

**Go:**
```go
data, _ := os.ReadFile("data.json")
var items []Item
json.Unmarshal(data, &items)
filtered := lo.Filter(items, func(i Item, _ int) bool { return i.Active })
```

**TypeScript:**
```typescript
const data: Item[] = JSON.parse(await readFile('data.json', 'utf-8'));
const filtered = data.filter((item): item is ActiveItem => item.active);
```

## Adapting to Other Languages

The examples above use JavaScript, Python, Go, and Rust, but the concepts apply to **any language**. Use this mapping to adapt:

| Concept | Your Language Equivalent |
|---------|-------------------------|
| **Module system** | ES Modules → `import`/`export` · Python → `import` · Go → `package` · **C#** → `namespace`/`using` · **Java** → `package`/`import` · **Kotlin** → `package`/`import` · **Swift** → `import` module |
| **Error handling** | JS → `try/catch` · Python → `try/except` · Go → `error` return · Rust → `Result<T,E>` · **C#/Java** → `try/catch` · **Swift** → `do/try/catch` · **Kotlin** → `try/catch` + `Result` |
| **Collections** | JS → `Array/Map/Set` · Python → `list/dict/set` · Go → `slice/map` · Rust → `Vec/HashMap` · **C#** → `List/Dictionary` · **Java** → `ArrayList/HashMap` · **Swift** → `Array/Dictionary/Set` |
| **Package manager** | `npm` · `pip` · `go mod` · `cargo` · **C#** → `dotnet`/`NuGet` · **Java** → `maven`/`gradle` · **Swift** → `SPM` · **Kotlin** → `gradle` |
| **Test runner** | `jest`/`vitest` · `pytest` · `go test` · `cargo test` · **C#** → `dotnet test` · **Java** → `JUnit` · **Swift** → `XCTest` · **Kotlin** → `JUnit`/`kotest` |
| **Type system** | JS → dynamic · Python → dynamic+hints · Go → static structural · Rust → static nominal · **C#/Java/Kotlin/Swift** → static nominal |

> **Tip**: When adapting, focus on the *concept* (e.g., "memoization", "pattern matching"), not the syntax. Find your language's idiomatic way to express it.

# Best Practices

- Challenge each instruction: "Does the agent really need this context?"
- Keep SKILL.md under 500 lines
- Show concepts in at least 2 languages (JavaScript + Python minimum)
- Add Go/Rust/TypeScript when they show a meaningfully different approach
- Include an adaptation note for languages not explicitly covered
- Provide complete, runnable commands
- Reference supporting files with relative paths (e.g., `./details.md`)
- Use intention-revealing names for all files
- Show command chaining when helpful

# Validation Checklist

When completing a task with this skill, verify:
- [ ] CLI commands executed successfully
- [ ] Output matches expected format
- [ ] No errors in console output
- [ ] Results are validated with test commands
- [ ] [Domain-specific validation item]

# Troubleshooting

## Issue: [Common Problem]

**Symptoms**: [What user sees]

**Investigation**:
```bash
# Check logs or status
command-to-diagnose
```

**Solution**: [How to fix with specific commands]

## Issue: [Another Problem]

**Symptoms**: [What user sees]

**Investigation**:
```bash
# Diagnostic command
another-diagnostic-command
```

**Solution**: [How to fix]

# Supporting Files

- See `./examples/basic-examples.md` or `./_examples/basic-examples.md` for fundamental implementations (per project convention)
- See `./examples/advanced-examples.md` or `./_examples/advanced-examples.md` for complex scenarios

## Related Skills

- **[related-skill-1]** - [how it relates to this skill]
- **[related-skill-2]** - [how it relates to this skill]
- → **[pack-id]**: [skill-name] (for [specific use case])

Remember: [Key insight or principle]!
