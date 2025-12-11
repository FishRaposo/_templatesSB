# {{DIRECTORY_NAME}}/ - Directory Index

> ⚠️ **MANDATORY** when directory has 5+ files: Navigation index for {{DIRECTORY_NAME}}/

**Purpose**: This index provides navigation and overview for the `{{DIRECTORY_NAME}}/` directory.  
**Last Updated**: {{LAST_UPDATED_DATE}}  
**File Count**: {{FILE_COUNT}} files

---

## 📁 Directory Overview

**Path**: `{{DIRECTORY_PATH}}/`  
**Purpose**: {{DIRECTORY_PURPOSE}}

### Quick Stats
- **Total Files**: {{FILE_COUNT}}
- **Subdirectories**: {{SUBDIRECTORY_COUNT}}
- **Primary Language**: {{PRIMARY_LANGUAGE}}

---

## 📑 File Listing

### By Category

{{#each FILE_CATEGORIES}}
#### {{category_name}}
{{#each files}}
- [`{{filename}}`]({{filename}}) - {{description}}
{{/each}}
{{/each}}

### Alphabetical Listing

| File | Type | Description | Last Modified |
|------|------|-------------|---------------|
{{#each ALL_FILES}}
| [`{{filename}}`]({{filename}}) | {{type}} | {{description}} | {{modified}} |
{{/each}}

---

## 🗂️ Subdirectories

{{#each SUBDIRECTORIES}}
### [`{{name}}/`]({{name}}/)
- **Purpose**: {{purpose}}
- **File Count**: {{file_count}}
- **Key Files**: {{key_files}}
{{/each}}

---

## 🔗 Key Files

### Entry Points
{{#each ENTRY_POINTS}}
- [`{{filename}}`]({{filename}}) - {{description}}
{{/each}}

### Configuration
{{#each CONFIG_FILES}}
- [`{{filename}}`]({{filename}}) - {{description}}
{{/each}}

### Tests
{{#each TEST_FILES}}
- [`{{filename}}`]({{filename}}) - {{description}}
{{/each}}

---

## 📊 Directory Structure

```
{{DIRECTORY_NAME}}/
{{#each STRUCTURE_TREE}}
{{indent}}{{item}}
{{/each}}
```

---

## 🔄 Dependencies

### Internal Dependencies
{{#each INTERNAL_DEPS}}
- `{{module}}` depends on `{{dependency}}`
{{/each}}

### External Dependencies
{{#each EXTERNAL_DEPS}}
- `{{package}}` - {{purpose}}
{{/each}}

---

## 📝 Conventions

### Naming Conventions
- **Files**: {{FILE_NAMING_CONVENTION}}
- **Functions**: {{FUNCTION_NAMING_CONVENTION}}
- **Classes**: {{CLASS_NAMING_CONVENTION}}

### Organization Principles
{{#each ORGANIZATION_PRINCIPLES}}
- {{this}}
{{/each}}

---

## 🔧 Common Operations

### Adding New Files
1. Follow naming convention: `{{FILE_NAMING_PATTERN}}`
2. Add to appropriate category
3. Update this INDEX.md
4. Update parent INDEX.md if exists

### Modifying Files
1. Check dependencies before changing
2. Update tests if behavior changes
3. Update documentation
4. Update CHANGELOG.md

### Removing Files
1. Check for dependencies
2. Update imports/references
3. Remove from this INDEX.md
4. Update CHANGELOG.md

---

## 📋 Maintenance Checklist

### When to Update This Index
- [ ] New files added to directory
- [ ] Files removed from directory
- [ ] File purposes changed
- [ ] Directory structure changed
- [ ] New subdirectories created

### Update Process
1. Run directory scan
2. Update file counts
3. Update file listing
4. Update structure tree
5. Verify all links work

---

## 🔗 Related Documentation

- [Parent INDEX.md](../INDEX.md) - Parent directory index
- [Project INDEX.md](../../INDEX.md) - Project-wide index
- [AGENTS.md](../../AGENTS.md) - Development conventions

---

**Last Updated**: {{LAST_UPDATED_DATE}}  
**Indexed Files**: {{FILE_COUNT}}

---

*This index is mandatory for directories with 5+ files. Keep it updated when adding, removing, or modifying files in this directory.*
