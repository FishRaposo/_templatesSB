# {{PROJECT_NAME}} - Changelog

> All notable changes to {{PROJECT_NAME}} will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- {{#each UNRELEASED_ADDED}}
- {{this}}
{{/each}}

### Changed
- {{#each UNRELEASED_CHANGED}}
- {{this}}
{{/each}}

### Deprecated
- {{#each UNRELEASED_DEPRECATED}}
- {{this}}
{{/each}}

### Removed
- {{#each UNRELEASED_REMOVED}}
- {{this}}
{{/each}}

### Fixed
- {{#each UNRELEASED_FIXED}}
- {{this}}
{{/each}}

### Security
- {{#each UNRELEASED_SECURITY}}
- {{this}}
{{/each}}

## [{{CURRENT_VERSION}}] - {{RELEASE_DATE}}

### Added
{{#each VERSION_ADDED}}
- {{this}}
{{/each}}

### Changed
{{#each VERSION_CHANGED}}
- {{this}}
{{/each}}

### Deprecated
{{#each VERSION_DEPRECATED}}
- {{this}}
{{/each}}

### Removed
{{#each VERSION_REMOVED}}
- {{this}}
{{/each}}

### Fixed
{{#each VERSION_FIXED}}
- {{this}}
{{/each}}

### Security
{{#each VERSION_SECURITY}}
- {{this}}
{{/each}}

## [Previous Versions]

{{#each PREVIOUS_VERSIONS}}
### [{{version}}] - {{date}}
#### Added
{{#each added}}
- {{this}}
{{/each}}
#### Changed
{{#each changed}}
- {{this}}
{{/each}}
#### Fixed
{{#each fixed}}
- {{this}}
{{/each}}
{{/each}}

---

## 📝 Changelog Guidelines

### What to Include
- **Added**: New features, new capabilities, new endpoints
- **Changed**: Changes in existing functionality, improvements
- **Deprecated**: Features that will be removed in future versions
- **Removed**: Features removed in this version
- **Fixed**: Bug fixes, error corrections
- **Security**: Vulnerability fixes, security improvements

### Format Rules
1. **Always** include version number and release date
2. **Use** past tense for all entries ("Fixed bug" not "Fix bug")
3. **Be** specific and descriptive
4. **Include** issue numbers or PR references when applicable
5. **Group** changes by type (Added, Changed, Fixed, etc.)

### Version Format
Follow semantic versioning: `MAJOR.MINOR.PATCH`
- **MAJOR**: Incompatible API changes
- **MINOR**: New functionality in a backwards compatible manner
- **PATCH**: Backwards compatible bug fixes

### Release Process
1. Update `Unreleased` section with new changes
2. Create new version entry with release date
3. Clear `Unreleased` section
4. Tag release in version control

---

**Last Updated**: {{LAST_UPDATED_DATE}}  
**Next Version**: {{NEXT_VERSION}}
