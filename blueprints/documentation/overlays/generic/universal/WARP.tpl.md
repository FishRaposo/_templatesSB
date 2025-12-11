## 📋 Table of Contents\n\n- [What Warp AI Should Read First](#1-what-warp-ai-should-read-first)\n- [Role & Expectations](#2-role--expectations-for-warp-ai)\n- [Recommended Warp AI Prompts](#3-recommended-warp-ai-prompts)\n- [Typical Warp Workflow](#4-typical-warp-workflow-for-this-repo)\n- [Security & Safety Best Practices](#5-security--safety-best-practices)\n- [When to Update This File](#6-when-to-update-this-file)\n- [Quick Reference: Essential Commands](#7-quick-reference-essential-commands)\n- [AI Prompt Engineering Tips](#8-ai-prompt-engineering-tips)\n\n---\n\n# WARP.md â€“ Warp AI & Agent Mode Guide

**Purpose**: Explain how to use Warp + Agent Mode effectively in this repository.

**Last Updated**: 2025-12-08  
**Project**: [PROJECT_NAME]  
**Primary Tech**: [LANGUAGE / FRAMEWORK / PLATFORM]  
**Version**: 2.0

---

## 1. What Warp AI Should Read First

When using Warp AI/Agent Mode in this project, read these files in order:

1. [`README.md`](README.md) â€“ project overview, setup, and basic usage  
2. [`AGENTS.md`](AGENTS.md) â€“ comprehensive AI development assistant guide (MANDATORY READING)  
3. [`FEATURES.md`](FEATURES.md) â€“ current feature set and capability matrix  
4. [`WORKFLOWS.md`](WORKFLOWS.md) â€“ user workflows and navigation paths  
5. [`TESTS.md`](TESTS.md) â€“ complete testing strategy (7-layer approach)  
6. [`TESTING-STRATEGY.md`](TESTING-STRATEGY.md) â€“ how tests are organized and run

> **Update this list** to match the actual docs in this repo. The order matters - start with high-level context, then dive into specifics.

---

## 2. Role & Expectations for Warp AI

Warp AI should act as a **senior [ROLE - e.g., "Flutter engineer", "React developer", "Python backend engineer"]** with 5+ years of production experience in:

- **[PRIMARY_TECH_1]** - [Specific version/pattern used in this project]  
- **[PRIMARY_TECH_2]** - [Specific version/pattern used in this project]  
- **[PRIMARY_TECH_3]** - [Specific version/pattern used in this project]  
- **Testing** - Unit, integration, and E2E testing with 85%+ coverage requirements
- **Architecture** - [Specific architecture pattern used: Clean, Hexagonal, Microservices, etc.]

### Nonâ€‘negotiable Rules

When suggesting or applying changes, Warp AI must:

1. **Follow the architecture**
   - Respect existing layering and boundaries (e.g., `domain/`, `data/`, `presentation/`, `infra/`)
   - Reuse existing patterns (repositories, services, providers, hooks, etc.) instead of inventing new ones ad hoc
   - No direct database calls from UI layer - must go through repository/service layer

2. **Always include tests**
   - No feature or bugfix is "done" without comprehensive tests
   - Coverage requirements are **MANDATORY**:
     - Unit tests: 90%+ coverage (business logic, services, utilities)
     - Component tests: 80%+ coverage (UI components, state management)
     - Integration tests: 70%+ coverage (workflows, cross-module interactions)
     - Overall: 85%+ coverage minimum
   - For every change, explicitly specify:
     - Which tests to add/change
     - Exact paths (e.g., `tests/unit/...`, `integration_test/...`, `e2e/...`)
     - How to run them (commands)

3. **Document meaningful changes**
   - Update or propose updates to:
     - [`CHANGELOG.md`](CHANGELOG.md) (if user-visible behavior changes)
     - [`FEATURES.md`](FEATURES.md) / [`ROADMAP.md`](ROADMAP.md) (if feature status changes)
     - Any relevant design/testing docs ([`ARCHITECTURE.md`](ARCHITECTURE.md), [`TESTS.md`](TESTS.md), etc.)

4. **Be safe by default**
   - Avoid destructive commands (e.g., `rm -rf`, `git reset --hard`) unless explicitly requested and clearly understood
   - Prefer small, focused diffs over broad refactors
   - Always verify files exist before modifying them
   - Generate .gitignore to keep `_templates/` private (AI-managed pattern)

5. **Follow testing workflow**
   - For bug fixes: Write a failing test that reproduces the bug first, then fix it
   - For new features: Write tests as you implement (TDD approach)
   - No accumulation of "test debt" - tests must be written immediately, not "later"

---

## 3. Recommended Warp AI Prompts

Use these prompt patterns when interacting with Warp AI for maximum effectiveness.

### 3.1 Understanding the Codebase

- "Read [`AGENTS.md`](AGENTS.md), [`FEATURES.md`](FEATURES.md), and [`WORKFLOWS.md`](WORKFLOWS.md), then summarize how [FEATURE_NAME] flows from [DATA_LAYER] â†’ [BUSINESS_LAYER] â†’ [UI_LAYER]. Point me to the key files involved."

- "Based on [`AGENTS.md`](AGENTS.md), explain how [PATTERN_NAME] (repositories/providers/services) are supposed to be structured in this app, and list any violations you see in the current code under [`src/`](src/)."

- "Analyze the testing strategy in [`TESTS.md`](TESTS.md) and [`TESTING-STRATEGY.md`](TESTING-STRATEGY.md). What are the coverage requirements, and which test types should I prioritize for [FEATURE_NAME]?"

- "Use the project context from these docs to explain the architecture decisions. Why was [ARCHITECTURAL_PATTERN] chosen over alternatives?"

### 3.2 Implementing a Feature

- "Using the patterns in [`AGENTS.md`](AGENTS.md) and the requirements in [`FEATURES.md`](FEATURES.md) section **[SECTION_NAME]**, design the architecture for adding feature **[FEATURE_NAME]**. Specify:
  1. Data model changes (if database involved)
  2. Repository interface and implementation updates
  3. Service/business logic layer changes
  4. UI component structure
  5. State management approach (providers, hooks, etc.)
  6. Navigation/integration with existing features
  7. Required tests (unit, component, integration) with exact file paths"

- "Implement the UI and state management for workflow **[WORKFLOW_NAME]** as defined in [`WORKFLOWS.md`](WORKFLOWS.md), following the screen and navigation patterns already used in [`presentation/`](presentation/). Include:
  1. Complete widget/component implementation
  2. State management setup (providers/context/hooks)
  3. Tests for the new functionality
  4. Documentation updates needed"

- "Add feature **[FEATURE_NAME]** following the feature-based architecture. Create the directory structure, barrel exports, and stub implementations for each layer (data, domain, presentation)."

### 3.3 Fixing Bugs

- "Given this failing test in [TEST_FILE_PATH] and error output, identify the root cause using the patterns and standards from [`AGENTS.md`](AGENTS.md). Propose a minimal fix plus any additional tests needed to prevent regressions."

- "A user reported bug: **[BUG_DESCRIPTION]**. Using [`WORKFLOWS.md`](WORKFLOWS.md) and the codebase, trace the likely source and propose:
  1. Root cause analysis
  2. Minimal fix implementation
  3. Regression test to add
  4. Any related fixes needed"

### 3.4 Refactoring Code

- "Based on [`AGENTS.md`](AGENTS.md) standards, identify opportunities to improve [CODE_SECTION]. Propose refactors that:
  1. Improve testability
  2. Reduce coupling
  3. Improve performance
  4. Maintain or improve test coverage"

- "Extract [FUNCTIONALITY] into a reusable [COMPONENT/SERVICE] following the patterns in [`AGENTS.md`](AGENTS.md). Update all call sites and ensure tests still pass."

### 3.5 Testing & Quality

- "Generate comprehensive tests for [FEATURE_NAME] following the 7-layer testing strategy from [`TESTS.md`](TESTS.md). Include:
  1. Unit tests for business logic
  2. Component/widget tests for UI
  3. Integration tests for workflows
  4. System tests for critical paths"

- "Review test coverage for [MODULE]. Identify gaps and generate tests to achieve 85%+ coverage."

- "Analyze this code for security vulnerabilities and test coverage gaps. Propose fixes and security-focused tests."

### 3.6 Documentation

- "Update [`FEATURES.md`](FEATURES.md) and [`WORKFLOWS.md`](WORKFLOWS.md) to reflect the new [FEATURE_NAME] capability. Include:
  1. Feature description and capabilities
  2. User workflow steps
  3. Technical implementation notes"

---

## 4. Typical Warp Workflow for This Repo

A good way to use Warp terminal + AI here:

### Phase 1: Understanding & Planning

1. **Ask AI to analyze context**
   ```
   "I want to [TASK - add feature/fix bug/refactor]. Read the relevant docs and tell me:
   - Which files and modules are involved
   - What architectural patterns to follow
   - What testing is required
   - Any potential challenges"
   ```

2. **Navigate and inspect**
   ```bash
   # Use these commands to explore
   ls [DIRECTORY]
   cat [FILE_PATH]
   rg "PATTERN" [DIRECTORY]  # ripgrep for searching
   find . -name "*.dart" -o -name "*.ts" -o -name "*.py" | head -20
   ```

3. **Verify understanding**
   ```
   "Based on my inspection of [FILES], confirm my understanding:
   - [Your understanding of the architecture]
   - [Your understanding of the data flow]
   - [Your planned approach]
   Is this correct?"
   ```

### Phase 2: Implementation

4. **Request specific changes**
   ```
   "Implement [SPECIFIC_CHANGE] following the patterns in [REFERENCE_FILE].
   Generate the complete code and specify exactly where each file should be placed."
   ```

5. **Review generated code**
   ```bash
   # Check the files AI suggests creating/modifying
   cat [GENERATED_FILE_PATH]
   flutter analyze [FILE]
   dart format --set-exit-if-changed [FILE]
   ```

6. **Apply changes cautiously**
   - Review every file change
   - Understand what each change does
   - Ensure it follows project patterns

### Phase 3: Testing & Verification

7. **Generate and run tests**
   ```bash
   # Create test files as specified by AI
   flutter test [TEST_FILE]
   flutter test --coverage
   dart pub global run coverage:format_coverage --lcov --in=coverage --out=coverage/lcov.info
   genhtml coverage/lcov.info -o coverage/html
   ```

8. **Verify quality gates**
   ```bash
   flutter analyze
   dart format --set-exit-if-changed .
   # Check coverage meets thresholds
   ```

9. **Update documentation**
   - Update relevant docs as specified by AI
   - Verify documentation accuracy

### Phase 4: Completion

10. **Final verification**
    ```bash
    # Full test suite
    flutter test
    
    # Build verification
    flutter build apk --release
    
    # If applicable: integration tests
    flutter test integration_test
    ```

11. **Commit preparation**
    ```bash
    git status
    git add [FILES]
    git commit -m "feat: [DESCRIPTION] [Unit: X%, Widget: Y%, Int: Z%]"
    ```

---

## 5. Security & Safety Best Practices

When working with Warp AI in this repository:

### File Access
- **DO** verify files exist before reading (`test -f [FILE]` or `ls [FILE]`)
- **DO** use relative paths when possible
- **DON'T** access files outside project root without explicit permission

### Command Execution
- **DO** preview commands before execution
- **DO** understand what each command does
- **DON'T** run `rm -rf`, `git reset --hard`, or destructive commands without confirmation
- **DO** use `--dry-run` flags when available

### Code Generation
- **DO** validate generated code follows project patterns
- **DO** ensure comprehensive test coverage
- **DON'T** commit generated code without review
- **DO** update .gitignore to keep _templates/ private

### Testing Requirements
- **ALWAYS** write tests for new code (no exceptions)
- **NEVER** lower coverage thresholds
- **ALWAYS** run full test suite before considering task complete
- **NEVER** commit with failing tests

---

## 6. When to Update This File

Update `WARP.md` when any of the following change:

- Navigation structure or key workflows (update references to `WORKFLOWS.md`)
- Architecture standards in `AGENTS.md` (e.g., new layers, new patterns)
- Testing policies, coverage thresholds, or CI gates
- New documentation files are introduced that AI should read first
- Development workflow changes significantly
- Technology stack updates (new frameworks, tools, versions)

Keep this file **short, opinionated, and tightly aligned** with `AGENTS.md`, `FEATURES.md`, and `WORKFLOWS.md`. It is meant as the **entry point for Warp AI**, not as a full replacement for the other docs.

---

## 7. Quick Reference: Essential Commands

```bash
# Setup & Dependencies
flutter pub get                    # Install Flutter dependencies
dart pub get                       # Install Dart dependencies
npm install                        # Install Node.js dependencies

# Development
flutter run                        # Run app in debug mode
flutter run -d [DEVICE_ID]         # Run on specific device
npm run dev                        # Start development server

# Testing
flutter test                       # Run all tests
flutter test test/[FILE]           # Run specific test file
flutter test --coverage            # Run with coverage
npm test                           # Run Node.js tests

# Code Quality
flutter analyze                    # Analyze Dart code
dart format .                      # Format Dart code
npm run lint                       # Run linter

# Build
flutter build apk --release        # Build Android APK
flutter build ios --release        # Build iOS app
npm run build                      # Build for production

# Database (if applicable)
dart run build_runner build        # Generate Drift code
npm run db:migrate                 # Run database migrations

# Documentation
dart doc .                         # Generate Dart docs
```

---

## 8. AI Prompt Engineering Tips

For best results when using Warp AI:

### âœ… Good Prompts
- Specific and contextual: "Using the Riverpod pattern from `AGENTS.md`, create a provider for..."
- Include constraints: "Follow the testing requirements from `TESTS.md` and achieve 90% coverage..."
- Reference files: "Based on the architecture in `ARCHITECTURE.md`, implement..."
- Multi-step: "First analyze the current implementation, then propose a refactor, then implement with tests"

### âŒ Bad Prompts
- Vague: "Fix this bug" (without context or error details)
- Generic: "Write good code" (not specific to project patterns)
- No constraints: "Add a feature" (without specifying which feature or requirements)
- Ignoring docs: "Implement X" (without referencing project standards)

### ðŸŽ¯ Perfect Prompt Structure
```
Task: [Specific task description]
Context: [Reference relevant docs: AGENTS.md, FEATURES.md, etc.]
Constraints: [Testing requirements, architecture patterns, performance goals]
Deliverables: [Expected output: code, tests, docs, etc.]
```

Example:
```
Task: Add barcode scanning feature to inventory app
Context: Follow AGENTS.md architecture (data/domain/presentation layers), use existing repository patterns
Constraints: 90% unit test coverage, 80% widget test coverage, follow Material 3 design
Deliverables: Complete implementation with tests, updated FEATURES.md and WORKFLOWS.md
```

---

**Template Status**: âœ… Production Ready  
**AI Integration**: ðŸ¤– Comprehensive Warp AI workflow guide  
**Best Practices**: âœ… Based on real-world Flutter/Riverpod project patterns  
**Last Updated**: 2025-12-08  
**Version**: 2.0

---

*This WARP.md template provides comprehensive guidance for Warp AI integration, following the same quality standards as other templates in this collection (10/10 quality score).*