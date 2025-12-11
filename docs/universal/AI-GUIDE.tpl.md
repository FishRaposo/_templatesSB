# AI Development Assistant Guide (Universal)

**Purpose**: Quick start guide for AI development assistants (Claude, GPT, etc.) to understand and contribute to [PROJECT_NAME].

**Last Updated**: 2025-12-09
**Version**: 2.1
**Three Pillars**: Scripting, Testing, Documenting  
**Project**: [PROJECT_NAME]  
**AI Assistant Compatibility**: Claude, GPT-4, Gemini, and other advanced AI assistants

---

## 🤖 How to Use This Template

### For AI Development Assistants:
1. **Read this file first** - Provides project context and AI-specific guidance
2. **Review universal/README.md** - Understand project documentation structure
3. **Check universal/TESTING-STRATEGY.md** - Learn testing approach
4. **Reference examples/TESTING-EXAMPLES.md** - See concrete implementations
5. **Execute QUICKSTART-AI.md** - Set up new projects or features
6. **Reference API docs** - Understand technical implementation
7. **Apply Three Pillars Framework** - SCRIPTING, TESTING, DOCUMENTING for all work

### For Human Developers:
1. **Provide this template to AI assistants** - Ensures consistent understanding
2. **Customize bracketed sections** - Replace with project-specific information
3. **Update regularly** - Keep AI guidance current with project changes

---

## 🎯 Project Quick Overview

### Project Identity
- **Name**: [PROJECT_NAME]
- **Type**: [PROJECT_TYPE] (Mobile App, Web App, API, Library, etc.)
- **Primary Language**: [PRIMARY_LANGUAGE]
- **Framework**: [PRIMARY_FRAMEWORK]
- **Status**: [DEVELOPMENT_STATUS]

### Core Purpose
[ONE_SENTENCE_PROJECT_DESCRIPTION]

### Key Technologies
- **Frontend**: [FRONTEND_TECH_STACK]
- **Backend**: [BACKEND_TECH_STACK]
- **Database**: [DATABASE_TECHNOLOGY]
- **Testing**: [TESTING_FRAMEWORK]
- **Deployment**: [DEPLOYMENT_PLATFORM]

---

## 🧠 AI Assistant Capabilities

### What I Can Help With:
- ✅ **Code Analysis**: Review and understand existing codebase
- ✅ **Feature Development**: Implement new features following project patterns
- ✅ **Bug Fixes**: Debug and resolve issues systematically
- ✅ **Documentation**: Create and update project documentation
- ✅ **Testing**: Write unit, integration, and end-to-end tests
- ✅ **Refactoring**: Improve code organization and performance
- ✅ **Deployment**: Assist with build and deployment processes

### Development Approach:
1. **Read First**: Always examine existing code before making changes
2. **Ask Questions**: Clarify requirements when uncertain
3. **Follow Patterns**: Maintain consistency with existing code style
4. **Test Changes**: Ensure all modifications are properly tested
5. **Document Updates**: Keep documentation synchronized with code
6. **Mandatory Comments**: Add comprehensive code comments for all new code
7. **Modular Design**: For scalable applications, follow modular architecture patterns in universal/FRAMEWORK-PATTERNS.md
8. **Template Privacy**: When setting up new projects, ensure _templates/ folder is added to .gitignore to maintain template collection privacy
9. **Three Pillars Validation**: Apply SCRIPTING, TESTING, DOCUMENTING framework to all work
10. **Validation Script**: Use `.\scripts\ai-workflow.ps1` for Three Pillars compliance checking

---

## 🚨 **Optional: Critical Validation Requirements**

### **🚨 CRITICAL**: Three Pillars Validation - Complete project validation before starting any development work

**Three Pillars Validation Checklist**:
- **🎯 SCRIPTING**: Project setup, automation, and workflow validation
- **🧪 TESTING**: Test coverage, CI/CD integration, and quality gates
- **📚 DOCUMENTING**: Documentation completeness, template integration, and update processes
- **Project Context**: Analyze project type, size, and team structure
- **Architecture Understanding**: Verify modular design principles are applied
- **Validation Script**: Run `.\scripts\ai-workflow.ps1` for automated compliance checking

### **⚡ Quick Adaptation Prompts (For Experienced Users)**

**🚀 QUICK ADAPTATION (Drop-in → Run)** - Three Pillars Framework:
```
"Run the AI quickstart with Three Pillars validation. Analyze this project and adapt the documentation templates:
1. Apply Three Pillars Framework: SCRIPTING, TESTING, DOCUMENTING
2. Read universal/AI-GUIDE.md, universal/DOCUMENTATION-BLUEPRINT.md, and all companion templates
3. Detect project context (web app, mobile app, API, library, CLI tool)
4. Adapt all [BRACKETED_PLACEHOLDERS] with project-specific information
5. Validate template integration and documentation completeness
6. Apply mandatory commenting standards and modular design principles
7. Run validation script: .\scripts\ai-workflow.ps1"
```

**🔍 THREE PILLARS PROJECT DETECTION PROMPT**:
```
"Analyze this project structure with Three Pillars framework and provide:
1. SCRIPTING: Project automation and workflow analysis
2. TESTING: Current test coverage and strategy assessment
3. DOCUMENTING: Documentation completeness and template integration
4. Project type classification (web/mobile/API/library/CLI)
5. Technology stack identification
6. Team size and complexity assessment
7. Recommended template adaptations
8. Critical documentation priorities
9. Validation script execution: .\scripts\ai-workflow.ps1"
```

### Mandatory Code Comments Requirements:
- **Class/Interface Headers**: Every class and interface must have a header comment explaining purpose, usage, and examples
- **Method Documentation**: All public methods must document parameters, return values, exceptions, and usage examples
- **Complex Logic**: Any complex algorithm or business logic must have inline comments explaining the approach
- **Configuration Documentation**: All configuration files and environment variables must be documented
- **API Documentation**: All API endpoints must document request/response formats, authentication, and error codes

### Comment Examples:
```javascript
/**
 * UserService handles user authentication and profile management
 * @example
 * const userService = new UserService();
 * const user = await userService.createUser(userData);
 */
class UserService {
  /**
   * Creates a new user with validation and error handling
   * @param {Object} userData - User profile data
   * @param {string} userData.email - User email address
   * @param {string} userData.name - User display name
   * @returns {Promise<User>} Created user object
   * @throws {ValidationError} When email is invalid
   */
  async createUser(userData) {
    // Validate email format before processing
    if (!this.isValidEmail(userData.email)) {
      throw new ValidationError('Invalid email format');
    }
    
    // Hash password for security
    const hashedPassword = await this.hashPassword(userData.password);
    
    return await this.database.save({
      ...userData,
      password: hashedPassword
    });
  }
}
```

---

## 📁 Project Structure for AI Understanding

```
[PROJECT_DIRECTORY]/
├── [SOURCE_DIRECTORY]/          # Main implementation
│   ├── [FEATURE_MODULE_1]/      # [MODULE_1_PURPOSE]
│   ├── [FEATURE_MODULE_2]/      # [MODULE_2_PURPOSE]
│   └── [SHARED_COMPONENTS]/     # Reusable components
├── tests/                       # Test files
│   ├── unit/                    # Unit tests
│   ├── integration/             # Integration tests
│   └── e2e/                     # End-to-end tests
├── docs/                        # Documentation
│   ├── API-REFERENCE.md         # Complete API documentation
│   ├── USER-MANUAL.md           # End-user guide
│   └── legal/                   # Legal documentation
├── [CONFIG_DIRECTORY]/          # Configuration files
└── [ASSETS_DIRECTORY]/          # Static assets
```

### Key Files to Understand:
- **README.md**: Project overview and setup instructions
- **CONTEXT.md**: Architecture decisions and project philosophy
- **TODO.md**: Current development roadmap and priorities
- **AGENTS.md**: Specific AI development workflows
- **API-REFERENCE.md**: Complete technical documentation

---

## 🛠️ Development Guidelines for AI

### Code Style Standards:
- **Language**: [CODING_LANGUAGE] version [VERSION]
- **Style Guide**: [STYLE_GUIDE_NAME]
- **Linting**: [LINTING_TOOL] configuration
- **Formatting**: [FORMATTING_TOOL] settings

### File Naming Conventions:
- **Source Files**: [FILE_NAMING_PATTERN]
- **Test Files**: [TEST_FILE_NAMING_PATTERN]
- **Documentation**: [DOC_FILE_NAMING_PATTERN]

### Code Organization Principles:
1. **Single Responsibility**: Each file/module has one clear purpose
2. **Consistent Structure**: Follow established patterns across the codebase
3. **Clear Dependencies**: Explicitly declare and manage dependencies
4. **Test Coverage**: Maintain [TARGET_COVERAGE]% test coverage
5. **Documentation**: Keep code comments and API docs current

---

## 🧪 Testing Strategy (MANDATORY)

### 🚨 **CRITICAL: Comprehensive Testing Required**
**All code changes MUST include unit, integration, and system tests. Pull requests without tests will be rejected.**

### **Test Coverage Requirements** (Non-negotiable):
```yaml
Unit Tests:     90% minimum, 95% target (50% of test suite)
Widget Tests:   80% minimum, 90% target (30% of test suite)
Integration:    70% minimum, 85% target (15% of test suite)
System/E2E:     60% minimum, 80% target (5% of test suite)
Overall:        85% minimum, 90% target
```

### **Test Pyramid Structure**:
```
                 System Tests (5%)
                ┌─────────────────┐
               │  Integration     │ (15%)
              ┌─────────────────────┐
             │     Widget Tests       │ (30%)
            ┌───────────────────────────┐
           │       Unit Tests             │ (50%)
          └───────────────────────────────┘
```

### **Test Types and Requirements**:

#### **1. Unit Tests (Highest Priority)**
- **Every public function** must have comprehensive unit tests
- **Test isolation**: Mock all external dependencies (database, API, file I/O)
- **Arrange-Act-Assert pattern**: Clear test structure with descriptive names
- **Edge cases**: Null values, boundary conditions, error paths
- **Performance-critical code**: Benchmarks and performance assertions
- **Business logic**: Core algorithms, calculations, transformations

#### **2. Widget Tests (UI Layer)**
- **All custom widgets** tested in isolation
- **User interactions**: Tap, swipe, long-press, keyboard input
- **State management**: Loading, error, success, empty states
- **Navigation**: Screen transitions with correct data passing
- **Form validation**: Error messages, field validation, submission
- **Accessibility**: Screen readers, semantic labels, focus management
- **Golden tests**: Visual regression testing for critical UI

#### **3. Integration Tests (Workflow Testing)**
- **Complete user workflows**: End-to-end scenarios
- **Database operations**: Real database with migrations
- **Platform features**: Camera, file I/O, sharing, permissions
- **State persistence**: App restart, configuration changes
- **Error recovery**: Network failures, permission denials, crashes
- **Multi-screen flows**: Navigation flow with data consistency

#### **4. System Tests (E2E & Performance)**
- **Critical user journeys**: Core app functionality E2E
- **Cross-platform testing**: Android and iOS verification
- **Real device testing**: Simulators + physical devices
- **Performance benchmarks**: Startup time, database queries, UI rendering
- **Memory leak testing**: Long-running scenarios, navigation loops
- **Security validation**: Input sanitization, data encryption

### **Mandatory Test Checklist** (Before Every PR):

```dart
// Pre-Submission Checklist - Complete ALL items:
- [ ] Unit tests for all new public functions (90%+ coverage)
- [ ] Widget tests for UI changes (80%+ coverage)
- [ ] Integration tests for complete workflows (70%+ coverage)
- [ ] System tests for E2E critical paths (at least 1 E2E test)
- [ ] All tests pass locally (`flutter test` and `flutter test test/file_name.dart`)
- [ ] Mock files generated (`flutter packages pub run build_runner build`)
- [ ] No test warnings or deprecation notices
- [ ] Performance benchmarks added for critical paths (measured with Stopwatch)
- [ ] Error scenarios tested and validated (null, invalid data, exceptions)
- [ ] Test documentation with clear descriptions and comments
- [ ] Coverage report generated and meets thresholds (`flutter test --coverage`)
- [ ] CI/CD pipeline passes (GitHub Actions automated test execution)
```

### **Test Quality Standards**:

1. **Descriptive Test Names**: `test('should return formatted date when given valid timestamp')`
   - ❌ Bad: `test('works correctly')`
   - ✅ Good: `test('should increment quantity by 1 and update timestamp')`

2. **Clear Arrange-Act-Assert Structure**:
   ```dart
   test('should add inventory item', () async {
     // Arrange - Set up test data and mocks
     final mockRepository = MockInventoryRepository();
     final useCase = AddItemUseCase(mockRepository);
     final item = TestDataFactory.createInventoryItem();
     
     // Act - Execute the operation
     await useCase(item);
     
     // Assert - Verify expected behavior
     verify(mockRepository.addItem(item)).called(1);
     expect(await mockRepository.getAllItems(), hasLength(1));
   });
   ```

3. **Comprehensive Edge Cases**:
   ```dart
   // Test these scenarios ALWAYS:
   - Valid input produces correct output
   - Invalid input throws appropriate exceptions
   - Null input handled gracefully
   - Empty collections handled correctly
   - Boundary values (0, max int, empty string)
   - Concurrent operations (race conditions)
   - Network/database failures
   ```

4. **Test Independence**: Each test must be able to run alone or in any order
   - Use `setUp()` and `tearDown()` for isolation
   - Clean database between tests
   - Reset mocks between tests

### **Testing Tools and Dependencies**:
```yaml
dev_dependencies:
  flutter_test:               # Core Flutter testing
    sdk: flutter
  mockito: ^5.4.2            # Mock generation
  build_runner: ^2.4.7       # Code generation for mocks
  integration_test:          # E2E testing
    sdk: flutter
  golden_toolkit: ^0.15.0    # Visual regression testing
  fake_cloud_firestore:      # Mock Firebase if needed
  network_image_mock: ^2.1.1 # Mock network images
  bloc_test: ^9.1.5          # If using BLoC pattern
```

### **CI/CD Integration** (GitHub Actions):
```yaml
# .github/workflows/test.yml
name: Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: subosito/flutter-action@v2
      - run: flutter pub get
      - run: flutter analyze
      - run: flutter test --coverage
      - name: Check coverage threshold
        run: |
          dart pub global activate coverage
          dart pub global run coverage:format_coverage --check-ignore
          # Fail if coverage below 85%
          if (( $(echo "$coverage < 85" | bc -l) )); then
            echo "Coverage below 85% threshold"
            exit 1
          fi
      - uses: codecov/codecov-action@v3
        with:
          files: ./coverage/lcov.info
```

---

## 🚀 Deployment and Build

### Build Commands:
```bash
# Development build
[DEV_BUILD_COMMAND]

# Production build
[PROD_BUILD_COMMAND]

# Run tests
[RUN_TESTS_COMMAND]

# Generate documentation
[GENERATE_DOCS_COMMAND]
```

### Deployment Process:
1. **Code Review**: All changes must pass code review
2. **Testing**: Ensure all tests pass in CI/CD
3. **Build**: Generate production build artifacts
4. **Deploy**: Deploy to [DEPLOYMENT_TARGET]
5. **Verify**: Confirm deployment is successful

---

## 🤝 Collaboration Guidelines

### Working with Human Developers:
- **Communicate Clearly**: Explain reasoning behind code changes
- **Ask for Clarification**: When requirements are ambiguous
- **Provide Options**: Suggest multiple approaches when appropriate
- **Respect Decisions**: Follow team decisions on architecture and patterns
- **Learn Feedback**: Incorporate feedback to improve future contributions

### Code Review Process:
1. **Self-Review**: Review own code before submitting
2. **Check Test Coverage**: Verify all new code has comprehensive tests
3. **Explain Changes**: Provide clear descriptions of modifications
4. **Document Test Coverage**: List test files created/modified
5. **Address Feedback**: Respond to review comments promptly
6. **Iterate**: Make necessary revisions based on feedback
7. **Final Approval**: Ensure all reviewers approve changes

---

## 📚 Reference Documentation

### Essential Reading:
- **[CONTEXT_FILE]**: Architecture and design decisions
- **[API_REFERENCE_FILE]**: Complete technical documentation
- **[DEVELOPMENT_GUIDELINES_FILE]**: Coding standards and practices
- **[TESTING_STRATEGY_FILE]**: Testing approach and requirements
- **[DEPLOYMENT_GUIDE_FILE]**: Build and deployment instructions

### Quick References:
- **[CHEAT_SHEET_FILE]**: Common commands and patterns
- **[TROUBLESHOOTING_FILE]**: Common issues and solutions
- **[FAQ_FILE]**: Frequently asked questions

---

## ⚠️ Common Pitfalls to Avoid

### Technical Pitfalls:
- **Don't**: Modify code without understanding existing patterns
- **Don't**: Skip testing or write incomplete tests
- **Don't**: Make breaking changes without proper communication
- **Don't**: Ignore error handling and edge cases
- **Don't**: Leave TODO comments without creating actual TODO items

### Process Pitfalls:
- **Don't**: Assume requirements without asking questions
- **Don't**: Make architectural decisions without team discussion
- **Don't**: Submit large, monolithic changes
- **Don't**: Ignore documentation updates
- **Don't**: Work on outdated code versions

---

## 🎯 Success Metrics

### Code Quality Indicators:
- **Test Coverage**: Maintain [TARGET_COVERAGE]% or higher
- **Code Review**: All changes pass peer review
- **Documentation**: All public APIs documented
- **Performance**: Meet [PERFORMANCE_REQUIREMENTS] requirements
- **Security**: Pass [SECURITY_REQUIREMENTS] checks

### Collaboration Indicators:
- **Clear Communication**: Explanations are understood by team
- **Responsive Feedback**: Address review comments promptly
- **Pattern Consistency**: Follow established code patterns
- **Knowledge Sharing**: Contribute to team documentation

---

## 🔄 Getting Started Workflow

1. **Read Project Context**: Study CONTEXT.md and README.md
2. **Understand Current State**: Review TODO.md and recent commits
3. **Identify Task**: Choose a task from TODO.md or receive assignment
4. **Analyze Requirements**: Understand what needs to be implemented
5. **Plan Approach**: Design solution following project patterns
6. **Implement Code**: Write clean, tested code following standards
7. **Test Thoroughly**: Ensure all tests pass and coverage is maintained
8. **Document Changes**: Update relevant documentation
9. **Submit for Review**: Create pull request with clear description
10. **Address Feedback**: Incorporate review feedback and finalize

---

**AI Assistant Version**: [TEMPLATE_VERSION]  
**Last Updated**: [CURRENT_DATE]  
**Project**: [PROJECT_NAME]  
**Compatibility**: [AI_ASSISTANTS_SUPPORTED]

---

*This template helps AI development assistants quickly understand project context, follow established patterns, and contribute effectively to the development process. Customize bracketed sections for your specific project.*
