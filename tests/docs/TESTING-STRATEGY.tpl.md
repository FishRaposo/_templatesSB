# Universal Template System - Unknown Stack
# Generated: 2025-12-10
# Purpose: Testing utilities
# Tier: base
# Stack: unknown
# Category: testing

# Universal Testing Strategy & Implementation Guide

**Purpose**: Technology-agnostic testing strategy covering all test types: Unit Tests, Component/UI Tests, Integration Tests, Feature Tests, Workflow Tests, System Tests, and E2E Tests. This document provides universal testing philosophy, organization structure, and best practices applicable to any software project.

**Last Updated**: 2025-12-09
**Version**: 2.1 (Three Pillars Framework)
**Three Pillars**: Scripting, Testing, Documenting  
**Framework**: Universal - All Languages & Platforms  
**Test Types**: 7-Layer Testing Strategy

---

## 📋 Table of Contents

1. [Testing Strategy Overview](#testing-strategy-overview)
2. [Test Types & Specifications](#test-types--specifications)
3. [Test Organization & Structure](#test-organization--structure)
4. [Coverage Requirements](#coverage-requirements)
5. [CI/CD Integration](#cicd-integration)
6. [Implementation Guidelines](#implementation-guidelines)
7. [Test Debugging & Maintenance](#test-debugging--maintenance)
8. [Technology-Specific Implementations](#technology-specific-implementations)

---

## 🎯 Testing Strategy Overview

### **Testing Philosophy - Three Pillars Framework**

**Test Everything That Matters** (🧪 TESTING Pillar):
- Every feature must be tested
- Every workflow must be validated
- Every user journey must work correctly
- Performance must be measured
- Errors must be handled gracefully
- **Three Pillars Integration**: Testing validates both Scripting (automation) and Documenting (accuracy)

**Test Early, Test Often** (Three Pillars Approach):
- Write tests during development (TDD preferred)
- Run tests continuously during development
- No code without tests
- No merge without passing tests
- **Scripting Integration**: Automated test execution via `.\scripts\ai-workflow.ps1`
- **Documentation Integration**: Test results inform documentation updates

**Test Quality Metrics** (Three Pillars Standards):
- **Coverage**: 85%+ overall minimum (🧪 TESTING)
- **Reliability**: Zero flaky tests
- **Maintainability**: Clear, readable, well-documented tests (📚 DOCUMENTING)
- **Performance**: All tests run in under 5 minutes
- **Automation**: Integrated with `.\scripts\ai-workflow.ps1` (🎯 SCRIPTING)

---

### **Test Types Overview**

| Test Type | Level | Purpose | Scope | Speed | CI/CD |
|-----------|-------|---------|-------|-------|-------|
| **Unit Tests** | 1 | Individual functions/methods | Single unit | Fastest | ✅ |
| **Component Tests** | 2 | UI components in isolation | Single component | Fast | ✅ |
| **Integration Tests** | 3 | Component interactions | Multiple components | Medium | ✅ |
| **Feature Tests** | 4 | Complete features end-to-end | Feature module | Medium | ✅ |
| **Workflow Tests** | 5 | User workflows across features | Cross-feature journeys | Medium-Slow | ✅ |
| **System Tests** | 6 | Entire system with platform | Full system + platform | Slow | ⚠️ |
| **E2E Tests** | 7 | Production-like scenarios | Real environment | Slowest | ⏳ |

---

## 🧪 Test Types & Specifications

### **1. Unit Tests (Foundation)**

**Purpose**: Test individual functions, methods, and classes in complete isolation from external dependencies.

**Scope**:
- Business logic in use cases/services
- Repository implementations
- Utility functions and helpers
- Data model validation
- Algorithm implementations
- Pure functions

**Characteristics**:
- Fast execution (< 10ms per test)
- No external dependencies (fully mocked)
- Tests a single unit of code in isolation
- High coverage required (90%+)
- Run frequently during development (watch mode)

**Principles**:
- **Arrange-Act-Assert**: Clear test structure
- **Test Independence**: Each test can run alone or in any order
- **Single Responsibility**: Each test verifies one behavior
- **Descriptive Names**: Test names should read like specifications

**When to Write**:
- ✅ For every public function/method
- ✅ For all business logic
- ✅ For data transformations
- ✅ For validation logic
- ✅ For error handling paths
- ✅ For edge cases and boundary conditions

**When NOT to Write**:
- ❌ Private methods (test through public API)
- ❌ Auto-generated code
- ❌ Third-party library code
- ❌ Simple getters/setters (unless complex logic)

---

### **2. Component/UI Tests (Presentation Layer)**

**Purpose**: Test individual UI components in isolation, verifying rendering, user interactions, and state management.

**Scope**:
- Single UI components
- Rendering with various props/data
- User interactions (clicks, input, gestures)
- State changes and re-rendering
- Event handling
- Visual states (loading, error, empty)

**Characteristics**:
- Tests UI in isolation from business logic
- Simulates user interactions
- Verifies visual elements and state
- Medium-fast execution (< 100ms)
- Coverage target: 80%+

**Framework-Specific Notes**:
- **Flutter**: "Widget Tests" - Test widgets with `flutter_test`
- **React**: "Component Tests" - Test components with React Testing Library
- **Vue**: "Component Tests" - Test components with Vue Test Utils
- **Angular**: "Component Tests" - Test components with Angular Testing Library
- **Native Mobile**: "UI Tests" - Test native UI components

**When to Write**:
- ✅ For every reusable UI component
- ✅ For user interaction handling
- ✅ For state-driven UI changes
- ✅ For forms and input validation
- ✅ For navigation elements
- ✅ For error/success/loading states

**When NOT to Write**:
- ❌ Business logic (move to unit tests)
- ❌ API calls (mock responses)
- ❌ Navigation flows (use integration/feature tests)

---

### **3. Integration Tests (Component Collaboration)**

**Purpose**: Test interactions between multiple components, services, and layers to verify they work together correctly.

**Scope**:
- Database operations
- API calls and responses
- Repository with real database
- Services with multiple dependencies
- Multi-step operations
- Platform features (camera, file I/O, permissions)

**Characteristics**:
- Tests component collaboration
- Uses real implementations with test configurations
- May use in-memory/test databases
- Slower execution (< 500ms)
- Coverage target: 70%+

**When to Write**:
- ✅ For database CRUD operations
- ✅ For repository implementations
- ✅ For service layer integration
- ✅ For multi-step business operations
- ✅ For platform integration (camera, storage, etc.)
- ✅ For authentication/authorization flows

**When NOT to Write**:
- ❌ Single function testing (use unit tests)
- ❌ UI-only testing (use component tests)
- ❌ Complete user journeys (use feature/workflow tests)

---

### **4. Feature Tests (End-to-End Feature Validation)**

**Purpose**: Test complete features end-to-end as cohesive units, validating all user actions within a feature work correctly.

**Definition**: A feature is a cohesive set of functionality that delivers value to the user. Examples:
- **Item Management Feature**: Add, edit, delete, view items
- **Search Feature**: Search, filter, sort results
- **Import/Export Feature**: CSV import/export with validation
- **Authentication Feature**: Login, logout, password reset
- **Payment Feature**: Complete purchase flow

**Scope**:
- All user actions within a feature
- All screens/components of a feature
- Feature-specific validation logic
- Feature error handling
- Feature edge cases
- Performance within feature boundaries

**Characteristics**:
- Duration: 1-5 seconds per test
- Scope: Complete feature, multiple screens/components
- Isolation: Feature isolated from other features (internal components work together)
- Data: Test data factories for realistic scenarios
- Mocks: Minimal - only external dependencies (payment gateways, email services)
- Coverage: One test per major feature capability
- CI/CD: ✅ Run on every commit

**Feature Test vs Integration Test**:
- **Feature Test**: Tests complete feature as user experiences it (multi-screen, multi-action, user perspective)
- **Integration Test**: Tests component interactions (single operation, multi-component, developer perspective)

**When to Write**:
- ✅ For each major feature
- ✅ For CRUD operations per entity
- ✅ For complete search/filter functionality
- ✅ For import/export features
- ✅ For authentication flows
- ✅ For payment/purchase flows

**When NOT to Write**:
- ❌ Single functions (use unit tests)
- ❌ Single components (use component tests)
- ❌ Component-only integration (use integration tests)

---

### **5. Workflow Tests (User Journey Validation)**

**Purpose**: Test complete user workflows end-to-end, validating sequences of actions users perform to accomplish goals across multiple features.

**Definition**: A workflow is a sequence of actions a user takes to accomplish a specific goal. Examples:
- **Onboarding Workflow**: First-time user adds first item and experiences success
- **Inventory Management Workflow**: Scan item → review → categorize → add to inventory
- **Data Backup Workflow**: Export inventory → transfer to new device → import → verify
- **Purchase Workflow**: Browse → select → pay → receive confirmation → verify purchase

**Scope**:
- End-to-end user journeys across multiple features
- Real-world user scenarios
- Complete sequences from start to finish
- Success paths (user achieves goal)
- Error paths (user recovers from failures)
- Edge cases (unlikely but possible scenarios)

**Characteristics**:
- Duration: 5-10 seconds per test
- Scope: Complete user journey, typically across multiple features
- Realism: Mimics real user behavior patterns
- Data: Realistic scenarios with test data factories
- Mocks: Minimal - real database, real navigation, real APIs in test environment
- Coverage: One test per critical user journey
- CI/CD: ✅ Run on every PR (important but slower)

**Workflow Test vs Feature Test**:
- **Workflow Test**: Tests user journey across multiple features (multi-feature, start-to-finish goal)
- **Feature Test**: Tests complete feature in isolation (single feature, internal completeness)

**Critical Workflows to Test**:
- ✅ **Onboarding**: New user's first successful interaction
- ✅ **Core Business Flow**: Primary value proposition workflows
- ✅ **Data Portability**: Export/import across devices/versions
- ✅ **Purchase/Upgrade**: Conversion-critical workflows
- ✅ **Error Recovery**: Critical failure and recovery paths

**When NOT to Write**:
- ❌ Simple feature flows (use feature tests)
- ❌ Unit functionality (use unit tests)
- ❌ Single screen behavior (use component tests)
- ❌ Too many - 1-2 per critical path is sufficient

---

### **6. System Tests (Platform & Performance)**

**Purpose**: Test entire application with platform integration, performance benchmarks, and system-level concerns.

**Scope**:
- Platform features (camera, storage, geolocation, notifications)
- OS integration (iOS/Android specific features, Windows/Mac/Linux differences)
- Real device testing (simulators and physical devices)
- Performance under load
- Memory usage patterns
- Startup time and app launch
- Battery consumption (mobile)
- Network condition handling (offline, slow, intermittent)

**Characteristics**:
- Full app with real dependencies
- Platform-specific implementations
- Slowest automated tests (10-30s)
- Run on real devices or high-fidelity emulators/simulators
- CI/CD: ⚠️ Run on release builds or scheduled runs (not every commit)

**When to Write**:
- ✅ Platform-specific features (camera, GPS, file system)
- ✅ Performance benchmarks (startup, critical paths)
- ✅ Memory leak detection
- ✅ Cross-platform compatibility verification
- ✅ Real device validation

**When NOT to Write**:
- ❌ Business logic (use unit tests)
- ❌ UI components (use component tests)
- ❌ Standard flows (use integration/feature tests)

---

### **7. E2E Tests (Production Validation)**

**Purpose**: Test complete user scenarios in production-like environment with real devices, real network, and real services.

**Scope**:
- Real devices (physical hardware)
- Real network conditions (not mocked)
- Real app stores (for in-app purchases)
- Multiple device types and OS versions
- Production API endpoints
- Real third-party services (Stripe, Firebase, Auth0, etc.)
- Critical user paths only

**Characteristics**:
- Slowest tests (30s+ per test)
- External dependencies
- Flakiest due to network, timing, environment issues
- Requires special test infrastructure
- CI/CD: ⏳ Run manually before release or scheduled (daily/weekly)
- Expensive to maintain

**When to Write**:
- ✅ **Critical user journeys** that must absolutely work
- ✅ **Smoke tests** for production deployments
- ✅ **Purchase flows** with real payment systems
- ✅ **Cross-device synchronization**
- ✅ **Real-time features** with production WebSockets

**When NOT to Write**:
- ❌ Anything that can be tested at lower levels
- ❌ Edge cases (use unit/integration tests)
- ❌ Error handling (use unit/integration tests)
- ❌ Comprehensive coverage (use lower-level tests)

**E2E Test Philosophy**: 
> "E2E tests should give you confidence that your most critical user journeys work in production. They should not be your primary testing strategy."

---

## 📊 Test Coverage Strategy

### **Coverage Requirements by Test Type**

| Test Type | Target Coverage | Test Suite % | Rationale |
|-----------|-----------------|--------------|-----------|
| **Unit Tests** | 90%+ | ~25% | Foundation - every function tested |
| **Component Tests** | 80%+ | ~25% | All UI components tested |
| **Integration Tests** | 70%+ | ~20% | Key integrations validated |
| **Feature Tests** | 70%+ | ~15% | Complete features validated |
| **Workflow Tests** | 60%+ | ~10% | Critical flows only |
| **System Tests** | 50%+ | ~4% | Platform-specific features |
| **E2E Tests** | 40%+ | ~1% | Smoke tests only |
| **Overall** | **85%+** | **100%** | **Minimum acceptable quality** |

### **Coverage Goals**

**Minimum (MVP Launch)**:
- Overall: 85%
- Unit: 90%
- Component: 80%
- Integration: 70%
- Feature: 70%
- Critical workflows: 100% (all critical flows tested)

**Target (Production Quality)**:
- Overall: 90%
- Unit: 95%
- Component: 90%
- Integration: 85%
- Feature: 80%
- Workflow: 70%

**Exception Handling**:
- Generated code: Exclude from coverage
- Third-party libraries: Exclude from coverage
- Platform-specific code: Cover per platform
- Error paths: Must be covered
- Edge cases: Should be covered

---

## 📁 Test Organization & Structure

### **Directory Structure Template**

```
project/
test/                                  # All tests
├── unit/                             # Unit tests (~25%)
│   ├── domain/
│   │   ├── entities/
│   │   ├── usecases/
│   │   └── repositories/
│   ├── data/
│   │   ├── models/
│   │   ├── repositories/
│   │   └── datasources/
│   └── core/
│       ├── utils/
│       └── exceptions/
│
├── component/                        # Component/UI tests (~25%)
│   ├── components/
│   │   └── [component-name]_test.ext
│   └── pages/
│       └── [page-name]_test.ext
│
├── integration/                      # Integration tests (~20%)
│   ├── database_test.ext
│   ├── repository_test.ext
│   ├── service_test.ext
│   └── api_test.ext
│
├── feature/                          # Feature tests (~15%)
│   ├── item_management_feature_test.ext
│   ├── search_feature_test.ext
│   ├── import_export_feature_test.ext
│   └── auth_feature_test.ext
│
├── workflow/                         # Workflow tests (~10%)
│   ├── onboarding_workflow_test.ext
│   ├── core_business_workflow_test.ext
│   ├── data_portability_workflow_test.ext
│   └── purchase_workflow_test.ext
│
├── system/                           # System tests (~4%)
│   ├── performance_test.ext
│   ├── memory_test.ext
│   └── platform_integration_test.ext
│
├── e2e/                              # E2E tests (~1%)
│   └── smoke_test.ext
│
├── helpers/                          # Test utilities
│   ├── test_data_factory.ext
│   ├── custom_matchers.ext
│   └── test_setup.ext
│
└── mocks/                            # Generated mocks
    └── mock_[service].ext
```

### **Naming Conventions**

```
Unit Tests:
  Subject: functionName_WhenCondition_ExpectedResult
  Example: incrementQuantity_WhenItemExists_IncrementsByOne

Component Tests:
  Subject: ComponentName_WhenAction_ShouldResult
  Example: InventoryCard_WhenClicked_ShouldEmitItem

Integration Tests:
  Subject: Service_WhenAction_ShouldIntegrate
  Example: InventoryService_WhenSaving_ShouldPersistToDatabase

Feature Tests:
  Subject: Feature_WhenUserAction_ShouldCompleteFeature
  Example: ItemCreation_WhenValidData_ShouldCreateAndDisplayItem

Workflow Tests:
  Subject: Workflow_WhenUserGoal_ShouldCompleteJourney
  Example: Onboarding_WhenNewUser_ShouldCompleteFirstItemAddition
```

---

## 🔧 CI/CD Integration

### **Test Execution Strategy**

```yaml
# Test Pipeline Configuration
Pre-commit (Local):
  - Unit tests only
  - Fast feedback (< 30 seconds)
  - Run on changed files only

Pre-push (Local):
  - Unit tests
  - Component tests
  - Integration tests
  - Full suite (< 5 minutes)

Pull Request (CI):
  - All test types except E2E
  - Coverage threshold check
  - Parallel execution
  - Full suite (< 10 minutes)

Main Branch (CI):
  - All test types including E2E
  - Full coverage report
  - Performance benchmarks
  - Daily scheduled run

Release (CD):
  - E2E smoke tests mandatory
  - System tests on real devices
  - Manual approval gate
  - Full regression suite
```

### **CI/CD Configuration Template**

```yaml
# .github/workflows/test.yml
name: Test Suite

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Environment
        uses: actions/setup-[language]@v3
        with:
          [language]-version: '[VERSION]'
      
      - name: Install Dependencies
        run: [INSTALL_COMMAND]
      
      - name: Run Unit Tests
        run: [TEST_COMMAND] test/unit/ --coverage
      
      - name: Check Coverage Threshold
        run: |
          # Fail if coverage below 90%
          if [ $COVERAGE -lt 90 ]; then
            echo "Unit test coverage below 90%"
            exit 1
          fi
      
      - name: Upload Coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage/lcov.info

  component-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup Environment
        uses: actions/setup-[language]@v3
      - name: Install Dependencies
        run: [INSTALL_COMMAND]
      - name: Run Component Tests
        run: [TEST_COMMAND] test/component/

  integration-tests:
    runs-on: ubuntu-latest
    services:
      database:
        image: postgres:latest
        env:
          POSTGRES_PASSWORD: test
    steps:
      - uses: actions/checkout@v3
      - name: Setup Environment
        uses: actions/setup-[language]@v3
      - name: Install Dependencies
        run: [INSTALL_COMMAND]
      - name: Run Integration Tests
        run: [TEST_COMMAND] test/integration/

  feature-tests:
    runs-on: ubuntu-latest
    needs: [unit-tests, component-tests]
    steps:
      - uses: actions/checkout@v3
      - name: Setup Environment
        uses: actions/setup-[language]@v3
      - name: Install Dependencies
        run: [INSTALL_COMMAND]
      - name: Run Feature Tests
        run: [TEST_COMMAND] test/feature/

  workflow-tests:
    runs-on: ubuntu-latest
    needs: [integration-tests]
    if: github.event_name == 'pull_request'
    steps:
      - uses: actions/checkout@v3
      - name: Setup Environment
        uses: actions/setup-[language]@v3
      - name: Install Dependencies
        run: [INSTALL_COMMAND]
      - name: Run Workflow Tests
        run: [TEST_COMMAND] test/workflow/

  e2e-tests:
    runs-on: ubuntu-latest
    needs: [feature-tests, workflow-tests]
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v3
      - name: Setup Environment
        uses: actions/setup-[language]@v3
      - name: Install Dependencies
        run: [INSTALL_COMMAND]
      - name: Run E2E Tests
        run: [TEST_COMMAND] test/e2e/
```

---

## 🛠️ Implementation Guidelines

### **Writing Testable Code**

```
Good Testable Code:
✅ Pure functions when possible
✅ Dependency injection
✅ Single responsibility
✅ Clear inputs and outputs
✅ Avoid global state
✅ Use interfaces/abstractions
✅ Separate logic from side effects

Bad for Testing:
❌ Global variables
❌ Static methods with hidden dependencies
❌ Tight coupling
❌ Mixing logic with I/O
❌ Large functions with multiple responsibilities
❌ Direct instantiation of dependencies
```

### **Test Data Management**

```
Test Factories:
- Create consistent test data
- Allow easy customization
- Keep tests readable
- Prevent duplication

Test Fixtures:
- Load from files for complex data
- Version control test data
- Reset between tests

Database Strategy:
- Use in-memory database for speed
- Reset database between test suites
- Use transactions to rollback changes
- Seed minimal required data
```

### **Mocking Strategy**

```
When to Mock:
✅ External APIs
✅ Databases (for unit tests)
✅ File systems
✅ Time/randomness
✅ Third-party services

When NOT to Mock:
❌ Your own business logic
❌ Internal functions
❌ Test subjects themselves
❌ What you're actually testing

Mock Best Practices:
- Mock interfaces, not concrete classes
- Keep mocks simple
- Verify mock interactions
- Use mocking libraries (Mockito, Jest, Moq)
```

---

## 🔍 Test Debugging & Maintenance

### **Common Test Issues**

```
Flaky Tests:
- Use explicit waits, not sleep()
- Reset state between tests
- Avoid race conditions
- Use test isolation
- Fix root cause, don't retry

Slow Tests:
- Mock external dependencies
- Use in-memory databases
- Run tests in parallel
- Remove unnecessary setup
- Profile test execution

Brittle Tests:
- Test behavior, not implementation
- Use semantic selectors
- Avoid test duplication
- Keep tests focused
- Refactor tests regularly
```

### **Test Maintenance Checklist**

```
- [ ] Tests run in under 5 minutes
- [ ] Coverage maintained above threshold
- [ ] No flaky tests
- [ ] Tests are readable and documented
- [ ] Mock objects are up to date
- [ ] Test data is realistic
- [ ] CI/CD pipeline passes consistently
- [ ] Test failures provide clear messages
- [ ] Tests are refactored with code changes
- [ ] Performance benchmarks are tracked
```

---

## 🚀 Technology-Specific Implementations

For concrete code examples and framework-specific implementations, see:

**📄 `_TESTS-TECH-SPECIFIC.md`** - Complete testing implementations for:
- Flutter/Dart
- React/TypeScript
- Vue/JavaScript
- Angular/TypeScript
- Node.js/Express
- .NET/C#

Each technology section includes:
- Setup instructions
- All 7 test type implementations
- Framework-specific tools and libraries
- CI/CD configuration examples
- Best practices and patterns

---

## 📈 Test Metrics & Reporting

### **Key Metrics to Track**

```
Coverage Metrics:
- Line coverage
- Branch coverage
- Function coverage
- Statement coverage

Quality Metrics:
- Test execution time
- Number of flaky tests
- Test failure rate
- Bug escape rate
- Test maintenance time

Performance Metrics:
- Test suite execution time
- Performance regression detection
- Memory usage during tests
- CPU usage during tests
```

### **Reporting Tools**

```
- Coverage reports (lcov, cobertura)
- Test dashboards (Allure, ReportPortal)
- CI/CD integration (GitHub Actions, Jenkins)
- Performance tracking (custom benchmarks)
```

---

### **Quick Reference: Choosing the Right Test Type**

```
Question: What am I testing?

├─ A single function/method? → Unit Test
├─ A UI component? → Component Test
├─ Multiple components working together? → Integration Test
├─ A complete user-facing feature? → Feature Test
├─ A multi-feature user journey? → Workflow Test
├─ Platform-specific functionality? → System Test
└─ Critical production workflow? → E2E Test

Question: How critical is this?

├─ Core business logic? → Unit + Feature tests
├─ User-visible feature? → Component + Feature tests
├─ Critical user journey? → Workflow + E2E tests
└─ Platform integration? → System tests
```

---

**Guide Version**: 2.0 (Universal)  
**Last Updated**: 2025-12-08  
**Framework**: Universal - All Technologies  
**Maintainer**: [MAINTAINER_NAME]

---

*This universal testing guide provides technology-agnostic testing strategy and principles. For concrete implementations in your specific technology stack, refer to `_TESTS-TECH-SPECIFIC.md`.*