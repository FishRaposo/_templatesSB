# {{PROJECT_NAME}} - Evaluation and Testing Guide

> Comprehensive testing strategy and evaluation framework for {{PROJECT_NAME}}

## 🎯 Testing Philosophy

{{PROJECT_NAME}} follows a comprehensive testing approach that ensures reliability, performance, and maintainability through multiple layers of validation.

## 📋 Testing Categories

### 1. Unit Tests
- **Purpose**: Test individual components in isolation
- **Coverage Target**: {{UNIT_TEST_COVERAGE}}%
- **Tools**: {{UNIT_TEST_TOOLS}}
- **Location**: `{{TEST_DIR}}/unit/`

### 2. Integration Tests
- **Purpose**: Test component interactions
- **Coverage Target**: {{INTEGRATION_TEST_COVERAGE}}%
- **Tools**: {{INTEGRATION_TEST_TOOLS}}
- **Location**: `{{TEST_DIR}}/integration/`

### 3. End-to-End Tests
- **Purpose**: Test complete user workflows
- **Coverage Target**: {{E2E_TEST_COVERAGE}}%
- **Tools**: {{E2E_TEST_TOOLS}}
- **Location**: `{{TEST_DIR}}/e2e/`

### 4. Performance Tests
- **Purpose**: Validate performance requirements
- **Metrics**: Response time, throughput, resource usage
- **Tools**: {{PERFORMANCE_TEST_TOOLS}}
- **Location**: `{{TEST_DIR}}/performance/`

### 5. Security Tests
- **Purpose**: Identify security vulnerabilities
- **Scope**: Authentication, authorization, data protection
- **Tools**: {{SECURITY_TEST_TOOLS}}
- **Location**: `{{TEST_DIR}}/security/`

## 🔄 Testing Workflow

### Pre-Commit Checks
```bash
# Run all unit tests
{{UNIT_TEST_COMMAND}}

# Check code coverage
{{COVERAGE_COMMAND}}

# Run linting
{{LINT_COMMAND}}

# Type checking (if applicable)
{{TYPE_CHECK_COMMAND}}
```

### Pre-Push Validation
```bash
# Full test suite
{{FULL_TEST_COMMAND}}

# Integration tests
{{INTEGRATION_TEST_COMMAND}}

# Build verification
{{BUILD_TEST_COMMAND}}
```

### Continuous Integration
```yaml
# .github/workflows/test.yml
name: Test Suite
on: [push, pull_request]
jobs:
  test:
    runs-on: {{CI_RUNNER}}
    steps:
      - uses: actions/checkout@v3
      - name: Setup
        run: {{SETUP_COMMAND}}
      - name: Run Tests
        run: {{CI_TEST_COMMAND}}
      - name: Coverage
        run: {{CI_COVERAGE_COMMAND}}
```

## 📊 Test Structure

### Test Organization
```
{{TEST_DIR}}/
├── unit/                  # Unit tests
│   ├── core/             # Core functionality
│   ├── utils/            # Utility functions
│   └── components/       # Individual components
├── integration/          # Integration tests
│   ├── api/              # API integration
│   ├── database/         # Database integration
│   └── external/         # External service integration
├── e2e/                  # End-to-end tests
│   ├── workflows/        # User workflows
│   ├── scenarios/        # Business scenarios
│   └── regression/       # Regression tests
├── performance/          # Performance tests
│   ├── load/             # Load testing
│   ├── stress/           # Stress testing
│   └── benchmark/        # Benchmarking
└── security/             # Security tests
    ├── auth/             # Authentication
    ├── data/             # Data protection
    └── vulnerability/    # Vulnerability scanning
```

### Test Naming Conventions
- Unit tests: `{{MODULE_NAME}}.test.{{EXT}}`
- Integration tests: `{{FEATURE_NAME}}.integration.test.{{EXT}}`
- E2E tests: `{{WORKFLOW_NAME}}.e2e.test.{{EXT}}`

## ✅ Test Quality Standards

### Test Requirements
1. **Clarity**: Tests must be self-documenting
2. **Isolation**: Tests must not depend on each other
3. **Repeatability**: Tests must produce consistent results
4. **Speed**: Tests must run efficiently
5. **Coverage**: Critical paths must be covered

### Test Review Checklist
- [ ] Test has clear purpose
- [ ] Assertions are meaningful
- [ ] Test covers edge cases
- [ ] Test is maintainable
- [ ] Test has proper setup/teardown

## 🚨 Evaluation Metrics

### Code Coverage
| Type | Current | Target | Trend |
|------|---------|--------|-------|
| Lines | {{CURRENT_LINE_COVERAGE}}% | {{TARGET_LINE_COVERAGE}}% | {{COVERAGE_TREND}} |
| Branches | {{CURRENT_BRANCH_COVERAGE}}% | {{TARGET_BRANCH_COVERAGE}}% | {{BRANCH_TREND}} |
| Functions | {{CURRENT_FUNCTION_COVERAGE}}% | {{TARGET_FUNCTION_COVERAGE}}% | {{FUNCTION_TREND}} |

### Performance Benchmarks
| Metric | Baseline | Target | Current |
|--------|----------|--------|---------|
| Response Time | {{BASELINE_RESPONSE}}ms | {{TARGET_RESPONSE}}ms | {{CURRENT_RESPONSE}}ms |
| Throughput | {{BASELINE_THROUGHPUT}} req/s | {{TARGET_THROUGHPUT}} req/s | {{CURRENT_THROUGHPUT}} req/s |
| Memory Usage | {{BASELINE_MEMORY}}MB | {{TARGET_MEMORY}}MB | {{CURRENT_MEMORY}}MB |

### Quality Gates
- All tests must pass
- Coverage must meet targets
- Performance must meet benchmarks
- Security scans must be clean

## 🔧 Testing Tools and Configuration

### Primary Testing Framework
```json
{
  "framework": "{{TEST_FRAMEWORK}}",
  "version": "{{FRAMEWORK_VERSION}}",
  "config": "{{TEST_CONFIG_FILE}}"
}
```

### Test Configuration
```{{TEST_CONFIG_EXT}}
# {{TEST_CONFIG_FILE}}
{{TEST_CONFIG_CONTENT}}
```

### Coverage Configuration
```{{COVERAGE_CONFIG_EXT}}
# {{COVERAGE_CONFIG_FILE}}
{{COVERAGE_CONFIG_CONTENT}}
```

## 📝 Test Documentation

### Test Case Template
```markdown
#### Test Case: {{TEST_CASE_NAME}}
- **Objective**: {{OBJECTIVE}}
- **Prerequisites**: {{PREREQUISITES}}
- **Test Steps**:
  {{#each TEST_STEPS}}
  {{@index}}. {{this}}
  {{/each}}
- **Expected Results**: {{EXPECTED_RESULTS}}
- **Actual Results**: {{ACTUAL_RESULTS}}
- **Status**: {{STATUS}}
```

### Test Report Template
```markdown
# Test Report - {{DATE}}

## Summary
- Total Tests: {{TOTAL_TESTS}}
- Passed: {{PASSED_TESTS}}
- Failed: {{FAILED_TESTS}}
- Skipped: {{SKIPPED_TESTS}}
- Coverage: {{COVERAGE_PERCENTAGE}}%

## Failed Tests
{{#each FAILED_TESTS}}
- {{name}}: {{reason}}
{{/each}}

## Performance Results
{{#each PERFORMANCE_RESULTS}}
- {{metric}}: {{value}}
{{/each}}
```

## 🔄 Continuous Improvement

### Test Maintenance
- Review and update tests regularly
- Remove obsolete tests
- Add tests for new features
- Optimize slow tests

### Metrics Tracking
- Monitor test execution time
- Track coverage trends
- Analyze failure patterns
- Measure flakiness

### Process Improvements
- Automate manual test cases
- Parallelize test execution
- Implement test prioritization
- Enhance test reporting

## 🚨 Common Testing Issues

### Flaky Tests
**Problem**: Tests pass/fail inconsistently
**Solutions**:
- Add proper waits/timeouts
- Isolate from external dependencies
- Fix race conditions
- Use deterministic data

### Slow Tests
**Problem**: Tests take too long to run
**Solutions**:
- Optimize test data setup
- Use mocks for external calls
- Parallelize independent tests
- Implement test selection

### Coverage Gaps
**Problem**: Important code not covered
**Solutions**:
- Add missing test cases
- Refactor for testability
- Use coverage tools to identify gaps
- Prioritize critical paths

## 📚 Related Documentation

- [WORKFLOW.md](WORKFLOW.md) - Test workflows
- [docs/DOCUMENTATION-MAINTENANCE.md](docs/DOCUMENTATION-MAINTENANCE.md) - Test documentation maintenance
- [CHANGELOG.md](CHANGELOG.md) - Test-related changes

---

## 📋 Evaluation Checklist

### Before Release
- [ ] All tests passing
- [ ] Coverage targets met
- [ ] Performance benchmarks satisfied
- [ ] Security scans clean
- [ ] Documentation updated

### Regular Maintenance
- [ ] Review test failures
- [ ] Update test data
- [ ] Optimize test performance
- [ ] Update test tools
- [ ] Train team on testing

---

**Last Updated**: {{LAST_UPDATED_DATE}}  
**Test Framework Version**: {{FRAMEWORK_VERSION}}  
**Next Review**: {{NEXT_REVIEW_DATE}}

---

*This evaluation guide ensures {{PROJECT_NAME}} maintains high quality through comprehensive testing and continuous evaluation.*
