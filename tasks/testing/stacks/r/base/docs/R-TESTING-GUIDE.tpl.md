# R Testing Guide - Comprehensive Testing Framework

**Tier**: {{TIER}} | **Stack**: R | **Task**: testing

## Overview

This guide provides comprehensive testing patterns for R statistical computing projects, covering unit tests, integration tests, system tests, and workflow tests. The framework follows R ecosystem best practices and integrates seamlessly with the Universal Template System.

## Test Suite Architecture

```
R Testing Framework
├── Unit Tests (18 KB) - Component-level validation
├── Integration Tests (23 KB) - System interaction testing
├── System Tests (26 KB) - End-to-end workflow validation
└── Workflow Tests (20 KB) - Development process testing
```

## Quick Start

### 1. Setup Testing Infrastructure
```r
# Install required packages
install.packages(c("testthat", "mockery", "checkmate", "assertthat"))

# Additional packages for specific test types
install.packages(c("httr", "DBI", "future", "bench", "profmem"))
install.packages(c("devtools", "usethis", "pkgdown", "rcmdcheck"))
```

### 2. Create Test Structure
```bash
# Create standard R package test structure
mkdir -p tests/testthat
mkdir -p tests/testdata
mkdir -p tests/fixtures
```

### 3. Copy Test Templates
```bash
# Copy appropriate test suite to your project
cp UNIT-TESTS.tpl.R tests/testthat/test-unit.R
cp INTEGRATION-TESTS.tpl.R tests/testthat/test-integration.R
cp SYSTEM-TESTS.tpl.R tests/testthat/test-system.R
cp WORKFLOW-TESTS.tpl.R tests/testthat/test-workflow.R
```

## Test Suite Details

### Unit Tests (18 KB)
**Purpose**: Test individual functions, statistical operations, and data transformations in isolation.

**Key Components:**
- Statistical function validation (mean, correlation, regression)
- Data manipulation testing (dplyr, tidyr, stringr)
- Visualization object testing (ggplot2)
- Machine learning model validation
- Time series operation testing
- Error handling and edge cases

**Usage:**
```r
# Run unit tests
devtools::test(filter = "unit")
testthat::test_file("tests/testthat/test-unit.R")
```

### Integration Tests (23 KB)
**Purpose**: Test interactions between components, external APIs, and data pipelines.

**Key Components:**
- End-to-end data pipeline validation
- API integration with mocking
- Database connectivity and operations
- File I/O operations
- Configuration management
- Parallel processing integration

**Usage:**
```r
# Run integration tests
devtools::test(filter = "integration")
testthat::test_file("tests/testthat/test-integration.R")
```

### System Tests (26 KB)
**Purpose**: Validate complete analysis workflows, performance, and system behavior.

**Key Components:**
- Complete analysis workflow execution
- Performance and scalability testing
- Result reproducibility validation
- Error recovery and resilience
- Parallel processing systems
- Targets pipeline integration

**Usage:**
```r
# Run system tests
devtools::test(filter = "system")
testthat::test_file("tests/testthat/test-system.R")
```

### Workflow Tests (20 KB)
**Purpose**: Test development workflows, package building, and deployment processes.

**Key Components:**
- Package structure validation
- R CMD check compliance
- Documentation generation
- CI/CD pipeline validation
- Docker containerization
- CRAN submission requirements

**Usage:**
```r
# Run workflow tests
devtools::test(filter = "workflow")
testthat::test_file("tests/testthat/test-workflow.R")
```

## R-Specific Testing Patterns

### testthat Framework Integration
```r
# Standard test structure
test_that("function works correctly", {
  # Arrange
  test_data <- create_test_data()
  
  # Act  
  result <- my_function(test_data)
  
  # Assert
  expect_equal(result$expected, 42)
  expect_true(is.data.frame(result))
})
```

### Statistical Testing Patterns
```r
# Statistical validation with tolerance
test_that("statistical functions produce valid results", {
  result <- t.test(group_a, group_b)
  expect_true(result$p.value > 0)
  expect_true(result$p.value < 1)
  expect_is(result, "htest")
  
  # Test with tolerance for floating point
  expect_equal(mean(data), expected_mean, tolerance = 0.01)
})
```

### Data Manipulation Testing
```r
# Tidyverse pipeline testing
test_that("dplyr operations work correctly", {
  result <- test_data %>%
    filter(!is.na(value)) %>%
    group_by(category) %>%
    summarise(mean_value = mean(value))
  
  expect_true(nrow(result) > 0)
  expect_true(all(!is.na(result$mean_value)))
})
```

### Visualization Testing
```r
# ggplot2 object validation
test_that("plots are created correctly", {
  plot <- ggplot(test_data, aes(x = x, y = y)) + geom_point()
  
  expect_is(plot, "gg")
  expect_is(plot, "ggplot")
  expect_equal(length(plot$layers), 1)
  
  # Test plot data extraction
  plot_data <- ggplot_build(plot)$data[[1]]
  expect_equal(nrow(plot_data), nrow(test_data))
})
```

### Mock Testing Patterns
```r
# External dependency mocking
test_that("API integration works with mocking", {
  mock_response <- function(...) {
    list(status_code = 200, content = list(data = "test"))
  }
  
  with_mock(
    `httr::GET` = mock_response,
    result <- fetch_api_data("/endpoint")
    expect_equal(result$status_code, 200)
  )
})
```

### Performance Testing
```r
# Performance benchmarking
test_that("function performs efficiently", {
  large_data <- create_large_test_data(n = 10000)
  
  timing <- system.time({
    result <- my_function(large_data)
  })
  
  expect_true(timing["elapsed"] < 5)  # Should complete within 5 seconds
})
```

## Test Data Management

### Test Data Factories
```r
# Reusable test data creation
create_test_data <- function(n = 100, seed = 123) {
  set.seed(seed)
  data.frame(
    id = 1:n,
    value = rnorm(n, mean = 50, sd = 10),
    category = sample(c("A", "B", "C"), n, replace = TRUE),
    date = seq.Date(from = as.Date("2023-01-01"), by = "day", length.out = n)
  )
}
```

### Mock Data for APIs
```r
# API response mocking
create_mock_api_response <- function(endpoint) {
  switch(endpoint,
    "/users" = list(users = list(list(id = 1, name = "Test"))),
    "/data" = list(data = list(x = 1:10, y = rnorm(10))),
    list(error = "Not found")
  )
}
```

## Running Tests

### Individual Test Files
```r
# Run specific test file
testthat::test_file("tests/testthat/test-unit.R")

# Run with specific filter
devtools::test(filter = "statistical")
```

### All Tests
```r
# Run all tests
devtools::test()

# Run with coverage
covr::package_coverage()
```

### Parallel Testing
```r
# Enable parallel testing
library(future)
plan(multisession, workers = 4)
devtools::test()
```

## CI/CD Integration

### GitHub Actions
```yaml
name: R-CMD-check
on: [push, pull_request]
jobs:
  R-CMD-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: r-lib/actions/setup-r@v2
      - uses: r-lib/actions/setup-r-dependencies@v2
      - uses: r-lib/actions/check-r-package@v2
```

### Coverage Reporting
```r
# Generate coverage report
library(covr)
coverage <- package_coverage()
report(coverage)
codecov(coverage)
```

## Performance Optimization

### Memory Management
```r
# Monitor memory usage
library(profmem)
memory_usage <- profmem({
  result <- large_data_operation()
})

total_mb <- sum(memory_usage$bytes) / (1024 * 1024)
```

### Benchmarking
```r
# Performance benchmarking
library(bench)
benchmarks <- bench::mark(
  method1 = approach1(data),
  method2 = approach2(data),
  iterations = 100
)
```

## Best Practices

### 1. **Test Independence**
```r
# Each test should be independent
test_that("test is independent", {
  # Create fresh data
  test_data <- create_test_data()
  
  # Don't rely on global state
  withr::with_options(
    list(digits = 3),
    result <- format_number(123.456)
  )
  
  expect_equal(result, "123")
})
```

### 2. **Meaningful Test Names**
```r
# Use descriptive test names
test_that("statistical_summary_handles_missing_data_correctly", {
  # Rather than: test_that("summary works", {
})
```

### 3. **Appropriate Test Data**
```r
# Use realistic test data
test_that("analysis_works_with_realistic_data", {
  test_data <- create_realistic_test_data(n = 1000)
  # Rather than: test_data <- data.frame(x = 1:3)
})
```

### 4. **Error Testing**
```r
# Test both success and failure cases
test_that("function_handles_errors_correctly", {
  # Success case
  expect_equal(safe_divide(10, 2), 5)
  
  # Error case
  expect_error(safe_divide(10, 0), "division by zero")
})
```

### 5. **Reproducible Tests**
```r
# Use fixed seeds for reproducibility
test_that("random_operations_are_reproducible", {
  set.seed(123)
  result1 <- random_operation()
  
  set.seed(123)
  result2 <- random_operation()
  
  expect_equal(result1, result2)
})
```

## Common Pitfalls and Solutions

### 1. **Floating Point Comparisons**
```r
# Use tolerance for floating point comparisons
test_that("floating_point_comparison_works", {
  result <- calculate_mean(c(0.1, 0.2))
  expect_equal(result, 0.15, tolerance = 1e-10)
  # Rather than: expect_equal(result, 0.15)
})
```

### 2. **File Path Issues**
```r
# Use portable file paths
test_that("file_operations_work", {
  temp_dir <- tempfile()
  dir.create(temp_dir)
  on.exit(unlink(temp_dir, recursive = TRUE), add = TRUE)
  
  file_path <- file.path(temp_dir, "test_file.txt")
  # Rather than: file_path <- "test_file.txt"
})
```

### 3. **Time-Dependent Tests**
```r
# Control time-dependent operations
test_that("time_dependent_function_works", {
  fixed_time <- as.POSIXct("2023-01-01 12:00:00")
  with_mock(
    `Sys.time` = function() fixed_time,
    result <- time_dependent_function()
  )
})
```

## Test Coverage Guidelines

### Coverage Targets by Tier
- **MVP**: 60-70% coverage, focus on core functionality
- **Core**: 80-85% coverage, include edge cases
- **Enterprise**: 90%+ coverage, include all scenarios

### Coverage Analysis
```r
# Generate coverage report
library(covr)
coverage <- package_coverage(type = "tests")
report(coverage, file = "coverage_report.html")

# Check specific file coverage
coverage <- file_coverage("R/main.R")
```

## Integration with Universal Template System

### Blueprint Integration
The testing framework integrates with blueprint-driven development:

```r
# Blueprint-specific test patterns
if (blueprint == "mins") {
  # Test monetization-specific functions
  test_monetization_models()
} else if (blueprint == "saas") {
  # Test subscription management
  test_subscription_workflows()
}
```

### Stack-Specific Optimization
```r
# R-specific optimizations
test_that("r_optimizations_work", {
  # Test data.table performance
  if (requireNamespace("data.table", quietly = TRUE)) {
    dt_result <- as.data.table(test_data)[, .(mean_value = mean(value)), by = category]
    expect_true(nrow(dt_result) > 0)
  }
  
  # Test tidyverse operations
  tidy_result <- test_data %>%
    group_by(category) %>%
    summarise(mean_value = mean(value))
  expect_true(nrow(tidy_result) > 0)
})
```

## Troubleshooting

### Common Issues
1. **Package loading failures**: Ensure all dependencies are installed
2. **Test file discovery**: Check file naming conventions
3. **Memory issues**: Use smaller test datasets or implement memory management
4. **Parallel testing conflicts**: Use proper isolation techniques

### Debugging Tests
```r
# Debug specific test
debugonce(test_function)
testthat::test_file("tests/testthat/test-unit.R", reporter = "debug")

# Interactive debugging
with_reporter(
  reporter = DebugReporter$new(),
  test_that("debug_this_test", {
    # Your test code here
  })
)
```

This comprehensive testing framework ensures robust validation of R statistical computing projects across all development phases, from unit testing to production deployment, following R ecosystem best practices and integrating seamlessly with the Universal Template System.