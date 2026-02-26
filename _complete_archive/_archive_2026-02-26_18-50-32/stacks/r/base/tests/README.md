# R Test Suites - Comprehensive Testing Framework

This directory contains four comprehensive test suites for R statistical computing projects, following best practices for testing in the R ecosystem.

## Test Suite Overview

### 1. **Unit Tests** (`unit-tests.tpl.R` - 18 KB)
Comprehensive unit testing for statistical functions, data manipulation, and visualizations.

**Coverage Areas:**
- ✅ Statistical function testing (mean, correlation, regression, t-tests)
- ✅ Data manipulation testing (dplyr, tidyr, stringr operations)
- ✅ Visualization testing (ggplot2 object creation and formatting)
- ✅ Machine learning model testing
- ✅ Time series operations
- ✅ Missing data handling
- ✅ Error handling and edge cases
- ✅ Performance and scalability testing
- ✅ Reproducibility validation

**Key Features:**
- Test data factories for consistent test data
- Statistical validation with tolerance checks
- Mock and stub testing patterns
- Edge case and boundary testing
- Memory usage monitoring

### 2. **Integration Tests** (`integration-tests.tpl.R` - 23 KB)
End-to-end testing for data pipelines, external APIs, and database integration.

**Coverage Areas:**
- ✅ Complete data pipeline workflows
- ✅ API integration with mocking
- ✅ Database connectivity and operations
- ✅ File I/O operations
- ✅ Configuration management
- ✅ Parallel processing integration
- ✅ Error recovery and resilience
- ✅ Performance integration testing

**Key Features:**
- Realistic test datasets (1000+ records)
- Mock API responses for external dependencies
- Database transaction testing
- Connection pooling validation
- Parallel processing benchmarks

### 3. **System Tests** (`system-tests.tpl.R` - 26 KB)
System-level testing for end-to-end analysis workflows, performance, and reproducibility.

**Coverage Areas:**
- ✅ Complete analysis workflows
- ✅ System performance and scalability
- ✅ Result reproducibility across environments
- ✅ Error handling and recovery
- ✅ Parallel processing systems
- ✅ Targets pipeline integration
- ✅ System resource management
- ✅ Memory efficiency testing

**Key Features:**
- Multi-scenario testing (missing data, outliers, trend changes)
- Performance benchmarking with bench package
- Memory profiling with profmem
- Targets pipeline validation
- Cross-environment reproducibility

### 4. **Workflow Tests** (`workflow-tests.tpl.R` - 20 KB)
Development workflow testing for package building, CI/CD, documentation, and deployment.

**Coverage Areas:**
- ✅ Package structure validation
- ✅ R CMD check compliance
- ✅ Documentation generation (roxygen2, pkgdown)
- ✅ CI/CD pipeline validation (GitHub Actions)
- ✅ Docker containerization
- ✅ CRAN submission requirements
- ✅ Vignette building
- ✅ Release automation

**Key Features:**
- Complete package lifecycle testing
- GitHub Actions workflow validation
- Docker container testing
- CRAN compliance checking
- Automated release scripts

## R-Specific Testing Patterns

### testthat Framework Integration
```r
# Standard testthat structure
test_that("function works correctly", {
  # Arrange
  test_data <- create_test_data()
  
  # Act
  result <- my_function(test_data)
  
  # Assert
  expect_equal(result$expected_value, 42)
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
})
```

### Mock Testing Patterns
```r
# External dependency mocking
test_that("API integration works with mocking", {
  with_mock(
    `httr::GET` = function(...) create_mock_response(),
    
    result <- fetch_api_data("/endpoint")
    expect_equal(result$status_code, 200)
  )
})
```

## Usage Instructions

### Basic Setup
1. Copy the appropriate test file to your project's `tests/testthat/` directory
2. Rename the file to remove the `.tpl` extension
3. Update the `{{PROJECT_NAME}}`, `{{AUTHOR}}`, and `{{VERSION}}` placeholders
4. Customize the test data factories and functions for your specific project

### Running Tests
```bash
# Run all tests
Rscript -e "devtools::test()"

# Run specific test file
Rscript -e "testthat::test_file('tests/testthat/unit-tests.R')"

# Run with coverage
Rscript -e "covr::package_coverage()"
```

### Integration with CI/CD
The workflow tests include templates for:
- GitHub Actions workflows
- Docker containerization
- Automated testing scripts
- Release automation

## File Sizes and Complexity

| Test Suite | Size | Complexity | Focus Area |
|------------|------|------------|------------|
| Unit Tests | 18 KB | Basic-Intermediate | Individual components |
| Integration Tests | 23 KB | Intermediate | Component interactions |
| System Tests | 26 KB | Advanced | End-to-end workflows |
| Workflow Tests | 20 KB | Advanced | Development processes |

## Best Practices Implemented

### 1. **Test Organization**
- Clear test contexts and descriptions
- Logical grouping of related tests
- Consistent naming conventions

### 2. **Test Data Management**
- Reusable test data factories
- Consistent random seed usage
- Appropriate data sizes for testing

### 3. **Error Handling**
- Comprehensive error case testing
- Graceful failure handling
- Appropriate error messages

### 4. **Performance Awareness**
- Memory usage monitoring
- Execution time measurement
- Scalability testing

### 5. **Reproducibility**
- Fixed random seeds
- Environment isolation
- Result validation

## Dependencies

### Core Testing
- `testthat` - Primary testing framework
- `mockery` - Mocking capabilities
- `checkmate` - Input validation
- `assertthat` - Assertion functions

### Integration Testing
- `httr` / `httr2` - HTTP requests
- `DBI` - Database connectivity
- `jsonlite` - JSON handling
- `future` - Parallel processing

### System Testing
- `bench` - Performance benchmarking
- `profmem` - Memory profiling
- `targets` - Pipeline management
- `callr` - Isolated R processes

### Workflow Testing
- `devtools` - Package development
- `usethis` - Project setup
- `pkgdown` - Documentation generation
- `rcmdcheck` - Package checking
- `roxygen2` - Documentation
- `git2r` - Git integration

## Customization Guidelines

### For Data Science Projects
- Focus on unit tests for statistical functions
- Emphasize data validation in integration tests
- Include model validation in system tests
- Add data pipeline testing in workflow tests

### For Package Development
- Prioritize R CMD check compliance
- Include comprehensive documentation testing
- Test across multiple R versions
- Validate CRAN submission requirements

### For Production Systems
- Emphasize error handling and recovery
- Include performance benchmarks
- Test deployment processes
- Validate monitoring and logging

## Maintenance and Updates

### Regular Updates
- Update test data factories as data structures change
- Refresh mock responses when APIs change
- Update dependencies and test compatibility
- Review and update performance benchmarks

### Continuous Improvement
- Monitor test execution times
- Analyze test coverage reports
- Update tests based on bug reports
- Refactor tests for better maintainability

This comprehensive testing framework ensures robust validation of R statistical computing projects across all development phases, from unit testing to production deployment.