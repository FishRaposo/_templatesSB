# -----------------------------------------------------------------------------
# FILE: unit-tests.tpl.R
# PURPOSE: Comprehensive unit test suite for R statistical computing projects
# USAGE: Copy to tests/testthat/ directory and extend for specific projects
# AUTHOR: {{AUTHOR}}
# VERSION: {{VERSION}}
# SINCE: {{VERSION}}
# -----------------------------------------------------------------------------

"""
{{PROJECT_NAME}} - Unit Test Suite
Comprehensive unit tests for statistical functions, data manipulation, and visualizations.

Author: {{AUTHOR}}
Created: {{DATE}}
"""

# Load required libraries
library(testthat)
library(mockery)
library(checkmate)
library(assertthat)

# Setup test environment
context("Unit Tests - {{PROJECT_NAME}}")

# -----------------------------------------------------------------------------
# TEST DATA FACTORIES
# -----------------------------------------------------------------------------

#' Create test data frame for statistical testing
create_test_data <- function(n = 100, seed = 123) {
  set.seed(seed)
  data.frame(
    id = 1:n,
    group = sample(c("A", "B", "C"), n, replace = TRUE),
    numeric_var = rnorm(n, mean = 50, sd = 10),
    categorical_var = sample(c("low", "medium", "high"), n, replace = TRUE),
    date_var = seq.Date(from = as.Date("2023-01-01"), by = "day", length.out = n),
    missing_var = c(rnorm(n-5), rep(NA, 5))
  )
}

#' Create test time series data
create_test_ts <- function(n = 365, frequency = 7, seed = 123) {
  set.seed(seed)
  ts(rnorm(n, mean = 100, sd = 15), frequency = frequency)
}

#' Create test model objects
create_test_models <- function(data) {
  list(
    linear = lm(numeric_var ~ group, data = data),
    logistic = glm(categorical_var ~ numeric_var, data = data, family = binomial),
    random_forest = randomForest::randomForest(group ~ numeric_var, data = data)
  )
}

# -----------------------------------------------------------------------------
# STATISTICAL FUNCTION TESTS
# -----------------------------------------------------------------------------

test_that("Statistical functions produce valid results", {
  test_data <- create_test_data()
  
  # Test basic statistics
  expect_equal(mean(test_data$numeric_var), 50, tolerance = 2)
  expect_equal(sd(test_data$numeric_var), 10, tolerance = 2)
  expect_equal(cor(test_data$id, test_data$numeric_var), 0, tolerance = 0.1)
  
  # Test t-test functionality
  group_a <- test_data$numeric_var[test_data$group == "A"]
  group_b <- test_data$numeric_var[test_data$group == "B"]
  t_test_result <- t.test(group_a, group_b)
  
  expect_is(t_test_result, "htest")
  expect_true(t_test_result$p.value > 0)  # Should have p-value
  expect_true(t_test_result$p.value < 1)  # Should have valid p-value
})

test_that("Statistical tests handle edge cases", {
  # Test with all NA values
  na_data <- c(NA, NA, NA, NA, NA)
  expect_error(t.test(na_data), "not enough")
  
  # Test with single value
  single_data <- c(5, 5, 5, 5, 5)
  expect_error(t.test(single_data), "data are essentially")
  
  # Test with zero variance
  zero_var_data <- c(10, 10, 10, 10, 10)
  expect_error(t.test(zero_var_data), "data are essentially")
})

test_that("Regression models work correctly", {
  test_data <- create_test_data()
  
  # Linear regression
  model <- lm(numeric_var ~ group, data = test_data)
  expect_is(model, "lm")
  expect_equal(length(coef(model)), 3)  # Intercept + 2 group coefficients
  expect_true(summary(model)$r.squared >= 0)
  expect_true(summary(model)$r.squared <= 1)
  
  # Predictions
  predictions <- predict(model, newdata = test_data)
  expect_equal(length(predictions), nrow(test_data))
  expect_true(all(!is.na(predictions)))
})

test_that("Correlation analysis produces valid results", {
  test_data <- create_test_data()
  
  # Pearson correlation
  pearson_cor <- cor(test_data$id, test_data$numeric_var, method = "pearson")
  expect_true(abs(pearson_cor) <= 1)
  
  # Spearman correlation
  spearman_cor <- cor(test_data$id, test_data$numeric_var, method = "spearman")
  expect_true(abs(spearman_cor) <= 1)
  
  # Correlation matrix
  cor_matrix <- cor(test_data[, c("id", "numeric_var")], use = "complete.obs")
  expect_equal(nrow(cor_matrix), 2)
  expect_equal(ncol(cor_matrix), 2)
  expect_equal(diag(cor_matrix), c(1, 1))
})

# -----------------------------------------------------------------------------
# DATA MANIPULATION TESTS
# -----------------------------------------------------------------------------

test_that("dplyr operations work correctly", {
  test_data <- create_test_data()
  
  # Filter operations
  filtered <- test_data %>% filter(group == "A")
  expect_equal(nrow(filtered), sum(test_data$group == "A"))
  expect_true(all(filtered$group == "A"))
  
  # Select operations
  selected <- test_data %>% select(id, group)
  expect_equal(ncol(selected), 2)
  expect_equal(names(selected), c("id", "group"))
  
  # Mutate operations
  mutated <- test_data %>% mutate(new_var = numeric_var * 2)
  expect_true("new_var" %in% names(mutated))
  expect_equal(mutated$new_var[1], mutated$numeric_var[1] * 2)
  
  # Group operations
  grouped_summary <- test_data %>% 
    group_by(group) %>% 
    summarise(mean_numeric = mean(numeric_var, na.rm = TRUE))
  
  expect_equal(nrow(grouped_summary), 3)  # 3 groups
  expect_equal(names(grouped_summary), c("group", "mean_numeric"))
})

test_that("tidyr operations work correctly", {
  test_data <- create_test_data()
  
  # Pivot longer
  long_data <- test_data %>% 
    pivot_longer(cols = c(numeric_var, id), names_to = "variable", values_to = "value")
  
  expect_equal(ncol(long_data), ncol(test_data) - 1 + 2)  # Original minus pivoted plus names/values
  expect_true("variable" %in% names(long_data))
  expect_true("value" %in% names(long_data))
  
  # Pivot wider
  wide_data <- test_data %>% 
    select(id, group, numeric_var) %>% 
    pivot_wider(names_from = group, values_from = numeric_var)
  
  expect_true("A" %in% names(wide_data))
  expect_true("B" %in% names(wide_data))
  expect_true("C" %in% names(wide_data))
})

test_that("Missing data handling works correctly", {
  test_data <- create_test_data()
  
  # NA detection
  expect_true(any(is.na(test_data$missing_var)))
  
  # NA removal
  complete_cases <- test_data %>% drop_na(missing_var)
  expect_equal(nrow(complete_cases), nrow(test_data) - 5)
  expect_true(all(!is.na(complete_cases$missing_var)))
  
  # NA replacement
  filled_data <- test_data %>% 
    mutate(missing_var = replace_na(missing_var, 0))
  
  expect_true(all(!is.na(filled_data$missing_var)))
  expect_equal(sum(filled_data$missing_var == 0), 5)
})

test_that("String manipulation works correctly", {
  test_strings <- c("hello world", "R programming", "test123")
  
  # String length
  expect_equal(str_length(test_strings), c(11, 13, 7))
  
  # String subset
  expect_equal(str_sub(test_strings, 1, 5), c("hello", "R pro", "test1"))
  
  # String detection
  expect_equal(str_detect(test_strings, "[0-9]"), c(FALSE, FALSE, TRUE))
  
  # String replacement
  replaced <- str_replace(test_strings, "world", "universe")
  expect_equal(replaced[1], "hello universe")
})

# -----------------------------------------------------------------------------
# VISUALIZATION TESTS
# -----------------------------------------------------------------------------

test_that("ggplot2 objects are created correctly", {
  test_data <- create_test_data()
  
  # Basic scatter plot
  scatter_plot <- ggplot(test_data, aes(x = id, y = numeric_var)) + 
    geom_point()
  
  expect_is(scatter_plot, "gg")
  expect_is(scatter_plot, "ggplot")
  expect_equal(length(scatter_plot$layers), 1)
  
  # Line plot with grouping
  line_plot <- ggplot(test_data, aes(x = date_var, y = numeric_var, color = group)) + 
    geom_line()
  
  expect_is(line_plot, "gg")
  expect_true("colour" %in% names(line_plot$mapping))
  
  # Histogram
  hist_plot <- ggplot(test_data, aes(x = numeric_var)) + 
    geom_histogram(bins = 30)
  
  expect_is(hist_plot, "gg")
  expect_equal(length(hist_plot$layers), 1)
})

test_that("Plot themes and formatting work correctly", {
  test_data <- create_test_data()
  
  # Theme application
  themed_plot <- ggplot(test_data, aes(x = id, y = numeric_var)) + 
    geom_point() + 
    theme_minimal()
  
  expect_is(themed_plot, "gg")
  
  # Labels and titles
  labeled_plot <- ggplot(test_data, aes(x = id, y = numeric_var)) + 
    geom_point() + 
    labs(title = "Test Plot", x = "ID", y = "Value")
  
  expect_is(labeled_plot, "gg")
})

test_that("Plot data extraction works correctly", {
  test_data <- create_test_data()
  
  plot <- ggplot(test_data, aes(x = id, y = numeric_var)) + geom_point()
  
  # Extract plot data
  plot_data <- ggplot_build(plot)$data[[1]]
  expect_equal(nrow(plot_data), nrow(test_data))
  expect_true("x" %in% names(plot_data))
  expect_true("y" %in% names(plot_data))
})

# -----------------------------------------------------------------------------
# MACHINE LEARNING TESTS
# -----------------------------------------------------------------------------

test_that("Model training works correctly", {
  test_data <- create_test_data()
  
  # Random Forest
  if (requireNamespace("randomForest", quietly = TRUE)) {
    rf_model <- randomForest::randomForest(
      group ~ numeric_var, 
      data = test_data, 
      ntree = 50
    )
    
    expect_is(rf_model, "randomForest")
    expect_true(rf_model$ntree == 50)
    expect_true(length(rf_model$err.rate) > 0)
    
    # Predictions
    predictions <- predict(rf_model, newdata = test_data)
    expect_equal(length(predictions), nrow(test_data))
  }
})

test_that("Model evaluation metrics work correctly", {
  test_data <- create_test_data()
  
  # Create binary outcome for classification
  test_data$binary_outcome <- ifelse(test_data$numeric_var > median(test_data$numeric_var), "high", "low")
  test_data$binary_outcome <- as.factor(test_data$binary_outcome)
  
  # Train model
  model <- glm(binary_outcome ~ numeric_var, data = test_data, family = binomial)
  predictions <- predict(model, newdata = test_data, type = "response")
  predicted_classes <- ifelse(predictions > 0.5, "high", "low")
  
  # Confusion matrix
  conf_matrix <- table(Predicted = predicted_classes, Actual = test_data$binary_outcome)
  expect_equal(nrow(conf_matrix), 2)
  expect_equal(ncol(conf_matrix), 2)
  
  # Accuracy
  accuracy <- sum(diag(conf_matrix)) / sum(conf_matrix)
  expect_true(accuracy >= 0)
  expect_true(accuracy <= 1)
})

# -----------------------------------------------------------------------------
# TIME SERIES TESTS
# -----------------------------------------------------------------------------

test_that("Time series operations work correctly", {
  test_ts <- create_test_ts()
  
  # Basic time series properties
  expect_is(test_ts, "ts")
  expect_true(length(test_ts) > 0)
  
  # Decomposition
  if (length(test_ts) >= 2 * frequency(test_ts)) {
    decomp <- decompose(test_ts)
    expect_is(decomp, "decomposed.ts")
    expect_true(all(names(decomp) %in% c("x", "seasonal", "trend", "random", "figure", "type")))
  }
})

# -----------------------------------------------------------------------------
# UTILITY FUNCTION TESTS
# -----------------------------------------------------------------------------

test_that("Data validation functions work correctly", {
  test_data <- create_test_data()
  
  # Check data frame structure
  expect_true(is.data.frame(test_data))
  expect_true(nrow(test_data) > 0)
  expect_true(ncol(test_data) > 0)
  
  # Check variable types
  expect_is(test_data$numeric_var, "numeric")
  expect_is(test_data$group, "character")
  expect_is(test_data$date_var, "Date")
})

test_that("Configuration and setup functions work correctly", {
  # Test random seed setting
  set.seed(123)
  data1 <- rnorm(10)
  
  set.seed(123)
  data2 <- rnorm(10)
  
  expect_equal(data1, data2)
})

# -----------------------------------------------------------------------------
# PERFORMANCE AND SCALABILITY TESTS
# -----------------------------------------------------------------------------

test_that("Functions handle large datasets", {
  # Create large dataset
  large_data <- create_test_data(n = 10000)
  
  # Test data processing
  expect_equal(nrow(large_data), 10000)
  
  # Test statistical operations
  large_mean <- mean(large_data$numeric_var)
  expect_is(large_mean, "numeric")
  expect_true(!is.na(large_mean))
  
  # Test dplyr operations
  large_filtered <- large_data %>% filter(group == "A")
  expect_true(nrow(large_filtered) > 0)
  expect_true(nrow(large_filtered) < nrow(large_data))
})

# -----------------------------------------------------------------------------
# ERROR HANDLING TESTS
# -----------------------------------------------------------------------------

test_that("Functions handle invalid inputs gracefully", {
  # Test with empty data
  empty_data <- data.frame()
  expect_error(mean(empty_data$nonexistent), "object of type 'closure'")
  
  # Test with wrong data types
  expect_error(cor("string1", "string2"), "numeric")
  
  # Test with incompatible dimensions
  expect_error(data.frame(x = 1:5, y = 1:3), "arguments imply")
})

# -----------------------------------------------------------------------------
# MOCK AND STUB TESTS
# -----------------------------------------------------------------------------

test_that("External dependencies can be mocked", {
  # Mock file reading
  mock_file_content <- "id,numeric_var\n1,10\n2,20\n3,30"
  
  # Create temporary file
  temp_file <- tempfile(fileext = ".csv")
  writeLines(mock_file_content, temp_file)
  
  # Test file reading
  data <- read.csv(temp_file)
  expect_equal(nrow(data), 3)
  expect_equal(ncol(data), 2)
  
  # Cleanup
  unlink(temp_file)
})

# -----------------------------------------------------------------------------
# REPRODUCIBILITY TESTS
# -----------------------------------------------------------------------------

test_that("Results are reproducible with set seed", {
  # Set seed and generate data
  set.seed(42)
  data1 <- rnorm(100, mean = 0, sd = 1)
  
  # Reset seed and generate again
  set.seed(42)
  data2 <- rnorm(100, mean = 0, sd = 1)
  
  # Should be identical
  expect_equal(data1, data2)
  
  # Statistical properties should match
  expect_equal(mean(data1), mean(data2))
  expect_equal(sd(data1), sd(data2))
})

# -----------------------------------------------------------------------------
# EDGE CASE AND BOUNDARY TESTS
# -----------------------------------------------------------------------------

test_that("Functions handle edge cases correctly", {
  # Test with extreme values
  extreme_data <- data.frame(
    x = c(-Inf, Inf, NaN, NA, .Machine$double.xmax, .Machine$double.xmin)
  )
  
  expect_true(all(is.infinite(extreme_data$x[1:2])))
  expect_true(is.nan(extreme_data$x[3]))
  expect_true(is.na(extreme_data$x[4]))
  
  # Test with very small datasets
  tiny_data <- data.frame(x = 1, y = 2)
  expect_equal(nrow(tiny_data), 1)
  
  # Test with single unique value
  constant_data <- rep(5, 10)
  expect_equal(sd(constant_data), 0)
})

# -----------------------------------------------------------------------------
# INTEGRATION TESTS (BASIC LEVEL)
# -----------------------------------------------------------------------------

test_that("Multiple functions work together correctly", {
  test_data <- create_test_data()
  
  # Chain multiple operations
  result <- test_data %>%
    filter(!is.na(missing_var)) %>%
    group_by(group) %>%
    summarise(
      mean_numeric = mean(numeric_var),
      n = n()
    ) %>%
    arrange(desc(mean_numeric))
  
  expect_true(is.data.frame(result))
  expect_true(nrow(result) <= 3)  # Max 3 groups
  expect_true(all(c("group", "mean_numeric", "n") %in% names(result)))
})

# Print summary
cat("Unit test suite created successfully!\n")
cat("Components included:\n")
cat("- Statistical function tests (mean, correlation, regression)\n")
cat("- Data manipulation tests (dplyr, tidyr, stringr)\n")
cat("- Visualization tests (ggplot2)\n")
cat("- Machine learning tests\n")
cat("- Time series tests\n")
cat("- Performance and scalability tests\n")
cat("- Error handling and edge case tests\n")
cat("- Reproducibility tests\n")
cat("Total tests: ", testthat:::count_tests(), "\n")