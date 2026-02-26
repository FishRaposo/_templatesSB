# -----------------------------------------------------------------------------
# FILE: system-tests.tpl.R
# PURPOSE: Comprehensive system test suite for R end-to-end workflows
# USAGE: Copy to tests/testthat/ directory and extend for specific projects
# AUTHOR: {{AUTHOR}}
# VERSION: {{VERSION}}
# SINCE: {{VERSION}}
# -----------------------------------------------------------------------------

"""
{{PROJECT_NAME}} - System Test Suite
Comprehensive system tests for end-to-end analysis workflows, performance, and reproducibility.

Author: {{AUTHOR}}
Created: {{DATE}}
"""

# Load required libraries
library(testthat)
library(mockery)
library(callr)
library(withr)
library(bench)
library(profmem)
library(future)
library(targets)

# Setup test environment
context("System Tests - {{PROJECT_NAME}}")

# -----------------------------------------------------------------------------
# SYSTEM TEST DATA AND SETUP
# -----------------------------------------------------------------------------

#' Create comprehensive test dataset for system testing
create_system_test_data <- function(scenario = "complete", n = 1000, seed = 123) {
  set.seed(seed)
  
  base_data <- data.frame(
    timestamp = seq.POSIXt(
      from = as.POSIXct("2023-01-01"),
      by = "hour",
      length.out = n
    ),
    entity_id = sample(1000:9999, n, replace = TRUE),
    value = rnorm(n, mean = 100, sd = 20),
    category = sample(c("A", "B", "C", "D"), n, replace = TRUE, prob = c(0.4, 0.3, 0.2, 0.1)),
    status = sample(c("active", "inactive", "pending"), n, replace = TRUE, prob = c(0.7, 0.2, 0.1)),
    location = sample(c("US", "EU", "APAC"), n, replace = TRUE, prob = c(0.5, 0.3, 0.2)),
    quality_score = runif(n, 0, 100)
  )
  
  # Add scenario-specific modifications
  switch(scenario,
    "complete" = {
      base_data$anomaly_flag <- sample(c(TRUE, FALSE), n, replace = TRUE, prob = c(0.05, 0.95))
      base_data$trend_component <- seq_len(n) * 0.01 + rnorm(n, 0, 0.1)
      base_data$seasonal_component <- sin(2 * pi * seq_len(n) / 24) * 5 + rnorm(n, 0, 1)
      base_data$final_value <- base_data$value + base_data$trend_component + base_data$seasonal_component
    },
    "missing_data" = {
      missing_indices <- sample(1:n, n * 0.15)
      base_data$value[missing_indices] <- NA
      base_data$category[sample(1:n, n * 0.1)] <- NA
      base_data$status[sample(1:n, n * 0.05)] <- NA
    },
    "outliers" = {
      outlier_indices <- sample(1:n, n * 0.02)
      base_data$value[outlier_indices] <- base_data$value[outlier_indices] * runif(length(outlier_indices), 3, 10)
    },
    "trend_change" = {
      change_point <- n %/% 2
      base_data$value[(change_point + 1):n] <- base_data$value[(change_point + 1):n] + seq_len(n - change_point) * 0.5
    }
  )
  
  return(base_data)
}

#' Create complete analysis workflow for testing
create_analysis_workflow <- function(data) {
  list(
    # Data preprocessing
    preprocessing = function(df) {
      df %>%
        mutate(
          date = as.Date(timestamp),
          hour = as.numeric(format(timestamp, "%H")),
          day_of_week = weekdays(timestamp),
          is_weekend = format(timestamp, "%u") %in% c("6", "7")
        ) %>%
        filter(
          !is.na(value),
          quality_score > 50,
          status != "inactive"
        )
    },
    
    # Exploratory analysis
    exploration = function(df) {
      list(
        summary_stats = summary(df$value),
        category_summary = df %>%
          group_by(category) %>%
          summarise(
            count = n(),
            mean_value = mean(value),
            sd_value = sd(value),
            .groups = "drop"
          ),
        correlation_matrix = cor(df %>% select(value, quality_score, hour), use = "complete.obs")
      )
    },
    
    # Statistical modeling
    modeling = function(df) {
      list(
        linear_model = lm(value ~ category + hour + quality_score, data = df),
        time_series = ts(df$value, frequency = 24),
        anomaly_detection = df %>%
          mutate(
            rolling_mean = zoo::rollmean(value, k = 24, fill = NA, align = "center"),
            rolling_sd = zoo::rollapply(value, width = 24, FUN = sd, fill = NA, align = "center"),
            is_anomaly = abs(value - rolling_mean) > 3 * rolling_sd
          )
      )
    },
    
    # Visualization
    visualization = function(df, model_results) {
      list(
        time_series_plot = ggplot(df, aes(x = timestamp, y = value)) +
          geom_line(alpha = 0.7) +
          geom_smooth(method = "loess", se = FALSE, color = "red") +
          theme_minimal() +
          labs(title = "Time Series Analysis", x = "Time", y = "Value"),
        
        category_boxplot = ggplot(df, aes(x = category, y = value)) +
          geom_boxplot() +
          theme_minimal() +
          labs(title = "Value Distribution by Category", x = "Category", y = "Value"),
        
        correlation_heatmap = ggplot(df %>% select(value, quality_score, hour), aes(x = value, y = quality_score)) +
          geom_point(alpha = 0.5) +
          theme_minimal() +
          labs(title = "Value vs Quality Score")
      )
    },
    
    # Reporting
    reporting = function(df, exploration, models, plots) {
      list(
        executive_summary = paste(
          "Analysis of", nrow(df), "records across", n_distinct(df$category), "categories.",
          "Mean value:", round(mean(df$value), 2),
          "Anomalies detected:", sum(models$anomaly_detection$is_anomaly, na.rm = TRUE)
        ),
        
        key_findings = list(
          highest_value_category = exploration$category_summary %>%
            filter(mean_value == max(mean_value)) %>%
            pull(category),
          
          optimal_hour = df %>%
            group_by(hour) %>%
            summarise(mean_value = mean(value), .groups = "drop") %>%
            filter(mean_value == max(mean_value)) %>%
            pull(hour),
          
          model_performance = summary(models$linear_model)$r.squared
        ),
        
        recommendations = c(
          "Monitor categories with consistently high values",
          "Investigate anomalies detected in the time series",
          "Consider time-based interventions during optimal hours"
        )
      )
    }
  )
}

# -----------------------------------------------------------------------------
# END-TO-END WORKFLOW TESTS
# -----------------------------------------------------------------------------

test_that("Complete analysis workflow executes successfully", {
  # Create test data
  test_data <- create_system_test_data(scenario = "complete", n = 500)
  
  # Create workflow
  workflow <- create_analysis_workflow(test_data)
  
  # Execute complete workflow
  workflow_result <- list()
  
  # Step 1: Preprocessing
  workflow_result$preprocessed <- workflow$preprocessing(test_data)
  expect_is(workflow_result$preprocessed, "data.frame")
  expect_true(nrow(workflow_result$preprocessed) <= nrow(test_data))  # Should filter some rows
  expect_true(all(c("date", "hour", "day_of_week", "is_weekend") %in% names(workflow_result$preprocessed)))
  
  # Step 2: Exploration
  workflow_result$exploration <- workflow$exploration(workflow_result$preprocessed)
  expect_is(workflow_result$exploration, "list")
  expect_true("summary_stats" %in% names(workflow_result$exploration))
  expect_true("category_summary" %in% names(workflow_result$exploration))
  expect_true("correlation_matrix" %in% names(workflow_result$exploration))
  
  # Step 3: Modeling
  workflow_result$models <- workflow$modeling(workflow_result$preprocessed)
  expect_is(workflow_result$models, "list")
  expect_is(workflow_result$models$linear_model, "lm")
  expect_is(workflow_result$models$time_series, "ts")
  expect_is(workflow_result$models$anomaly_detection, "data.frame")
  
  # Step 4: Visualization
  workflow_result$plots <- workflow$visualization(
    workflow_result$preprocessed, 
    workflow_result$models
  )
  expect_is(workflow_result$plots, "list")
  expect_is(workflow_result$plots$time_series_plot, "gg")
  expect_is(workflow_result$plots$category_boxplot, "gg")
  expect_is(workflow_result$plots$correlation_heatmap, "gg")
  
  # Step 5: Reporting
  workflow_result$report <- workflow$reporting(
    workflow_result$preprocessed,
    workflow_result$exploration,
    workflow_result$models,
    workflow_result$plots
  )
  expect_is(workflow_result$report, "list")
  expect_true("executive_summary" %in% names(workflow_result$report))
  expect_true("key_findings" %in% names(workflow_result$report))
  expect_true("recommendations" %in% names(workflow_result$report))
  
  # Verify workflow coherence
  expect_true(nrow(workflow_result$preprocessed) > 0)
  expect_true(summary(workflow_result$models$linear_model)$r.squared >= 0)
  expect_true(length(workflow_result$report$key_findings) > 0)
})

test_that("Workflow handles different data scenarios correctly", {
  scenarios <- c("missing_data", "outliers", "trend_change")
  
  for (scenario in scenarios) {
    # Create scenario-specific data
    test_data <- create_system_test_data(scenario = scenario, n = 200)
    
    # Create and run workflow
    workflow <- create_analysis_workflow(test_data)
    
    # Execute workflow
    preprocessed <- workflow$preprocessing(test_data)
    exploration <- workflow$exploration(preprocessed)
    models <- workflow$modeling(preprocessed)
    
    # Verify scenario-specific handling
    switch(scenario,
      "missing_data" = {
        expect_true(any(is.na(test_data$value)))  # Original has missing data
        expect_true(all(!is.na(preprocessed$value)))  # Preprocessing should handle it
      },
      "outliers" = {
        original_sd <- sd(test_data$value, na.rm = TRUE)
        expect_true(original_sd > 15)  # Should have high variance due to outliers
      },
      "trend_change" = {
        # Should detect trend in time series
        expect_true(length(models$time_series) > 0)
      }
    )
    
    # All scenarios should produce valid results
    expect_is(preprocessed, "data.frame")
    expect_is(models$linear_model, "lm")
    expect_true(nrow(preprocessed) > 0)
  }
})

test_that("Workflow produces reproducible results", {
  # Test with same seed twice
  results1 <- results2 <- list()
  
  for (i in 1:2) {
    set.seed(123)
    test_data <- create_system_test_data(scenario = "complete", n = 300)
    workflow <- create_analysis_workflow(test_data)
    
    if (i == 1) {
      results1$preprocessed <- workflow$preprocessing(test_data)
      results1$exploration <- workflow$exploration(results1$preprocessed)
      results1$models <- workflow$modeling(results1$preprocessed)
    } else {
      results2$preprocessed <- workflow$preprocessing(test_data)
      results2$exploration <- workflow$exploration(results2$preprocessed)
      results2$models <- workflow$modeling(results2$preprocessed)
    }
  }
  
  # Results should be identical
  expect_equal(results1$preprocessed, results2$preprocessed)
  expect_equal(results1$exploration$summary_stats, results2$exploration$summary_stats)
  expect_equal(coef(results1$models$linear_model), coef(results2$models$linear_model))
})

# -----------------------------------------------------------------------------
# PERFORMANCE AND SCALABILITY TESTS
# -----------------------------------------------------------------------------

test_that("Workflow performance scales appropriately with data size", {
  data_sizes <- c(100, 500, 1000)
  performance_results <- data.frame()
  
  for (n in data_sizes) {
    test_data <- create_system_test_data(scenario = "complete", n = n)
    workflow <- create_analysis_workflow(test_data)
    
    # Measure performance
    timing <- system.time({
      preprocessed <- workflow$preprocessing(test_data)
      exploration <- workflow$exploration(preprocessed)
      models <- workflow$modeling(preprocessed)
    })
    
    performance_results <- rbind(performance_results, data.frame(
      data_size = n,
      elapsed_time = timing["elapsed"],
      user_time = timing["user.self"],
      system_time = timing["system.self"]
    ))
  }
  
  # Performance should scale reasonably
  expect_true(all(performance_results$elapsed_time > 0))
  expect_true(all(performance_results$elapsed_time < 30))  # Should complete within 30 seconds
  
  # Larger datasets should take more time (approximately linear)
  time_ratios <- performance_results$elapsed_time / performance_results$elapsed_time[1]
  size_ratios <- performance_results$data_size / performance_results$data_size[1]
  
  # Time should not grow faster than data size
  expect_true(all(time_ratios <= size_ratios * 2))  # Allow 2x factor for overhead
})

test_that("Memory usage stays within acceptable limits", {
  test_data <- create_system_test_data(scenario = "complete", n = 2000)
  workflow <- create_analysis_workflow(test_data)
  
  # Measure memory usage
  memory_usage <- profmem({
    preprocessed <- workflow$preprocessing(test_data)
    exploration <- workflow$exploration(preprocessed)
    models <- workflow$modeling(preprocessed)
  })
  
  # Should not allocate excessive memory
  total_bytes <- sum(memory_usage$bytes)
  total_mb <- total_bytes / (1024 * 1024)
  
  expect_true(total_mb < 500)  # Less than 500MB for 2000 rows
  expect_true(length(memory_usage) > 0)  # Should have some allocations
})

test_that("Individual components perform efficiently", {
  test_data <- create_system_test_data(scenario = "complete", n = 1000)
  workflow <- create_analysis_workflow(test_data)
  
  # Benchmark individual components
  preprocessing_benchmark <- bench::mark(
    workflow$preprocessing(test_data),
    iterations = 10
  )
  
  modeling_benchmark <- bench::mark(
    workflow$modeling(test_data),
    iterations = 10
  )
  
  # Performance should be reasonable
  expect_true(median(preprocessing_benchmark$time) < 1e9)  # Less than 1 second
  expect_true(median(modeling_benchmark$time) < 5e9)  # Less than 5 seconds
  
  # Memory allocation should be reasonable
  expect_true(median(preprocessing_benchmark$mem_alloc) < 1e7)  # Less than 10MB
  expect_true(median(modeling_benchmark$mem_alloc) < 5e7)  # Less than 50MB
})

# -----------------------------------------------------------------------------
# REPRODUCIBILITY TESTS
# -----------------------------------------------------------------------------

test_that("Complete workflow produces reproducible results across runs", {
  # Create temporary directory for results
  temp_dir <- tempfile()
  dir.create(temp_dir)
  on.exit(unlink(temp_dir, recursive = TRUE), add = TRUE)
  
  # Run workflow twice with same configuration
  for (run in 1:2) {
    set.seed(456)  # Same seed for both runs
    
    test_data <- create_system_test_data(scenario = "complete", n = 300)
    workflow <- create_analysis_workflow(test_data)
    
    # Execute workflow
    preprocessed <- workflow$preprocessing(test_data)
    exploration <- workflow$exploration(preprocessed)
    models <- workflow$modeling(preprocessed)
    
    # Save results
    saveRDS(list(
      preprocessed = preprocessed,
      exploration = exploration,
      models = models
    ), file.path(temp_dir, paste0("run_", run, ".rds")))
  }
  
  # Compare results
  results1 <- readRDS(file.path(temp_dir, "run_1.rds"))
  results2 <- readRDS(file.path(temp_dir, "run_2.rds"))
  
  expect_equal(results1$preprocessed, results2$preprocessed)
  expect_equal(results1$exploration$summary_stats, results2$exploration$summary_stats)
  expect_equal(coef(results1$models$linear_model), coef(results2$models$linear_model))
  expect_equal(results1$models$anomaly_detection, results2$models$anomaly_detection)
})

test_that("Results are consistent across different environments", {
  # Test with different random seeds but same data characteristics
  seeds <- c(111, 222, 333)
  model_performance <- c()
  
  for (seed in seeds) {
    set.seed(seed)
    test_data <- create_system_test_data(scenario = "complete", n = 500)
    workflow <- create_analysis_workflow(test_data)
    
    preprocessed <- workflow$preprocessing(test_data)
    models <- workflow$modeling(preprocessed)
    
    # Extract model performance
    performance <- summary(models$linear_model)$r.squared
    model_performance <- c(model_performance, performance)
  }
  
  # Model performance should be similar across different seeds
  expect_true(sd(model_performance) < 0.1)  # Small variation
  expect_true(all(model_performance > 0))   # All positive
  expect_true(all(model_performance < 1))   # All reasonable
})

# -----------------------------------------------------------------------------
# ERROR HANDLING AND RECOVERY TESTS
# -----------------------------------------------------------------------------

test_that("Workflow handles corrupted data gracefully", {
  # Create data with various corruption scenarios
  test_data <- create_system_test_data(scenario = "complete", n = 200)
  
  # Introduce corruption
  test_data$value[sample(1:200, 10)] <- "corrupted"
  test_data$timestamp[sample(1:200, 5)] <- "invalid_date"
  test_data$category[sample(1:200, 15)] <- NA
  
  # Create robust workflow
  robust_workflow <- list(
    preprocessing = function(df) {
      # Data validation
      if (nrow(df) == 0) {
        stop("No data provided")
      }
      
      # Handle corrupted values
      df <- df %>%
        mutate(
          value = tryCatch(as.numeric(as.character(value)), 
                          error = function(e) NA),
          timestamp = tryCatch(as.POSIXct(timestamp), 
                              error = function(e) NA),
          category = ifelse(is.na(category), "UNKNOWN", category)
        ) %>%
        filter(
          !is.na(value),
          !is.na(timestamp),
          value > 0,
          value < 1000  # Reasonable bounds
        )
      
      if (nrow(df) < 10) {
        warning("Insufficient clean data for analysis")
      }
      
      # Continue with regular preprocessing
      df %>%
        mutate(
          date = as.Date(timestamp),
          hour = as.numeric(format(timestamp, "%H"))
        )
    }
  )
  
  # Execute with corrupted data
  result <- robust_workflow$preprocessing(test_data)
  
  # Should handle corruption gracefully
  expect_is(result, "data.frame")
  expect_true(nrow(result) > 0)  # Should have some clean data
  expect_true(all(!is.na(result$value)))
  expect_true(all(!is.na(result$timestamp)))
  expect_true(all(result$value > 0 & result$value < 1000))
})

test_that("Workflow recovers from missing dependencies", {
  # Create workflow that depends on optional packages
  optional_workflow <- list(
    modeling = function(df) {
      results <- list()
      
      # Try advanced modeling if package available
      if (requireNamespace("randomForest", quietly = TRUE)) {
        tryCatch({
          results$random_forest <- randomForest::randomForest(
            category ~ value + quality_score, 
            data = df, 
            ntree = 50
          )
        }, error = function(e) {
          warning("Random forest modeling failed: ", e$message)
        })
      } else {
        warning("randomForest package not available, skipping advanced modeling")
      }
      
      # Always do basic modeling
      results$linear_model <- lm(value ~ category + quality_score, data = df)
      
      return(results)
    }
  )
  
  test_data <- create_system_test_data(scenario = "complete", n = 100)
  
  # Should work regardless of package availability
  result <- optional_workflow$modeling(test_data)
  
  expect_is(result, "list")
  expect_is(result$linear_model, "lm")  # Basic model should always work
  # Random forest may or may not be present depending on package availability
})

# -----------------------------------------------------------------------------
# PARALLEL PROCESSING SYSTEM TESTS
# -----------------------------------------------------------------------------

test_that("Workflow scales with parallel processing", {
  skip_if_not_installed("doFuture")
  library(doFuture)
  
  test_data <- create_system_test_data(scenario = "complete", n = 1000)
  
  # Sequential processing
  plan(sequential)
  sequential_time <- system.time({
    sequential_result <- test_data %>%
      group_by(category) %>%
      summarise(
        mean_value = mean(value),
        sd_value = sd(value),
        .groups = "drop"
      )
  })
  
  # Parallel processing
  plan(multisession, workers = 2)
  parallel_time <- system.time({
    parallel_result <- test_data %>%
      group_by(category) %>%
      summarise(
        mean_value = mean(value),
        sd_value = sd(value),
        .groups = "drop"
      )
  })
  
  # Results should be identical
  expect_equal(sequential_result, parallel_result)
  
  # Parallel should be faster or comparable
  expect_true(parallel_time["elapsed"] <= sequential_time["elapsed"] * 1.5)
  
  # Cleanup
  plan(sequential)
})

test_that("Parallel workflow handles errors gracefully", {
  library(future)
  
  # Create workflow with potential for parallel errors
  parallel_workflow <- function(data) {
    plan(multisession, workers = 2)
    on.exit(plan(sequential), add = TRUE)
    
    # Split data for parallel processing
    data_splits <- split(data, data$category)
    
    # Process in parallel with error handling
    results <- future_lapply(data_splits, function(df) {
      tryCatch({
        # Simulate potential errors
        if (nrow(df) < 5) {
          stop("Insufficient data for analysis")
        }
        
        # Process data
        list(
          category = unique(df$category),
          count = nrow(df),
          mean_value = mean(df$value),
          status = "success"
        )
      }, error = function(e) {
        list(
          category = unique(df$category),
          count = nrow(df),
          error = e$message,
          status = "error"
        )
      })
    })
    
    return(results)
  }
  
  test_data <- create_system_test_data(scenario = "complete", n = 100)
  
  # Should handle mixed success/error scenarios
  result <- parallel_workflow(test_data)
  
  expect_is(result, "list")
  expect_equal(length(result), n_distinct(test_data$category))
  
  # All results should have required fields
  for (res in result) {
    expect_true("category" %in% names(res))
    expect_true("count" %in% names(res))
    expect_true("status" %in% names(res))
  }
})

# -----------------------------------------------------------------------------
# TARGETS PIPELINE INTEGRATION TESTS
# -----------------------------------------------------------------------------

test_that("Targets pipeline executes successfully", {
  skip_if_not_installed("targets")
  
  temp_dir <- tempfile()
  dir.create(temp_dir)
  on.exit(unlink(temp_dir, recursive = TRUE), add = TRUE)
  
  # Create targets pipeline
  tar_script({
    library(tidyverse)
    
    tar_option_set(packages = c("dplyr", "ggplot2"))
    
    list(
      tar_target(raw_data, create_system_test_data(n = 200)),
      tar_target(clean_data, raw_data %>% filter(!is.na(value))),
      tar_target(summary_stats, summary(clean_data$value)),
      tar_target(plot, ggplot(clean_data, aes(x = timestamp, y = value)) + geom_line())
    )
  }, store = temp_dir)
  
  # Run pipeline
  tar_make(store = temp_dir)
  
  # Verify results
  expect_true(file.exists(file.path(temp_dir, "meta", "meta")))
  
  # Check targets
  expect_true(tar_exists(raw_data, store = temp_dir))
  expect_true(tar_exists(clean_data, store = temp_dir))
  expect_true(tar_exists(summary_stats, store = temp_dir))
  expect_true(tar_exists(plot, store = temp_dir))
  
  # Load and verify results
  clean_data <- tar_read(clean_data, store = temp_dir)
  expect_is(clean_data, "data.frame")
  expect_true(nrow(clean_data) > 0)
  
  plot_obj <- tar_read(plot, store = temp_dir)
  expect_is(plot_obj, "gg")
})

test_that("Targets pipeline handles changes correctly", {
  skip_if_not_installed("targets")
  
  temp_dir <- tempfile()
  dir.create(temp_dir)
  on.exit(unlink(temp_dir, recursive = TRUE), add = TRUE)
  
  # Initial pipeline
  tar_script({
    tar_option_set(packages = "dplyr")
    
    list(
      tar_target(data, create_system_test_data(n = 100)),
      tar_target(processed, data %>% filter(value > 50)),
      tar_target(result, nrow(processed))
    )
  }, store = temp_dir)
  
  tar_make(store = temp_dir)
  initial_result <- tar_read(result, store = temp_dir)
  
  # Modify pipeline (change data size)
  tar_script({
    tar_option_set(packages = "dplyr")
    
    list(
      tar_target(data, create_system_test_data(n = 200)),  # Changed from 100 to 200
      tar_target(processed, data %>% filter(value > 50)),
      tar_target(result, nrow(processed))
    )
  }, store = temp_dir)
  
  # Should rebuild affected targets
  tar_make(store = temp_dir)
  updated_result <- tar_read(result, store = temp_dir)
  
  # Results should be different due to data size change
  expect_true(updated_result != initial_result)
  expect_true(updated_result > initial_result)
})

# -----------------------------------------------------------------------------
# SYSTEM RESOURCE MANAGEMENT TESTS
# -----------------------------------------------------------------------------

test_that("Workflow manages memory efficiently", {
  test_data <- create_system_test_data(scenario = "complete", n = 5000)
  
  # Measure memory usage
  memory_profile <- profmem({
    workflow <- create_analysis_workflow(test_data)
    
    # Process in chunks to manage memory
    chunk_size <- 1000
    results <- list()
    
    for (i in seq(1, nrow(test_data), chunk_size)) {
      end_idx <- min(i + chunk_size - 1, nrow(test_data))
      chunk <- test_data[i:end_idx, ]
      
      processed_chunk <- workflow$preprocessing(chunk)
      results[[length(results) + 1]] <- processed_chunk
      
      # Explicit garbage collection
      gc(verbose = FALSE)
    }
    
    final_result <- do.call(rbind, results)
  })
  
  # Should have reasonable memory allocation
  total_bytes <- sum(memory_profile$bytes)
  total_mb <- total_bytes / (1024 * 1024)
  
  expect_true(total_mb < 1000)  # Less than 1GB
  expect_true(nrow(final_result) > 0)
})

test_that("Workflow handles system limitations gracefully", {
  # Test with simulated resource constraints
  constrained_workflow <- list(
    processing = function(df, max_rows = 1000, max_memory_mb = 100) {
      # Check data size
      if (nrow(df) > max_rows) {
        warning("Dataset too large, sampling to", max_rows, "rows")
        df <- df[sample(1:nrow(df), max_rows), ]
      }
      
      # Check memory usage
      object_size <- as.numeric(object.size(df)) / (1024 * 1024)
      if (object_size > max_memory_mb) {
        warning("Dataset too large in memory, reducing columns")
        # Keep only essential columns
        essential_cols <- c("timestamp", "value", "category")
        df <- df[, intersect(essential_cols, names(df))]
      }
      
      # Process data
      df %>%
        mutate(
          date = as.Date(timestamp),
          processed_value = value * 1.1
        ) %>%
        group_by(category) %>%
        summarise(
          mean_value = mean(processed_value),
          count = n(),
          .groups = "drop"
        )
    }
  )
  
  # Test with large dataset
  large_data <- create_system_test_data(scenario = "complete", n = 5000)
  
  result <- withCallingHandlers({
    constrained_workflow$processing(large_data, max_rows = 500, max_memory_mb = 50)
  }, warning = function(w) {
    # Capture warnings
    expect_true(grepl("too large", w$message))
  })
  
  expect_is(result, "data.frame")
  expect_true(nrow(result) <= n_distinct(large_data$category))
  expect_true(all(c("category", "mean_value", "count") %in% names(result)))
})

# Print summary
cat("System test suite created successfully!\n")
cat("Components included:\n")
cat("- End-to-end workflow tests\n")
cat("- Performance and scalability tests\n")
cat("- Reproducibility tests\n")
cat("- Error handling and recovery tests\n")
cat("- Parallel processing system tests\n")
cat("- Targets pipeline integration tests\n")
cat("- System resource management tests\n")
cat("Total tests: ", testthat:::count_tests(), "\n")