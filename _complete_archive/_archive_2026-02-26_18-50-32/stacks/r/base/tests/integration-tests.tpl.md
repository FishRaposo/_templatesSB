# -----------------------------------------------------------------------------
# FILE: integration-tests.tpl.R
# PURPOSE: Comprehensive integration test suite for R data pipelines and APIs
# USAGE: Copy to tests/testthat/ directory and extend for specific projects
# AUTHOR: {{AUTHOR}}
# VERSION: {{VERSION}}
# SINCE: {{VERSION}}
# -----------------------------------------------------------------------------

"""
{{PROJECT_NAME}} - Integration Test Suite
Comprehensive integration tests for data pipelines, external APIs, and database connectivity.

Author: {{AUTHOR}}
Created: {{DATE}}
"""

# Load required libraries
library(testthat)
library(mockery)
library(httr)
library(httr2)
library(DBI)
library(jsonlite)
library(future)

# Setup test environment
context("Integration Tests - {{PROJECT_NAME}}")

# -----------------------------------------------------------------------------
# TEST DATA AND SETUP
# -----------------------------------------------------------------------------

#' Create realistic test dataset for integration testing
create_integration_test_data <- function(n = 1000, seed = 123) {
  set.seed(seed)
  
  # Simulate real-world data with multiple sources
  data.frame(
    # Customer data
    customer_id = 1:n,
    customer_name = paste("Customer", 1:n),
    email = paste0("customer", 1:n, "@example.com"),
    
    # Transaction data
    transaction_date = seq.Date(
      from = as.Date("2023-01-01"), 
      by = "day", 
      length.out = n
    ),
    amount = round(runif(n, 10, 1000), 2),
    category = sample(c("Food", "Transport", "Entertainment", "Utilities", "Other"), 
                     n, replace = TRUE, prob = c(0.3, 0.2, 0.2, 0.2, 0.1)),
    
    # Geographic data
    city = sample(c("New York", "Los Angeles", "Chicago", "Houston", "Phoenix"), 
                 n, replace = TRUE, prob = c(0.4, 0.3, 0.15, 0.1, 0.05)),
    state = sample(c("NY", "CA", "IL", "TX", "AZ"), n, replace = TRUE),
    
    # Product data
    product_id = sample(1000:9999, n, replace = TRUE),
    product_name = paste("Product", sample(letters, n, replace = TRUE)),
    quantity = sample(1:10, n, replace = TRUE),
    
    # Quality metrics
    rating = sample(1:5, n, replace = TRUE, prob = c(0.05, 0.1, 0.25, 0.35, 0.25)),
    satisfaction_score = round(runif(n, 0, 100), 1),
    
    # Missing data simulation
    missing_flag = sample(c(TRUE, FALSE), n, replace = TRUE, prob = c(0.05, 0.95))
  ) %>%
    mutate(
      amount = ifelse(missing_flag, NA, amount),
      rating = ifelse(missing_flag, NA, rating)
    ) %>%
    select(-missing_flag)
}

#' Create test API responses for mocking
create_mock_api_response <- function(endpoint, status_code = 200) {
  responses <- list(
    "/customers" = list(
      customers = list(
        list(id = 1, name = "John Doe", email = "john@example.com"),
        list(id = 2, name = "Jane Smith", email = "jane@example.com")
      ),
      total = 2,
      page = 1,
      per_page = 10
    ),
    
    "/transactions" = list(
      transactions = list(
        list(
          id = 1,
          customer_id = 1,
          amount = 150.50,
          date = "2023-12-01",
          category = "Food"
        ),
        list(
          id = 2,
          customer_id = 2,
          amount = 75.25,
          date = "2023-12-02",
          category = "Transport"
        )
      ),
      total = 2
    ),
    
    "/products" = list(
      products = list(
        list(id = 1001, name = "Widget A", price = 29.99, category = "Electronics"),
        list(id = 1002, name = "Widget B", price = 49.99, category = "Electronics")
      ),
      total = 2
    )
  )
  
  structure(
    list(
      status_code = status_code,
      content = responses[[endpoint]] %||% list(error = "Not found"),
      headers = list(`content-type` = "application/json")
    ),
    class = "response"
  )
}

# -----------------------------------------------------------------------------
# DATA PIPELINE INTEGRATION TESTS
# -----------------------------------------------------------------------------

test_that("End-to-end data pipeline processes data correctly", {
  # Setup test data
  raw_data <- create_integration_test_data(n = 500)
  
  # Simulate data pipeline
  pipeline_result <- raw_data %>%
    # Step 1: Data validation
    {
      # Check required columns
      required_cols <- c("customer_id", "transaction_date", "amount", "category")
      if (!all(required_cols %in% names(.))) {
        stop("Missing required columns")
      }
      .
    } %>%
    # Step 2: Data cleaning
    mutate(
      amount = ifelse(is.na(amount), 0, amount),
      category = toupper(category),
      transaction_date = as.Date(transaction_date)
    ) %>%
    # Step 3: Feature engineering
    mutate(
      transaction_month = format(transaction_date, "%Y-%m"),
      amount_category = case_when(
        amount < 50 ~ "Small",
        amount < 200 ~ "Medium",
        amount < 500 ~ "Large",
        TRUE ~ "Extra Large"
      ),
      days_since_start = as.numeric(transaction_date - min(transaction_date))
    ) %>%
    # Step 4: Aggregation
    group_by(customer_id, transaction_month, category) %>%
    summarise(
      total_amount = sum(amount),
      transaction_count = n(),
      avg_amount = mean(amount),
      .groups = "drop"
    ) %>%
    # Step 5: Final processing
    filter(total_amount > 0) %>%
    arrange(customer_id, transaction_month)
  
  # Verify pipeline results
  expect_is(pipeline_result, "data.frame")
  expect_true(nrow(pipeline_result) > 0)
  expect_true(all(c("customer_id", "transaction_month", "category", "total_amount") %in% names(pipeline_result)))
  expect_true(all(pipeline_result$total_amount >= 0))
  expect_true(all(!is.na(pipeline_result$transaction_count)))
})

test_that("Data pipeline handles missing data correctly", {
  # Create data with various missing patterns
  test_data <- create_integration_test_data(n = 100)
  test_data$amount[sample(1:100, 20)] <- NA
  test_data$category[sample(1:100, 15)] <- NA
  test_data$customer_id[sample(1:100, 10)] <- NA
  
  # Pipeline with missing data handling
  result <- test_data %>%
    # Remove completely missing records
    filter(!is.na(customer_id)) %>%
    # Handle missing amounts
    mutate(
      amount = case_when(
        is.na(amount) & category == "Food" ~ 25,
        is.na(amount) & category == "Transport" ~ 50,
        is.na(amount) ~ 30,
        TRUE ~ amount
      )
    ) %>%
    # Handle missing categories
    mutate(
      category = ifelse(is.na(category), "Other", category)
    ) %>%
    # Validate final data
    {
      # Check for any remaining NAs
      na_count <- sum(is.na(.))
      if (na_count > 0) {
        warning(paste("Still have", na_count, "NA values after cleaning"))
      }
      .
    }
  
  expect_true(all(!is.na(result$customer_id)))
  expect_true(all(!is.na(result$amount)))
  expect_true(all(!is.na(result$category)))
  expect_true(nrow(result) <= 90)  # Some rows should be removed
})

test_that("Data pipeline handles data type conversions", {
  test_data <- create_integration_test_data(n = 50)
  
  # Force some type issues
  test_data$amount <- as.character(test_data$amount)
  test_data$transaction_date <- as.character(test_data$transaction_date)
  
  # Pipeline with type conversions
  result <- test_data %>%
    mutate(
      amount = as.numeric(amount),
      transaction_date = as.Date(transaction_date),
      customer_id = as.integer(customer_id)
    )
  
  # Verify types
  expect_is(result$amount, "numeric")
  expect_is(result$transaction_date, "Date")
  expect_is(result$customer_id, "integer")
  
  # Verify no conversion errors
  expect_true(all(!is.na(result$amount)))
  expect_true(all(!is.na(result$transaction_date)))
  expect_true(all(!is.na(result$customer_id)))
})

# -----------------------------------------------------------------------------
# API INTEGRATION TESTS
# -----------------------------------------------------------------------------

test_that("API client can fetch data successfully", {
  # Mock API responses
  mock_response <- function(url, ...) {
    if (grepl("customers", url)) {
      return(create_mock_api_response("/customers"))
    } else if (grepl("transactions", url)) {
      return(create_mock_api_response("/transactions"))
    } else if (grepl("products", url)) {
      return(create_mock_api_response("/products"))
    } else {
      return(create_mock_api_response("/unknown", 404))
    }
  }
  
  # Test API integration
  with_mock(
    `httr::GET` = mock_response,
    
    # Test customer API
    customer_response <- GET("https://api.example.com/customers")
    expect_equal(customer_response$status_code, 200)
    customer_data <- content(customer_response, "parsed")
    expect_true("customers" %in% names(customer_data))
    expect_true(length(customer_data$customers) > 0)
    
    # Test transaction API
    transaction_response <- GET("https://api.example.com/transactions")
    expect_equal(transaction_response$status_code, 200)
    transaction_data <- content(transaction_response, "parsed")
    expect_true("transactions" %in% names(transaction_data))
    
    # Test error handling
    error_response <- GET("https://api.example.com/unknown")
    expect_equal(error_response$status_code, 404)
  )
})

test_that("API integration handles errors gracefully", {
  # Mock API with errors
  mock_error_response <- function(url, ...) {
    if (grepl("timeout", url)) {
      stop("Timeout error")
    } else if (grepl("server-error", url)) {
      structure(
        list(status_code = 500, content = list(error = "Internal server error")),
        class = "response"
      )
    } else if (grepl("rate-limit", url)) {
      structure(
        list(status_code = 429, content = list(error = "Rate limit exceeded")),
        class = "response"
      )
    } else {
      create_mock_api_response("/customers")
    }
  }
  
  # Test error handling
  with_mock(
    `httr::GET` = mock_error_response,
    
    # Test timeout handling
    expect_error(GET("https://api.example.com/timeout"), "Timeout")
    
    # Test server error handling
    server_response <- GET("https://api.example.com/server-error")
    expect_equal(server_response$status_code, 500)
    
    # Test rate limit handling
    rate_response <- GET("https://api.example.com/rate-limit")
    expect_equal(rate_response$status_code, 429)
  )
})

test_that("API data transformation works correctly", {
  # Mock API response
  mock_api_data <- function() {
    list(
      transactions = list(
        list(id = 1, amount = 100.50, date = "2023-12-01", category = "food"),
        list(id = 2, amount = 200.75, date = "2023-12-02", category = "transport"),
        list(id = 3, amount = 50.25, date = "2023-12-03", category = "entertainment")
      )
    )
  }
  
  # Transform API data to analysis format
  transform_api_data <- function(api_response) {
    api_response$transactions %>%
      map_df(function(tx) {
        data.frame(
          transaction_id = tx$id,
          amount = as.numeric(tx$amount),
          transaction_date = as.Date(tx$date),
          category = toupper(tx$category),
          amount_category = ifelse(as.numeric(tx$amount) > 100, "High", "Low")
        )
      })
  }
  
  # Test transformation
  api_data <- mock_api_data()
  transformed_data <- transform_api_data(api_data)
  
  expect_is(transformed_data, "data.frame")
  expect_equal(nrow(transformed_data), 3)
  expect_true(all(c("transaction_id", "amount", "transaction_date", "category") %in% names(transformed_data)))
  expect_true(all(transformed_data$category %in% c("FOOD", "TRANSPORT", "ENTERTAINMENT")))
  expect_true(all(transformed_data$amount_category %in% c("High", "Low")))
})

# -----------------------------------------------------------------------------
# DATABASE INTEGRATION TESTS
# -----------------------------------------------------------------------------

test_that("Database connection and operations work correctly", {
  # Skip if database not available
  skip_if_not_installed("RSQLite")
  
  # Create in-memory database for testing
  con <- dbConnect(RSQLite::SQLite(), ":memory:")
  
  # Create test data
  test_data <- create_integration_test_data(n = 100)
  
  # Write data to database
  dbWriteTable(con, "transactions", test_data)
  
  # Test data retrieval
  retrieved_data <- dbGetQuery(con, "SELECT * FROM transactions LIMIT 10")
  expect_equal(nrow(retrieved_data), 10)
  expect_equal(ncol(retrieved_data), ncol(test_data))
  
  # Test complex queries
  query_result <- dbGetQuery(con, "
    SELECT category, COUNT(*) as count, AVG(amount) as avg_amount
    FROM transactions 
    WHERE amount IS NOT NULL
    GROUP BY category
    ORDER BY count DESC
  ")
  
  expect_true(nrow(query_result) > 0)
  expect_true(all(c("category", "count", "avg_amount") %in% names(query_result)))
  expect_true(all(!is.na(query_result$count)))
  
  # Cleanup
  dbDisconnect(con)
})

test_that("Database transaction handling works correctly", {
  skip_if_not_installed("RSQLite")
  
  con <- dbConnect(RSQLite::SQLite(), ":memory:")
  
  # Create table
  dbExecute(con, "
    CREATE TABLE test_transactions (
      id INTEGER PRIMARY KEY,
      amount REAL,
      category TEXT,
      transaction_date DATE
    )
  ")
  
  # Test transaction rollback
  tryCatch({
    dbBegin(con)
    
    # Insert valid data
    dbExecute(con, "INSERT INTO test_transactions (amount, category) VALUES (100.50, 'Food')")
    dbExecute(con, "INSERT INTO test_transactions (amount, category) VALUES (200.75, 'Transport')")
    
    # Insert invalid data (should cause error)
    dbExecute(con, "INSERT INTO test_transactions (amount, category) VALUES ('invalid', 'Test')")
    
    dbCommit(con)
  }, error = function(e) {
    dbRollback(con)
  })
  
  # Verify rollback worked
  result <- dbGetQuery(con, "SELECT COUNT(*) as count FROM test_transactions")
  expect_equal(result$count, 0)  # Should be empty due to rollback
  
  # Test successful transaction
  dbBegin(con)
  dbExecute(con, "INSERT INTO test_transactions (amount, category) VALUES (150.25, 'Food')")
  dbCommit(con)
  
  result <- dbGetQuery(con, "SELECT COUNT(*) as count FROM test_transactions")
  expect_equal(result$count, 1)
  
  dbDisconnect(con)
})

test_that("Database connection pooling works correctly", {
  skip_if_not_installed("RSQLite")
  skip_if_not_installed("pool")
  
  library(pool)
  
  # Create connection pool
  pool <- dbPool(
    drv = RSQLite::SQLite(),
    dbname = ":memory:",
    minSize = 1,
    maxSize = 5,
    idleTimeout = 3600000
  )
  
  # Test multiple connections
  results <- lapply(1:3, function(i) {
    dbGetQuery(pool, "SELECT 1 as test_col, ? as id", params = list(i))
  })
  
  expect_equal(length(results), 3)
  expect_equal(results[[1]]$test_col, 1)
  expect_equal(results[[2]]$id, 2)
  
  # Cleanup
  poolClose(pool)
})

# -----------------------------------------------------------------------------
# FILE SYSTEM INTEGRATION TESTS
# -----------------------------------------------------------------------------

test_that("File I/O operations work correctly", {
  # Create temporary directory
  temp_dir <- tempfile()
  dir.create(temp_dir)
  on.exit(unlink(temp_dir, recursive = TRUE), add = TRUE)
  
  # Create test data
  test_data <- create_integration_test_data(n = 50)
  
  # Test CSV writing and reading
  csv_file <- file.path(temp_dir, "test_data.csv")
  write.csv(test_data, csv_file, row.names = FALSE)
  
  expect_true(file.exists(csv_file))
  
  # Read data back
  read_data <- read.csv(csv_file)
  expect_equal(nrow(read_data), nrow(test_data))
  expect_equal(ncol(read_data), ncol(test_data))
  
  # Test RDS serialization
  rds_file <- file.path(temp_dir, "test_data.rds")
  saveRDS(test_data, rds_file)
  
  read_rds_data <- readRDS(rds_file)
  expect_equal(nrow(read_rds_data), nrow(test_data))
  expect_equal(class(read_rds_data), class(test_data))
})

test_that("Configuration file handling works correctly", {
  temp_dir <- tempfile()
  dir.create(temp_dir)
  on.exit(unlink(temp_dir, recursive = TRUE), add = TRUE)
  
  # Create mock configuration
  config <- list(
    database = list(
      host = "localhost",
      port = 5432,
      name = "test_db",
      user = "test_user"
    ),
    api = list(
      base_url = "https://api.example.com",
      timeout = 30,
      retry_attempts = 3
    ),
    processing = list(
      batch_size = 1000,
      parallel_workers = 4
    )
  )
  
  # Write configuration to JSON
  config_file <- file.path(temp_dir, "config.json")
  write(jsonlite::toJSON(config, auto_unbox = TRUE, pretty = TRUE), config_file)
  
  expect_true(file.exists(config_file))
  
  # Read configuration back
  read_config <- jsonlite::fromJSON(config_file)
  expect_equal(read_config$database$host, "localhost")
  expect_equal(read_config$api$timeout, 30)
  expect_equal(read_config$processing$batch_size, 1000)
})

# -----------------------------------------------------------------------------
# PARALLEL PROCESSING INTEGRATION TESTS
# -----------------------------------------------------------------------------

test_that("Parallel processing works correctly", {
  skip_if_not_installed("doFuture")
  library(doFuture)
  
  # Setup parallel backend
  plan(multisession, workers = 2)
  registerDoFuture()
  
  # Create test data
  test_data <- create_integration_test_data(n = 100)
  
  # Test parallel processing
  result <- foreach(i = 1:4, .combine = rbind) %dopar% {
    # Simulate expensive computation
    Sys.sleep(0.1)
    subset_data <- test_data[sample(1:nrow(test_data), 10), ]
    data.frame(
      iteration = i,
      mean_amount = mean(subset_data$amount, na.rm = TRUE),
      row_count = nrow(subset_data)
    )
  }
  
  expect_equal(nrow(result), 4)
  expect_true(all(result$iteration %in% 1:4))
  expect_true(all(result$row_count == 10))
  
  # Cleanup
  plan(sequential)
})

test_that("Future-based parallel processing works correctly", {
  # Test future_lapply
  test_function <- function(x) {
    sum_result <- sum(1:x)
    Sys.sleep(0.01)  # Simulate work
    return(sum_result)
  }
  
  # Sequential execution
  sequential_result <- lapply(1:5, test_function)
  
  # Parallel execution
  plan(multisession, workers = 2)
  parallel_result <- future_lapply(1:5, test_function)
  
  expect_equal(sequential_result, parallel_result)
  
  # Cleanup
  plan(sequential)
})

# -----------------------------------------------------------------------------
# ERROR RECOVERY AND RESILIENCE TESTS
# -----------------------------------------------------------------------------

test_that("System recovers from partial failures", {
  # Simulate partial data failure
  test_data <- create_integration_test_data(n = 100)
  
  # Introduce some corrupted data
  test_data$amount[sample(1:100, 5)] <- "corrupted"
  
  # Processing with error recovery
  process_with_recovery <- function(data) {
    results <- list()
    errors <- list()
    
    for (i in 1:nrow(data)) {
      tryCatch({
        row <- data[i, ]
        
        # Try to process amount
        amount <- as.numeric(as.character(row$amount))
        if (is.na(amount)) {
          stop(paste("Invalid amount in row", i))
        }
        
        # Process row
        processed_row <- data.frame(
          customer_id = row$customer_id,
          amount = amount,
          category = row$category,
          status = "processed"
        )
        
        results[[length(results) + 1]] <- processed_row
        
      }, error = function(e) {
        # Log error but continue processing
        errors[[length(errors) + 1]] <- list(
          row = i,
          error = e$message,
          original_data = data[i, ]
        )
      })
    }
    
    list(
      processed = do.call(rbind, results),
      errors = errors,
      success_rate = length(results) / nrow(data)
    )
  }
  
  result <- process_with_recovery(test_data)
  
  expect_true(length(result$processed) < nrow(test_data))  # Some should fail
  expect_true(length(result$errors) > 0)  # Should have errors
  expect_true(result$success_rate > 0.9)  # Most should succeed
  expect_true(all(result$processed$status == "processed"))
})

test_that("Retry mechanism works for transient failures", {
  # Simulate API with transient failures
  api_call_count <- 0
  
  mock_unreliable_api <- function() {
    api_call_count <<- api_call_count + 1
    
    # Fail first 2 times, succeed on 3rd
    if (api_call_count < 3) {
      stop("Temporary API failure")
    } else {
      return(list(status = "success", data = "test_data"))
    }
  }
  
  # Retry mechanism
  retry_operation <- function(operation, max_retries = 3, delay = 1) {
    for (attempt in 1:max_retries) {
      result <- tryCatch({
        operation()
      }, error = function(e) {
        if (attempt == max_retries) {
          stop(paste("Failed after", max_retries, "attempts:", e$message))
        }
        Sys.sleep(delay)
        NULL
      })
      
      if (!is.null(result)) {
        return(list(
          result = result,
          attempts = attempt,
          success = TRUE
        ))
      }
    }
  }
  
  result <- retry_operation(mock_unreliable_api)
  
  expect_true(result$success)
  expect_equal(result$attempts, 3)
  expect_equal(result$result$status, "success")
})

# -----------------------------------------------------------------------------
# PERFORMANCE INTEGRATION TESTS
# -----------------------------------------------------------------------------

test_that("Integration processes complete within reasonable time", {
  # Create larger dataset for performance testing
  large_data <- create_integration_test_data(n = 5000)
  
  # Measure processing time
  processing_time <- system.time({
    result <- large_data %>%
      mutate(
        amount = ifelse(is.na(amount), 0, amount),
        transaction_month = format(transaction_date, "%Y-%m")
      ) %>%
      group_by(customer_id, transaction_month) %>%
      summarise(
        total_amount = sum(amount),
        transaction_count = n(),
        .groups = "drop"
      )
  })
  
  # Should complete within reasonable time (adjust based on system)
  expect_true(processing_time["elapsed"] < 10)  # 10 seconds max
  expect_true(nrow(result) > 0)
  expect_true(all(!is.na(result$total_amount)))
})

test_that("Memory usage stays within reasonable bounds", {
  # Create moderately large dataset
  test_data <- create_integration_test_data(n = 10000)
  
  # Measure initial memory
  initial_memory <- gc()[2, 2]  # Used MB
  
  # Process data
  result <- test_data %>%
    mutate(
      amount_category = case_when(
        amount < 50 ~ "Small",
        amount < 200 ~ "Medium",
        amount < 500 ~ "Large",
        TRUE ~ "Extra Large"
      )
    ) %>%
    group_by(amount_category) %>%
    summarise(
      count = n(),
      total_amount = sum(amount, na.rm = TRUE),
      avg_amount = mean(amount, na.rm = TRUE),
      .groups = "drop"
    )
  
  # Measure final memory
  final_memory <- gc()[2, 2]
  memory_increase <- final_memory - initial_memory
  
  # Memory increase should be reasonable (less than 100MB for this operation)
  expect_true(memory_increase < 100)
  expect_equal(nrow(result), 4)  # Should have 4 categories
})

# Print summary
cat("Integration test suite created successfully!\n")
cat("Components included:\n")
cat("- Data pipeline integration tests\n")
cat("- API integration tests with mocking\n")
cat("- Database integration tests\n")
cat("- File system integration tests\n")
cat("- Parallel processing integration tests\n")
cat("- Error recovery and resilience tests\n")
cat("- Performance integration tests\n")
cat("Total tests: ", testthat:::count_tests(), "\n")