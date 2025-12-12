# File: testing-utilities.tpl.R
# Purpose: Test helpers using 'testthat'
# Generated for: {{PROJECT_NAME}}

library(testthat)

#' Setup test environment
#'
#' @return NULL
setup_tests <- function() {
  Sys.setenv(R_TESTING = "true")
}

#' Custom expectation: Assert numeric value is within range
#'
#' @param object Value to check
#' @param min Minimum value
#' @param max Maximum value
expect_in_range <- function(object, min, max) {
  act <- quasi_label(enquo(object), arg = "object")
  
  if (!is.numeric(act$val)) {
    fail(sprintf("%s is not numeric", act$lab))
  }
  
  if (act$val < min || act$val > max) {
    fail(sprintf("%s is %f, expected between %f and %f", act$lab, act$val, min, max))
  }
  
  succeed()
}

#' Example Test Suite
#'
#' @return NULL
run_example_tests <- function() {
  test_that("Math works", {
    expect_equal(1 + 1, 2)
    expect_in_range(5, 0, 10)
  })
}
