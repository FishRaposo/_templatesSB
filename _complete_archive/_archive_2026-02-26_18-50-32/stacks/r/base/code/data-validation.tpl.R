# File: data-validation.tpl.R
# Purpose: Data validation utilities using 'validate' package
# Generated for: {{PROJECT_NAME}}

library(validate)
library(logger)

#' Validate a data frame against a set of rules
#'
#' @param data The data frame to validate
#' @param strict Boolean, whether to stop execution on failure
#' @return The validated data frame or throws error
validate_dataset <- function(data, strict = FALSE) {
  # Define validation rules
  rules <- validator(
    is.numeric(amount),
    amount >= 0,
    is.character(id),
    !is.na(email)
  )
  
  # Check data against rules
  results <- confront(data, rules)
  summary_stats <- summary(results)
  
  # Log validation summary
  log_info("Validation complete. Passes: {summary_stats$passes}, Fails: {summary_stats$fails}")
  
  if (any(summary_stats$fails > 0)) {
    failed_rules <- summary_stats[summary_stats$fails > 0, ]
    log_warn("Validation failed for some records: {jsonlite::toJSON(failed_rules)}")
    
    if (strict) {
      stop("Data validation failed. See logs for details.")
    }
  }
  
  return(data)
}

#' Example usage
example_validation <- function() {
  df <- data.frame(
    id = c("1", "2", "3"),
    amount = c(100, -50, 200),
    email = c("a@b.com", NA, "c@d.com")
  )
  
  tryCatch({
    validate_dataset(df)
  }, error = function(e) {
    log_error("Validation routine error: {e$message}")
  })
}
