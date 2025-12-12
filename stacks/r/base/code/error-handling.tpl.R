# File: error-handling.tpl.R
# Purpose: Centralized error handling helpers
# Generated for: {{PROJECT_NAME}}

library(logger)

#' Execute a block of code with standardized error handling
#'
#' @param expr Expression to evaluate
#' @param context String describing the context
#' @param on_error Function to call on error (optional)
#' @return Result of expression or NULL on error
safe_execute <- function(expr, context = "Unknown Context", on_error = NULL) {
  tryCatch({
    log_info("Starting: {context}")
    result <- expr
    log_info("Completed: {context}")
    return(result)
  }, error = function(e) {
    log_error("Error in {context}: {e$message}")
    if (!is.null(on_error)) {
      on_error(e)
    }
    return(NULL)
  }, warning = function(w) {
    log_warn("Warning in {context}: {w$message}")
    # Warnings usually don't stop execution in R, but we might want to return NULL depending on strictness
    invokeRestart("muffleWarning")
  })
}

#' Custom Error Class
#' 
#' @param message Error message
#' @param code Error code
#' @return Error object
AppError <- function(message, code = "INTERNAL_ERROR") {
  structure(
    list(message = message, code = code),
    class = c("AppError", "error", "condition")
  )
}

#' Throw an AppError
#'
#' @param message Error message
#' @param code Error code
stop_with_code <- function(message, code = "INTERNAL_ERROR") {
  stop(AppError(message, code))
}
