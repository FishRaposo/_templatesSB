# File: logging-utilities.tpl.R
# Purpose: Logging setup using 'log4r'
# Generated for: {{PROJECT_NAME}}

library(log4r)

#' Initialize Logger
#'
#' @param log_file Path to log file
#' @param level Log level (DEBUG, INFO, WARN, ERROR)
#' @return Logger object
init_logger <- function(log_file = "app.log", level = "INFO") {
  
  # Console appender
  console_appender <- console_appender(layout = default_log_layout())
  
  # File appender
  file_appender <- file_appender(log_file, append = TRUE, layout = default_log_layout())
  
  logger <- logger(
    threshold = level,
    appenders = list(console_appender, file_appender)
  )
  
  return(logger)
}

#' Global Logger Instance (Singleton patternish)
global_logger <- init_logger()

#' Helper functions for logging
log_info <- function(msg) {
  log4r::info(global_logger, msg)
}

log_error <- function(msg) {
  log4r::error(global_logger, msg)
}

log_warn <- function(msg) {
  log4r::warn(global_logger, msg)
}

log_debug <- function(msg) {
  log4r::debug(global_logger, msg)
}
