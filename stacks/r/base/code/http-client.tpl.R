# File: http-client.tpl.R
# Purpose: HTTP client wrapper using 'httr2'
# Generated for: {{PROJECT_NAME}}

library(httr2)
library(logger)

#' Create a base request with standard headers and retry policy
#'
#' @param base_url Base URL for the API
#' @return httr2 request object
create_api_client <- function(base_url) {
  request(base_url) %>%
    req_headers(
      "User-Agent" = "{{PROJECT_NAME}}/1.0.0",
      "Accept" = "application/json"
    ) %>%
    req_retry(
      max_tries = 3,
      backoff = ~ 2^.x
    ) %>%
    req_timeout(30)
}

#' Perform a GET request and parse JSON response
#'
#' @param client httr2 request object
#' @param path Endpoint path
#' @return Parsed list or error
api_get <- function(client, path) {
  req <- client %>% req_url_path_append(path)
  
  resp <- tryCatch({
    req_perform(req)
  }, error = function(e) {
    log_error("HTTP Request failed: {e$message}")
    stop(e)
  })
  
  if (resp_status(resp) >= 400) {
    log_error("API Error: {resp_status(resp)}")
    stop(paste("API Error:", resp_status(resp)))
  }
  
  resp %>% resp_body_json()
}

#' Example usage
example_http_usage <- function() {
  client <- create_api_client("https://api.example.com")
  data <- api_get(client, "users/1")
  print(data)
}
