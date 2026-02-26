task_trace_path <- function() {
  p <- Sys.getenv('TASK_TRACE_PATH')
  if (nchar(p) == 0) {
    return(file.path('artifacts', 'task-trace.jsonl'))
  }
  p
}

.task_trace_write <- function(ev) {
  p <- task_trace_path()
  dir.create(dirname(p), recursive = TRUE, showWarnings = FALSE)
  if (is.null(ev$ts)) {
    ev$ts <- as.numeric(Sys.time())
  }
  line <- NULL
  if (requireNamespace('jsonlite', quietly = TRUE)) {
    line <- jsonlite::toJSON(ev, auto_unbox = TRUE, null = 'null')
  } else {
    line <- paste0('{"task_id":', dQuote(ev$task_id), ',"type":', dQuote(ev$type), ',"ts":', ev$ts, '}')
  }
  cat(paste0(line, "\n"), file = p, append = TRUE)
}

task_trace_emit <- function(task_id, type, name = NULL, key = NULL, table = NULL, keys = NULL, value = NULL, fields = NULL) {
  ev <- list(task_id = task_id, type = type)
  if (!is.null(name)) ev$name <- name
  if (!is.null(key)) ev$key <- key
  if (!is.null(table)) ev$table <- table
  if (!is.null(keys)) ev$keys <- keys
  if (!is.null(value)) ev$value <- value
  if (!is.null(fields)) {
    for (k in names(fields)) {
      ev[[k]] <- fields[[k]]
    }
  }
  .task_trace_write(ev)
}
