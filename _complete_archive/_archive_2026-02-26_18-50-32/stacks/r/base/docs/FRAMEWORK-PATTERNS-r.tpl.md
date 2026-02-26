<!--
File: FRAMEWORK-PATTERNS-r.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# R Framework Patterns - {{PROJECT_NAME}}

**Tier**: {{TIER}} | **Stack**: R

## 📊 R's Role in Your Ecosystem

R serves as the **data analysis and statistical computing layer** - your "analyze data, build models, and generate insights" powerhouse. It handles data processing, statistical analysis, machine learning, and visualization.

### **Core Responsibilities**
- **Data Processing**: Data cleaning, transformation, and manipulation
- **Statistical Analysis**: Hypothesis testing, regression, and advanced statistics
- **Machine Learning**: Model training, evaluation, and deployment
- **Data Visualization**: Advanced plotting and visualization
- **Reproducible Research**: Literate programming with R Markdown

## 🏗️ Three Pillars Integration

### **1. Universal Principles Applied to R**
- **Clean Architecture**: Modular script organization
- **Dependency Management**: Package management with renv
- **Testing Strategy**: Unit testing with testthat
- **Configuration Management**: Environment-specific settings

### **2. Tier-Specific R Patterns**

#### **MVP Tier - Data Exploration**
**Purpose**: Quick data analysis and visualization
**Characteristics**:
- Simple data loading and cleaning
- Basic statistical analysis
- Simple visualizations
- Minimal testing
- Interactive exploration

**When to Use**:
- Data exploration and prototyping
- Quick analysis tasks
- Learning R fundamentals
- Ad-hoc data investigations

**MVP R Pattern**:
```r
# Load required packages
library(tidyverse)
library(ggplot2)

# Load data
data <- read_csv("data.csv")

# Basic data exploration
summary(data)
str(data)

# Simple visualization
ggplot(data, aes(x = variable1, y = variable2)) +
  geom_point() +
  ggtitle("Simple Scatter Plot")

# Basic statistical analysis
t_test_result <- t.test(data$group1, data$group2)
print(t_test_result)
```

#### **CORE Tier - Production Analysis**
**Purpose**: Real-world data analysis with proper structure
**Characteristics**:
- Modular script organization
- Comprehensive data processing
- Advanced statistical methods
- Professional visualizations
- Reproducible workflows
- Unit testing

**When to Use**:
- Production data analysis
- Research projects
- Business intelligence
- Data-driven decision making

**CORE R Pattern**:
```r
# Load required packages
library(tidyverse)
library(ggplot2)
library(testthat)
library(renv)

# Data processing module
process_data <- function(raw_data) {
  data <- raw_data %>%
    filter(!is.na(important_variable)) %>%
    mutate(
      derived_variable = calculate_derived_value(important_variable),
      category = case_when(
        variable1 > 100 ~ "High",
        variable1 > 50 ~ "Medium",
        TRUE ~ "Low"
      )
    ) %>%
    select(id, important_variable, derived_variable, category)
  
  return(data)
}

# Analysis module
analyze_data <- function(processed_data) {
  # Statistical analysis
  model <- lm(outcome ~ predictor1 + predictor2, data = processed_data)
  
  # Visualization
  plot <- ggplot(processed_data, aes(x = predictor1, y = outcome, color = category)) +
    geom_point() +
    geom_smooth(method = "lm") +
    theme_minimal()
  
  return(list(model = model, plot = plot))
}

# Main analysis workflow
main <- function() {
  # Load data
  raw_data <- read_csv("data/raw_data.csv")
  
  # Process data
  processed_data <- process_data(raw_data)
  
  # Analyze data
  results <- analyze_data(processed_data)
  
  # Save results
  write_rds(results$model, "results/model.rds")
  ggsave("results/plot.png", results$plot, width = 8, height = 6)
  
  return(results)
}

# Unit tests
test_that("data processing works correctly", {
  test_data <- tibble(
    id = 1:10,
    important_variable = c(1:5, NA, 6:10),
    variable1 = 1:10 * 10
  )
  
  processed <- process_data(test_data)
  
  expect_equal(nrow(processed), 9) # NA should be filtered out
  expect_true(all(!is.na(processed$important_variable)))
})
```

#### **FULL Tier - Enterprise Data Science**
**Purpose**: Large-scale data analysis with enterprise requirements
**Characteristics**:
- Advanced modular architecture
- Comprehensive testing suite
- Performance optimization
- Parallel processing
- Advanced machine learning
- Production deployment
- Comprehensive documentation

**When to Use**:
- Enterprise data science projects
- Large-scale data analysis
- Production machine learning
- Research with high reproducibility requirements

**FULL R Pattern**:
```r
# Load required packages
library(tidyverse)
library(ggplot2)
library(testthat)
library(renv)
library(future)
library(mlr3)
library(plumber)
library(targets)

# Configuration management
Config <- R6::R6Class("Config",
  public = list(
    environment = NULL,
    data_path = NULL,
    results_path = NULL,
    
    initialize = function(env = "development") {
      self$environment <- env
      self$data_path <- file.path("data", env)
      self$results_path <- file.path("results", env)
      
      # Create directories if they don't exist
      dir.create(self$data_path, showWarnings = FALSE)
      dir.create(self$results_path, showWarnings = FALSE)
    },
    
    get_data_path = function(filename) {
      return(file.path(self$data_path, filename))
    },
    
    get_results_path = function(filename) {
      return(file.path(self$results_path, filename))
    }
  )
)

# Data processing with parallel processing
process_data_parallel <- function(raw_data, n_cores = 4) {
  plan(multisession, workers = n_cores)
  
  processed_data <- raw_data %>%
    future_group_by(group_variable) %>%
    future_do(
      mutate(
        derived_variable = future_apply(
          important_variable, 
          1, 
          calculate_complex_derived_value
        ),
        category = future_case_when(
          variable1 > 100 ~ "High",
          variable1 > 50 ~ "Medium",
          TRUE ~ "Low"
        )
      )
    ) %>%
    future_ungroup()
  
  return(processed_data)
}

# Advanced machine learning pipeline
create_ml_pipeline <- function() {
  # Define task
  task <- mlr3::TaskClassif$new(
    id = "classification_task",
    backend = as.data.table(processed_data),
    target = "outcome"
  )
  
  # Define learner
  learner <- mlr3::lrn(
    "classif.ranger",
    num.trees = 500,
    mtry = 10,
    importance = "impurity"
  )
  
  # Define resampling
  resampling <- mlr3::rsmp("cv", folds = 5)
  
  # Define measure
  measure <- mlr3::msr("classif.auc")
  
  # Create pipeline
  pipeline <- mlr3pipelines::Pipeline$new(
    task = task,
    learner = learner,
    resampling = resampling,
    measures = measure
  )
  
  return(pipeline)
}

# Advanced visualization with interactivity
create_interactive_plot <- function(data) {
  plot <- ggplot(data, aes(x = predictor1, y = outcome, color = category)) +
    geom_point(alpha = 0.6) +
    geom_smooth(method = "loess", se = FALSE) +
    facet_wrap(~group_variable) +
    theme_minimal() +
    theme(legend.position = "bottom")
  
  # Add interactivity with plotly
  interactive_plot <- plotly::ggplotly(plot) %>%
    plotly::layout(
      title = "Interactive Data Visualization",
      xaxis = list(title = "Predictor Variable"),
      yaxis = list(title = "Outcome Variable")
    )
  
  return(interactive_plot)
}

# API endpoint for model predictions
#* @post /predict
predict_endpoint <- function(req, res) {
  # Parse request
  input_data <- plumber::req_post_body_json(req)
  
  # Validate input
  if (is.null(input_data$features)) {
    return(res$status <- 400)
  }
  
  # Make prediction
  prediction <- predict(model, newdata = as.data.frame(input_data$features))
  
  # Return result
  list(
    prediction = as.character(prediction),
    confidence = as.numeric(prediction$probabilities[1]),
    timestamp = as.character(Sys.time())
  )
}

# Main analysis workflow with targets
# _targets.R
tar_option_set(
  packages = c("tidyverse", "ggplot2", "mlr3", "future"),
  format = "rds"
)

list(
  tar_target(raw_data, read_csv(config$get_data_path("raw_data.csv"))),
  tar_target(processed_data, process_data_parallel(raw_data)),
  tar_target(analysis_results, analyze_data(processed_data)),
  tar_target(ml_pipeline, create_ml_pipeline()),
  tar_target(final_report, create_report(analysis_results, ml_pipeline))
)

# Comprehensive testing suite
test_that("data processing handles edge cases", {
  # Test NA handling
  test_data_na <- tibble(
    id = 1:10,
    important_variable = rep(NA, 10),
    variable1 = 1:10 * 10
  )
  
  expect_error(process_data(test_data_na), "No non-missing values")
  
  # Test empty data
  expect_error(process_data(tibble()), "Empty data")
})

test_that("machine learning pipeline works correctly", {
  # Create test data
  test_data <- tibble(
    outcome = factor(rep(c("A", "B"), each = 50)),
    predictor1 = rnorm(100),
    predictor2 = rnorm(100)
  )
  
  # Test pipeline creation
  pipeline <- create_ml_pipeline(test_data)
  expect_is(pipeline, "Pipeline")
  
  # Test pipeline execution
  results <- pipeline$train()
  expect_true(results$score > 0.5)
})
```

## 📦 Blessed Patterns (Never Deviate)

### **Data Processing: Tidyverse**
**Why**: Consistent, readable, and efficient data manipulation

**Tidyverse Patterns**:
```r
# MVP: Basic data processing
processed_data <- raw_data %>%
  filter(!is.na(important_variable)) %>%
  mutate(derived = variable1 * 2) %>%
  select(id, important_variable, derived)

# CORE: Advanced data processing
processed_data <- raw_data %>%
  filter(
    !is.na(important_variable) &
    variable2 > threshold_value
  ) %>%
  group_by(group_variable) %>%
  mutate(
    derived_variable = calculate_derived_value(important_variable),
    category = case_when(
      variable1 > 100 ~ "High",
      variable1 > 50 ~ "Medium",
      TRUE ~ "Low"
    )
  ) %>%
  ungroup() %>%
  select(id, group_variable, important_variable, derived_variable, category)

# FULL: Performance-optimized data processing
processed_data <- raw_data %>%
  data.table() %>%  # Convert to data.table for performance
  .[!is.na(important_variable) & variable2 > threshold_value] %>%
  .[, derived_variable := calculate_derived_value(important_variable), by = group_variable] %>%
  .[, category := fifelse(variable1 > 100, "High", 
                         fifelse(variable1 > 50, "Medium", "Low"))] %>%
  .[order(group_variable, important_variable)]
```

### **Visualization: ggplot2**
**Why**: Professional, publication-quality visualizations

**ggplot2 Patterns**:
```r
# MVP: Simple visualization
simple_plot <- ggplot(data, aes(x = variable1, y = variable2)) +
  geom_point() +
  ggtitle("Simple Scatter Plot")

# CORE: Professional visualization
professional_plot <- ggplot(data, aes(x = predictor, y = outcome, color = category)) +
  geom_point(alpha = 0.7, size = 3) +
  geom_smooth(method = "lm", se = TRUE, color = "black") +
  scale_color_brewer(palette = "Set1") +
  theme_minimal() +
  theme(
    plot.title = element_text(hjust = 0.5, face = "bold"),
    axis.title = element_text(size = 12),
    legend.position = "bottom"
  ) +
  labs(
    title = "Relationship Between Predictor and Outcome by Category",
    x = "Predictor Variable",
    y = "Outcome Variable",
    color = "Category"
  )

# FULL: Advanced visualization with interactivity
advanced_plot <- ggplot(data, aes(x = date, y = value, color = group)) +
  geom_line(linewidth = 1) +
  geom_point(size = 2, alpha = 0.6) +
  facet_wrap(~category, scales = "free_y") +
  scale_color_viridis_d() +
  theme_minimal() +
  theme(
    strip.text = element_text(size = 10, face = "bold"),
    legend.position = "bottom",
    panel.grid.major.x = element_line(color = "gray90")
  ) +
  labs(
    title = "Time Series Analysis by Group and Category",
    subtitle = "Interactive visualization with plotly",
    x = "Date",
    y = "Value",
    color = "Group"
  )

# Convert to interactive plotly
interactive_plot <- plotly::ggplotly(advanced_plot) %>%
  plotly::layout(
    hovermode = "closest",
    xaxis = list(title = "Date"),
    yaxis = list(title = "Value")
  ) %>%
  plotly::config(displayModeBar = TRUE)
```

### **Machine Learning: mlr3**
**Why**: Unified interface for machine learning

**mlr3 Patterns**:
```r
# MVP: Simple machine learning
simple_model <- lm(outcome ~ predictor1 + predictor2, data = training_data)
predictions <- predict(simple_model, newdata = test_data)

# CORE: mlr3 pipeline
library(mlr3)
library(mlr3learners)
library(mlr3tuning)

# Define task
task <- TaskClassif$new(
  id = "classification_task",
  backend = as.data.table(training_data),
  target = "outcome"
)

# Define learner
learner <- lrn("classif.ranger", 
               num.trees = 200, 
               mtry = 5)

# Define resampling
resampling <- rsmp("cv", folds = 5)

# Train and evaluate
result <- resample(task, learner, resampling, 
                  measures = msr("classif.auc"))

# Get best model
best_model <- result$aggregate()

# FULL: Advanced mlr3 pipeline with tuning
advanced_pipeline <- function() {
  # Define task
  task <- TaskClassif$new(
    id = "advanced_classification",
    backend = as.data.table(training_data),
    target = "outcome"
  )
  
  # Define search space
  search_space <- ps(
    num.trees = p_int(lower = 100, upper = 1000),
    mtry = p_int(lower = 2, upper = 10),
    min.node.size = p_int(lower = 1, upper = 10)
  )
  
  # Define tuner
  tuner <- tnr("random_search", batch_size = 10)
  
  # Define auto-tuner
  auto_tuner <- auto_tuner(
    tuner = tuner,
    learner = lrn("classif.ranger"),
    resampling = rsmp("holdout"),
    measure = msr("classif.auc"),
    term_evals = term("evals", n_evals = 50)
  )
  
  # Tune model
  tune_result <- auto_tuner$optimize(task, search_space)
  
  # Get best model
  best_model <- tune_result$result_y
  
  # Train final model on full data
  final_model <- auto_tuner$train(task, tune_result$archive$best())
  
  return(list(
    model = final_model,
    tuning_results = tune_result,
    performance = auto_tuner$assess(task, resampling = rsmp("cv", folds = 10))
  ))
}
```

## 🧪 Testing Strategy by Tier

### **MVP Testing**
- Basic functionality testing
- Simple data validation
- Manual testing of visualizations

### **CORE Testing**
- Unit tests for functions
- Data validation tests
- Visualization output tests
- Performance benchmarks

### **FULL Testing**
- All CORE tests plus:
- Integration tests
- Performance tests
- Memory usage tests
- Reproducibility tests

**Testing Patterns**:
```r
# MVP: Simple test
test_that("data loading works", {
  data <- load_data("test_data.csv")
  expect_equal(nrow(data), 100)
  expect_equal(ncol(data), 5)
})

# CORE: Comprehensive testing
library(testthat)

context("Data Processing")

test_that("process_data handles missing values correctly", {
  test_data <- tibble(
    id = 1:10,
    important_variable = c(1:5, NA, 6:10),
    variable1 = 1:10 * 10
  )
  
  processed <- process_data(test_data)
  
  expect_equal(nrow(processed), 9) # NA should be filtered out
  expect_true(all(!is.na(processed$important_variable)))
  expect_true("derived_variable" %in% names(processed))
})

test_that("process_data creates correct categories", {
  test_data <- tibble(
    id = 1:10,
    important_variable = 1:10,
    variable1 = c(150, 75, 25, 120, 80, 30, 110, 60, 40, 90)
  )
  
  processed <- process_data(test_data)
  
  expect_equal(sum(processed$category == "High"), 4)
  expect_equal(sum(processed$category == "Medium"), 3)
  expect_equal(sum(processed$category == "Low"), 3)
})

# FULL: Advanced testing with mocking
context("Machine Learning Pipeline")

test_that("ml pipeline handles edge cases", {
  # Create mock data
  mock_data <- mockery::mock()
  
  when(mock_data$get_data()) %>% then_return(tibble(
    outcome = factor(rep(c("A", "B"), each = 50)),
    predictor1 = rnorm(100),
    predictor2 = rnorm(100)
  ))
  
  # Test pipeline with mock data
  pipeline <- create_ml_pipeline(mock_data$get_data())
  
  expect_is(pipeline$model, "LearnerClassif")
  expect_true(pipeline$performance$score > 0.5)
})

test_that("visualization functions work correctly", {
  test_data <- tibble(
    x = 1:10,
    y = 1:10 * 2,
    group = rep(c("A", "B"), each = 5)
  )
  
  plot <- create_scatter_plot(test_data)
  
  expect_is(plot, "ggplot")
  expect_true("x" %in% names(plot$data))
  expect_true("y" %in% names(plot$data))
})
```

## 📊 Performance Optimization

### **Data Processing Performance**
```r
# MVP: Basic performance
system.time({
  processed_data <- raw_data %>%
    filter(!is.na(important_variable)) %>%
    mutate(derived = variable1 * 2)
})

# CORE: Performance optimization
system.time({
  processed_data <- raw_data %>%
    data.table() %>%  # Convert to data.table
    .[!is.na(important_variable)] %>%
    .[, derived := variable1 * 2]
})

# FULL: Parallel processing
library(future)
library(doFuture)

# Set up parallel backend
plan(multisession, workers = 4)
registerDoFuture()

system.time({
  processed_data <- raw_data %>%
    future_group_by(group_variable) %>%
    future_do(
      mutate(
        derived = future_apply(variable1, 1, complex_calculation),
        category = future_case_when(
          variable1 > 100 ~ "High",
          variable1 > 50 ~ "Medium",
          TRUE ~ "Low"
        )
      )
    ) %>%
    future_ungroup()
})
```

### **Memory Optimization**
```r
# MVP: Basic memory usage
object.size(raw_data)

# CORE: Memory optimization
# Use appropriate data types
optimized_data <- raw_data %>%
  mutate(
    across(where(is.character), as.factor),
    across(where(is.numeric), function(x) ifelse(is.whole(x), as.integer(x), x))
  )

# FULL: Advanced memory management
# Use data.table for large datasets
dt_data <- as.data.table(raw_data)
setkey(dt_data, id)  # Set key for fast joins

# Use fst for fast serialization
library(fst)
write_fst(dt_data, "data.fst")
read_fst("data.fst")

# Memory profiling
library(profmem)
profmem({
  large_data <- read_csv("large_data.csv")
  processed <- process_data(large_data)
})
```

## 🔗 Integration Patterns

### **Database Integration**
```r
# MVP: Simple database connection
library(DBI)
library(RPostgres)

con <- dbConnect(RPostgres::Postgres(),
                 dbname = "mydatabase",
                 host = "localhost",
                 user = "myuser",
                 password = "mypassword")

data <- dbGetQuery(con, "SELECT * FROM mytable")
dbDisconnect(con)

# CORE: Database integration with pooling
library(pool)

pool <- dbPool(
  drv = RPostgres::Postgres(),
  dbname = "mydatabase",
  host = "localhost",
  user = "myuser",
  password = "mypassword",
  maxSize = 10
)

data <- pool %>%
  tbl("mytable") %>%
  collect()

poolClose(pool)

# FULL: Advanced database integration
library(dbplyr)
library(odbc)

con <- dbConnect(odbc::odbc(),
                 driver = "PostgreSQL",
                 database = "mydatabase",
                 uid = "myuser",
                 pwd = "mypassword",
                 host = "localhost")

# Use dbplyr for database operations
remote_data <- tbl(con, "mytable") %>%
  filter(!is.na(important_variable)) %>%
  mutate(derived = important_variable * 2) %>%
  select(id, important_variable, derived) %>%
  collect()

dbDisconnect(con)
```

### **API Integration**
```r
# MVP: Simple API call
library(httr)

response <- GET("https://api.example.com/data")
data <- content(response, "parsed")

# CORE: API integration with error handling
api_call <- function(endpoint, params = list()) {
  tryCatch({
    response <- GET(
      url = endpoint,
      query = params,
      add_headers("Authorization" = Sys.getenv("API_KEY")),
      timeout(10)
    )
    
    if (http_status(response)$category == "Success") {
      return(content(response, "parsed"))
    } else {
      warning(paste("API call failed:", http_status(response)$message))
      return(NULL)
    }
  }, error = function(e) {
    warning(paste("API call error:", e$message))
    return(NULL)
  })
}

# FULL: Advanced API integration
library(httr2)
library(jsonlite)

# Create request with retry logic
get_api_data <- function(endpoint, max_retries = 3) {
  for (i in 1:max_retries) {
    tryCatch({
      request <- request(endpoint) %>%
        req_url_query(list(api_key = Sys.getenv("API_KEY"))) %>%
        req_timeout(10) %>%
        req_retry("transient", max_tries = 3)
      
      response <- req_perform(request)
      
      if (resp_is_error(response)) {
        warning(paste("Attempt", i, "failed:", resp_status_desc(response)))
        if (i == max_retries) {
          stop("Max retries reached")
        }
        Sys.sleep(2^i)  # Exponential backoff
      } else {
        data <- resp_body_json(response)
        return(data)
      }
    }, error = function(e) {
      warning(paste("Attempt", i, "error:", e$message))
      if (i == max_retries) {
        stop("Max retries reached")
      }
      Sys.sleep(2^i)
    })
  }
}
```

## 📈 Reproducible Research

### **R Markdown**
```r
# MVP: Simple R Markdown document
---
title: "Simple Analysis"
author: "Researcher"
date: "`r Sys.Date()`"
output: html_document
---

```{r setup, include=FALSE}
knitr::opts_chunk$set(echo = TRUE)
library(tidyverse)
```

```{r load-data}
data <- read_csv("data.csv")
summary(data)
```

```{r analysis}
model <- lm(outcome ~ predictor, data = data)
summary(model)
```

# CORE: Professional R Markdown report
---
title: "Comprehensive Data Analysis"
author: "Research Team"
date: "`r format(Sys.time(), '%B %d, %Y')`"
output:
  html_document:
    toc: true
    toc_float: true
    theme: cosmo
    highlight: tango
  pdf_document:
    toc: true
    number_sections: true
---

```{r setup, include=FALSE}
knitr::opts_chunk$set(
  echo = TRUE,
  warning = FALSE,
  message = FALSE,
  fig.width = 8,
  fig.height = 6,
  cache = TRUE
)

library(tidyverse)
library(ggplot2)
library(knitr)
library(kableExtra)
```

```{r load-and-process}
data <- read_csv("data/raw_data.csv") %>%
  filter(!is.na(important_variable)) %>%
  mutate(derived = variable1 * 2)

# Display processed data summary
data %>%
  summary() %>%
  kable() %>%
  kable_styling(bootstrap_options = c("striped", "hover"))
```

```{r analysis-and-visualization}
# Statistical analysis
model <- lm(outcome ~ predictor1 + predictor2, data = data)
model_summary <- summary(model)

# Visualization
plot <- ggplot(data, aes(x = predictor1, y = outcome)) +
  geom_point() +
  geom_smooth(method = "lm") +
  theme_minimal()

plot

# Model summary table
model_summary$coefficients %>%
  as.data.frame() %>%
  kable(digits = 4) %>%
  kable_styling()
```

# FULL: Advanced reproducible research with targets
---
title: "Advanced Reproducible Research"
author: "Research Team"
date: "`r format(Sys.time(), '%B %d, %Y')`"
output:
  html_document:
    toc: true
    toc_float: true
    code_folding: hide
    theme: journal
  pdf_document:
    toc: true
    number_sections: true
    fig_width: 7
    fig_height: 5
---

```{r setup, include=FALSE}
knitr::opts_chunk$set(
  echo = FALSE,
  warning = FALSE,
  message = FALSE,
  cache = TRUE,
  autodep = TRUE
)

# Load targets pipeline
source("_targets.R")

# Set up parallel processing
library(future)
plan(multisession, workers = 4)
```

```{r targets-pipeline}
# Run targets pipeline
tar_make()

# Load results
tar_load(final_report)
```

```{r results-visualization}
# Interactive visualization
final_report$visualization

# Model performance summary
final_report$performance %>%
  kable(digits = 3) %>%
  kable_styling(full_width = FALSE)
```

```{r conclusions}
# Conclusions and recommendations
final_report$conclusions
```
```

## 🚀 Best Practices Summary

### **MVP Best Practices**
- Keep analysis simple and focused
- Use basic visualizations
- Manual testing and validation
- Simple R Markdown reports

### **CORE Best Practices**
- Modular script organization
- Comprehensive data processing
- Professional visualizations
- Unit testing
- Reproducible workflows

### **FULL Best Practices**
- Advanced modular architecture
- Parallel processing
- Comprehensive testing suite
- Performance optimization
- Production deployment
- Advanced reproducible research

---*R Framework Patterns - Use this as your canonical reference for all R data analysis and research*
