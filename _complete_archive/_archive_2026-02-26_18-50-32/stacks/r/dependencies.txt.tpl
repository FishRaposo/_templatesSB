# R Stack Dependencies Template
# Complete package management and configuration for R projects

# Install packages from CRAN
cran_packages <- c(
  # Core Data Science
  "dplyr",
  "tidyr", 
  "purrr",
  "readr",
  "stringr",
  "forcats",
  "tibble",
  "ggplot2",
  
  # Data Manipulation
  "data.table",
  "lubridate",
  "readxl",
  "jsonlite",
  "httr2",
  
  # Statistical Analysis
  "stats",
  "broom",
  "infer",
  "modelr",
  
  # Machine Learning
  "caret",
  "randomForest",
  "xgboost",
  "e1071",
  "glmnet",
  
  # Visualization
  "plotly",
  "leaflet",
  "ggvis",
  "shiny",
  "shinydashboard",
  
  # Time Series
  "forecast",
  "tsibble",
  "feasts",
  
  # Reporting
  "rmarkdown",
  "knitr",
  "bookdown",
  
  # Testing
  "testthat",
  "assertthat",
  "checkmate",
  
  # Utilities
  "magrittr",
  "rlang",
  "glue",
  "logger"
)

# Install CRAN packages
install.packages(cran_packages, repos = "https://cloud.r-project.org/")

# Install packages from Bioconductor (if needed)
if (!require("BiocManager")) install.packages("BiocManager", repos = "https://cloud.r-project.org/")
BiocManager::install(c("Biobase"))

# Install development tools
install.packages(c("devtools", "renv"), repos = "https://cloud.r-project.org/")

# Initialize renv
renv::init()

cat("R dependencies installation script created successfully\n")
cat("Run this script in R to install all dependencies\n")
