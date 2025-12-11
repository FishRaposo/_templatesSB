# ----------------------------------------------------------------------------- 
# FILE: dependencies.txt.tpl
# PURPOSE: Generic dependency management template for any technology stack
# USAGE: Adapt this template for your specific technology stack
# AUTHOR: [[.Author]]
# VERSION: [[.Version]]
# SINCE: [[.Version]]
# -----------------------------------------------------------------------------

# Generic Dependencies Template
# This file serves as a starting point for managing dependencies in any technology stack.
# Adapt the sections below to match your specific package manager and dependencies.

# =============================================================================
# DEPENDENCY MANAGEMENT ADAPTATION GUIDE
# =============================================================================

# For different package managers, convert this format:
# 
# Node.js/npm:      -> package.json with dependencies/devDependencies sections
# Python/pip:       -> requirements.txt and requirements-dev.txt
# Go modules:       -> go.mod with require/replace sections
# Java/Maven:       -> pom.xml with dependencies/dependencyManagement
# Ruby/bundler:     -> Gemfile with gems/groups
# PHP/composer:     -> composer.json with require/require-dev
# Rust/cargo:       -> Cargo.toml with dependencies/dev-dependencies
# .NET/NuGet:       -> .csproj with PackageReference items

# =============================================================================
# CORE DEPENDENCIES (Required for production)
# =============================================================================

# Web Framework (choose one for your stack)
# web-framework-version: "latest-stable"  # e.g., express, fastapi, gin, django

# Database/ORM (choose one for your stack)
# database-driver: "latest-stable"        # e.g., psycopg2, mongoose, gorm
# orm-library: "latest-stable"            # e.g., sqlalchemy, prisma, ent

# Configuration Management
# config-parser: "latest-stable"          # e.g., dotenv, pyyaml, viper

# Logging
# logging-library: "latest-stable"        # e.g., winston, python-logging, zap

# HTTP Client (for external APIs)
# http-client: "latest-stable"            # e.g., axios, requests, httpx

# Data Validation
# validation-library: "latest-stable"     # e.g., joi, pydantic, validator

# Authentication/Security
# auth-library: "latest-stable"           # e.g., passport, authlib, casbin
# encryption: "latest-stable"             # e.g., bcrypt, crypto, argon2

# =============================================================================
# DEVELOPMENT DEPENDENCIES (Required for development)
# =============================================================================

# Testing Framework
# test-framework: "latest-stable"         # e.g., jest, pytest, testing

# Code Quality/Linting
# linter: "latest-stable"                 # e.g., eslint, flake8, golangci-lint
# formatter: "latest-stable"               # e.g., prettier, black, gofmt

# Type Checking (if applicable)
# type-checker: "latest-stable"           # e.g., typescript, mypy, type-checker

# Documentation
# doc-generator: "latest-stable"           # e.g., jsdoc, sphinx, godoc

# Development Server
# dev-server: "latest-stable"              # e.g., nodemon, uvicorn, air

# =============================================================================
# DEPLOYMENT DEPENDENCIES
# =============================================================================

# Process Management
# process-manager: "latest-stable"         # e.g., pm2, supervisor, systemd

# Monitoring/Health Checks
# monitoring: "latest-stable"              # e.g., prometheus, health-check, metrics

# Container Support
# container-tools: "latest-stable"         # e.g., docker, buildpacks, k8s-client

# =============================================================================
# EXAMPLE CONVERSIONS
# =============================================================================

# Node.js (package.json):
# {
#   "dependencies": {
#     "express": "^4.18.0",
#     "mongoose": "^6.0.0",
#     "dotenv": "^16.0.0"
#   },
#   "devDependencies": {
#     "jest": "^28.0.0",
#     "eslint": "^8.0.0",
#     "nodemon": "^2.0.0"
#   }
# }

# Python (requirements.txt):
# fastapi==0.68.0
# sqlalchemy==1.4.23
# python-dotenv==0.19.0
# pytest==6.2.5
# black==21.9b0

# Go (go.mod):
# require (
#     github.com/gin-gonic/gin v1.7.4
#     github.com/spf13/viper v1.10.1
#     github.com/stretchr/testify v1.7.0
# )

# =============================================================================
# ADAPTATION INSTRUCTIONS
# =============================================================================

# 1. Choose your package manager and convert this template to the appropriate format
# 2. Replace placeholder entries with actual package names and versions for your stack
# 3. Remove sections that don't apply to your technology
# 4. Add stack-specific dependencies as needed
# 5. Update version constraints according to your project's requirements
# 6. Consider security scanning and vulnerability management tools

# =============================================================================
# SECURITY CONSIDERATIONS
# =============================================================================

# - Use specific version numbers instead of "latest" in production
# - Regularly update dependencies to patch security vulnerabilities
# - Use tools like npm audit, safety, or gosec to scan for vulnerabilities
# - Pin transitive dependencies when possible for reproducible builds
# - Consider using dependency management platforms like Snyk or Dependabot

# =============================================================================
# BEST PRACTICES
# =============================================================================

# - Separate production and development dependencies
# - Use semantic versioning for version constraints
# - Document why each dependency is needed
# - Keep dependency list minimal and focused
# - Regularly review and remove unused dependencies
# - Use lock files for reproducible builds (package-lock.json, Pipfile.lock, etc.)

# End of Generic Dependencies Template
# Adapt this file for your specific technology stack and requirements.
