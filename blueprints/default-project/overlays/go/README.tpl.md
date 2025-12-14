# {{PROJECT_NAME}} - Go Project

> Universal Template System - Documentation Blueprint - Go Overlay

## Overview

{{PROJECT_NAME}} is a Go project generated with the Universal Template System.

## Quick Start

```bash
# Get dependencies
go mod download

# Run the application
go run main.go

# Run tests
go test ./...
```

## Project Structure

```
{{PROJECT_NAME}}/
├── cmd/                 # Application entry points
├── internal/            # Private application code
├── pkg/                 # Public libraries
├── docs/                # Documentation
├── go.mod              # Module definition
├── go.sum              # Dependency checksums
└── README.md           # This file
```

## Documentation

- API Documentation (see docs/API.md when generated)
- Contributing Guide (see CONTRIBUTING.md when generated)
- Changelog (see CHANGELOG.md when generated)

## Development

```bash
# Run linting
golangci-lint run

# Run tests with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Build binary
go build -o bin/{{PROJECT_NAME}} ./cmd/...
```

## AI Agent Notes

This project follows Universal Template System conventions.

---

**Generated with**: Universal Template System  
**Stack**: Go  
**Tier**: {{TIER}}
