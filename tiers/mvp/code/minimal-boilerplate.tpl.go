// File: minimal-boilerplate.tpl.go
// Purpose: Template for unknown implementation
// Generated for: {{PROJECT_NAME}}

# Minimal Boilerplate Template (MVP Tier)

## Purpose
Provides the absolute minimum code structure for MVP projects following the minimal viable product approach.

## Usage
This template should be used for:
- Prototype projects
- Proof of concepts
- Early-stage startups
- Internal tools with limited scope

## Structure
```go
// [[.ProjectName]] - Minimal MVP Application
// Author: [[.Author]]
// Version: [[.Version]]

package main

import (
    "fmt"
    "log"
)

// Minimal entry point - just enough to validate the concept
func main() {
    fmt.Println("MVP Application Starting...")
    
    // Initialize core functionality only
    if err := initializeCore(); err != nil {
        log.Fatal("Failed to initialize:", err)
    }
    
    // Start minimal service
    startMinimalService()
}

func initializeCore() error {
    // Only essential initialization
    // No advanced configuration, no optional features
    return nil
}

func startMinimalService() {
    // Basic service loop
    // No monitoring, no advanced error handling
    fmt.Println("MVP Service Running")
}
```

## MVP Guidelines
- **Focus**: Core functionality only
- **Complexity**: Keep it simple and direct
- **Dependencies**: Minimal external dependencies
- **Error Handling**: Basic error logging only
- **Testing**: Manual testing sufficient
- **Documentation**: Inline comments only

## What's NOT Included (Compared to Core/Full)
- No advanced configuration management
- No comprehensive logging
- No monitoring/metrics
- No automated testing framework
- No API documentation generation
- No deployment automation
