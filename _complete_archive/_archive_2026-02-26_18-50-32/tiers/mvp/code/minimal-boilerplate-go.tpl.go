// File: minimal-boilerplate-go.tpl.go
// Purpose: Template for unknown implementation
// Generated for: {{PROJECT_NAME}}

# Minimal Boilerplate Template (MVP Tier - Go)

## Purpose
Provides the absolute minimum Go code structure for MVP projects following the minimal viable product approach.

## Usage
This template should be used for:
- Prototype applications
- Proof of concepts
- Early-stage startup services
- Internal tools with limited scope

## Structure
```go
package main

// [[.ProjectName]] - Minimal MVP Application
// Author: [[.Author]]
// Version: [[.Version]]

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// MVPApplication represents the minimal application structure
//
// This struct contains the essential fields needed for MVP development:
// - status: Current application status for user feedback
// - running: Boolean flag to control the service loop
// - stopChan: Channel for receiving shutdown signals
//
// MVP approach: Minimal fields with no advanced features like
// configuration management, metrics, or health checks.
type MVPApplication struct {
	status   string
	running  bool
	stopChan chan os.Signal
}

// NewMVPApplication creates a new MVP application instance
//
// This function initializes the application with default values.
// MVP approach: No configuration options, no dependency injection,
// no advanced initialization patterns.
//
// Returns:
//   *MVPApplication: A new application instance ready to run
func NewMVPApplication() *MVPApplication {
	return &MVPApplication{
		status:   "MVP Application Starting...",
		stopChan: make(chan os.Signal, 1),
	}
}

// initializeCore initializes core functionality only
//
// MVP approach: Simulated initialization with basic status update.
// In production, this would include:
//   - Database connections
//   - API client setup
//   - Basic configuration loading
// No advanced features like circuit breakers, retry logic, or monitoring.
//
// Returns:
//   error: Always returns nil for MVP simplicity
func (app *MVPApplication) initializeCore() error {
	// Only essential initialization
	// No advanced configuration, no optional features
	app.status = "MVP Service Running"
	return nil
}

// startMinimalService starts the minimal service loop
//
// MVP approach: Simple service loop with basic signal handling.
// This method:
//   1. Sets up signal handlers for graceful shutdown
//   2. Runs a basic service loop with periodic actions
//   3. Responds to shutdown signals
// No advanced features like HTTP servers, graceful shutdown with context,
// or service discovery.
func (app *MVPApplication) startMinimalService() {
	app.running = true
	
	// Setup signal handling for graceful shutdown
	// MVP: Basic signal handling, no context cancellation or timeouts
	signal.Notify(app.stopChan, syscall.SIGINT, syscall.SIGTERM)
	
	// Basic service loop
	// MVP: Simple select-based loop, no worker pools or goroutine management
	for app.running {
		select {
		case <-app.stopChan:
			app.running = false
			fmt.Println("MVP Service stopping...")
		default:
			app.performBasicAction()
			time.Sleep(1 * time.Second)
		}
	}
}

// performBasicAction performs basic service functionality
//
// MVP approach: Simple console output for demonstration.
// In production, this would contain core business logic:
//   - Data processing
//   - API calls
//   - Background tasks
// No advanced features like error handling, logging, or metrics.
func (app *MVPApplication) performBasicAction() {
	// Basic functionality
	// Add your core business logic here
	fmt.Println("Performing basic MVP action")
}

// Run starts the MVP application
//
// This is the main entry point that orchestrates the application lifecycle:
//   1. Initialize core functionality
//   2. Start the service loop
//   3. Handle shutdown gracefully
//
// MVP approach: Basic error handling and logging.
// No advanced features like structured logging, error wrapping,
// or startup health checks.
//
// Returns:
//   error: Always returns nil for MVP simplicity
func (app *MVPApplication) Run() error {
	// Initialize core functionality
	if err := app.initializeCore(); err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}
	
	fmt.Println(app.status)
	
	// Start minimal service
	app.startMinimalService()
	
	fmt.Println("MVP Application stopped")
	return nil
}

// main is the application entry point
//
// MVP approach: Simple main function with basic error handling.
// No advanced features like command-line parsing, configuration loading,
// or graceful shutdown with context.
func main() {
	// Create application instance
	// MVP: No dependency injection or factory patterns
	app := NewMVPApplication()
	
	// Run the application
	// MVP: Basic error logging, no structured logging or error reporting
	if err := app.Run(); err != nil {
		log.Fatal("Failed to run application:", err)
	}
}
```

## MVP Guidelines
- **Focus**: Core functionality only
- **Complexity**: Keep it simple and direct
- **Dependencies**: Standard library only
- **Error Handling**: Basic error logging only
- **Testing**: Manual testing sufficient
- **Documentation**: Inline comments only

## What's NOT Included (Compared to Core/Full)
- No advanced configuration management
- No comprehensive logging frameworks
- No monitoring/metrics collection
- No automated testing framework
- No API documentation generation
- No deployment automation
- No database integration
- No HTTP server framework
- No middleware system
- No graceful shutdown with context
- No structured logging
