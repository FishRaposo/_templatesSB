// File: basic-tests.tpl.go
// Purpose: Template for unknown implementation
// Generated for: {{PROJECT_NAME}}

# Basic Testing Template (MVP Tier)

## Purpose
Provides minimal testing patterns for MVP projects where speed and simplicity are prioritized over comprehensive coverage.

## Usage
This template should be used for:
- Quick validation of core functionality
- Manual testing scenarios
- Simple integration checks
- Basic error condition testing

## Structure
```go
// [[.ProjectName]] - Basic Tests
// Author: [[.Author]]
// Version: [[.Version]]

package main

import (
    "testing"
    "fmt"
)

// TestCoreFunctionality validates the main MVP feature
func TestCoreFunctionality(t *testing.T) {
    // Test the absolute core functionality
    result := coreFunction()
    expected := "expected-result"
    
    if result != expected {
        t.Errorf("Expected %s, got %s", expected, result)
    }
}

// TestBasicErrorHandling validates error scenarios
func TestBasicErrorHandling(t *testing.T) {
    // Test basic error conditions
    _, err := functionThatShouldFail()
    
    if err == nil {
        t.Error("Expected error but got none")
    }
}

// TestManualValidation provides manual testing checklist
func TestManualValidation(t *testing.T) {
    t.Skip("Manual validation required - see checklist below")
    
    // Manual testing checklist:
    // 1. Application starts without errors
    // 2. Core feature produces expected output
    // 3. Basic error conditions are handled
    // 4. No memory leaks or crashes
}

// Helper functions for testing
func coreFunction() string {
    return "expected-result"
}

func functionThatShouldFail() (string, error) {
    return "", fmt.Errorf("intentional test error")
}
```

## MVP Testing Guidelines
- **Focus**: Core functionality validation only
- **Coverage**: Manual testing acceptable
- **Automation**: Basic unit tests for critical paths
- **Complexity**: Keep tests simple and readable
- **Tools**: Use standard testing library only

## Manual Testing Checklist
- [ ] Application starts successfully
- [ ] Core feature works as expected
- [ ] Basic error conditions handled
- [ ] No obvious memory issues
- [ ] User interface (if any) is functional
- [ ] Data persistence (if required) works

## What's NOT Included (Compared to Core/Full)
- No comprehensive test coverage requirements
- No automated integration testing
- No performance benchmarking
- No load testing
- No security testing
- No end-to-end testing automation
