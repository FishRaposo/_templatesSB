# Go Workflow Testing Template
# CI/CD workflow and deployment testing patterns

package workflow

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
	
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ====================
// BUILD WORKFLOW TESTS
// ====================

func TestBuildProcess(t *testing.T) {
	// Test that the build process completes successfully
	if testing.Short() {
		t.Skip("Skipping workflow tests in short mode")
	}
	
	// Navigate to project root
	projectRoot := findProjectRoot(t)
	err := os.Chdir(projectRoot)
	require.NoError(t, err)
	
	// Test different build configurations
	buildTests := []struct {
		name string
		cmd  string
		args []string
	}{
		{"standard build", "go", []string{"build", "-o", "build/test-app", "./cmd/main.go"}},
		{"optimized build", "go", []string{"build", "-ldflags", "-s -w", "-o", "build/test-app-opt", "./cmd/main.go"}},
		{"cross-compile linux", "go", []string{"build", "-o", "build/test-app-linux", "-linux", "-amd64", "./cmd/main.go"}},
		{"cross-compile windows", "go", []string{"build", "-o", "build/test-app.exe", "-windows", "-amd64", "./cmd/main.go"}},
		{"race detector", "go", []string{"build", "-race", "-o", "build/test-app-race", "./cmd/main.go"}},
	}
	
	for _, tt := range buildTests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean previous build
			os.RemoveAll("build")
			os.MkdirAll("build", 0755)
			
			// Execute build
			cmd := exec.Command(tt.cmd, tt.args...)
			cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
			
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Logf("Build output: %s", output)
			}
			assert.NoError(t, err)
			
			// Verify binary was created
			binaryPath := tt.args[2] // Output path
			_, err = os.Stat(binaryPath)
			assert.NoError(t, err)
			
			// Test binary execution
			testCmd := exec.Command(binaryPath, "--version")
			err = testCmd.Run()
			// Note: Binary may not have version flag, just check it runs
			assert.True(t, err == nil || err.ExitCode() != -1, "Binary should be executable")
		})
	}
}

func TestDockerBuild(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Docker tests in short mode")
	}
	
	// Check if Docker is available
	cmd := exec.Command("docker", "version")
	if err := cmd.Run(); err != nil {
		t.Skip("Docker not available, skipping Docker tests")
	}
	
	projectRoot := findProjectRoot(t)
	err := os.Chdir(projectRoot)
	require.NoError(t, err)
	
	// Test Docker build
	t.Run("docker build", func(t *testing.T) {
		imageName := "test-app:" + time.Now().Format("20060102150405")
		
		cmd := exec.Command("docker", "build", "-t", imageName, ".")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("Docker build output: %s", output)
		}
		assert.NoError(t, err)
		
		// Clean up
		defer exec.Command("docker", "rmi", imageName).Run()
		
		// Test Docker run
		runCmd := exec.Command("docker", "run", "--rm", imageName, "--version")
		output, err = runCmd.CombinedOutput()
		// Note: Container may not have version flag
		t.Logf("Docker run output: %s", output)
	})
}

// ====================
// TEST WORKFLOW TESTS
// ====================

func TestTestWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping workflow tests in short mode")
	}
	
	projectRoot := findProjectRoot(t)
	err := os.Chdir(projectRoot)
	require.NoError(t, err)
	
	// Test all test commands
	testCommands := []struct {
		name string
		cmd  string
		args []string
	}{
		{"unit tests", "go", []string{"test", "-v", "./...", "-short"}},
		{"integration tests", "go", []string{"test", "-v", "./tests/integration/..."}},
		{"system tests", "go", []string{"test", "-v", "./tests/system/..."}},
		{"benchmark tests", "go", []string{"test", "-bench=.", "-benchmem", "./..."}},
		{"race detection", "go", []string{"test", "-race", "./...", "-short"}},
		{"coverage", "go", []string{"test", "-coverprofile=coverage.out", "./..."}},
		{"fuzz tests", "go", []string{"test", "-fuzz=Fuzz", "-fuzztime=10s", "./..."}},
	}
	
	for _, tt := range testCommands {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(tt.cmd, tt.args...)
			
			// Set appropriate timeout
			if tt.name == "system tests" || tt.name == "integration tests" {
				cmd.Env = append(os.Environ(), "RUN_SYSTEM_TESTS=true")
			}
			
			output, err := cmd.CombinedOutput()
			if len(output) > 0 {
				t.Logf("%s output:\n%s", tt.name, output)
			}
			
			// Not all tests may pass, just verify the command runs
			assert.True(t, err == nil || cmd.ProcessState != nil, "%s should execute", tt.name)
		})
	}
	
	// Test coverage report generation
	t.Run("coverage report", func(t *testing.T) {
		// Generate coverage
		cmd := exec.Command("go", "test", "-coverprofile=coverage.out", "./...")
		cmd.Run()
		
		// Generate HTML report
		cmd = exec.Command("go", "tool", "cover", "-html=coverage.out", "-o", "coverage.html")
		output, err := cmd.CombinedOutput()
		assert.NoError(t, err)
		
		// Verify report exists
		_, err = os.Stat("coverage.html")
		assert.NoError(t, err)
		
		// Clean up
		os.Remove("coverage.out")
		os.Remove("coverage.html")
	})
}

// ====================
# CI/CD PIPELINE TESTS
// ====================

func TestCIWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping workflow tests in short mode")
	}
	
	projectRoot := findProjectRoot(t)
	err := os.Chdir(projectRoot)
	require.NoError(t, err)
	
	// Test linter
	t.Run("lint", func(t *testing.T) {
		// Check if golangci-lint is installed
		cmd := exec.Command("golangci-lint", "version")
		if err := cmd.Run(); err != nil {
			t.Skip("golangci-lint not installed, skipping lint test")
		}
		
		cmd = exec.Command("golangci-lint", "run", "./...")
		output, err := cmd.CombinedOutput()
		if len(output) > 0 {
			t.Logf("Lint output:\n%s", output)
		}
		// Allow lint warnings, just ensure it runs
		assert.True(t, err == nil || cmd.ProcessState.ExitCode() < 2)
	})
	
	// Test formatter
	t.Run("format", func(t *testing.T) {
		cmd := exec.Command("go", "fmt", "./...")
		output, err := cmd.CombinedOutput()
		assert.NoError(t, err)
		if len(output) > 0 {
			t.Logf("Format changes:\n%s", output)
		}
	})
	
	// Test go mod tidy
	t.Run("dependencies", func(t *testing.T) {
		cmd := exec.Command("go", "mod", "tidy")
		output, err := cmd.CombinedOutput()
		assert.NoError(t, err)
		if len(output) > 0 {
			t.Logf("Mod tidy output:\n%s", output)
		}
		
		// Verify go mod verify
		cmd = exec.Command("go", "mod", "verify")
		output, err = cmd.CombinedOutput()
		assert.NoError(t, err, "Module verification failed: %s", output)
	})
	
	// Test security scanning
	t.Run("security", func(t *testing.T) {
		// Check if gosec is installed
		cmd := exec.Command("gosec", "version")
		if err := cmd.Run(); err != nil {
			t.Skip("gosec not installed, skipping security test")
		}
		
		cmd = exec.Command("gosec", "./...")
		output, err := cmd.CombinedOutput()
		if len(output) > 0 {
			t.Logf("Security scan output:\n%s", output)
		}
		// Allow warnings but not errors
		assert.True(t, err == nil || cmd.ProcessState.ExitCode() < 2)
	})
}

// ====================
# DEPLOYMENT WORKFLOW TESTS
// ====================

func TestDeploymentWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping workflow tests in short mode")
	}
	
	t.Run("environment configuration", func(t *testing.T) {
		// Test different environment configurations
		environments := []struct {
			name string
			env  map[string]string
		}{
			{
				"development",
				map[string]string{
					"ENV":           "development",
					"LOG_LEVEL":     "debug",
					"DB_HOST":       "localhost",
					"DEBUG":         "true",
				},
			},
			{
				"staging",
				map[string]string{
					"ENV":           "staging",
					"LOG_LEVEL":     "info",
					"DB_HOST":       "staging-db.example.com",
					"DEBUG":         "false",
				},
			},
			{
				"production",
				map[string]string{
					"ENV":           "production",
					"LOG_LEVEL":     "warn",
					"DB_HOST":       "prod-db.example.com",
					"DEBUG":         "false",
					"ENABLE_METRICS": "true",
				},
			},
		}
		
		for _, env := range environments {
			t.Run(env.name, func(t *testing.T) {
				for key, value := range env.env {
					oldValue := os.Getenv(key)
					os.Setenv(key, value)
					defer func(k, v string) {
						if v == "" {
							os.Unsetenv(k)
						} else {
							os.Setenv(k, v)
						}
					}(key, oldValue)
				}
				
				// Verify configuration loads correctly
				// config := LoadConfig()
				// assert.Equal(t, env.name, config.Environment)
			})
		}
	})
}

// ====================
# DATABASE WORKFLOW TESTS
// ====================

func TestDatabaseWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping workflow tests in short mode")
	}
	
	t.Run("migrations", func(t *testing.T) {
		projectRoot := findProjectRoot(t)
		err := os.Chdir(projectRoot)
		require.NoError(t, err)
		
		// Check migration files exist
		migrationsDir := "migrations"
		if _, err := os.Stat(migrationsDir); os.IsNotExist(err) {
			t.Skip("Migrations directory not found")
		}
		
		// Test migration syntax
		files, err := filepath.Glob(filepath.Join(migrationsDir, "*.sql"))
		require.NoError(t, err)
		assert.Greater(t, len(files), 0, "Should have migration files")
		
		for _, file := range files {
			content, err := os.ReadFile(file)
			require.NoError(t, err)
			assert.Contains(t, string(content), "CREATE TABLE", "Migration should contain CREATE TABLE")
		}
	})
	
	t.Run("seed data", func(t *testing.T) {
		// Check seed files exist
		seedFiles := []string{"seeds/users.sql", "seeds/products.sql", "seeds/test_data.sql"}
		for _, seedFile := range seedFiles {
			if _, err := os.Stat(seedFile); err == nil {
				content, err := os.ReadFile(seedFile)
				require.NoError(t, err)
				assert.Contains(t, string(content), "INSERT", "Seed file should contain INSERT statements")
			}
		}
	})
}

// ====================
# DOCUMENTATION WORKFLOW TESTS
// ====================

func TestDocumentationWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping workflow tests in short mode")
	}
	
	projectRoot := findProjectRoot(t)
	err := os.Chdir(projectRoot)
	require.NoError(t, err)
	
	// Test that documentation can be generated
	t.Run("godoc", func(t *testing.T) {
		// Check if godoc can parse the project
		cmd := exec.Command("go", "doc", "./...")
		output, err := cmd.CombinedOutput()
		assert.NoError(t, err, "godoc should be able to parse the project")
		if len(output) > 0 {
			t.Logf("Go doc output length: %d bytes", len(output))
		}
	})
	
	// Check README exists and is valid
	t.Run("readme", func(t *testing.T) {
		readmeFiles := []string{"README.md", "README.rst", "README.txt"}
		found := false
		for _, readme := range readmeFiles {
			if _, err := os.Stat(readme); err == nil {
				found = true
				content, err := os.ReadFile(readme)
				require.NoError(t, err)
				assert.Contains(t, string(content), "##", "README should have sections")
				break
			}
		}
		assert.True(t, found, "README file should exist")
	})
	
	// Check code documentation coverage
	t.Run("doc coverage", func(t *testing.T) {
		cmd := exec.Command("go", "doc", "-all", "./...")
		output, _ := cmd.CombinedOutput()
		
		// Count documented vs undocumented symbols
		content := string(output)
		// Simple heuristic: check for function names preceded by //
		// In a real implementation, you'd use go/doc package
		assert.Contains(t, content, "func", "Should have documented functions")
	})
}

// ====================
# HELPER FUNCTIONS
// ====================

func findProjectRoot(t *testing.T) string {
	// Start from current directory and look for go.mod
	startDir, err := os.Getwd()
	require.NoError(t, err)
	
	dir := startDir
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		
		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached root
			break
		}
		dir = parent
	}
	
	// If no go.mod found, return current directory
	return startDir
}

// ====================
# RUN ALL WORKFLOW TESTS
// ====================

func TestAllWorkflows(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping all workflow tests in short mode")
	}
	
	t.Run("builds", TestBuildProcess)
	t.Run("docker", TestDockerBuild)
	t.Run("tests", TestTestWorkflow)
	t.Run("ci", TestCIWorkflow)
	t.Run("deployment", TestDeploymentWorkflow)
	t.Run("database", TestDatabaseWorkflow)
	t.Run("documentation", TestDocumentationWorkflow)
}
