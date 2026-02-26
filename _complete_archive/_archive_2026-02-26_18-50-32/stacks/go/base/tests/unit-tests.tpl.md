# Go Unit Testing Template
# Comprehensive unit testing patterns and examples for Go projects

package main

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ====================
// BASIC UNIT TEST PATTERNS
// ====================

// TestSimpleFunction demonstrates basic unit test structure
func TestSimpleFunction(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected int
		wantErr  bool
	}{
		{"positive number", 5, 25, false},
		{"zero", 0, 0, false},
		{"negative number", -3, 9, false},
		{"large number", 100, 10000, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Square(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestWithSetupTeardown demonstrates test setup and teardown
func TestWithSetupTeardown(t *testing.T) {
	// Setup
	db := setupTestDB(t)
	defer db.Close()

	// Test
	user := &User{Name: "John Doe", Email: "john@example.com"}
	err := db.CreateUser(user)
	assert.NoError(t, err)
	assert.NotZero(t, user.ID)

	// Verify
	found, err := db.GetUser(user.ID)
	assert.NoError(t, err)
	assert.Equal(t, user.Name, found.Name)
}

// ====================
// TABLE DRIVEN TESTS
// ====================

func TestCalculateDiscount(t *testing.T) {
	tests := []struct {
		name        string
		customerType string
		amount      float64
		expected    float64
	}{
		{"regular customer", "regular", 100.0, 0.0},
		{"premium customer small purchase", "premium", 50.0, 2.5},
		{"premium customer large purchase", "premium", 200.0, 20.0},
		{"vip customer", "vip", 100.0, 15.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			discount := CalculateDiscount(tt.customerType, tt.amount)
			assert.InDelta(t, tt.expected, discount, 0.01)
		})
	}
}

// ====================
// MOCK TESTING
// ====================

// MockRepository demonstrates mocking with testify
-type MockRepository struct {
	mock.Mock
}

func (m *MockRepository) GetUser(id int) (*User, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}

func (m *MockRepository) SaveUser(user *User) error {
	args := m.Called(user)
	return args.Error(0)
}

func TestServiceWithMock(t *testing.T) {
	// Create mock
	mockRepo := new(MockRepository)
	
	// Setup expectations
	expectedUser := &User{ID: 1, Name: "John Doe", Email: "john@example.com"}
	mockRepo.On("GetUser", 1).Return(expectedUser, nil)
	mockRepo.On("SaveUser", mock.AnythingOfType("*User")).Return(nil)

	// Create service with mock
	service := NewUserService(mockRepo)

	// Execute
	user, err := service.GetUser(1)
	
	// Assert
	assert.NoError(t, err)
	assert.Equal(t, expectedUser, user)
	mockRepo.AssertExpectations(t)
}

// ====================
// BENCHMARK TESTS
// ====================

func BenchmarkSquare(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Square(i)
	}
}

func BenchmarkSquareParallel(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			Square(i)
			i++
		}
	})
}

// ====================
// FUZZ TESTS
// ====================

func FuzzReverse(f *testing.F) {
	testcases := []string{"Hello, world", " ", "!12345"}
	for _, tc := range testcases {
		f.Add(tc)
	}
	
	f.Fuzz(func(t *testing.T, orig string) {
		rev, err1 := Reverse(orig)
		if err1 != nil {
			return
		}
		
		doubleRev, err2 := Reverse(rev)
		if err2 != nil {
			return
		}
		
		assert.Equal(t, orig, doubleRev)
	})
}

// ====================
// CONCURRENT TESTING
// ====================

func TestConcurrentAccess(t *testing.T) {
	counter := NewCounter()
	
	// Run concurrent goroutines
	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func() {
			counter.Increment()
			done <- true
		}()
	}
	
	// Wait for all goroutines
	for i := 0; i < 100; i++ {
		<-done
	}
	
	assert.Equal(t, 100, counter.Value())
}

// ====================
// ERROR HANDLING TESTS
// ====================

func TestErrorCases(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		errMsg  string
	}{
		{"empty input", "", true, "input cannot be empty"},
		{"invalid format", "invalid", true, "invalid format"},
		{"too long", string(make([]byte, 1001)), true, "input too long"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ProcessInput(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ====================
// HTTP HANDLER TESTS
// ====================

func TestUserHandler(t *testing.T) {
	// Create test request
	req, err := http.NewRequest("GET", "/users/1", nil)
	require.NoError(t, err)
	
	// Create response recorder
	rr := httptest.NewRecorder()
	
	// Create handler
	handler := http.HandlerFunc(GetUserHandler)
	
	// Execute request
	handler.ServeHTTP(rr, req)
	
	// Assert response
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "John Doe")
}

// ====================
// DATABASE TESTS
// ====================

func TestUserRepository(t *testing.T) {
	// Use test container or in-memory database
	db := setupTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)

	t.Run("create user", func(t *testing.T) {
		user := &User{
			Name:  "John Doe",
			Email: "john@example.com",
		}
		
		err := repo.Create(user)
		assert.NoError(t, err)
		assert.NotZero(t, user.ID)
		assert.WithinDuration(t, time.Now(), user.CreatedAt, time.Second)
	})

	t.Run("find user by email", func(t *testing.T) {
		user, err := repo.FindByEmail("john@example.com")
		assert.NoError(t, err)
		assert.NotNil(t, user)
		assert.Equal(t, "john@example.com", user.Email)
	})

	t.Run("user not found", func(t *testing.T) {
		user, err := repo.FindByEmail("nonexistent@example.com")
		assert.Error(t, err)
		assert.Nil(t, user)
		assert.True(t, errors.Is(err, ErrUserNotFound))
	})
}

// ====================
// HELPER FUNCTIONS
// ====================

// setupTestDB creates a test database connection
func setupTestDB(t *testing.T) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	
	// Run migrations
	_, err = db.Exec(`
		CREATE TABLE users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			email TEXT UNIQUE NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
	`)
	require.NoError(t, err)
	
	return db
}

// mustExec executes a query and fails the test if there's an error
func mustExec(t *testing.T, db *sql.DB, query string, args ...interface{}) sql.Result {
	result, err := db.Exec(query, args...)
	require.NoError(t, err)
	return result
}

// ====================
// CUSTOM ASSERTIONS
// ====================

func AssertUser(t *testing.T, expected, actual *User) {
	t.Helper()
	assert.Equal(t, expected.ID, actual.ID)
	assert.Equal(t, expected.Name, actual.Name)
	assert.Equal(t, expected.Email, actual.Email)
	assert.WithinDuration(t, expected.CreatedAt, actual.CreatedAt, time.Second)
}

// ====================
// TEST MAIN
// ====================

func TestMain(m *testing.M) {
	// Setup
	log.Println("Setting up tests...")
	
	// Run tests
	code := m.Run()
	
	// Teardown
	log.Println("Tearing down tests...")
	
	os.Exit(code)
}
