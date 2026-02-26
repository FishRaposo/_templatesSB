# Basic Unit Testing Examples

## Example 1: Testing a Calculator

### JavaScript (Jest)

```javascript
// calculator.js
class Calculator {
  add(a, b) { return a + b; }
  subtract(a, b) { return a - b; }
  multiply(a, b) { return a * b; }
  divide(a, b) {
    if (b === 0) throw new Error('Cannot divide by zero');
    return a / b;
  }
}

// calculator.test.js
describe('Calculator', () => {
  let calc;
  
  beforeEach(() => {
    calc = new Calculator();
  });
  
  test('adds two positive numbers', () => {
    expect(calc.add(2, 3)).toBe(5);
  });
  
  test('adds negative numbers', () => {
    expect(calc.add(-2, -3)).toBe(-5);
  });
  
  test('subtracts correctly', () => {
    expect(calc.subtract(5, 3)).toBe(2);
  });
  
  test('multiplies correctly', () => {
    expect(calc.multiply(4, 3)).toBe(12);
  });
  
  test('divides correctly', () => {
    expect(calc.divide(10, 2)).toBe(5);
  });
  
  test('throws on divide by zero', () => {
    expect(() => calc.divide(10, 0)).toThrow('Cannot divide by zero');
  });
});
```

### Python (pytest)

```python
# calculator.py
class Calculator:
    def add(self, a, b): return a + b
    def subtract(self, a, b): return a - b
    def multiply(self, a, b): return a * b
    def divide(self, a, b):
        if b == 0:
            raise ValueError('Cannot divide by zero')
        return a / b

# test_calculator.py
import pytest

@pytest.fixture
def calc():
    return Calculator()

def test_adds_positive_numbers(calc):
    assert calc.add(2, 3) == 5

def test_adds_negative_numbers(calc):
    assert calc.add(-2, -3) == -5

def test_subtracts(calc):
    assert calc.subtract(5, 3) == 2

def test_multiplies(calc):
    assert calc.multiply(4, 3) == 12

def test_divides(calc):
    assert calc.divide(10, 2) == 5

def test_divide_by_zero_raises(calc):
    with pytest.raises(ValueError, match='Cannot divide by zero'):
        calc.divide(10, 0)
```

### Go

```go
// calculator.go
func Add(a, b int) int { return a + b }
func Subtract(a, b int) int { return a - b }
func Multiply(a, b int) int { return a * b }
func Divide(a, b int) (int, error) {
    if b == 0 {
        return 0, errors.New("cannot divide by zero")
    }
    return a / b, nil
}

// calculator_test.go
func TestAdd(t *testing.T) {
    result := Add(2, 3)
    if result != 5 {
        t.Errorf("Add(2, 3) = %d; want 5", result)
    }
}

func TestDivide(t *testing.T) {
    result, err := Divide(10, 2)
    if err != nil {
        t.Errorf("unexpected error: %v", err)
    }
    if result != 5 {
        t.Errorf("Divide(10, 2) = %d; want 5", result)
    }
}

func TestDivideByZero(t *testing.T) {
    _, err := Divide(10, 0)
    if err == nil {
        t.Error("expected error for divide by zero")
    }
}
```

## Example 2: Parameterized Tests

### JavaScript

```javascript
test.each([
  [2, 3, 5],
  [0, 0, 0],
  [-1, 1, 0],
  [100, 200, 300],
])('adds %i + %i = %i', (a, b, expected) => {
  expect(add(a, b)).toBe(expected);
});
```

### Python

```python
@pytest.mark.parametrize("a,b,expected", [
    (2, 3, 5),
    (0, 0, 0),
    (-1, 1, 0),
    (100, 200, 300),
])
def test_add(a, b, expected):
    assert add(a, b) == expected
```

### Go

```go
func TestAddCases(t *testing.T) {
    cases := []struct{ a, b, want int }{
        {2, 3, 5},
        {0, 0, 0},
        {-1, 1, 0},
    }
    
    for _, c := range cases {
        t.Run(fmt.Sprintf("%d+%d", c.a, c.b), func(t *testing.T) {
            got := Add(c.a, c.b)
            if got != c.want {
                t.Errorf("Add(%d, %d) = %d; want %d", c.a, c.b, got, c.want)
            }
        })
    }
}
```

## Example 3: Testing with Setup/Teardown

### JavaScript

```javascript
describe('UserRepository', () => {
  let db;
  let repo;
  
  beforeAll(async () => {
    db = await createTestDatabase();
  });
  
  afterAll(async () => {
    await db.close();
  });
  
  beforeEach(async () => {
    await db.clear('users');
    repo = new UserRepository(db);
  });
  
  test('saves user', async () => {
    const user = { name: 'John', email: 'john@example.com' };
    const id = await repo.save(user);
    expect(id).toBeDefined();
  });
  
  test('finds user by id', async () => {
    const user = { name: 'Jane', email: 'jane@example.com' };
    const id = await repo.save(user);
    
    const found = await repo.findById(id);
    expect(found.name).toBe('Jane');
  });
});
```

### Python

```python
@pytest.fixture(scope='module')
def database():
    db = create_test_database()
    yield db
    db.close()

@pytest.fixture
def repo(database):
    database.clear('users')
    return UserRepository(database)

def test_saves_user(repo):
    user = {'name': 'John', 'email': 'john@example.com'}
    id = repo.save(user)
    assert id is not None

def test_finds_user(repo):
    user = {'name': 'Jane', 'email': 'jane@example.com'}
    id = repo.save(user)
    
    found = repo.find_by_id(id)
    assert found['name'] == 'Jane'
```

## Best Practices Demonstrated

- **Arrange-Act-Assert** structure
- **Descriptive test names**
- **Isolated tests** with setup/teardown
- **Parameterized tests** for multiple cases
- **Error case testing**
- **One concept per test**
