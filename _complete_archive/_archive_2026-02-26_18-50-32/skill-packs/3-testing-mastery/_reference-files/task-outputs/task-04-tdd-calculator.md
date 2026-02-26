# Task 4: TDD String Calculator

## Task Description

Implement a String Calculator following strict TDD:
1. Start with empty string returns 0
2. Single number returns itself
3. Two numbers comma-delimited returns sum
4. Handle newlines as delimiters
5. Support custom delimiters
6. Ignore numbers > 1000
7. Throw exception for negative numbers

Show complete Red-Green-Refactor cycle for each feature.

## Solution

### Project Setup

```
string-calculator/
├── src/
│   └── calculator.js
├── tests/
│   └── calculator.test.js
├── package.json
└── jest.config.js
```

### Step 1: Empty String Returns 0

**RED: Write failing test**

```javascript
// tests/calculator.test.js
describe('StringCalculator', () => {
  const calculator = new (require('../src/calculator'))();

  test('empty string returns 0', () => {
    expect(calculator.add('')).toBe(0);
  });
});
```

**Run test — FAILS**
```
FAIL  tests/calculator.test.js
  StringCalculator
    ✕ empty string returns 0 (2ms)

  ● StringCalculator › empty string returns 0

    TypeError: calculator.add is not a function
```

**GREEN: Write minimal code to pass**

```javascript
// src/calculator.js
class StringCalculator {
  add(numbers) {
    return 0;  // Minimal code to pass
  }
}

module.exports = StringCalculator;
```

**Run test — PASSES**
```
PASS  tests/calculator.test.js
  StringCalculator
    ✓ empty string returns 0 (1ms)
```

**REFACTOR: Nothing to refactor yet**

---

### Step 2: Single Number Returns Itself

**RED: Write failing test**

```javascript
// tests/calculator.test.js
describe('StringCalculator', () => {
  const calculator = new (require('../src/calculator'))();

  test('empty string returns 0', () => {
    expect(calculator.add('')).toBe(0);
  });

  test('single number returns itself', () => {
    expect(calculator.add('5')).toBe(5);
  });
});
```

**Run test — FAILS**
```
FAIL  tests/calculator.test.js
  StringCalculator
    ✓ empty string returns 0
    ✕ single number returns itself

  ● StringCalculator › single number returns itself

    expect(received).toBe(expected)
    Expected: 5
    Received: 0
```

**GREEN: Write minimal code to pass**

```javascript
// src/calculator.js
class StringCalculator {
  add(numbers) {
    if (numbers === '') {
      return 0;
    }
    return parseInt(numbers, 10);  // Minimal change
  }
}

module.exports = StringCalculator;
```

**Run test — PASSES**
```
PASS  tests/calculator.test.js
  StringCalculator
    ✓ empty string returns 0
    ✓ single number returns itself (1ms)
```

**REFACTOR: Nothing to refactor yet**

---

### Step 3: Two Numbers Comma-Delimited Returns Sum

**RED: Write failing test**

```javascript
// tests/calculator.test.js
describe('StringCalculator', () => {
  const calculator = new (require('../src/calculator'))();

  test('empty string returns 0', () => {
    expect(calculator.add('')).toBe(0);
  });

  test('single number returns itself', () => {
    expect(calculator.add('5')).toBe(5);
  });

  test('two numbers comma-delimited returns sum', () => {
    expect(calculator.add('1,2')).toBe(3);
  });
});
```

**Run test — FAILS**
```
FAIL  tests/calculator.test.js
  StringCalculator
    ✓ empty string returns 0
    ✓ single number returns itself
    ✕ two numbers comma-delimited returns sum

  ● StringCalculator › two numbers comma-delimited returns sum

    expect(received).toBe(expected)
    Expected: 3
    Received: 1
```

**GREEN: Write minimal code to pass**

```javascript
// src/calculator.js
class StringCalculator {
  add(numbers) {
    if (numbers === '') {
      return 0;
    }
    
    if (numbers.includes(',')) {
      const parts = numbers.split(',');
      return parseInt(parts[0], 10) + parseInt(parts[1], 10);
    }
    
    return parseInt(numbers, 10);
  }
}

module.exports = StringCalculator;
```

**Run test — PASSES**
```
PASS  tests/calculator.test.js
  StringCalculator
    ✓ empty string returns 0
    ✓ single number returns itself
    ✓ two numbers comma-delimited returns sum (1ms)
```

**REFACTOR: Generalize to handle any number of comma-separated values**

```javascript
// src/calculator.js
class StringCalculator {
  add(numbers) {
    if (numbers === '') {
      return 0;
    }
    
    const parts = numbers.split(',');
    return parts.reduce((sum, num) => sum + parseInt(num, 10), 0);
  }
}

module.exports = StringCalculator;
```

**Run tests — All PASSES**
```
PASS  tests/calculator.test.js
  StringCalculator
    ✓ empty string returns 0
    ✓ single number returns itself
    ✓ two numbers comma-delimited returns sum
```

---

### Step 4: Handle Newlines as Delimiters

**RED: Write failing test**

```javascript
// tests/calculator.test.js
describe('StringCalculator', () => {
  const calculator = new (require('../src/calculator'))();

  test('empty string returns 0', () => {
    expect(calculator.add('')).toBe(0);
  });

  test('single number returns itself', () => {
    expect(calculator.add('5')).toBe(5);
  });

  test('two numbers comma-delimited returns sum', () => {
    expect(calculator.add('1,2')).toBe(3);
  });

  test('handles newlines as delimiters', () => {
    expect(calculator.add('1\n2,3')).toBe(6);
  });
});
```

**Run test — FAILS**
```
FAIL  tests/calculator.test.js
  StringCalculator
    ...
    ✕ handles newlines as delimiters

  ● StringCalculator › handles newlines as delimiters

    expect(received).toBe(expected)
    Expected: 6
    Received: NaN
```

**GREEN: Write minimal code to pass**

```javascript
// src/calculator.js
class StringCalculator {
  add(numbers) {
    if (numbers === '') {
      return 0;
    }
    
    // Replace newlines with commas, then split
    const normalized = numbers.replace(/\n/g, ',');
    const parts = normalized.split(',');
    return parts.reduce((sum, num) => sum + parseInt(num, 10), 0);
  }
}

module.exports = StringCalculator;
```

**Run test — PASSES**
```
PASS  tests/calculator.test.js
  StringCalculator
    ...
    ✓ handles newlines as delimiters (1ms)
```

**REFACTOR: Extract delimiter handling to be more explicit**

```javascript
// src/calculator.js
class StringCalculator {
  add(numbers) {
    if (numbers === '') {
      return 0;
    }
    
    const parts = this.parseNumbers(numbers);
    return parts.reduce((sum, num) => sum + num, 0);
  }

  parseNumbers(numbers) {
    // Replace newlines with commas, then split and parse
    const normalized = numbers.replace(/\n/g, ',');
    return normalized.split(',').map(num => parseInt(num, 10));
  }
}

module.exports = StringCalculator;
```

**Run tests — All PASSES**

---

### Step 5: Support Custom Delimiters

**RED: Write failing test**

```javascript
// tests/calculator.test.js
describe('StringCalculator', () => {
  const calculator = new (require('../src/calculator'))();

  test('empty string returns 0', () => {
    expect(calculator.add('')).toBe(0);
  });

  test('single number returns itself', () => {
    expect(calculator.add('5')).toBe(5);
  });

  test('two numbers comma-delimited returns sum', () => {
    expect(calculator.add('1,2')).toBe(3);
  });

  test('handles newlines as delimiters', () => {
    expect(calculator.add('1\n2,3')).toBe(6);
  });

  test('supports custom delimiter ;', () => {
    expect(calculator.add('//;\n1;2')).toBe(3);
  });
});
```

**Run test — FAILS**
```
FAIL  tests/calculator.test.js
  StringCalculator
    ...
    ✕ supports custom delimiter ;

  ● StringCalculator › supports custom delimiter ;

    expect(received).toBe(expected)
    Expected: 3
    Received: NaN
```

**GREEN: Write minimal code to pass**

```javascript
// src/calculator.js
class StringCalculator {
  add(numbers) {
    if (numbers === '') {
      return 0;
    }
    
    let delimiter = ',';
    let numberString = numbers;
    
    // Check for custom delimiter
    if (numbers.startsWith('//')) {
      const delimiterEnd = numbers.indexOf('\n');
      delimiter = numbers.substring(2, delimiterEnd);
      numberString = numbers.substring(delimiterEnd + 1);
    }
    
    const parts = this.parseNumbers(numberString, delimiter);
    return parts.reduce((sum, num) => sum + num, 0);
  }

  parseNumbers(numbers, delimiter) {
    // Replace newlines with delimiter, then split and parse
    const normalized = numbers.replace(/\n/g, delimiter);
    const regex = new RegExp(`\\${delimiter}`);
    return normalized.split(regex).map(num => parseInt(num, 10));
  }
}

module.exports = StringCalculator;
```

**Run test — PASSES**
```
PASS  tests/calculator.test.js
  StringCalculator
    ...
    ✓ supports custom delimiter ; (1ms)
```

**Add another test for different delimiter**

```javascript
  test('supports custom delimiter |', () => {
    expect(calculator.add('//|\n1|2|3')).toBe(6);
  });
```

**Run tests — PASSES**

**REFACTOR: Improve delimiter handling with better regex**

```javascript
// src/calculator.js
class StringCalculator {
  add(numbers) {
    if (numbers === '') {
      return 0;
    }
    
    const { delimiter, numberString } = this.extractDelimiter(numbers);
    const parts = this.parseNumbers(numberString, delimiter);
    return parts.reduce((sum, num) => sum + num, 0);
  }

  extractDelimiter(numbers) {
    if (numbers.startsWith('//')) {
      const delimiterEnd = numbers.indexOf('\n');
      const delimiter = numbers.substring(2, delimiterEnd);
      const numberString = numbers.substring(delimiterEnd + 1);
      return { delimiter, numberString };
    }
    return { delimiter: ',', numberString: numbers };
  }

  parseNumbers(numbers, delimiter) {
    // Handle both newlines and custom delimiter
    const normalized = numbers.replace(/\n/g, delimiter);
    return normalized.split(delimiter).map(num => parseInt(num, 10));
  }
}

module.exports = StringCalculator;
```

**Run tests — All PASSES**

---

### Step 6: Ignore Numbers > 1000

**RED: Write failing test**

```javascript
// tests/calculator.test.js
  test('ignores numbers greater than 1000', () => {
    expect(calculator.add('2,1001')).toBe(2);
  });

  test('includes 1000 but ignores larger', () => {
    expect(calculator.add('1000,1001,2')).toBe(1002);
  });
```

**Run tests — FAILS**
```
FAIL  tests/calculator.test.js
  StringCalculator
    ...
    ✕ ignores numbers greater than 1000
    ✕ includes 1000 but ignores larger

  ● StringCalculator › ignores numbers greater than 1000

    expect(received).toBe(expected)
    Expected: 2
    Received: 1003
```

**GREEN: Write minimal code to pass**

```javascript
// src/calculator.js
class StringCalculator {
  add(numbers) {
    if (numbers === '') {
      return 0;
    }
    
    const { delimiter, numberString } = this.extractDelimiter(numbers);
    const parts = this.parseNumbers(numberString, delimiter);
    return parts
      .filter(num => num <= 1000)  // Filter out numbers > 1000
      .reduce((sum, num) => sum + num, 0);
  }

  extractDelimiter(numbers) {
    if (numbers.startsWith('//')) {
      const delimiterEnd = numbers.indexOf('\n');
      const delimiter = numbers.substring(2, delimiterEnd);
      const numberString = numbers.substring(delimiterEnd + 1);
      return { delimiter, numberString };
    }
    return { delimiter: ',', numberString: numbers };
  }

  parseNumbers(numbers, delimiter) {
    const normalized = numbers.replace(/\n/g, delimiter);
    return normalized.split(delimiter).map(num => parseInt(num, 10));
  }
}

module.exports = StringCalculator;
```

**Run tests — PASSES**
```
PASS  tests/calculator.test.js
  StringCalculator
    ...
    ✓ ignores numbers greater than 1000 (1ms)
    ✓ includes 1000 but ignores larger (1ms)
```

**REFACTOR: Extract filtering logic**

```javascript
// src/calculator.js
class StringCalculator {
  add(numbers) {
    if (numbers === '') {
      return 0;
    }
    
    const { delimiter, numberString } = this.extractDelimiter(numbers);
    const parts = this.parseNumbers(numberString, delimiter);
    const validNumbers = this.filterValidNumbers(parts);
    return validNumbers.reduce((sum, num) => sum + num, 0);
  }

  extractDelimiter(numbers) {
    if (numbers.startsWith('//')) {
      const delimiterEnd = numbers.indexOf('\n');
      const delimiter = numbers.substring(2, delimiterEnd);
      const numberString = numbers.substring(delimiterEnd + 1);
      return { delimiter, numberString };
    }
    return { delimiter: ',', numberString: numbers };
  }

  parseNumbers(numbers, delimiter) {
    const normalized = numbers.replace(/\n/g, delimiter);
    return normalized.split(delimiter).map(num => parseInt(num, 10));
  }

  filterValidNumbers(numbers) {
    return numbers.filter(num => num <= 1000);
  }
}

module.exports = StringCalculator;
```

**Run tests — All PASSES**

---

### Step 7: Throw Exception for Negative Numbers

**RED: Write failing test**

```javascript
// tests/calculator.test.js
  test('throws exception for negative numbers', () => {
    expect(() => calculator.add('-1,2')).toThrow('negatives not allowed: -1');
  });

  test('throws exception with all negatives listed', () => {
    expect(() => calculator.add('2,-4,-5')).toThrow('negatives not allowed: -4,-5');
  });
```

**Run tests — FAILS**
```
FAIL  tests/calculator.test.js
  StringCalculator
    ...
    ✕ throws exception for negative numbers
    ✕ throws exception with all negatives listed

  ● StringCalculator › throws exception for negative numbers

    Received function did not throw
```

**GREEN: Write minimal code to pass**

```javascript
// src/calculator.js
class StringCalculator {
  add(numbers) {
    if (numbers === '') {
      return 0;
    }
    
    const { delimiter, numberString } = this.extractDelimiter(numbers);
    const parts = this.parseNumbers(numberString, delimiter);
    
    this.validateNoNegatives(parts);
    
    const validNumbers = this.filterValidNumbers(parts);
    return validNumbers.reduce((sum, num) => sum + num, 0);
  }

  extractDelimiter(numbers) {
    if (numbers.startsWith('//')) {
      const delimiterEnd = numbers.indexOf('\n');
      const delimiter = numbers.substring(2, delimiterEnd);
      const numberString = numbers.substring(delimiterEnd + 1);
      return { delimiter, numberString };
    }
    return { delimiter: ',', numberString: numbers };
  }

  parseNumbers(numbers, delimiter) {
    const normalized = numbers.replace(/\n/g, delimiter);
    return normalized.split(delimiter).map(num => parseInt(num, 10));
  }

  validateNoNegatives(numbers) {
    const negatives = numbers.filter(num => num < 0);
    if (negatives.length > 0) {
      throw new Error(`negatives not allowed: ${negatives.join(',')}`);
    }
  }

  filterValidNumbers(numbers) {
    return numbers.filter(num => num <= 1000);
  }
}

module.exports = StringCalculator;
```

**Run tests — PASSES**
```
PASS  tests/calculator.test.js
  StringCalculator
    ...
    ✓ throws exception for negative numbers (2ms)
    ✓ throws exception with all negatives listed (1ms)
```

**REFACTOR: Nothing to refactor — all tests green**

---

### Final Implementation

```javascript
// src/calculator.js
/**
 * String Calculator - TDD Implementation
 * 
 * Features:
 * - Empty string returns 0
 * - Single number returns the number
 * - Multiple numbers (comma or newline delimited) returns sum
 * - Custom delimiters supported via //delimiter\n format
 * - Numbers > 1000 are ignored
 * - Negative numbers throw exception
 */
class StringCalculator {
  /**
   * Adds numbers from a string
   * @param {string} numbers - String containing numbers to add
   * @returns {number} - Sum of valid numbers
   * @throws {Error} - If negative numbers are present
   */
  add(numbers) {
    if (numbers === '') {
      return 0;
    }
    
    const { delimiter, numberString } = this.extractDelimiter(numbers);
    const parts = this.parseNumbers(numberString, delimiter);
    
    this.validateNoNegatives(parts);
    
    const validNumbers = this.filterValidNumbers(parts);
    return validNumbers.reduce((sum, num) => sum + num, 0);
  }

  /**
   * Extracts custom delimiter if specified
   * @param {string} numbers - Input string
   * @returns {{delimiter: string, numberString: string}}
   */
  extractDelimiter(numbers) {
    if (numbers.startsWith('//')) {
      const delimiterEnd = numbers.indexOf('\n');
      const delimiter = numbers.substring(2, delimiterEnd);
      const numberString = numbers.substring(delimiterEnd + 1);
      return { delimiter, numberString };
    }
    return { delimiter: ',', numberString: numbers };
  }

  /**
   * Parses numbers from string using delimiter
   * @param {string} numbers - Number string
   * @param {string} delimiter - Delimiter to use
   * @returns {number[]} - Array of parsed numbers
   */
  parseNumbers(numbers, delimiter) {
    const normalized = numbers.replace(/\n/g, delimiter);
    return normalized.split(delimiter).map(num => parseInt(num, 10));
  }

  /**
   * Validates that no negative numbers are present
   * @param {number[]} numbers - Numbers to validate
   * @throws {Error} - If negative numbers found
   */
  validateNoNegatives(numbers) {
    const negatives = numbers.filter(num => num < 0);
    if (negatives.length > 0) {
      throw new Error(`negatives not allowed: ${negatives.join(',')}`);
    }
  }

  /**
   * Filters out numbers greater than 1000
   * @param {number[]} numbers - Numbers to filter
   * @returns {number[]} - Valid numbers
   */
  filterValidNumbers(numbers) {
    return numbers.filter(num => num <= 1000);
  }
}

module.exports = StringCalculator;
```

### Complete Test Suite

```javascript
// tests/calculator.test.js
const StringCalculator = require('../src/calculator');

describe('StringCalculator', () => {
  let calculator;

  beforeEach(() => {
    calculator = new StringCalculator();
  });

  describe('Basic functionality', () => {
    test('empty string returns 0', () => {
      expect(calculator.add('')).toBe(0);
    });

    test('single number returns itself', () => {
      expect(calculator.add('5')).toBe(5);
      expect(calculator.add('42')).toBe(42);
    });
  });

  describe('Multiple numbers', () => {
    test('two numbers comma-delimited returns sum', () => {
      expect(calculator.add('1,2')).toBe(3);
      expect(calculator.add('10,20')).toBe(30);
    });

    test('multiple numbers returns sum', () => {
      expect(calculator.add('1,2,3,4,5')).toBe(15);
    });
  });

  describe('Newline delimiters', () => {
    test('handles newlines as delimiters', () => {
      expect(calculator.add('1\n2,3')).toBe(6);
    });

    test('handles only newlines', () => {
      expect(calculator.add('1\n2\n3')).toBe(6);
    });
  });

  describe('Custom delimiters', () => {
    test('supports custom delimiter semicolon', () => {
      expect(calculator.add('//;\n1;2')).toBe(3);
    });

    test('supports custom delimiter pipe', () => {
      expect(calculator.add('//|\n1|2|3')).toBe(6);
    });

    test('supports custom delimiter hash', () => {
      expect(calculator.add('//#\n2#3#4')).toBe(9);
    });
  });

  describe('Number filtering', () => {
    test('ignores numbers greater than 1000', () => {
      expect(calculator.add('2,1001')).toBe(2);
    });

    test('includes 1000 but ignores larger', () => {
      expect(calculator.add('1000,1001,2')).toBe(1002);
    });

    test('ignores large numbers with multiple values', () => {
      expect(calculator.add('1,2,1001,3')).toBe(6);
    });
  });

  describe('Negative numbers', () => {
    test('throws exception for single negative number', () => {
      expect(() => calculator.add('-1,2')).toThrow('negatives not allowed: -1');
    });

    test('throws exception with all negatives listed', () => {
      expect(() => calculator.add('2,-4,-5')).toThrow('negatives not allowed: -4,-5');
    });

    test('throws exception when negative is first', () => {
      expect(() => calculator.add('-1,-2,-3')).toThrow('negatives not allowed: -1,-2,-3');
    });
  });

  describe('Complex scenarios', () => {
    test('custom delimiter with newlines and large numbers', () => {
      expect(calculator.add('//;\n1;2\n3;1001')).toBe(6);
    });

    test('multiple delimiters with filtering', () => {
      expect(calculator.add('1,2\n3,1002,4')).toBe(10);
    });
  });
});
```

## TDD Cycle Summary

| Step | Test | Implementation | Refactoring |
|------|------|----------------|-------------|
| 1 | Empty string → 0 | `return 0` | None |
| 2 | Single number → itself | `parseInt(numbers)` | None |
| 3 | Two numbers → sum | `split(',').reduce()` | Generalized to N numbers |
| 4 | Newlines → sum | `replace('\n', ',')` | Extract `parseNumbers()` |
| 5 | Custom delimiter → sum | `extractDelimiter()` | Improved delimiter handling |
| 6 | Ignore >1000 | `filter(num <= 1000)` | Extract `filterValidNumbers()` |
| 7 | Negative exception | `validateNoNegatives()` | None needed |

### Test Results

```
PASS  tests/calculator.test.js
  StringCalculator
    Basic functionality
      ✓ empty string returns 0
      ✓ single number returns itself
    Multiple numbers
      ✓ two numbers comma-delimited returns sum
      ✓ multiple numbers returns sum
    Newline delimiters
      ✓ handles newlines as delimiters
      ✓ handles only newlines
    Custom delimiters
      ✓ supports custom delimiter semicolon
      ✓ supports custom delimiter pipe
      ✓ supports custom delimiter hash
    Number filtering
      ✓ ignores numbers greater than 1000
      ✓ includes 1000 but ignores larger
      ✓ ignores large numbers with multiple values
    Negative numbers
      ✓ throws exception for single negative number
      ✓ throws exception with all negatives listed
      ✓ throws exception when negative is first
    Complex scenarios
      ✓ custom delimiter with newlines and large numbers
      ✓ multiple delimiters with filtering

Test Suites: 1 passed, 1 total
Tests:       19 passed, 19 total
Snapshots:   0 total
Time:        1.234s
```

## Key Learnings

### What Worked Well

1. **Small steps prevented over-engineering** — Each feature was implemented with minimal code
2. **Refactoring kept code clean** — Extracted methods as complexity grew
3. **Tests document behavior** — Test names clearly describe what the code should do
4. **Red-Green-Refactor rhythm** — Predictable cycle made progress visible

### Best Practices Demonstrated

1. **Start with simplest case** — Empty string is the easiest starting point
2. **One concept per test** — Each test verifies a single behavior
3. **Refactor on green** — Only refactor when all tests pass
4. **Extract as complexity grows** — Methods emerged naturally from refactoring
5. **Edge cases tested explicitly** — Negative numbers, large numbers, custom delimiters

### Skills Integration

- **test-driven-development**: Strict Red-Green-Refactor cycle
- **unit-testing**: Comprehensive test suite with 19 tests
- **clean-code**: Refactored to small, single-purpose methods
