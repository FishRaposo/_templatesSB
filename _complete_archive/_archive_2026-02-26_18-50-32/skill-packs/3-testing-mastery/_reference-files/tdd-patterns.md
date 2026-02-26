<!-- Generated from task-outputs/task-04-tdd-calculator.md -->

# TDD String Calculator - Red-Green-Refactor Cycle

A complete walkthrough of Test-Driven Development implementing a String Calculator with step-by-step Red-Green-Refactor cycles.

## Overview

This guide demonstrates TDD through 7 incremental steps:
1. Empty string returns 0
2. Single number returns itself
3. Two numbers comma-delimited returns sum
4. Handle newlines as delimiters
5. Support custom delimiters
6. Ignore numbers > 1000
7. Throw exception for negative numbers

## The TDD Cycle

```
RED  → Write failing test
GREEN → Write minimal code to pass
REFACTOR → Clean up while keeping tests green
   ↓
Repeat
```

## Step 1: Empty String Returns 0

**RED: Failing Test**

```javascript
// tests/calculator.test.js
describe('StringCalculator', () => {
  const calculator = new (require('../src/calculator'))();

  test('empty string returns 0', () => {
    expect(calculator.add('')).toBe(0);
  });
});
```

**GREEN: Minimal Code**

```javascript
// src/calculator.js
class StringCalculator {
  add(numbers) {
    return 0;  // Minimal code to pass
  }
}

module.exports = StringCalculator;
```

**Result**: ✅ Test passes

## Step 2: Single Number Returns Itself

**RED: Failing Test**

```javascript
test('single number returns itself', () => {
  expect(calculator.add('5')).toBe(5);
});
```

**GREEN: Minimal Code**

```javascript
add(numbers) {
  if (numbers === '') {
    return 0;
  }
  return parseInt(numbers, 10);
}
```

## Step 3: Two Numbers Comma-Delimited

**RED: Failing Test**

```javascript
test('two numbers comma-delimited returns sum', () => {
  expect(calculator.add('1,2')).toBe(3);
});
```

**GREEN: Minimal Code**

```javascript
add(numbers) {
  if (numbers === '') return 0;
  
  if (numbers.includes(',')) {
    const parts = numbers.split(',');
    return parseInt(parts[0], 10) + parseInt(parts[1], 10);
  }
  
  return parseInt(numbers, 10);
}
```

**REFACTOR: Generalize for N numbers**

```javascript
add(numbers) {
  if (numbers === '') return 0;
  
  const parts = numbers.split(',');
  return parts.reduce((sum, num) => sum + parseInt(num, 10), 0);
}
```

## Step 4: Handle Newlines

**RED: Failing Test**

```javascript
test('handles newlines as delimiters', () => {
  expect(calculator.add('1\n2,3')).toBe(6);
});
```

**GREEN: Replace newlines with commas**

```javascript
add(numbers) {
  if (numbers === '') return 0;
  
  const normalized = numbers.replace(/\n/g, ',');
  const parts = normalized.split(',');
  return parts.reduce((sum, num) => sum + parseInt(num, 10), 0);
}
```

## Step 5: Custom Delimiters

**RED: Failing Test**

```javascript
test('supports custom delimiter ;', () => {
  expect(calculator.add('//;\n1;2')).toBe(3);
});
```

**GREEN: Parse custom delimiter**

```javascript
add(numbers) {
  if (numbers === '') return 0;
  
  let delimiter = ',';
  let numberString = numbers;
  
  if (numbers.startsWith('//')) {
    const delimiterEnd = numbers.indexOf('\n');
    delimiter = numbers.substring(2, delimiterEnd);
    numberString = numbers.substring(delimiterEnd + 1);
  }
  
  const normalized = numberString.replace(/\n/g, delimiter);
  return normalized.split(delimiter).reduce((sum, num) => sum + parseInt(num, 10), 0);
}
```

## Step 6: Ignore Numbers > 1000

**RED: Failing Test**

```javascript
test('ignores numbers greater than 1000', () => {
  expect(calculator.add('2,1001')).toBe(2);
});
```

**GREEN: Filter large numbers**

```javascript
add(numbers) {
  // ... setup code ...
  
  return normalized
    .split(delimiter)
    .map(num => parseInt(num, 10))
    .filter(num => num <= 1000)  // Filter out numbers > 1000
    .reduce((sum, num) => sum + num, 0);
}
```

## Step 7: Negative Numbers Exception

**RED: Failing Test**

```javascript
test('throws exception for negative numbers', () => {
  expect(() => calculator.add('-1,2')).toThrow('negatives not allowed: -1');
});
```

**GREEN: Validate and throw**

```javascript
add(numbers) {
  // ... setup code ...
  
  const parsed = normalized
    .split(delimiter)
    .map(num => parseInt(num, 10));
  
  const negatives = parsed.filter(num => num < 0);
  if (negatives.length > 0) {
    throw new Error(`negatives not allowed: ${negatives.join(',')}`);
  }
  
  return parsed
    .filter(num => num <= 1000)
    .reduce((sum, num) => sum + num, 0);
}
```

## Final Implementation

```javascript
// src/calculator.js
class StringCalculator {
  add(numbers) {
    if (numbers === '') return 0;
    
    const { delimiter, numberString } = this.extractDelimiter(numbers);
    const parts = this.parseNumbers(numberString, delimiter);
    
    this.validateNoNegatives(parts);
    
    return parts
      .filter(num => num <= 1000)
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

  validateNoNegatives(numbers) {
    const negatives = numbers.filter(num => num < 0);
    if (negatives.length > 0) {
      throw new Error(`negatives not allowed: ${negatives.join(',')}`);
    }
  }
}

module.exports = StringCalculator;
```

## Complete Test Suite

```javascript
// tests/calculator.test.js
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
    });

    test('multiple numbers returns sum', () => {
      expect(calculator.add('1,2,3,4,5')).toBe(15);
    });
  });

  describe('Newline delimiters', () => {
    test('handles newlines as delimiters', () => {
      expect(calculator.add('1\n2,3')).toBe(6);
    });
  });

  describe('Custom delimiters', () => {
    test('supports custom delimiter semicolon', () => {
      expect(calculator.add('//;\n1;2')).toBe(3);
    });

    test('supports custom delimiter pipe', () => {
      expect(calculator.add('//|\n1|2|3')).toBe(6);
    });
  });

  describe('Number filtering', () => {
    test('ignores numbers greater than 1000', () => {
      expect(calculator.add('2,1001')).toBe(2);
    });

    test('includes 1000 but ignores larger', () => {
      expect(calculator.add('1000,1001,2')).toBe(1002);
    });
  });

  describe('Negative numbers', () => {
    test('throws exception for single negative', () => {
      expect(() => calculator.add('-1,2')).toThrow('negatives not allowed: -1');
    });

    test('throws exception with all negatives listed', () => {
      expect(() => calculator.add('2,-4,-5')).toThrow('negatives not allowed: -4,-5');
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
| 4 | Newlines → sum | `replace('\n', ',')` | Extracted parseNumbers() |
| 5 | Custom delimiter → sum | `extractDelimiter()` | Improved delimiter handling |
| 6 | Ignore >1000 | `filter(num <= 1000)` | Extracted filterValidNumbers() |
| 7 | Negative exception | `validateNoNegatives()` | None needed |

## Test Results

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
    Custom delimiters
      ✓ supports custom delimiter semicolon
      ✓ supports custom delimiter pipe
    Number filtering
      ✓ ignores numbers greater than 1000
      ✓ includes 1000 but ignores larger
    Negative numbers
      ✓ throws exception for single negative
      ✓ throws exception with all negatives listed

Test Suites: 1 passed, 1 total
Tests:       19 passed, 19 total
```

## Key Learnings

1. **Small steps prevent over-engineering** — Each feature was implemented with minimal code
2. **Refactoring kept code clean** — Extracted methods as complexity grew
3. **Tests document behavior** — Test names clearly describe what the code should do
4. **Red-Green-Refactor rhythm** — Predictable cycle made progress visible
