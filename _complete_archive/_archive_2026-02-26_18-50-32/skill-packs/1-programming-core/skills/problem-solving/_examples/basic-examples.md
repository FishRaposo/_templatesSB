# Problem Solving Examples

## Two Sum Problem

**JavaScript:**
```javascript
function twoSum(nums, target) {
    const seen = new Map();
    for (let i = 0; i < nums.length; i++) {
        const complement = target - nums[i];
        if (seen.has(complement)) return [seen.get(complement), i];
        seen.set(nums[i], i);
    }
    return [];
}
console.log(twoSum([2, 7, 11, 15], 9)); // [0, 1]
```

**Python:**
```python
def two_sum(nums, target):
    seen = {}
    for i, n in enumerate(nums):
        complement = target - n
        if complement in seen:
            return [seen[complement], i]
        seen[n] = i
    return []

print(two_sum([2, 7, 11, 15], 9))  # [0, 1]
```

## FizzBuzz Problem

**JavaScript:**
```javascript
function fizzBuzz(n) {
    return Array.from({ length: n }, (_, i) => {
        const num = i + 1;
        if (num % 15 === 0) return 'FizzBuzz';
        if (num % 3 === 0) return 'Fizz';
        if (num % 5 === 0) return 'Buzz';
        return String(num);
    });
}
```

**Python:**
```python
def fizz_buzz(n):
    return [
        "FizzBuzz" if i % 15 == 0 else
        "Fizz" if i % 3 == 0 else
        "Buzz" if i % 5 == 0 else
        str(i)
        for i in range(1, n + 1)
    ]

print(fizz_buzz(15))
```

## When to Use
- Solve this coding problem efficiently
- Debug this algorithm issue
- Design a solution for complex requirements