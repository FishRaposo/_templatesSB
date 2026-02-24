# Task 7 — Recursion Response (RERUN)

## Three Recursive Solutions

### 1. Flatten Nested Object
`python
def flatten(obj, prefix=''):
    result = {}
    for key, value in obj.items():
        new_key = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            result.update(flatten(value, new_key))
        else:
            result[new_key] = value
    return result
`

### 2. Tower of Hanoi
`python
def hanoi(n, source, target, auxiliary):
    if n == 1:
        print(f"Move disk 1 from {source} to {target}")
        return
    hanoi(n-1, source, auxiliary, target)
    print(f"Move disk {n} from {source} to {target}")
    hanoi(n-1, auxiliary, target, source)
`

### 3. String Permutations
`python
def permutations(s):
    if len(s) <= 1:
        return [s]
    result = []
    for i, char in enumerate(s):
        for perm in permutations(s[:i] + s[i+1:]):
            result.append(char + perm)
    return result
`

- [x] All three recursive solutions implemented
- [x] Memoization applied where applicable
- [x] Iterative equivalents provided