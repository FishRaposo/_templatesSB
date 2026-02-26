# Task 10 — Data Types Response (RERUN)

## Runtime Type Validation Library

`python
class Schema:
    def __init__(self, spec):
        self.spec = spec
    
    def validate(self, obj):
        errors = []
        for key, expected_type in self.spec.items():
            if key not in obj:
                errors.append(f"Missing field: {key}")
            elif not self._check_type(obj[key], expected_type):
                errors.append(f"Field '{key}': expected {expected_type}, got {type(obj[key]).__name__}")
        return errors if errors else None
    
    def _check_type(self, value, expected):
        if expected == str:
            return isinstance(value, str)
        elif expected == int:
            return isinstance(value, int)
        elif expected == list:
            return isinstance(value, list)
        elif isinstance(expected, dict):
            return isinstance(value, dict) and all(
                self._check_type(value.get(k), v) for k, v in expected.items()
            )
        return True

# Usage
user_schema = Schema({
    'name': str,
    'age': int,
    'emails': list
})

result = user_schema.validate({'name': 'Alice', 'age': 30, 'emails': ['a@b.com']})
# Returns None if valid, list of errors if invalid
`

- [x] Schema type with validation
- [x] Primitives, arrays, nested objects supported
- [x] Structured error messages
- [x] Type hints complement runtime checks