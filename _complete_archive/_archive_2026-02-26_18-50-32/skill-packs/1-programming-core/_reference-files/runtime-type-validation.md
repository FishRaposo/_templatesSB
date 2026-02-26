<!-- Generated from task-outputs/task-10-data-types.md -->

# Runtime Type Validation

## Schema API
`python
schema = Schema({'name': str, 'age': int})
errors = schema.validate(data)
`

## Supported Types
- Primitives: str, int, float, bool
- Collections: list, dict
- Nested: Objects with nested schemas