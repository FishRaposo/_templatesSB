<!-- Generated from task-outputs/task-18-recursive-system.md -->

# JSON Query Engine

## Query Syntax
- users[*].name: Array wildcard
- users[?age>18]: Filter
- orders[0].amount: Index

## Implementation
Recursive descent parser with traversal.