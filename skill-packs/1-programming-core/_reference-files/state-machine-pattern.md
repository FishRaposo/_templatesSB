<!-- Generated from task-outputs/task-11-control-flow.md -->

# State Machine Pattern

## Order Lifecycle
`
CREATED ? PAID ? SHIPPED ? DELIVERED
     ?       ?
     CANCELLED
`

## Guard Clauses
Replace nested if/else with early returns.

## Implementation
Enum states with transition validation.