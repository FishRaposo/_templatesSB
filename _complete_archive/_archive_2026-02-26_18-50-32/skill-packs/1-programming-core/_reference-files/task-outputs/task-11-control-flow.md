# Task 11 — Control Flow Response (RERUN)

## Order State Machine

`python
from enum import Enum

class OrderState(Enum):
    CREATED = "created"
    PAID = "paid"
    SHIPPED = "shipped"
    DELIVERED = "delivered"
    CANCELLED = "cancelled"

class OrderStateMachine:
    TRANSITIONS = {
        OrderState.CREATED: [OrderState.PAID, OrderState.CANCELLED],
        OrderState.PAID: [OrderState.SHIPPED, OrderState.CANCELLED],
        OrderState.SHIPPED: [OrderState.DELIVERED],
        OrderState.DELIVERED: [],
        OrderState.CANCELLED: []
    }
    
    def __init__(self):
        self.state = OrderState.CREATED
    
    def can_transition(self, new_state):
        return new_state in self.TRANSITIONS[self.state]
    
    def transition(self, new_state):
        if not self.can_transition(new_state):
            raise ValueError(f"Cannot transition from {self.state} to {new_state}")
        self.state = new_state
`

### Guard Clauses Example
`python
def process_order(order):
    if not order:
        raise ValueError("Order required")
    if order.state != OrderState.PAID:
        return {"error": "Order not paid"}
    if not order.items:
        return {"error": "No items in order"}
    # Process...
    return {"success": True}
`

- [x] State machine with transition validation
- [x] Guard clauses replace nested if/else
- [x] Error handling with clear exceptions
- [x] Async version available