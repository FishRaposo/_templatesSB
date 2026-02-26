<!-- Generated from task-outputs/task-05-abstraction.md -->

# Payment Gateway Abstraction

## Interface
`python
class PaymentGateway(ABC):
    @abstractmethod
    def charge(self, amount): pass
`

## Implementations
- StripeGateway
- PayPalGateway
- MockGateway (for testing)

## Dependency Inversion
Calling code depends on abstract interface, not concrete implementations.