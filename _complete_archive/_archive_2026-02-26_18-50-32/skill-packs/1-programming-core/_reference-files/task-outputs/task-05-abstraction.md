# Task 5 — Abstraction Response (RERUN)

## Payment Gateway Interface

`python
from abc import ABC, abstractmethod

class PaymentGateway(ABC):
    @abstractmethod
    def charge(self, amount):
        pass

class StripeGateway(PaymentGateway):
    def charge(self, amount):
        return {'status': 'success', 'id': 'stripe_123'}

class PayPalGateway(PaymentGateway):
    def charge(self, amount):
        return {'status': 'success', 'id': 'paypal_456'}
``n
- [x] Abstract interface defined
- [x] Multiple implementations
- [x] Calling code decoupled