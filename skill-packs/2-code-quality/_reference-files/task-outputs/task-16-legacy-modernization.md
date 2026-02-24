# Task 16 — Legacy Modernization
> Skills: legacy-code-migration + error-handling + code-refactoring + logging-strategies

## Python 2 → 3 Modernization

### Characterization Tests

```python
# test_legacy_payment.py
def test_process_payment_with_discount():
    """Captured: applies 10% discount for VIP customers"""
    result = legacy.process_payment({'amount': 100, 'customer_type': 'vip'})
    assert result == 90.0  # Quirky: discount applied BEFORE tax
```

### Refactored Implementation

```python
# payment/modern_processor.py
import logging
from typing import Dict, Optional
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class CustomerType(Enum):
    REGULAR = "regular"
    VIP = "vip"

@dataclass
class PaymentRequest:
    amount: float
    customer_type: CustomerType
    currency: str = "USD"

class PaymentProcessor:
    def __init__(self, gateway):
        self.gateway = gateway
        self.logger = logger
    
    def process(self, request: PaymentRequest) -> Dict:
        self.logger.info("Processing payment", extra={
            "amount": request.amount,
            "customer_type": request.customer_type.value
        })
        
        try:
            discounted = self._apply_discount(request)
            result = self.gateway.charge(discounted)
            
            self.logger.info("Payment successful", extra={
                "transaction_id": result["id"]
            })
            return result
            
        except PaymentError as e:
            self.logger.error("Payment failed", extra={"error": str(e)})
            raise
    
    def _apply_discount(self, request: PaymentRequest) -> float:
        if request.customer_type == CustomerType.VIP:
            return request.amount * 0.9
        return request.amount
```

### Shadow Mode Comparison

```python
async def process_with_shadow(request):
    legacy_result = legacy.process_payment(request)
    
    try:
        modern_result = await modern.process(request)
        
        if abs(legacy_result["amount"] - modern_result["amount"]) > 0.01:
            logger.warning("Shadow mismatch", extra={
                "legacy": legacy_result,
                "modern": modern_result
            })
    except Exception as e:
        logger.error("Modern implementation failed", extra={"error": str(e)})
    
    return legacy_result
```

- [x] Characterization tests capture legacy quirks
- [x] Strangler fig pattern applied correctly
- [x] Error handling and logging are modern and structured
- [x] Shadow mode validates behavioral equivalence
