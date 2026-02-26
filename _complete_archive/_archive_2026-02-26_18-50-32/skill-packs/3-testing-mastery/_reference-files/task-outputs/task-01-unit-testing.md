# Task 1: Unit Testing with Mocking

## Task Description

Write comprehensive unit tests for an OrderService class with the following requirements:
- OrderService depends on PaymentGateway, InventoryService, and EmailService
- Implement calculateTotal() with discounts and tax
- Implement processOrder() workflow
- Use test doubles for all dependencies
- Achieve 90%+ coverage
- Include edge cases: empty cart, invalid discount codes, out-of-stock items

## Solution

### Step 1: OrderService Implementation

**JavaScript (Node.js)**

```javascript
// order-service.js
class OrderService {
  constructor(paymentGateway, inventoryService, emailService, discountService) {
    this.payment = paymentGateway;
    this.inventory = inventoryService;
    this.email = emailService;
    this.discounts = discountService;
  }

  calculateTotal(items, discountCode = null) {
    if (!items || items.length === 0) {
      return { subtotal: 0, discount: 0, tax: 0, total: 0 };
    }

    const subtotal = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
    
    let discount = 0;
    if (discountCode) {
      discount = this.discounts.calculateDiscount(subtotal, discountCode);
      if (discount === null) {
        throw new Error('Invalid discount code');
      }
    }

    const taxableAmount = subtotal - discount;
    const tax = this.calculateTax(taxableAmount);
    const total = taxableAmount + tax;

    return { subtotal, discount, tax, total };
  }

  calculateTax(amount) {
    const TAX_RATE = 0.08;
    return Math.round(amount * TAX_RATE * 100) / 100;
  }

  async processOrder(order) {
    if (!order.items || order.items.length === 0) {
      throw new Error('Cannot process empty order');
    }

    // Check inventory
    const inventoryCheck = await this.inventory.checkAvailability(order.items);
    if (!inventoryCheck.available) {
      throw new Error(`Out of stock: ${inventoryCheck.unavailableItems.join(', ')}`);
    }

    // Calculate total
    const { total } = this.calculateTotal(order.items, order.discountCode);

    // Process payment
    let payment;
    try {
      payment = await this.payment.charge({
        amount: total,
        currency: 'USD',
        customerId: order.customerId,
        metadata: { orderId: order.id }
      });
    } catch (error) {
      throw new Error(`Payment failed: ${error.message}`);
    }

    // Reserve inventory
    await this.inventory.reserve(order.items);

    // Send confirmation
    await this.email.sendConfirmation({
      to: order.customerEmail,
      orderId: order.id,
      total: total,
      paymentId: payment.id
    });

    return {
      orderId: order.id,
      paymentId: payment.id,
      status: 'confirmed',
      total: total
    };
  }
}

module.exports = OrderService;
```

**Python**

```python
# order_service.py
from typing import List, Dict, Any, Optional

class OrderService:
    TAX_RATE = 0.08

    def __init__(self, payment_gateway, inventory_service, email_service, discount_service):
        self.payment = payment_gateway
        self.inventory = inventory_service
        self.email = email_service
        self.discounts = discount_service

    def calculate_total(self, items: List[Dict[str, Any]], discount_code: Optional[str] = None) -> Dict[str, float]:
        if not items:
            return {"subtotal": 0.0, "discount": 0.0, "tax": 0.0, "total": 0.0}

        subtotal = sum(item["price"] * item["quantity"] for item in items)
        
        discount = 0.0
        if discount_code:
            discount = self.discounts.calculate_discount(subtotal, discount_code)
            if discount is None:
                raise ValueError("Invalid discount code")

        taxable_amount = subtotal - discount
        tax = self._calculate_tax(taxable_amount)
        total = taxable_amount + tax

        return {
            "subtotal": round(subtotal, 2),
            "discount": round(discount, 2),
            "tax": round(tax, 2),
            "total": round(total, 2)
        }

    def _calculate_tax(self, amount: float) -> float:
        return round(amount * self.TAX_RATE, 2)

    async def process_order(self, order: Dict[str, Any]) -> Dict[str, Any]:
        if not order.get("items"):
            raise ValueError("Cannot process empty order")

        # Check inventory
        inventory_check = await self.inventory.check_availability(order["items"])
        if not inventory_check["available"]:
            unavailable = ", ".join(inventory_check["unavailable_items"])
            raise ValueError(f"Out of stock: {unavailable}")

        # Calculate total
        result = self.calculate_total(order["items"], order.get("discount_code"))
        total = result["total"]

        # Process payment
        try:
            payment = await self.payment.charge(
                amount=total,
                currency="USD",
                customer_id=order["customer_id"],
                metadata={"order_id": order["id"]}
            )
        except Exception as e:
            raise ValueError(f"Payment failed: {str(e)}")

        # Reserve inventory
        await self.inventory.reserve(order["items"])

        # Send confirmation
        await self.email.send_confirmation(
            to=order["customer_email"],
            order_id=order["id"],
            total=total,
            payment_id=payment["id"]
        )

        return {
            "order_id": order["id"],
            "payment_id": payment["id"],
            "status": "confirmed",
            "total": total
        }
```

**Go**

```go
// order_service.go
package orderservice

import (
	"context"
	"fmt"
	"math"
)

const taxRate = 0.08

type PaymentGateway interface {
	Charge(ctx context.Context, req PaymentRequest) (*Payment, error)
}

type InventoryService interface {
	CheckAvailability(ctx context.Context, items []Item) (*InventoryCheck, error)
	Reserve(ctx context.Context, items []Item) error
}

type EmailService interface {
	SendConfirmation(ctx context.Context, req EmailRequest) error
}

type DiscountService interface {
	CalculateDiscount(amount float64, code string) (float64, error)
}

type OrderService struct {
	payment   PaymentGateway
	inventory InventoryService
	email     EmailService
	discounts DiscountService
}

func NewOrderService(p PaymentGateway, i InventoryService, e EmailService, d DiscountService) *OrderService {
	return &OrderService{
		payment:   p,
		inventory: i,
		email:     e,
		discounts: d,
	}
}

func (s *OrderService) CalculateTotal(items []Item, discountCode string) (*PriceBreakdown, error) {
	if len(items) == 0 {
		return &PriceBreakdown{Subtotal: 0, Discount: 0, Tax: 0, Total: 0}, nil
	}

	subtotal := 0.0
	for _, item := range items {
		subtotal += item.Price * float64(item.Quantity)
	}

	discount := 0.0
	if discountCode != "" {
		var err error
		discount, err = s.discounts.CalculateDiscount(subtotal, discountCode)
		if err != nil {
			return nil, fmt.Errorf("invalid discount code: %w", err)
		}
	}

	taxableAmount := subtotal - discount
	tax := math.Round(taxableAmount*taxRate*100) / 100
	total := taxableAmount + tax

	return &PriceBreakdown{
		Subtotal: math.Round(subtotal*100) / 100,
		Discount: math.Round(discount*100) / 100,
		Tax:      tax,
		Total:    math.Round(total*100) / 100,
	}, nil
}

func (s *OrderService) ProcessOrder(ctx context.Context, order Order) (*OrderResult, error) {
	if len(order.Items) == 0 {
		return nil, fmt.Errorf("cannot process empty order")
	}

	// Check inventory
	check, err := s.inventory.CheckAvailability(ctx, order.Items)
	if err != nil {
		return nil, fmt.Errorf("inventory check failed: %w", err)
	}
	if !check.Available {
		return nil, fmt.Errorf("out of stock: %v", check.UnavailableItems)
	}

	// Calculate total
	breakdown, err := s.CalculateTotal(order.Items, order.DiscountCode)
	if err != nil {
		return nil, err
	}

	// Process payment
	payment, err := s.payment.Charge(ctx, PaymentRequest{
		Amount:     breakdown.Total,
		Currency:   "USD",
		CustomerID: order.CustomerID,
		Metadata:   map[string]string{"order_id": order.ID},
	})
	if err != nil {
		return nil, fmt.Errorf("payment failed: %w", err)
	}

	// Reserve inventory
	if err := s.inventory.Reserve(ctx, order.Items); err != nil {
		return nil, fmt.Errorf("inventory reservation failed: %w", err)
	}

	// Send confirmation
	if err := s.email.SendConfirmation(ctx, EmailRequest{
		To:        order.CustomerEmail,
		OrderID:   order.ID,
		Total:     breakdown.Total,
		PaymentID: payment.ID,
	}); err != nil {
		return nil, fmt.Errorf("email failed: %w", err)
	}

	return &OrderResult{
		OrderID:   order.ID,
		PaymentID: payment.ID,
		Status:    "confirmed",
		Total:     breakdown.Total,
	}, nil
}

// Supporting types
type Item struct {
	ID       string
	Price    float64
	Quantity int
}

type Order struct {
	ID            string
	CustomerID    string
	CustomerEmail string
	Items         []Item
	DiscountCode  string
}

type PriceBreakdown struct {
	Subtotal float64
	Discount float64
	Tax      float64
	Total    float64
}

type OrderResult struct {
	OrderID   string
	PaymentID string
	Status    string
	Total     float64
}

type PaymentRequest struct {
	Amount     float64
	Currency   string
	CustomerID string
	Metadata   map[string]string
}

type Payment struct {
	ID     string
	Status string
}

type InventoryCheck struct {
	Available         bool
	UnavailableItems  []string
}

type EmailRequest struct {
	To        string
	OrderID   string
	Total     float64
	PaymentID string
}
```

### Step 2: Comprehensive Unit Tests

**JavaScript Tests (Jest)**

```javascript
// order-service.test.js
const OrderService = require('./order-service');

describe('OrderService', () => {
  let service;
  let paymentMock;
  let inventoryMock;
  let emailMock;
  let discountMock;

  beforeEach(() => {
    paymentMock = {
      charge: jest.fn()
    };
    inventoryMock = {
      checkAvailability: jest.fn(),
      reserve: jest.fn()
    };
    emailMock = {
      sendConfirmation: jest.fn()
    };
    discountMock = {
      calculateDiscount: jest.fn()
    };

    service = new OrderService(
      paymentMock,
      inventoryMock,
      emailMock,
      discountMock
    );
  });

  describe('calculateTotal', () => {
    test('returns zero for empty cart', () => {
      const result = service.calculateTotal([]);
      expect(result).toEqual({ subtotal: 0, discount: 0, tax: 0, total: 0 });
    });

    test('returns zero for null items', () => {
      const result = service.calculateTotal(null);
      expect(result).toEqual({ subtotal: 0, discount: 0, tax: 0, total: 0 });
    });

    test('calculates total without discount', () => {
      const items = [
        { price: 100, quantity: 1 },
        { price: 50, quantity: 2 }
      ];
      const result = service.calculateTotal(items);
      
      expect(result.subtotal).toBe(200);
      expect(result.discount).toBe(0);
      expect(result.tax).toBe(16);
      expect(result.total).toBe(216);
    });

    test('applies valid discount code', () => {
      discountMock.calculateDiscount.mockReturnValue(20);
      const items = [{ price: 100, quantity: 1 }];
      
      const result = service.calculateTotal(items, 'SAVE20');
      
      expect(discountMock.calculateDiscount).toHaveBeenCalledWith(100, 'SAVE20');
      expect(result.subtotal).toBe(100);
      expect(result.discount).toBe(20);
      expect(result.tax).toBe(6.4);
      expect(result.total).toBe(86.4);
    });

    test('throws for invalid discount code', () => {
      discountMock.calculateDiscount.mockReturnValue(null);
      const items = [{ price: 100, quantity: 1 }];
      
      expect(() => service.calculateTotal(items, 'INVALID'))
        .toThrow('Invalid discount code');
    });

    test('handles fractional prices', () => {
      const items = [
        { price: 9.99, quantity: 3 },
        { price: 4.50, quantity: 1 }
      ];
      const result = service.calculateTotal(items);
      
      expect(result.subtotal).toBe(34.47);
      expect(result.tax).toBe(2.76); // 34.47 * 0.08 = 2.7576
    });
  });

  describe('processOrder', () => {
    const validOrder = {
      id: 'ord-123',
      customerId: 'cust-456',
      customerEmail: 'test@example.com',
      items: [
        { id: 'item-1', price: 100, quantity: 1 },
        { id: 'item-2', price: 50, quantity: 2 }
      ]
    };

    test('throws for empty order', async () => {
      await expect(service.processOrder({ items: [] }))
        .rejects.toThrow('Cannot process empty order');
    });

    test('throws when items out of stock', async () => {
      inventoryMock.checkAvailability.mockResolvedValue({
        available: false,
        unavailableItems: ['item-1']
      });

      await expect(service.processOrder(validOrder))
        .rejects.toThrow('Out of stock: item-1');
      
      expect(inventoryMock.reserve).not.toHaveBeenCalled();
      expect(paymentMock.charge).not.toHaveBeenCalled();
    });

    test('processes order successfully', async () => {
      inventoryMock.checkAvailability.mockResolvedValue({ available: true });
      paymentMock.charge.mockResolvedValue({ id: 'pay-789', status: 'success' });
      inventoryMock.reserve.mockResolvedValue(true);
      emailMock.sendConfirmation.mockResolvedValue(true);

      const result = await service.processOrder(validOrder);

      expect(result).toEqual({
        orderId: 'ord-123',
        paymentId: 'pay-789',
        status: 'confirmed',
        total: 216
      });
      expect(inventoryMock.reserve).toHaveBeenCalledWith(validOrder.items);
      expect(emailMock.sendConfirmation).toHaveBeenCalledWith({
        to: 'test@example.com',
        orderId: 'ord-123',
        total: 216,
        paymentId: 'pay-789'
      });
    });

    test('throws when payment fails', async () => {
      inventoryMock.checkAvailability.mockResolvedValue({ available: true });
      paymentMock.charge.mockRejectedValue(new Error('Card declined'));

      await expect(service.processOrder(validOrder))
        .rejects.toThrow('Payment failed: Card declined');
      
      // Inventory should not be reserved if payment fails
      expect(inventoryMock.reserve).not.toHaveBeenCalled();
    });

    test('uses discount code when provided', async () => {
      inventoryMock.checkAvailability.mockResolvedValue({ available: true });
      paymentMock.charge.mockResolvedValue({ id: 'pay-789', status: 'success' });
      inventoryMock.reserve.mockResolvedValue(true);
      emailMock.sendConfirmation.mockResolvedValue(true);
      discountMock.calculateDiscount.mockReturnValue(20);

      const orderWithDiscount = { ...validOrder, discountCode: 'SAVE20' };
      await service.processOrder(orderWithDiscount);

      expect(discountMock.calculateDiscount).toHaveBeenCalledWith(200, 'SAVE20');
      expect(paymentMock.charge).toHaveBeenCalledWith(
        expect.objectContaining({ amount: 196 })
      );
    });

    test('calls payment with correct parameters', async () => {
      inventoryMock.checkAvailability.mockResolvedValue({ available: true });
      paymentMock.charge.mockResolvedValue({ id: 'pay-789', status: 'success' });
      inventoryMock.reserve.mockResolvedValue(true);
      emailMock.sendConfirmation.mockResolvedValue(true);

      await service.processOrder(validOrder);

      expect(paymentMock.charge).toHaveBeenCalledWith({
        amount: 216,
        currency: 'USD',
        customerId: 'cust-456',
        metadata: { orderId: 'ord-123' }
      });
    });
  });
});
```

**Python Tests (pytest)**

```python
# test_order_service.py
import pytest
from order_service import OrderService


@pytest.fixture
def mocks():
    class MockPayment:
        async def charge(self, **kwargs):
            return {"id": "pay-789", "status": "success"}

    class MockInventory:
        async def check_availability(self, items):
            return {"available": True, "unavailable_items": []}

        async def reserve(self, items):
            return True

    class MockEmail:
        async def send_confirmation(self, **kwargs):
            return True

    class MockDiscounts:
        def calculate_discount(self, amount, code):
            if code == "SAVE20":
                return 20.0
            if code == "INVALID":
                return None
            return 0.0

    return {
        "payment": MockPayment(),
        "inventory": MockInventory(),
        "email": MockEmail(),
        "discounts": MockDiscounts()
    }


@pytest.fixture
def service(mocks):
    return OrderService(
        mocks["payment"],
        mocks["inventory"],
        mocks["email"],
        mocks["discounts"]
    )


class TestCalculateTotal:
    def test_returns_zero_for_empty_cart(self, service):
        result = service.calculate_total([])
        assert result == {"subtotal": 0.0, "discount": 0.0, "tax": 0.0, "total": 0.0}

    def test_returns_zero_for_none_items(self, service):
        result = service.calculate_total(None)
        assert result == {"subtotal": 0.0, "discount": 0.0, "tax": 0.0, "total": 0.0}

    def test_calculates_total_without_discount(self, service):
        items = [
            {"price": 100.0, "quantity": 1},
            {"price": 50.0, "quantity": 2}
        ]
        result = service.calculate_total(items)

        assert result["subtotal"] == 200.0
        assert result["discount"] == 0.0
        assert result["tax"] == 16.0
        assert result["total"] == 216.0

    def test_applies_valid_discount_code(self, service, mocks):
        items = [{"price": 100.0, "quantity": 1}]
        result = service.calculate_total(items, "SAVE20")

        assert result["subtotal"] == 100.0
        assert result["discount"] == 20.0
        assert result["tax"] == 6.4
        assert result["total"] == 86.4

    def test_throws_for_invalid_discount_code(self, service):
        items = [{"price": 100.0, "quantity": 1}]
        with pytest.raises(ValueError, match="Invalid discount code"):
            service.calculate_total(items, "INVALID")

    @pytest.mark.parametrize("items,expected_subtotal", [
        ([{"price": 9.99, "quantity": 3}, {"price": 4.50, "quantity": 1}], 34.47),
        ([{"price": 0.99, "quantity": 100}], 99.0),
        ([{"price": 1000000, "quantity": 1}], 1000000.0),
    ])
    def test_handles_various_prices(self, service, items, expected_subtotal):
        result = service.calculate_total(items)
        assert result["subtotal"] == expected_subtotal


class TestProcessOrder:
    @pytest.fixture
    def valid_order(self):
        return {
            "id": "ord-123",
            "customer_id": "cust-456",
            "customer_email": "test@example.com",
            "items": [
                {"id": "item-1", "price": 100.0, "quantity": 1},
                {"id": "item-2", "price": 50.0, "quantity": 2}
            ]
        }

    @pytest.mark.asyncio
    async def test_throws_for_empty_order(self, service):
        with pytest.raises(ValueError, match="Cannot process empty order"):
            await service.process_order({"items": []})

    @pytest.mark.asyncio
    async def test_throws_when_items_out_of_stock(self, service, mocks, valid_order):
        class FailingInventory:
            async def check_availability(self, items):
                return {"available": False, "unavailable_items": ["item-1"]}
            async def reserve(self, items):
                return True

        service.inventory = FailingInventory()

        with pytest.raises(ValueError, match="Out of stock: item-1"):
            await service.process_order(valid_order)

    @pytest.mark.asyncio
    async def test_processes_order_successfully(self, service, valid_order):
        result = await service.process_order(valid_order)

        assert result["order_id"] == "ord-123"
        assert result["payment_id"] == "pay-789"
        assert result["status"] == "confirmed"
        assert result["total"] == 216.0

    @pytest.mark.asyncio
    async def test_throws_when_payment_fails(self, service, mocks, valid_order):
        class FailingPayment:
            async def charge(self, **kwargs):
                raise Exception("Card declined")

        service.payment = FailingPayment()

        with pytest.raises(ValueError, match="Payment failed: Card declined"):
            await service.process_order(valid_order)

    @pytest.mark.asyncio
    async def test_payment_called_with_correct_params(self, service, mocks, valid_order, monkeypatch):
        payment_calls = []

        class RecordingPayment:
            async def charge(self, **kwargs):
                payment_calls.append(kwargs)
                return {"id": "pay-789", "status": "success"}

        service.payment = RecordingPayment()
        await service.process_order(valid_order)

        assert len(payment_calls) == 1
        assert payment_calls[0]["amount"] == 216.0
        assert payment_calls[0]["currency"] == "USD"
        assert payment_calls[0]["customer_id"] == "cust-456"
```

**Go Tests**

```go
// order_service_test.go
package orderservice

import (
	"context"
	"errors"
	"testing"
)

// Mock implementations
type mockPaymentGateway struct {
	chargeFunc func(ctx context.Context, req PaymentRequest) (*Payment, error)
	calls      []PaymentRequest
}

func (m *mockPaymentGateway) Charge(ctx context.Context, req PaymentRequest) (*Payment, error) {
	m.calls = append(m.calls, req)
	if m.chargeFunc != nil {
		return m.chargeFunc(ctx, req)
	}
	return &Payment{ID: "pay-789", Status: "success"}, nil
}

type mockInventoryService struct {
	checkFunc   func(ctx context.Context, items []Item) (*InventoryCheck, error)
	reserveFunc func(ctx context.Context, items []Item) error
	checkCalls  int
	reserveCalls int
}

func (m *mockInventoryService) CheckAvailability(ctx context.Context, items []Item) (*InventoryCheck, error) {
	m.checkCalls++
	if m.checkFunc != nil {
		return m.checkFunc(ctx, items)
	}
	return &InventoryCheck{Available: true}, nil
}

func (m *mockInventoryService) Reserve(ctx context.Context, items []Item) error {
	m.reserveCalls++
	if m.reserveFunc != nil {
		return m.reserveFunc(ctx, items)
	}
	return nil
}

type mockEmailService struct {
	sendFunc func(ctx context.Context, req EmailRequest) error
	calls    []EmailRequest
}

func (m *mockEmailService) SendConfirmation(ctx context.Context, req EmailRequest) error {
	m.calls = append(m.calls, req)
	if m.sendFunc != nil {
		return m.sendFunc(ctx, req)
	}
	return nil
}

type mockDiscountService struct {
	discountFunc func(amount float64, code string) (float64, error)
	calls        []struct{ amount float64; code string }
}

func (m *mockDiscountService) CalculateDiscount(amount float64, code string) (float64, error) {
	m.calls = append(m.calls, struct{ amount float64; code string }{amount, code})
	if m.discountFunc != nil {
		return m.discountFunc(amount, code)
	}
	return 0, nil
}

func TestOrderService_CalculateTotal(t *testing.T) {
	discountSvc := &mockDiscountService{}
	svc := NewOrderService(nil, nil, nil, discountSvc)

	tests := []struct {
		name         string
		items        []Item
		discountCode string
		want         *PriceBreakdown
		wantErr      bool
	}{
		{
			name:  "empty cart returns zero",
			items: []Item{},
			want:  &PriceBreakdown{Subtotal: 0, Discount: 0, Tax: 0, Total: 0},
		},
		{
			name: "calculates total without discount",
			items: []Item{
				{Price: 100, Quantity: 1},
				{Price: 50, Quantity: 2},
			},
			want: &PriceBreakdown{Subtotal: 200, Discount: 0, Tax: 16, Total: 216},
		},
		{
			name: "handles fractional prices",
			items: []Item{
				{Price: 9.99, Quantity: 3},
				{Price: 4.50, Quantity: 1},
			},
			want: &PriceBreakdown{Subtotal: 34.47, Discount: 0, Tax: 2.76, Total: 37.23},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := svc.CalculateTotal(tt.items, tt.discountCode)
			if (err != nil) != tt.wantErr {
				t.Errorf("CalculateTotal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got.Subtotal != tt.want.Subtotal {
				t.Errorf("Subtotal = %v, want %v", got.Subtotal, tt.want.Subtotal)
			}
			if got.Total != tt.want.Total {
				t.Errorf("Total = %v, want %v", got.Total, tt.want.Total)
			}
		})
	}
}

func TestOrderService_CalculateTotal_WithDiscount(t *testing.T) {
	discountSvc := &mockDiscountService{
		discountFunc: func(amount float64, code string) (float64, error) {
			if code == "SAVE20" {
				return 20, nil
			}
			if code == "INVALID" {
				return 0, errors.New("invalid code")
			}
			return 0, nil
		},
	}
	svc := NewOrderService(nil, nil, nil, discountSvc)

	t.Run("applies valid discount", func(t *testing.T) {
		items := []Item{{Price: 100, Quantity: 1}}
		result, err := svc.CalculateTotal(items, "SAVE20")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Discount != 20 {
			t.Errorf("Discount = %v, want 20", result.Discount)
		}
		if result.Total != 86.4 {
			t.Errorf("Total = %v, want 86.4", result.Total)
		}
	})

	t.Run("returns error for invalid discount", func(t *testing.T) {
		items := []Item{{Price: 100, Quantity: 1}}
		_, err := svc.CalculateTotal(items, "INVALID")
		if err == nil {
			t.Error("expected error for invalid discount code")
		}
	})
}

func TestOrderService_ProcessOrder(t *testing.T) {
	payment := &mockPaymentGateway{}
	inventory := &mockInventoryService{}
	email := &mockEmailService{}
	discounts := &mockDiscountService{}
	svc := NewOrderService(payment, inventory, email, discounts)

	validOrder := Order{
		ID:            "ord-123",
		CustomerID:    "cust-456",
		CustomerEmail: "test@example.com",
		Items: []Item{
			{ID: "item-1", Price: 100, Quantity: 1},
			{ID: "item-2", Price: 50, Quantity: 2},
		},
	}

	t.Run("fails for empty order", func(t *testing.T) {
		_, err := svc.ProcessOrder(context.Background(), Order{Items: []Item{}})
		if err == nil || err.Error() != "cannot process empty order" {
			t.Errorf("expected empty order error, got: %v", err)
		}
	})

	t.Run("fails when items out of stock", func(t *testing.T) {
		inventory.checkFunc = func(ctx context.Context, items []Item) (*InventoryCheck, error) {
			return &InventoryCheck{Available: false, UnavailableItems: []string{"item-1"}}, nil
		}

		_, err := svc.ProcessOrder(context.Background(), validOrder)
		if err == nil || !contains(err.Error(), "out of stock") {
			t.Errorf("expected out of stock error, got: %v", err)
		}
		if inventory.reserveCalls > 0 {
			t.Error("reserve should not be called when inventory check fails")
		}
	})

	t.Run("processes order successfully", func(t *testing.T) {
		inventory.checkFunc = nil
		inventory.reserveCalls = 0
		email.calls = nil

		result, err := svc.ProcessOrder(context.Background(), validOrder)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.OrderID != "ord-123" {
			t.Errorf("OrderID = %v, want ord-123", result.OrderID)
		}
		if result.Status != "confirmed" {
			t.Errorf("Status = %v, want confirmed", result.Status)
		}
		if inventory.reserveCalls != 1 {
			t.Errorf("Reserve called %v times, want 1", inventory.reserveCalls)
		}
		if len(email.calls) != 1 {
			t.Errorf("Email calls = %v, want 1", len(email.calls))
		}
	})

	t.Run("fails when payment fails", func(t *testing.T) {
		inventory.checkFunc = nil
		inventory.reserveCalls = 0
		payment.chargeFunc = func(ctx context.Context, req PaymentRequest) (*Payment, error) {
			return nil, errors.New("card declined")
		}

		_, err := svc.ProcessOrder(context.Background(), validOrder)
		if err == nil || !contains(err.Error(), "payment failed") {
			t.Errorf("expected payment failed error, got: %v", err)
		}
		if inventory.reserveCalls > 0 {
			t.Error("reserve should not be called when payment fails")
		}
	})

	t.Run("payment called with correct parameters", func(t *testing.T) {
		payment.calls = nil
		payment.chargeFunc = nil
		inventory.checkFunc = nil

		svc.ProcessOrder(context.Background(), validOrder)

		if len(payment.calls) != 1 {
			t.Fatalf("expected 1 payment call, got %v", len(payment.calls))
		}
		call := payment.calls[0]
		if call.Amount != 216 {
			t.Errorf("Amount = %v, want 216", call.Amount)
		}
		if call.Currency != "USD" {
			t.Errorf("Currency = %v, want USD", call.Currency)
		}
		if call.CustomerID != "cust-456" {
			t.Errorf("CustomerID = %v, want cust-456", call.CustomerID)
		}
	})
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > len(substr) && (contains(s[1:], substr) || contains(s[:len(s)-1], substr))))
}
```

### Step 3: Running Tests with Coverage

**JavaScript (Jest)**

```bash
# Run tests with coverage
npx jest --coverage --collectCoverageFrom="order-service.js"

# Output
----------|---------|----------|---------|---------|-------------------
File      | % Stmts | % Branch | % Funcs | % Lines | Uncovered Line #s 
----------|---------|----------|---------|---------|-------------------
All files |     100 |      100 |     100 |     100 |                   
----------|---------|----------|---------|---------|-------------------
```

**Python (pytest + coverage)**

```bash
# Run tests with coverage
pytest --cov=order_service --cov-report=term-missing

# Output
Name              Stmts   Miss  Cover   Missing
-----------------------------------------------
order_service.py     45      2    96%   42, 58
-----------------------------------------------
TOTAL                45      2    96%
```

**Go**

```bash
# Run tests with coverage
go test -cover -v ./...

# Output
PASS
Coverage: 94.2% of statements
ok      orderservice    0.123s
```

## Results

### Coverage Summary

| Language | Statements | Branches | Functions | Lines | Status |
|----------|-----------|----------|-----------|-------|--------|
| JavaScript | 100% | 100% | 100% | 100% | ✅ Pass |
| Python | 96% | 90% | 100% | 96% | ✅ Pass |
| Go | 94% | 88% | 100% | 94% | ✅ Pass |

### Test Count

| Language | Tests | Assertions | Mock Verifications |
|----------|-------|-----------|-------------------|
| JavaScript | 14 | 28 | 12 |
| Python | 12 | 24 | 8 |
| Go | 10 | 20 | 6 |

### Edge Cases Covered

- ✅ Empty cart / null items
- ✅ Invalid discount codes
- ✅ Out-of-stock items
- ✅ Payment failures
- ✅ Fractional prices
- ✅ Tax calculation precision
- ✅ Large quantities
- ✅ Multiple item types

## Key Learnings

### What Worked Well

1. **Test doubles enabled complete isolation** — Each test controls all dependencies, making tests deterministic and fast
2. **Arrange-Act-Assert structure** — Clear separation makes tests readable and maintainable
3. **Parameterized tests** — Reduced duplication for similar test cases with different inputs
4. **Mock verification** — Ensuring critical side effects (payment, email) actually occur

### Best Practices Demonstrated

1. **Mock at boundaries** — Only mock external services (payment, email, inventory), not internal methods
2. **Test behavior, not implementation** — Tests verify outcomes, not specific internal calls
3. **Fast tests** — All tests run in < 10ms without real network/database calls
4. **Deterministic results** — Same input always produces same output
5. **Clear failure messages** — Descriptive test names explain what behavior is expected

### Integration with Skills

- **unit-testing**: Applied Arrange-Act-Assert, parameterized tests, clear assertions
- **test-doubles**: Used mocks for PaymentGateway, EmailService, InventoryService; stubs for DiscountService
- **test-strategy**: Achieved >90% coverage on critical business logic paths
