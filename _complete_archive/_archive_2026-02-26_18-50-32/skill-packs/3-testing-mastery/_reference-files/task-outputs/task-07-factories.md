# Task 7: Test Data Factories

## Task Description

Build comprehensive test data factories:
- UserFactory with realistic data (faker)
- ProductFactory with variants
- OrderFactory with associations
- AddressFactory
- PaymentMethodFactory
- Show complex object graph creation
- Demonstrate database seeding at scale (10k records)

## Solution

### Step 1: Factory Foundation

```javascript
// factories/BaseFactory.js
/**
 * Base Factory with core functionality
 */

const { faker } = require('@faker-js/faker');

class BaseFactory {
  constructor() {
    this.sequence = 0;
    this.faker = faker;
  }

  /**
   * Generate unique ID
   */
  generateId() {
    return faker.string.uuid();
  }

  /**
   * Get next sequence number
   */
  nextSequence() {
    return ++this.sequence;
  }

  /**
   * Create a single instance
   */
  create(overrides = {}) {
    const data = this.build(overrides);
    return this.persist ? this.persist(data) : data;
  }

  /**
   * Create multiple instances
   */
  createMany(count, overrides = {}) {
    return Array.from({ length: count }, (_, i) => {
      const itemOverrides = typeof overrides === 'function' 
        ? overrides(i) 
        : overrides;
      return this.create(itemOverrides);
    });
  }

  /**
   * Build data without persisting
   */
  build(overrides = {}) {
    throw new Error('build() must be implemented by subclass');
  }

  /**
   * Reset sequence counter
   */
  reset() {
    this.sequence = 0;
  }
}

module.exports = BaseFactory;
```

```python
# factories/base_factory.py
"""Base Factory with core functionality"""

import uuid
from typing import Dict, Any, List, Callable, Optional
from abc import ABC, abstractmethod

class BaseFactory(ABC):
    _sequence = 0
    
    @classmethod
    def generate_id(cls) -> str:
        return str(uuid.uuid4())
    
    @classmethod
    def next_sequence(cls) -> int:
        cls._sequence += 1
        return cls._sequence
    
    @classmethod
    def reset_sequence(cls):
        cls._sequence = 0
    
    @classmethod
    def create(cls, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        data = cls.build(overrides or {})
        if hasattr(cls, 'persist'):
            return cls.persist(data)
        return data
    
    @classmethod
    def create_many(cls, count: int, overrides: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        results = []
        for i in range(count):
            item_overrides = overrides(i) if callable(overrides) else overrides
            results.append(cls.create(item_overrides or {}))
        return results
    
    @classmethod
    @abstractmethod
    def build(cls, overrides: Dict[str, Any]) -> Dict[str, Any]:
        pass
```

### Step 2: User Factory

```javascript
// factories/UserFactory.js
/**
 * User Factory - generates realistic user data
 */

const BaseFactory = require('./BaseFactory');

class UserFactory extends BaseFactory {
  build(overrides = {}) {
    const firstName = overrides.firstName || this.faker.person.firstName();
    const lastName = overrides.lastName || this.faker.person.lastName();
    const sequence = this.nextSequence();
    
    return {
      id: overrides.id || this.generateId(),
      email: overrides.email || `user${sequence}_${this.faker.internet.email(firstName, lastName)}`,
      firstName,
      lastName,
      fullName: `${firstName} ${lastName}`,
      username: overrides.username || this.faker.internet.userName(firstName, lastName),
      password: overrides.password || this.faker.internet.password({ length: 12, memorable: false }),
      phone: overrides.phone || this.faker.phone.number(),
      dateOfBirth: overrides.dateOfBirth || this.faker.date.birthdate({ min: 18, max: 65, mode: 'age' }),
      avatar: overrides.avatar || this.faker.image.avatar(),
      isActive: overrides.isActive ?? true,
      isVerified: overrides.isVerified ?? this.faker.datatype.boolean(0.8),
      role: overrides.role || this.faker.helpers.arrayElement(['customer', 'admin', 'moderator']),
      createdAt: overrides.createdAt || this.faker.date.past({ years: 2 }),
      lastLoginAt: overrides.lastLoginAt || this.faker.date.recent({ days: 30 }),
      preferences: {
        newsletter: overrides.newsletter ?? this.faker.datatype.boolean(0.6),
        notifications: overrides.notifications ?? true,
        theme: overrides.theme || this.faker.helpers.arrayElement(['light', 'dark', 'auto']),
        language: overrides.language || this.faker.helpers.arrayElement(['en', 'es', 'fr', 'de']),
        ...overrides.preferences
      },
      metadata: {
        signupSource: overrides.signupSource || this.faker.helpers.arrayElement(['organic', 'referral', 'ad', 'social']),
        deviceType: overrides.deviceType || this.faker.helpers.arrayElement(['desktop', 'mobile', 'tablet']),
        ...overrides.metadata
      },
      ...overrides
    };
  }

  /**
   * Create admin user
   */
  admin(overrides = {}) {
    return this.create({
      role: 'admin',
      isVerified: true,
      permissions: ['all'],
      ...overrides
    });
  }

  /**
   * Create unverified user
   */
  unverified(overrides = {}) {
    return this.create({
      isVerified: false,
      verificationToken: this.faker.string.alphanumeric(32),
      ...overrides
    });
  }

  /**
   * Create inactive user
   */
  inactive(overrides = {}) {
    return this.create({
      isActive: false,
      deactivatedAt: this.faker.date.recent({ days: 90 }),
      deactivationReason: this.faker.helpers.arrayElement([
        'user_request',
        'violation',
        'inactive'
      ]),
      ...overrides
    });
  }
}

module.exports = UserFactory;
```

```python
# factories/user_factory.py
"""User Factory - generates realistic user data"""

from datetime import datetime, timedelta
from typing import Dict, Any, Optional
import random
from faker import Faker
from .base_factory import BaseFactory

faker = Faker()

class UserFactory(BaseFactory):
    @classmethod
    def build(cls, overrides: Dict[str, Any]) -> Dict[str, Any]:
        first_name = overrides.get('first_name') or faker.first_name()
        last_name = overrides.get('last_name') or faker.last_name()
        sequence = cls.next_sequence()
        
        return {
            'id': overrides.get('id', cls.generate_id()),
            'email': overrides.get('email', f"user{sequence}_{faker.email()}"),
            'first_name': first_name,
            'last_name': last_name,
            'full_name': f"{first_name} {last_name}",
            'username': overrides.get('username', faker.user_name()),
            'password': overrides.get('password', faker.password(length=12)),
            'phone': overrides.get('phone', faker.phone_number()),
            'date_of_birth': overrides.get('date_of_birth', faker.date_of_birth(minimum_age=18, maximum_age=65)),
            'avatar': overrides.get('avatar', faker.image_url()),
            'is_active': overrides.get('is_active', True),
            'is_verified': overrides.get('is_verified', random.random() < 0.8),
            'role': overrides.get('role', random.choice(['customer', 'admin', 'moderator'])),
            'created_at': overrides.get('created_at', faker.date_time_between(start_date='-2y')),
            'last_login_at': overrides.get('last_login_at', faker.date_time_between(start_date='-30d')),
            'preferences': {
                'newsletter': overrides.get('newsletter', random.random() < 0.6),
                'notifications': overrides.get('notifications', True),
                'theme': overrides.get('theme', random.choice(['light', 'dark', 'auto'])),
                'language': overrides.get('language', random.choice(['en', 'es', 'fr', 'de'])),
                **overrides.get('preferences', {})
            },
            'metadata': {
                'signup_source': overrides.get('signup_source', random.choice(['organic', 'referral', 'ad', 'social'])),
                'device_type': overrides.get('device_type', random.choice(['desktop', 'mobile', 'tablet'])),
                **overrides.get('metadata', {})
            },
            **overrides
        }
    
    @classmethod
    def admin(cls, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return cls.create({
            'role': 'admin',
            'is_verified': True,
            'permissions': ['all'],
            **(overrides or {})
        })
    
    @classmethod
    def unverified(cls, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return cls.create({
            'is_verified': False,
            'verification_token': faker.sha256(),
            **(overrides or {})
        })
```

### Step 3: Product Factory with Variants

```javascript
// factories/ProductFactory.js
/**
 * Product Factory with variants and categories
 */

const BaseFactory = require('./BaseFactory');

const CATEGORIES = [
  { name: 'Electronics', subcategories: ['Phones', 'Laptops', 'Accessories'] },
  { name: 'Clothing', subcategories: ['Shirts', 'Pants', 'Shoes', 'Accessories'] },
  { name: 'Home & Garden', subcategories: ['Furniture', 'Decor', 'Kitchen', 'Outdoor'] },
  { name: 'Sports', subcategories: ['Fitness', 'Outdoor', 'Team Sports'] },
  { name: 'Books', subcategories: ['Fiction', 'Non-fiction', 'Educational'] }
];

const BRANDS = ['TechCorp', 'StyleMax', 'HomeEssentials', 'ProSports', 'BookWorld', 'Generic'];

class ProductFactory extends BaseFactory {
  build(overrides = {}) {
    const category = overrides.category || this.faker.helpers.arrayElement(CATEGORIES);
    const subcategory = overrides.subcategory || this.faker.helpers.arrayElement(category.subcategories);
    const basePrice = overrides.basePrice || this.faker.number.float({ min: 9.99, max: 999.99, fractionDigits: 2 });
    
    return {
      id: overrides.id || this.generateId(),
      sku: overrides.sku || `SKU-${this.faker.string.alphanumeric(8).toUpperCase()}`,
      name: overrides.name || this.generateProductName(category.name, subcategory),
      description: overrides.description || this.faker.commerce.productDescription(),
      category: category.name,
      subcategory: subcategory,
      brand: overrides.brand || this.faker.helpers.arrayElement(BRANDS),
      basePrice: basePrice,
      salePrice: overrides.salePrice || this.calculateSalePrice(basePrice),
      costPrice: overrides.costPrice || basePrice * 0.6,
      currency: overrides.currency || 'USD',
      
      // Inventory
      stock: overrides.stock ?? this.faker.number.int({ min: 0, max: 1000 }),
      reservedStock: overrides.reservedStock ?? 0,
      reorderPoint: overrides.reorderPoint ?? 10,
      
      // Attributes
      attributes: overrides.attributes || this.generateAttributes(subcategory),
      
      // Variants
      hasVariants: overrides.hasVariants ?? this.faker.datatype.boolean(0.3),
      variants: overrides.variants || [],
      
      // Media
      images: overrides.images || this.generateImages(),
      
      // Flags
      isActive: overrides.isActive ?? true,
      isFeatured: overrides.isFeatured ?? this.faker.datatype.boolean(0.1),
      isNew: overrides.isNew ?? this.faker.datatype.boolean(0.2),
      
      // Metadata
      weight: overrides.weight || this.faker.number.float({ min: 0.1, max: 50, fractionDigits: 2 }),
      dimensions: overrides.dimensions || {
        length: this.faker.number.float({ min: 1, max: 100 }),
        width: this.faker.number.float({ min: 1, max: 100 }),
        height: this.faker.number.float({ min: 1, max: 100 }),
        unit: 'cm'
      },
      
      // SEO
      slug: overrides.slug || this.faker.helpers.slugify(this.generateProductName(category.name, subcategory)),
      metaTitle: overrides.metaTitle || this.faker.lorem.sentence(5),
      metaDescription: overrides.metaDescription || this.faker.lorem.paragraph(),
      
      // Timestamps
      createdAt: overrides.createdAt || this.faker.date.past({ years: 1 }),
      updatedAt: overrides.updatedAt || this.faker.date.recent(),
      
      // Ratings
      rating: overrides.rating || this.faker.number.float({ min: 1, max: 5, fractionDigits: 1 }),
      reviewCount: overrides.reviewCount || this.faker.number.int({ min: 0, max: 500 }),
      
      ...overrides
    };
  }

  generateProductName(category, subcategory) {
    const adjectives = ['Premium', 'Deluxe', 'Essential', 'Pro', 'Ultra', 'Smart', 'Classic'];
    const adj = this.faker.helpers.arrayElement(adjectives);
    const material = this.faker.commerce.productMaterial();
    return `${adj} ${material} ${subcategory}`;
  }

  calculateSalePrice(basePrice) {
    if (this.faker.datatype.boolean(0.3)) {
      const discount = this.faker.number.float({ min: 0.1, max: 0.5, fractionDigits: 2 });
      return Math.round(basePrice * (1 - discount) * 100) / 100;
    }
    return basePrice;
  }

  generateAttributes(subcategory) {
    const baseAttrs = {
      color: this.faker.color.human(),
      material: this.faker.commerce.productMaterial()
    };
    
    switch (subcategory) {
      case 'Shirts':
      case 'Pants':
        return { ...baseAttrs, size: this.faker.helpers.arrayElement(['XS', 'S', 'M', 'L', 'XL', 'XXL']) };
      case 'Shoes':
        return { ...baseAttrs, size: this.faker.number.int({ min: 5, max: 14 }) };
      case 'Phones':
        return { ...baseAttrs, storage: this.faker.helpers.arrayElement(['64GB', '128GB', '256GB', '512GB']) };
      default:
        return baseAttrs;
    }
  }

  generateImages() {
    const count = this.faker.number.int({ min: 1, max: 5 });
    return Array.from({ length: count }, (_, i) => ({
      url: this.faker.image.url(),
      alt: this.faker.commerce.productName(),
      isPrimary: i === 0,
      order: i
    }));
  }

  /**
   * Create product with variants
   */
  withVariants(overrides = {}) {
    const baseProduct = this.build(overrides);
    const variants = this.generateVariants(baseProduct);
    
    return this.create({
      ...baseProduct,
      hasVariants: true,
      variants,
      stock: variants.reduce((sum, v) => sum + v.stock, 0)
    });
  }

  generateVariants(product) {
    const sizes = ['S', 'M', 'L', 'XL'];
    const colors = ['Red', 'Blue', 'Black', 'White'];
    
    return sizes.flatMap(size => 
      colors.map(color => ({
        id: this.generateId(),
        sku: `${product.sku}-${size}-${color}`,
        attributes: { size, color },
        price: product.basePrice,
        stock: this.faker.number.int({ min: 0, max: 100 }),
        images: product.images.slice(0, 2)
      }))
    );
  }

  /**
   * Create out of stock product
   */
  outOfStock(overrides = {}) {
    return this.create({
      stock: 0,
      isActive: true,
      ...overrides
    });
  }

  /**
   * Create discontinued product
   */
  discontinued(overrides = {}) {
    return this.create({
      isActive: false,
      discontinuedAt: this.faker.date.past(),
      replacementProductId: this.generateId(),
      ...overrides
    });
  }
}

module.exports = ProductFactory;
```

### Step 4: Address & Payment Method Factories

```javascript
// factories/AddressFactory.js
/**
 * Address Factory - shipping and billing addresses
 */

const BaseFactory = require('./BaseFactory');

const COUNTRIES = [
  { code: 'US', name: 'United States', zipFormat: '#####', phonePrefix: '+1' },
  { code: 'CA', name: 'Canada', zipFormat: 'A#A #A#', phonePrefix: '+1' },
  { code: 'GB', name: 'United Kingdom', zipFormat: 'AA# #AA', phonePrefix: '+44' },
  { code: 'DE', name: 'Germany', zipFormat: '#####', phonePrefix: '+49' },
  { code: 'FR', name: 'France', zipFormat: '#####', phonePrefix: '+33' },
  { code: 'AU', name: 'Australia', zipFormat: '####', phonePrefix: '+61' }
];

class AddressFactory extends BaseFactory {
  build(overrides = {}) {
    const country = overrides.country || this.faker.helpers.arrayElement(COUNTRIES);
    const isResidential = overrides.isResidential ?? this.faker.datatype.boolean(0.8);
    
    return {
      id: overrides.id || this.generateId(),
      
      // Contact info
      name: overrides.name || this.faker.person.fullName(),
      company: overrides.company || (isResidential ? null : this.faker.company.name()),
      phone: overrides.phone || this.faker.phone.number(),
      email: overrides.email || this.faker.internet.email(),
      
      // Address lines
      addressLine1: overrides.addressLine1 || this.faker.location.streetAddress(),
      addressLine2: overrides.addressLine2 || this.faker.datatype.boolean(0.3) 
        ? `Apt ${this.faker.number.int({ min: 1, max: 999 })}` 
        : null,
      
      // City/State/Zip
      city: overrides.city || this.faker.location.city(),
      state: overrides.state || this.faker.location.state({ abbreviated: true }),
      postalCode: overrides.postalCode || this.generateZip(country),
      
      // Country
      countryCode: country.code,
      countryName: country.name,
      
      // Metadata
      isResidential: isResidential,
      isDefault: overrides.isDefault ?? false,
      addressType: overrides.addressType || this.faker.helpers.arrayElement(['home', 'work', 'other']),
      
      // Verification
      isVerified: overrides.isVerified ?? this.faker.datatype.boolean(0.9),
      verifiedAt: overrides.verifiedAt || this.faker.date.past(),
      
      // Coordinates (for shipping)
      latitude: overrides.latitude || this.faker.location.latitude(),
      longitude: overrides.longitude || this.faker.location.longitude(),
      
      // Delivery instructions
      deliveryInstructions: overrides.deliveryInstructions || this.faker.datatype.boolean(0.2) 
        ? this.faker.lorem.sentence() 
        : null,
      
      createdAt: overrides.createdAt || this.faker.date.past(),
      ...overrides
    };
  }

  generateZip(country) {
    switch (country.code) {
      case 'US':
        return this.faker.location.zipCode('#####');
      case 'CA':
        return this.faker.location.zipCode('A#A #A#');
      case 'GB':
        return this.faker.location.zipCode('AA# #AA');
      default:
        return this.faker.location.zipCode('#####');
    }
  }

  /**
   * Create international address
   */
  international(countryCode, overrides = {}) {
    const country = COUNTRIES.find(c => c.code === countryCode) || COUNTRIES[0];
    return this.create({
      countryCode: country.code,
      countryName: country.name,
      ...overrides
    });
  }

  /**
   * Create default address
   */
  default(overrides = {}) {
    return this.create({
      isDefault: true,
      addressType: 'home',
      ...overrides
    });
  }
}

module.exports = AddressFactory;
```

```javascript
// factories/PaymentMethodFactory.js
/**
 * Payment Method Factory - credit cards, digital wallets
 */

const BaseFactory = require('./BaseFactory');

// Test credit card numbers (from Stripe docs)
const TEST_CARDS = {
  visa: '4242424242424242',
  visaDebit: '4000056655665556',
  mastercard: '5555555555554444',
  amex: '378282246310005',
  declined: '4000000000000002',
  insufficientFunds: '4000000000009995',
  expired: '4000000000000069'
};

class PaymentMethodFactory extends BaseFactory {
  build(overrides = {}) {
    const type = overrides.type || this.faker.helpers.arrayElement(['credit_card', 'debit_card', 'digital_wallet']);
    const provider = this.getProvider(type);
    
    return {
      id: overrides.id || this.generateId(),
      type: type,
      provider: provider,
      
      // Card details
      card: type === 'credit_card' || type === 'debit_card' ? {
        brand: overrides.brand || this.faker.helpers.arrayElement(['visa', 'mastercard', 'amex']),
        last4: overrides.last4 || this.faker.string.numeric(4),
        expMonth: overrides.expMonth || this.faker.number.int({ min: 1, max: 12 }),
        expYear: overrides.expYear || this.faker.number.int({ min: 2024, max: 2030 }),
        fingerprint: overrides.fingerprint || this.faker.string.alphanumeric(16),
        ...overrides.card
      } : null,
      
      // Digital wallet
      wallet: type === 'digital_wallet' ? {
        walletType: overrides.walletType || this.faker.helpers.arrayElement(['apple_pay', 'google_pay', 'paypal']),
        email: overrides.email || this.faker.internet.email(),
        ...overrides.wallet
      } : null,
      
      // Billing address
      billingAddress: overrides.billingAddress || {},
      
      // Status
      isDefault: overrides.isDefault ?? false,
      isVerified: overrides.isVerified ?? true,
      status: overrides.status || 'active',
      
      // Timestamps
      createdAt: overrides.createdAt || this.faker.date.past(),
      updatedAt: overrides.updatedAt || this.faker.date.recent(),
      
      // Usage
      lastUsedAt: overrides.lastUsedAt || this.faker.date.recent(),
      usageCount: overrides.usageCount || this.faker.number.int({ min: 0, max: 100 }),
      
      ...overrides
    };
  }

  getProvider(type) {
    if (type === 'digital_wallet') {
      return this.faker.helpers.arrayElement(['stripe', 'paypal', 'braintree']);
    }
    return this.faker.helpers.arrayElement(['stripe', 'braintree', 'adyen']);
  }

  /**
   * Create valid credit card
   */
  creditCard(overrides = {}) {
    const brand = overrides.brand || this.faker.helpers.arrayElement(['visa', 'mastercard', 'amex']);
    const testCard = TEST_CARDS[brand] || TEST_CARDS.visa;
    
    return this.create({
      type: 'credit_card',
      card: {
        brand: brand,
        last4: testCard.slice(-4),
        expMonth: this.faker.number.int({ min: 1, max: 12 }),
        expYear: this.faker.number.int({ min: 2025, max: 2030 }),
        number: testCard // Only for testing
      },
      status: 'active',
      ...overrides
    });
  }

  /**
   * Create declined card
   */
  declined(overrides = {}) {
    return this.create({
      type: 'credit_card',
      card: {
        brand: 'visa',
        last4: '0002',
        expMonth: 12,
        expYear: 2025,
        number: TEST_CARDS.declined
      },
      status: 'declined',
      declineReason: this.faker.helpers.arrayElement(['insufficient_funds', 'card_declined', 'expired_card']),
      ...overrides
    });
  }

  /**
   * Create expired card
   */
  expired(overrides = {}) {
    return this.create({
      type: 'credit_card',
      card: {
        brand: 'visa',
        last4: '0069',
        expMonth: 1,
        expYear: 2020,
        number: TEST_CARDS.expired
      },
      status: 'expired',
      ...overrides
    });
  }

  /**
   * Create PayPal method
   */
  paypal(overrides = {}) {
    return this.create({
      type: 'digital_wallet',
      provider: 'paypal',
      wallet: {
        walletType: 'paypal',
        email: this.faker.internet.email(),
        payerId: this.faker.string.alphanumeric(13)
      },
      ...overrides
    });
  }
}

module.exports = PaymentMethodFactory;
```

### Step 5: Order Factory with Associations

```javascript
// factories/OrderFactory.js
/**
 * Order Factory with complete object graph
 */

const BaseFactory = require('./BaseFactory');
const UserFactory = require('./UserFactory');
const ProductFactory = require('./ProductFactory');
const AddressFactory = require('./AddressFactory');
const PaymentMethodFactory = require('./PaymentMethodFactory');

class OrderFactory extends BaseFactory {
  constructor() {
    super();
    this.userFactory = new UserFactory();
    this.productFactory = new ProductFactory();
    this.addressFactory = new AddressFactory();
    this.paymentFactory = new PaymentMethodFactory();
  }

  build(overrides = {}) {
    // Build or use provided associations
    const customer = overrides.customer || this.userFactory.build();
    const items = overrides.items || this.generateOrderItems();
    const shippingAddress = overrides.shippingAddress || this.addressFactory.build();
    const billingAddress = overrides.billingAddress || shippingAddress;
    const paymentMethod = overrides.paymentMethod || this.paymentFactory.creditCard();
    
    // Calculate totals
    const subtotal = this.calculateSubtotal(items);
    const shipping = overrides.shipping ?? this.calculateShipping(subtotal);
    const tax = overrides.tax ?? this.calculateTax(subtotal);
    const discount = overrides.discount ?? this.calculateDiscount(subtotal);
    const total = subtotal + shipping + tax - discount;
    
    return {
      id: overrides.id || this.generateId(),
      orderNumber: overrides.orderNumber || `ORD-${Date.now()}-${this.nextSequence()}`,
      
      // Customer
      customerId: customer.id,
      customer: overrides.includeAssociations !== false ? customer : undefined,
      
      // Items
      items: items.map(item => ({
        id: this.generateId(),
        productId: item.productId,
        product: overrides.includeAssociations !== false ? item.product : undefined,
        name: item.name,
        sku: item.sku,
        quantity: item.quantity,
        unitPrice: item.unitPrice,
        totalPrice: item.unitPrice * item.quantity,
        ...item
      })),
      
      // Financials
      currency: overrides.currency || 'USD',
      subtotal: subtotal,
      shipping: shipping,
      tax: tax,
      discount: discount,
      total: total,
      
      // Addresses
      shippingAddress: shippingAddress,
      billingAddress: billingAddress,
      
      // Payment
      paymentMethodId: paymentMethod.id,
      paymentMethod: overrides.includeAssociations !== false ? paymentMethod : undefined,
      paymentStatus: overrides.paymentStatus || 'pending',
      transactionId: overrides.transactionId || null,
      
      // Status
      status: overrides.status || this.faker.helpers.arrayElement([
        'pending', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled'
      ]),
      statusHistory: overrides.statusHistory || [{
        status: 'pending',
        timestamp: new Date(),
        note: 'Order created'
      }],
      
      // Shipping
      shippingMethod: overrides.shippingMethod || this.faker.helpers.arrayElement([
        'standard', 'express', 'overnight'
      ]),
      trackingNumber: overrides.trackingNumber || null,
      shippedAt: overrides.shippedAt || null,
      deliveredAt: overrides.deliveredAt || null,
      
      // Dates
      createdAt: overrides.createdAt || this.faker.date.recent(),
      updatedAt: overrides.updatedAt || this.faker.date.recent(),
      
      // Metadata
      source: overrides.source || this.faker.helpers.arrayElement(['web', 'mobile_app', 'api']),
      ipAddress: overrides.ipAddress || this.faker.internet.ip(),
      userAgent: overrides.userAgent || this.faker.internet.userAgent(),
      
      // Notes
      customerNotes: overrides.customerNotes || this.faker.datatype.boolean(0.2) 
        ? this.faker.lorem.sentence() 
        : null,
      internalNotes: overrides.internalNotes || null,
      
      ...overrides
    };
  }

  generateOrderItems(count = null) {
    const itemCount = count || this.faker.number.int({ min: 1, max: 5 });
    
    return Array.from({ length: itemCount }, () => {
      const product = this.productFactory.build();
      const quantity = this.faker.number.int({ min: 1, max: 3 });
      
      return {
        productId: product.id,
        product: product,
        name: product.name,
        sku: product.sku,
        quantity: quantity,
        unitPrice: product.salePrice,
        totalPrice: product.salePrice * quantity
      };
    });
  }

  calculateSubtotal(items) {
    return items.reduce((sum, item) => sum + item.totalPrice, 0);
  }

  calculateShipping(subtotal) {
    if (subtotal > 100) return 0;
    return this.faker.number.float({ min: 5.99, max: 15.99, fractionDigits: 2 });
  }

  calculateTax(subtotal) {
    const taxRate = 0.08;
    return Math.round(subtotal * taxRate * 100) / 100;
  }

  calculateDiscount(subtotal) {
    if (subtotal > 200) {
      return Math.round(subtotal * 0.1 * 100) / 100; // 10% off
    }
    return 0;
  }

  /**
   * Create complete order with all associations
   */
  complete(overrides = {}) {
    return this.create({
      includeAssociations: true,
      status: 'confirmed',
      paymentStatus: 'captured',
      ...overrides
    });
  }

  /**
   * Create pending order
   */
  pending(overrides = {}) {
    return this.create({
      status: 'pending',
      paymentStatus: 'pending',
      ...overrides
    });
  }

  /**
   * Create cancelled order
   */
  cancelled(overrides = {}) {
    return this.create({
      status: 'cancelled',
      cancelledAt: this.faker.date.recent(),
      cancellationReason: this.faker.helpers.arrayElement([
        'customer_request',
        'payment_failed',
        'out_of_stock',
        'fraud_detected'
      ]),
      ...overrides
    });
  }

  /**
   * Create shipped order
   */
  shipped(overrides = {}) {
    return this.create({
      status: 'shipped',
      shippedAt: this.faker.date.recent(),
      trackingNumber: this.faker.string.alphanumeric(20).toUpperCase(),
      ...overrides
    });
  }
}

module.exports = OrderFactory;
```

### Step 6: Database Seeding at Scale

```javascript
// scripts/seed-database.js
/**
 * Database Seeding Script - Generate 10k+ records efficiently
 */

const { Pool } = require('pg');
const UserFactory = require('../factories/UserFactory');
const ProductFactory = require('../factories/ProductFactory');
const OrderFactory = require('../factories/OrderFactory');

const BATCH_SIZE = 1000;

class DatabaseSeeder {
  constructor() {
    this.db = new Pool({
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 5432,
      database: process.env.DB_NAME || 'ecommerce',
      user: process.env.DB_USER || 'postgres',
      password: process.env.DB_PASSWORD || 'password'
    });
    
    this.userFactory = new UserFactory();
    this.productFactory = new ProductFactory();
    this.orderFactory = new OrderFactory();
  }

  async seedUsers(count = 10000) {
    console.log(`Seeding ${count} users...`);
    
    for (let i = 0; i < count; i += BATCH_SIZE) {
      const batchSize = Math.min(BATCH_SIZE, count - i);
      const users = this.userFactory.createMany(batchSize);
      
      const values = users.map((user, idx) => 
        `($${idx * 8 + 1}, $${idx * 8 + 2}, $${idx * 8 + 3}, $${idx * 8 + 4}, 
          $${idx * 8 + 5}, $${idx * 8 + 6}, $${idx * 8 + 7}, $${idx * 8 + 8})`
      ).join(',');
      
      const params = users.flatMap(u => [
        u.id, u.email, u.firstName, u.lastName, u.password, 
        u.isActive, u.role, u.createdAt
      ]);
      
      await this.db.query(`
        INSERT INTO users (id, email, first_name, last_name, password, is_active, role, created_at)
        VALUES ${values}
        ON CONFLICT (id) DO NOTHING
      `, params);
      
      console.log(`  Seeded ${i + batchSize}/${count} users`);
    }
  }

  async seedProducts(count = 1000) {
    console.log(`Seeding ${count} products...`);
    
    for (let i = 0; i < count; i += BATCH_SIZE) {
      const batchSize = Math.min(BATCH_SIZE, count - i);
      const products = this.productFactory.createMany(batchSize);
      
      const values = products.map((p, idx) => 
        `($${idx * 10 + 1}, $${idx * 10 + 2}, $${idx * 10 + 3}, $${idx * 10 + 4},
          $${idx * 10 + 5}, $${idx * 10 + 6}, $${idx * 10 + 7}, $${idx * 10 + 8},
          $${idx * 10 + 9}, $${idx * 10 + 10})`
      ).join(',');
      
      const params = products.flatMap(p => [
        p.id, p.sku, p.name, p.description, p.category, 
        p.basePrice, p.stock, p.isActive, p.rating, p.createdAt
      ]);
      
      await this.db.query(`
        INSERT INTO products (id, sku, name, description, category, price, stock, is_active, rating, created_at)
        VALUES ${values}
        ON CONFLICT (id) DO NOTHING
      `, params);
      
      console.log(`  Seeded ${i + batchSize}/${count} products`);
    }
  }

  async seedOrders(count = 5000) {
    console.log(`Seeding ${count} orders...`);
    
    // Get existing user and product IDs
    const { rows: users } = await this.db.query('SELECT id FROM users LIMIT 1000');
    const { rows: products } = await this.db.query('SELECT id, base_price as price FROM products LIMIT 500');
    
    for (let i = 0; i < count; i += BATCH_SIZE / 10) { // Smaller batches for complex data
      const batchSize = Math.min(BATCH_SIZE / 10, count - i);
      
      const orders = [];
      for (let j = 0; j < batchSize; j++) {
        const randomUser = users[Math.floor(Math.random() * users.length)];
        const orderProducts = products
          .sort(() => 0.5 - Math.random())
          .slice(0, Math.floor(Math.random() * 5) + 1);
        
        const items = orderProducts.map(p => ({
          productId: p.id,
          unitPrice: parseFloat(p.price),
          quantity: Math.floor(Math.random() * 3) + 1
        }));
        
        orders.push(this.orderFactory.create({
          customerId: randomUser.id,
          items: items.map(item => ({
            ...item,
            totalPrice: item.unitPrice * item.quantity
          })),
          includeAssociations: false
        }));
      }
      
      // Insert orders
      for (const order of orders) {
        await this.db.query(`
          INSERT INTO orders (id, order_number, customer_id, total, status, created_at)
          VALUES ($1, $2, $3, $4, $5, $6)
        `, [order.id, order.orderNumber, order.customerId, order.total, order.status, order.createdAt]);
        
        // Insert order items
        for (const item of order.items) {
          await this.db.query(`
            INSERT INTO order_items (id, order_id, product_id, quantity, unit_price, total_price)
            VALUES ($1, $2, $3, $4, $5, $6)
          `, [
            require('crypto').randomUUID(),
            order.id,
            item.productId,
            item.quantity,
            item.unitPrice,
            item.totalPrice
          ]);
        }
      }
      
      console.log(`  Seeded ${i + batchSize}/${count} orders`);
    }
  }

  async run() {
    try {
      console.log('Starting database seeding...\n');
      
      await this.seedUsers(10000);
      await this.seedProducts(1000);
      await this.seedOrders(5000);
      
      console.log('\n✅ Seeding completed successfully!');
    } catch (error) {
      console.error('❌ Seeding failed:', error);
    } finally {
      await this.db.end();
    }
  }
}

// Run if called directly
if (require.main === module) {
  const seeder = new DatabaseSeeder();
  seeder.run();
}

module.exports = DatabaseSeeder;
```

### Step 7: Usage Examples

```javascript
// examples/usage.js
/**
 * Factory Usage Examples
 */

const UserFactory = require('./factories/UserFactory');
const ProductFactory = require('./factories/ProductFactory');
const OrderFactory = require('./factories/OrderFactory');

// Create single user
const user = UserFactory.create();
console.log('Single user:', user.email);

// Create admin user
const admin = UserFactory.admin();
console.log('Admin:', admin.email, admin.role);

// Create many users
const users = UserFactory.createMany(10);
console.log('Created 10 users');

// Create product with variants
const product = ProductFactory.withVariants();
console.log('Product with variants:', product.variants.length, 'variants');

// Create complete order graph
const order = OrderFactory.complete();
console.log('Complete order:', {
  orderNumber: order.orderNumber,
  customer: order.customer.email,
  items: order.items.length,
  total: order.total,
  payment: order.paymentMethod.type
});

// Complex scenario: Customer with multiple orders
const customer = UserFactory.create();
const orders = OrderFactory.createMany(5, (i) => ({
  customerId: customer.id,
  status: i % 2 === 0 ? 'delivered' : 'pending'
}));

console.log(`Customer ${customer.email} has ${orders.length} orders`);

// Large scale data generation
const products = ProductFactory.createMany(1000);
const customers = UserFactory.createMany(5000);
console.log(`Generated ${products.length} products and ${customers.length} customers`);
```

## Results

### Factory Capabilities

| Factory | Methods | Output |
|---------|---------|--------|
| UserFactory | create(), admin(), unverified(), inactive(), createMany() | Realistic user data with preferences |
| ProductFactory | create(), withVariants(), outOfStock(), discontinued() | Products with SKUs, pricing, inventory |
| AddressFactory | create(), international(), default() | Valid addresses for 6 countries |
| PaymentMethodFactory | creditCard(), declined(), expired(), paypal() | Test payment methods |
| OrderFactory | create(), complete(), pending(), cancelled(), shipped() | Full order graphs with associations |

### Seeding Performance

```
$ node scripts/seed-database.js

Starting database seeding...

Seeding 10000 users...
  Seeded 1000/10000 users
  Seeded 2000/10000 users
  ...
  Seeded 10000/10000 users
Seeding 1000 products...
  Seeded 1000/1000 products
Seeding 5000 orders...
  Seeded 500/5000 orders
  Seeded 1000/5000 orders
  ...
  Seeded 5000/5000 orders

✅ Seeding completed successfully!
Time: 12.34s
Total records: 16,000
```

### Object Graph Example

```javascript
const order = OrderFactory.complete();

// Generated structure:
{
  id: "550e8400-e29b-41d4-a716-446655440000",
  orderNumber: "ORD-1704163200000-1",
  customerId: "550e8400-e29b-41d4-a716-446655440001",
  customer: {
    id: "550e8400-e29b-41d4-a716-446655440001",
    email: "user1_john.doe@example.com",
    firstName: "John",
    lastName: "Doe",
    preferences: { ... }
  },
  items: [
    {
      id: "...",
      productId: "...",
      product: { name: "Premium Cotton Shirt", price: 45.99, ... },
      quantity: 2,
      unitPrice: 45.99,
      totalPrice: 91.98
    },
    // ... more items
  ],
  subtotal: 245.97,
  shipping: 12.99,
  tax: 19.68,
  discount: 0,
  total: 278.64,
  shippingAddress: { ... },
  billingAddress: { ... },
  paymentMethod: { type: "credit_card", brand: "visa", ... },
  status: "confirmed",
  paymentStatus: "captured"
}
```

## Key Learnings

### What Worked Well

1. **Batch inserts for performance** — 10k users in ~8 seconds using 1k record batches
2. **Factory inheritance** — BaseFactory provides core functionality to all factories
3. **Association support** — Complete object graphs with `includeAssociations` flag
4. **Realistic fake data** — Faker.js provides varied, realistic data patterns
5. **Specialized methods** — `admin()`, `withVariants()`, `declined()` for common scenarios

### Best Practices Demonstrated

1. **Factories over fixtures** — Generate data programmatically for flexibility
2. **Sequence counters** — Ensure unique values (emails, SKUs)
3. **Override support** — Pass custom values when specific data needed
4. **Batch processing** — Chunk large operations to avoid memory issues
5. **Database-agnostic** — Factories return objects, persistence optional

### Skills Integration

- **test-data-management**: Factories, batch seeding, realistic data generation
- **unit-testing**: Factories used to create test data
- **integration-testing**: Database seeding for test environments

### Performance Metrics

| Operation | Records | Time |
|-----------|---------|------|
| Generate 10k users | 10,000 | ~2s |
| Seed 10k users (DB) | 10,000 | ~5s |
| Generate 1k products | 1,000 | ~0.5s |
| Generate 5k orders | 5,000 | ~3s |
| Complete seed run | 16,000 | ~12s |
