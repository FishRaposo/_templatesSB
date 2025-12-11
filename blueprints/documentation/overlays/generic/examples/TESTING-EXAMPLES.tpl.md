# Technology-Specific Test Implementation Guide

**Purpose**: Concrete test implementations for different technology stacks with real code examples for all 7 test types.

**Last Updated**: [CURRENT_DATE]  
**Compatible Frameworks**: Flutter, React, Vue, Angular, Node.js, Python, Java/Spring, .NET  
**Test Types Covered**: Unit, Component/UI, Integration, Feature, Workflow, System, E2E

---

## 📚 Prerequisites

**Before using this guide**, please read **`../universal/TESTING-STRATEGY.md`** (Universal Testing Strategy) which covers:
- Testing philosophy and principles
- Detailed descriptions of all 7 test types
- When to use each test type
- Coverage strategy
- Test organization patterns
- CI/CD integration strategies
- Best practices and anti-patterns

This document provides **concrete implementations** for the universal principles described in `../universal/TESTING-STRATEGY.md`.

---

## 🎯 How to Use This Guide

### For Your Technology Stack:
1. **Read `../universal/TESTING-STRATEGY.md`** first to understand the universal principles
2. **Find your framework section** below
3. **Copy the examples** and adapt to your project
4. **Follow the setup instructions** for your specific tech
5. **Use the patterns** as starting points for your tests
6. **Refer to coverage percentages** for each test type

### Quick Navigation:
- [Flutter/Dart](#flutterdart)
- [React/TypeScript](#reacttypescript)
- [Vue/JavaScript](#vuejavascript)
- [Angular/TypeScript](#angulartypescript)
- [Node.js/Express](#nodejsexpress)
- [Python/FastAPI](#pythonfastapi)
- [Java/Spring Boot](#javaspring-boot)
- [.NET/C#](#netc)

---

## Flutter/Dart

### Stack Overview
- **Unit Testing**: `flutter_test`, `mockito`
- **Widget Testing**: `flutter_test`
- **Integration Testing**: `integration_test`
- **E2E Testing**: `flutter_driver`, `patrol`

### Setup
```yaml
# pubspec.yaml
dev_dependencies:
  flutter_test:
    sdk: flutter
  mockito: ^5.4.2
  build_runner: ^2.4.7
  integration_test:
    sdk: flutter
  patrol: ^3.7.0
```

### 1. Unit Test Example
```dart
// test/unit/inventory_service_test.dart
import 'package:flutter_test/flutter_test.dart';
import 'package:mockito/mockito.dart';
import 'package:mockito/annotations.dart';
import 'package:my_app/inventory_service.dart';
import 'package:my_app/inventory_item.dart';

@GenerateMocks([InventoryRepository])
void main() {
  group('InventoryService', () {
    late InventoryService service;
    late MockInventoryRepository mockRepository;

    setUp(() {
      mockRepository = MockInventoryRepository();
      service = InventoryService(mockRepository);
    });

    test('should increment item quantity', () async {
      // Arrange
      final item = InventoryItem(
        id: '1',
        name: 'Test Item',
        quantity: 5,
      );
      when(mockRepository.getItem('1')).thenAnswer((_) async => item);
      when(mockRepository.updateQuantity('1', 6)).thenAnswer((_) async => true);

      // Act
      await service.incrementQuantity('1');

      // Assert
      verify(mockRepository.updateQuantity('1', 6)).called(1);
    });

    test('should throw exception when item not found', () async {
      // Arrange
      when(mockRepository.getItem('999')).thenAnswer((_) async => null);

      // Act & Assert
      expect(
        () => service.incrementQuantity('999'),
        throwsA(isA<ItemNotFoundException>()),
      );
    });
  });
}
```

### 2. Widget Test Example
```dart
// test/widget/inventory_card_test.dart
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter/material.dart';
import 'package:my_app/widgets/inventory_card.dart';

void main() {
  testWidgets('InventoryCard displays item correctly', (tester) async {
    // Arrange
    final item = InventoryItem(
      id: '1',
      name: 'Laptop',
      barcode: 'LAP-123',
      quantity: 10,
    );

    // Act
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: InventoryCard(item: item),
        ),
      ),
    );

    // Assert
    expect(find.text('Laptop'), findsOneWidget);
    expect(find.text('Barcode: LAP-123'), findsOneWidget);
    expect(find.text('10'), findsOneWidget);
  });

  testWidgets('InventoryCard calls onTap when tapped', (tester) async {
    // Arrange
    var tapped = false;
    final item = InventoryItem(id: '1', name: 'Test', quantity: 5);

    // Act
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: InventoryCard(
            item: item,
            onTap: () => tapped = true,
          ),
        ),
      ),
    );

    await tester.tap(find.byType(InventoryCard));
    await tester.pump();

    // Assert
    expect(tapped, isTrue);
  });
}
```

### 3. Integration Test Example
```dart
// test/integration/database_test.dart
import 'package:flutter_test/flutter_test.dart';
import 'package:my_app/database/app_database.dart';

void main() {
  group('AppDatabase Integration', () {
    late AppDatabase database;

    setUp(() {
      database = AppDatabase();
    });

    tearDown(() async {
      await database.close();
    });

    test('should perform complete CRUD operations', () async {
      // Create
      final item = InventoryItem(
        barcode: 'TEST-123',
        name: 'Integration Test Item',
        quantity: 5,
      );
      final id = await database.addItem(item);
      expect(id, greaterThan(0));

      // Read
      final savedItem = await database.getItem(id);
      expect(savedItem?.name, 'Integration Test Item');

      // Update
      await database.updateQuantity(id, 10);
      final updated = await database.getItem(id);
      expect(updated?.quantity, 10);

      // Delete
      await database.deleteItem(id);
      final deleted = await database.getItem(id);
      expect(deleted, isNull);
    });
  });
}
```

### 4. Feature Test Example
```dart
// test/feature/item_management_feature_test.dart
import 'package:flutter_test/flutter_test.dart';
import 'package:my_app/services/inventory_service.dart';
import 'package:my_app/models/inventory_item.dart';
import 'package:mockito/mockito.dart';

void main() {
  group('Item Management Feature', () {
    late InventoryService service;
    late MockInventoryRepository repository;

    setUp(() {
      repository = MockInventoryRepository();
      service = InventoryService(repository);
    });

    test('complete item lifecycle', () async {
      // Add
      final item = InventoryItem(
        barcode: 'FEATURE-1',
        name: 'Feature Test Item',
        quantity: 5,
      );
      when(repository.addItem(any)).thenAnswer((_) async => 1);
      final id = await service.addItem(item);
      expect(id, 1);

      // Read
      when(repository.getItem(1)).thenAnswer((_) async => item.copyWith(id: 1));
      final saved = await service.getItem(1);
      expect(saved?.name, 'Feature Test Item');

      // Update
      when(repository.updateQuantity(1, 10)).thenAnswer((_) async => true);
      await service.updateQuantity(1, 10);
      verify(repository.updateQuantity(1, 10)).called(1);

      // Delete
      when(repository.deleteItem(1)).thenAnswer((_) async => true);
      await service.deleteItem(1);
      verify(repository.deleteItem(1)).called(1);
    });
  });
}
```

### 5. Workflow Test Example
```dart
// test/workflow/onboarding_workflow_test.dart
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:my_app/main.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  group('Onboarding Workflow', () {
    test('new user completes first item addition', () async {
      // Launch app
      await tester.pumpWidget(const MyApp());
      await tester.pumpAndSettle();

      // Verify empty state
      expect(find.text('No items yet'), findsOneWidget);

      // Tap add button
      await tester.tap(find.byIcon(Icons.add));
      await tester.pumpAndSettle();

      // Fill form
      await tester.enterText(find.byKey(const Key('name_field')), 'First Item');
      await tester.enterText(find.byKey(const Key('barcode_field')), '123456');
      await tester.enterText(find.byKey(const Key('quantity_field')), '5');

      // Save
      await tester.tap(find.text('Save'));
      await tester.pumpAndSettle();

      // Verify success
      expect(find.text('Item added successfully'), findsOneWidget);
      expect(find.text('First Item'), findsOneWidget);
    });
  });
}
```

### 6. System Test Example
```dart
// test/system/performance_test.dart
import 'package:flutter_test/flutter_test.dart';
import 'package:my_app/main.dart';

void main() {
  testWidgets('app startup performance', (tester) async {
    final stopwatch = Stopwatch()..start();

    await tester.pumpWidget(const MyApp());
    await tester.pumpAndSettle();

    stopwatch.stop();

    expect(stopwatch.elapsedMilliseconds, lessThan(1000));
  });

  testWidgets('list scrolling performance', (tester) async {
    await tester.pumpWidget(const MyApp());
    await tester.pumpAndSettle();

    final stopwatch = Stopwatch()..start();

    await tester.fling(find.byType(ListView), const Offset(0, -500), 1000);
    await tester.pumpAndSettle();

    stopwatch.stop();

    expect(stopwatch.elapsedMilliseconds, lessThan(100));
  });
}
```

### 7. E2E Test Example
```dart
// test/e2e/smoke_test.dart
import 'package:patrol/patrol.dart';

void main() {
  patrolTest('complete smoke test', (PatrolTester $) async {
    // Launch app
    await $.pumpWidgetAndSettle(const MyApp());

    // Add item
    await $(FloatingActionButton).tap();
    await $.pumpAndSettle();

    await $(#name_field).enterText('E2E Test Item');
    await $(#barcode_field).enterText('E2E123');
    await $(#quantity_field).enterText('10');

    await $('Save').tap();
    await $.pumpAndSettle();

    // Verify item exists
    expect(await $(#inventory_list).$(#item_1).text, 'E2E Test Item');

    // Test search
    await $(#search_field).tap();
    await $.pumpAndSettle();

    await $(#search_field).enterText('E2E');
    await $.pumpAndSettle();

    // Verify search worked
    expect(await $(#inventory_list).children.length, 1);
  });
}
```

---

## React/TypeScript

### Stack Overview
- **Unit Testing**: Jest, React Testing Library
- **Component Testing**: React Testing Library
- **Integration Testing**: Jest + MSW (Mock Service Worker)
- **E2E Testing**: Cypress, Playwright

### Setup
```bash
npm install --save-dev jest @testing-library/react @testing-library/jest-dom ts-jest msw cypress
```

```json
// jest.config.json
{
  "preset": "ts-jest",
  "testEnvironment": "jsdom",
  "setupFilesAfterEnv": ["<rootDir>/src/setupTests.ts"]
}
```

### 1. Unit Test Example
```typescript
// src/services/inventoryService.test.ts
import { InventoryService } from './inventoryService';
import { InventoryRepository } from './inventoryRepository';
import { InventoryItem } from '../models/InventoryItem';

// Mock the repository
jest.mock('./inventoryRepository');

describe('InventoryService', () => {
  let service: InventoryService;
  let mockRepository: jest.Mocked<InventoryRepository>;

  beforeEach(() => {
    mockRepository = new InventoryRepository() as jest.Mocked<InventoryRepository>;
    service = new InventoryService(mockRepository);
  });

  describe('incrementQuantity', () => {
    it('should increment item quantity', async () => {
      // Arrange
      const item: InventoryItem = {
        id: '1',
        name: 'Test Item',
        barcode: 'TEST-123',
        quantity: 5,
      };
      mockRepository.getItem.mockResolvedValue(item);
      mockRepository.updateQuantity.mockResolvedValue(true);

      // Act
      await service.incrementQuantity('1');

      // Assert
      expect(mockRepository.updateQuantity).toHaveBeenCalledWith('1', 6);
    });

    it('should throw error when item not found', async () => {
      // Arrange
      mockRepository.getItem.mockResolvedValue(null);

      // Act & Assert
      await expect(service.incrementQuantity('999')).rejects.toThrow(
        'Item not found'
      );
    });
  });
});
```

### 2. Component Test Example
```typescript
// src/components/InventoryCard.test.tsx
import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { InventoryCard } from './InventoryCard';
import { InventoryItem } from '../models/InventoryItem';

describe('InventoryCard', () => {
  const mockItem: InventoryItem = {
    id: '1',
    name: 'Laptop',
    barcode: 'LAP-123',
    quantity: 10,
  };

  it('should display item information correctly', () => {
    // Act
    render(<InventoryCard item={mockItem} />);

    // Assert
    expect(screen.getByText('Laptop')).toBeInTheDocument();
    expect(screen.getByText('Barcode: LAP-123')).toBeInTheDocument();
    expect(screen.getByText('10')).toBeInTheDocument();
  });

  it('should call onClick when card is clicked', () => {
    // Arrange
    const onClickMock = jest.fn();
    render(<InventoryCard item={mockItem} onClick={onClickMock} />);

    // Act
    fireEvent.click(screen.getByTestId('inventory-card'));

    // Assert
    expect(onClickMock).toHaveBeenCalledWith('1');
  });

  it('should show out of stock badge when quantity is 0', () => {
    // Arrange
    const outOfStockItem = { ...mockItem, quantity: 0 };

    // Act
    render(<InventoryCard item={outOfStockItem} />);

    // Assert
    expect(screen.getByText('Out of Stock')).toBeInTheDocument();
  });
});
```

### 3. Integration Test Example
```typescript
// src/integration/inventoryFlow.test.ts
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from 'react-query';
import { InventoryPage } from '../pages/InventoryPage';
import { server } from '../mocks/server';
import { rest } from 'msw';

describe('InventoryPage Integration', () => {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  });

  const wrapper = ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );

  beforeAll(() => server.listen());
  afterEach(() => {
    server.resetHandlers();
    queryClient.clear();
  });
  afterAll(() => server.close());

  it('should load and display inventory items', async () => {
    // Arrange & Act
    render(<InventoryPage />, { wrapper });

    // Assert
    expect(screen.getByText('Loading...')).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText('Laptop')).toBeInTheDocument();
      expect(screen.getByText('Mouse')).toBeInTheDocument();
    });
  });

  it('should handle API error', async () => {
    // Arrange - Simulate API error
    server.use(
      rest.get('/api/inventory', (req, res, ctx) => {
        return res(ctx.status(500), ctx.json({ message: 'Server error' }));
      })
    );

    // Act
    render(<InventoryPage />, { wrapper });

    // Assert
    await waitFor(() => {
      expect(screen.getByText('Failed to load inventory')).toBeInTheDocument();
    });
  });
});
```

### 4. Feature Test Example
```typescript
// src/features/itemManagement.test.ts
import { InventoryService } from '../services/inventoryService';
import { InventoryRepository } from '../repositories/inventoryRepository';
import { InventoryItem } from '../models/InventoryItem';

describe('Item Management Feature', () => {
  let service: InventoryService;
  let repository: InventoryRepository;

  beforeEach(() => {
    repository = new InventoryRepository();
    service = new InventoryService(repository);
  });

  it('should complete item lifecycle', async () => {
    // Create
    const newItem: Omit<InventoryItem, 'id'> = {
      name: 'Feature Test Item',
      barcode: 'FEATURE-123',
      quantity: 5,
    };
    const created = await service.addItem(newItem);
    expect(created.id).toBeDefined();
    expect(created.name).toBe('Feature Test Item');

    // Read
    const fetched = await service.getItem(created.id);
    expect(fetched).toEqual(created);

    // Update
    await service.updateQuantity(created.id, 10);
    const updated = await service.getItem(created.id);
    expect(updated?.quantity).toBe(10);

    // Delete
    await service.deleteItem(created.id);
    const deleted = await service.getItem(created.id);
    expect(deleted).toBeNull();
  });

  it('should search items by name', async () => {
    // Arrange
    await service.addItem({ name: 'Apple iPhone', barcode: 'A1', quantity: 5 });
    await service.addItem({ name: 'Samsung Galaxy', barcode: 'S1', quantity: 3 });
    await service.addItem({ name: 'Apple Watch', barcode: 'A2', quantity: 2 });

    // Act
    const results = await service.searchItems('Apple');

    // Assert
    expect(results).toHaveLength(2);
    expect(results.every(item => item.name.includes('Apple'))).toBe(true);
  });
});
```

### 5. Workflow Test Example (Cypress)
```typescript
// cypress/e2e/onboarding.cy.ts
describe('Onboarding Workflow', () => {
  beforeEach(() => {
    cy.visit('/');
    cy.clearLocalStorage();
  });

  it('should complete first-time user onboarding', () => {
    // Verify empty state
    cy.contains('No items yet').should('be.visible');

    // Click add button
    cy.get('[data-testid="add-item-button"]').click();

    // Fill form
    cy.get('[data-testid="name-field"]').type('First Item');
    cy.get('[data-testid="barcode-field"]').type('123456');
    cy.get('[data-testid="quantity-field"]').type('5');

    // Submit
    cy.get('[data-testid="save-button"]').click();

    // Verify success
    cy.contains('Item added successfully').should('be.visible');
    cy.contains('First Item').should('be.visible');
    cy.contains('Barcode: 123456').should('be.visible');
  });

  it('should export and import inventory data', () => {
    // Setup: Add some items
    cy.addInventoryItem('Export Item 1', 'EXP-1', 5);
    cy.addInventoryItem('Export Item 2', 'EXP-2', 10);

    // Export
    cy.visit('/settings');
    cy.get('[data-testid="export-csv-button"]').click();
    cy.readFile('cypress/downloads/inventory.csv').should('exist');

    // Simulate new device - clear data
    cy.clearLocalStorage();
    cy.visit('/');
    cy.contains('No items yet').should('be.visible');

    // Import
    cy.visit('/settings');
    cy.get('[data-testid="import-csv-button"]').click();
    cy.get('input[type="file"]').selectFile('cypress/downloads/inventory.csv');
    cy.get('[data-testid="confirm-import-button"]').click();

    // Verify
    cy.contains('Successfully imported 2 items').should('be.visible');
    cy.contains('Export Item 1').should('be.visible');
    cy.contains('Export Item 2').should('be.visible');
  });
});
```

### 6. System Test Example
```typescript
// test/system/performance.test.ts
import lighthouse from 'lighthouse';
import chromeLauncher from 'chrome-launcher';

describe('System Tests', () => {
  let chrome: any;

  beforeAll(async () => {
    chrome = await chromeLauncher.launch({ chromeFlags: ['--headless'] });
  });

  afterAll(async () => {
    if (chrome) {
      await chrome.kill();
    }
  });

  it('should meet performance budget', async () => {
    const options = {
      logLevel: 'info',
      output: 'json',
      onlyCategories: ['performance'],
      port: chrome.port,
    };

    const runnerResult = await lighthouse('http://localhost:3000', options);

    const performanceScore = runnerResult.lhr.categories.performance.score * 100;
    expect(performanceScore).toBeGreaterThanOrEqual(90);
  });

  it('should be accessible', async () => {
    const result = await axe.run();
    expect(result.violations).toHaveLength(0);
  });
});
```

### 7. E2E Test Example (Playwright)
```typescript
// playwright/tests/smoke.spec.ts
import { test, expect } from '@playwright/test';

test.describe('Smoke Tests', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('complete user journey', async ({ page }) => {
    // User adds first item
    await page.getByRole('button', { name: /add item/i }).click();
    await page.getByTestId('name-field').fill('Playwright Test Item');
    await page.getByTestId('barcode-field').fill('PW-123');
    await page.getByTestId('quantity-field').fill('7');
    await page.getByRole('button', { name: /save/i }).click();

    // Verify item added
    await expect(page.getByText('Item added successfully')).toBeVisible();
    await expect(page.getByText('Playwright Test Item')).toBeVisible();

    // User searches for item
    await page.getByTestId('search-field').fill('Playwright');
    await expect(page.getByText('Playwright Test Item')).toBeVisible();

    // User updates quantity
    await page.getByText('Playwright Test Item').click();
    await page.getByLabel('Quantity').fill('10');
    await page.getByRole('button', { name: /update/i }).click();
    await expect(page.getByText('10')).toBeVisible();
  });

  test('error handling and recovery', async ({ page }) => {
    // Try to add item with invalid data
    await page.getByRole('button', { name: /add item/i }).click();
    await page.getByRole('button', { name: /save/i }).click();

    // Should show validation errors
    await expect(page.getByText('Name is required')).toBeVisible();

    // User fills required field and succeeds
    await page.getByTestId('name-field').fill('Error Recovery Item');
    await page.getByRole('button', { name: /save/i }).click();
    await expect(page.getByText('Item added successfully')).toBeVisible();
  });
});
```

---

## Vue/JavaScript

### Stack Overview
- **Unit Testing**: Vitest, Jest
- **Component Testing**: Vue Test Utils, @vue/test-utils
- **Integration Testing**: Vitest + MSW
- **E2E Testing**: Cypress, Playwright

### Setup
```bash
npm install --save-dev vitest @vue/test-utils @testing-library/vue msw cypress
```

```javascript
// vitest.config.js
import { defineConfig } from 'vitest/config';
import vue from '@vitejs/plugin-vue';

export default defineConfig({
  plugins: [vue()],
  test: {
    environment: 'jsdom',
  },
});
```

### 1. Unit Test Example
```javascript
// tests/unit/inventoryService.test.js
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { InventoryService } from '../../src/services/inventoryService.js';

describe('InventoryService', () => {
  let service;
  let mockRepository;

  beforeEach(() => {
    mockRepository = {
      getItem: vi.fn(),
      updateQuantity: vi.fn(),
    };
    service = new InventoryService(mockRepository);
  });

  it('should increment item quantity', async () => {
    // Arrange
    const item = {
      id: '1',
      name: 'Test Item',
      quantity: 5,
    };
    mockRepository.getItem.mockResolvedValue(item);
    mockRepository.updateQuantity.mockResolvedValue(true);

    // Act
    await service.incrementQuantity('1');

    // Assert
    expect(mockRepository.updateQuantity).toHaveBeenCalledWith('1', 6);
  });

  it('should throw error when item not found', async () => {
    // Arrange
    mockRepository.getItem.mockResolvedValue(null);

    // Act & Assert
    await expect(service.incrementQuantity('999')).rejects.toThrow('Item not found');
  });
});
```

### 2. Component Test Example
```javascript
// tests/components/InventoryCard.test.js
import { describe, it, expect } from 'vitest';
import { mount } from '@vue/test-utils';
import InventoryCard from '../../src/components/InventoryCard.vue';

describe('InventoryCard', () => {
  const mockItem = {
    id: '1',
    name: 'Laptop',
    barcode: 'LAP-123',
    quantity: 10,
  };

  it('renders item information correctly', () => {
    const wrapper = mount(InventoryCard, {
      props: { item: mockItem },
    });

    expect(wrapper.text()).toContain('Laptop');
    expect(wrapper.text()).toContain('Barcode: LAP-123');
    expect(wrapper.text()).toContain('10');
  });

  it('emits click event when card is clicked', async () => {
    const wrapper = mount(InventoryCard, {
      props: { item: mockItem },
    });

    await wrapper.trigger('click');

    expect(wrapper.emitted('click')).toHaveLength(1);
    expect(wrapper.emitted('click')[0]).toEqual(['1']);
  });
});
```

### 3. Integration Test Example
```javascript
// tests/integration/inventoryApi.test.js
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { setupServer } from 'msw/node';
import { rest } from 'msw';
import { fetchInventory } from '../../src/api/inventory.js';

const server = setupServer(
  rest.get('/api/inventory', (req, res, ctx) => {
    return res(ctx.json([
      { id: '1', name: 'Laptop', quantity: 10 },
      { id: '2', name: 'Mouse', quantity: 25 },
    ]));
  })
);

describe('Inventory API Integration', () => {
  beforeAll(() => server.listen());
  afterEach(() => server.resetHandlers());
  afterAll(() => server.close());

  it('should fetch inventory items', async () => {
    const items = await fetchInventory();
    expect(items).toHaveLength(2);
    expect(items[0].name).toBe('Laptop');
  });

  it('should handle API errors', async () => {
    server.use(
      rest.get('/api/inventory', (req, res, ctx) => {
        return res(ctx.status(500));
      })
    );

    await expect(fetchInventory()).rejects.toThrow('API Error');
  });
});
```

### 4. Feature Test Example
```javascript
// tests/features/itemManagement.test.js
import { describe, it, expect, beforeEach } from 'vitest';
import { InventoryService } from '../../src/services/inventoryService.js';

describe('Item Management Feature', () => {
  let service;
  let mockRepository;

  beforeEach(() => {
    mockRepository = {
      items: new Map(),
      addItem: vi.fn(async (item) => {
        const id = String(mockRepository.items.size + 1);
        mockRepository.items.set(id, { ...item, id });
        return id;
      }),
      getItem: vi.fn(async (id) => mockRepository.items.get(id)),
      updateQuantity: vi.fn(async (id, quantity) => {
        const item = mockRepository.items.get(id);
        if (item) {
          item.quantity = quantity;
          return true;
        }
        return false;
      }),
      deleteItem: vi.fn(async (id) => {
        return mockRepository.items.delete(id);
      }),
    };
    service = new InventoryService(mockRepository);
  });

  it('should complete item lifecycle', async () => {
    // Create
    const newItem = {
      name: 'Feature Test Item',
      barcode: 'FEATURE-123',
      quantity: 5,
    };
    const id = await service.addItem(newItem);
    expect(id).toBeDefined();

    // Read
    const saved = await service.getItem(id);
    expect(saved.name).toBe('Feature Test Item');

    // Update
    await service.updateQuantity(id, 10);
    const updated = await service.getItem(id);
    expect(updated.quantity).toBe(10);

    // Delete
    await service.deleteItem(id);
    const deleted = await service.getItem(id);
    expect(deleted).toBeNull();
  });
});
```

### 5. Workflow Test Example
```javascript
// cypress/e2e/workflows/onboarding.cy.js
describe('Onboarding Workflow', () => {
  beforeEach(() => {
    cy.visit('/');
    cy.clearLocalStorage();
  });

  it('should guide new user through first item addition', () => {
    // Verify empty state
    cy.contains('No items yet').should('be.visible');

    // Click add button
    cy.get('[data-testid="add-item-button"]').click();

    // Fill form
    cy.get('[data-testid="name-field"]').type('First Item');
    cy.get('[data-testid="barcode-field"]').type('123456');
    cy.get('[data-testid="quantity-field"]').type('5');

    // Save
    cy.get('[data-testid="save-button"]').click();

    // Verify success
    cy.contains('Item added successfully').should('be.visible');
    cy.contains('First Item').should('be.visible');
  });
});
```

---

## Angular/TypeScript

### Stack Overview
- **Unit Testing**: Jasmine, Karma
- **Component Testing**: Angular Testing Library
- **Integration Testing**: TestBed + HttpClientTestingModule
- **E2E Testing**: Protractor (legacy) or Cypress/Playwright

### Setup
```bash
ng add @cypress/schematic
```

```typescript
// karma.conf.js
module.exports = function (config) {
  config.set({
    frameworks: ['jasmine', '@angular-devkit/build-angular'],
    plugins: [
      require('karma-jasmine'),
      require('karma-chrome-launcher'),
      require('@angular-devkit/build-angular/plugins/karma'),
    ],
    browsers: ['ChromeHeadless'],
  });
};
```

### 1. Unit Test Example
```typescript
// src/app/services/inventory.service.spec.ts
import { TestBed } from '@angular/core/testing';
import { InventoryService } from './inventory.service';
import { InventoryRepository } from './inventory.repository';
import { of, throwError } from 'rxjs';
import { InventoryItem } from '../models/inventory-item.model';

describe('InventoryService', () => {
  let service: InventoryService;
  let mockRepository: jasmine.SpyObj<InventoryRepository>;

  beforeEach(() => {
    mockRepository = jasmine.createSpyObj('InventoryRepository', [
      'getItem',
      'updateQuantity',
    ]);

    TestBed.configureTestingModule({
      providers: [
        InventoryService,
        { provide: InventoryRepository, useValue: mockRepository },
      ],
    });

    service = TestBed.inject(InventoryService);
  });

  it('should increment item quantity', async () => {
    // Arrange
    const item: InventoryItem = {
      id: '1',
      name: 'Test Item',
      barcode: 'TEST-123',
      quantity: 5,
    };
    mockRepository.getItem.and.returnValue(of(item));
    mockRepository.updateQuantity.and.returnValue(of(true));

    // Act
    await service.incrementQuantity('1').toPromise();

    // Assert
    expect(mockRepository.updateQuantity).toHaveBeenCalledWith('1', 6);
  });

  it('should throw error when item not found', async () => {
    // Arrange
    mockRepository.getItem.and.returnValue(of(null));

    // Act & Assert
    try {
      await service.incrementQuantity('999').toPromise();
      fail('Should have thrown error');
    } catch (error) {
      expect(error.message).toBe('Item not found');
    }
  });
});
```

### 2. Component Test Example
```typescript
// src/app/components/inventory-card/inventory-card.component.spec.ts
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { InventoryCardComponent } from './inventory-card.component';
import { InventoryItem } from '../../models/inventory-item.model';
import { By } from '@angular/platform-browser';

describe('InventoryCardComponent', () => {
  let component: InventoryCardComponent;
  let fixture: ComponentFixture<InventoryCardComponent>;

  const mockItem: InventoryItem = {
    id: '1',
    name: 'Laptop',
    barcode: 'LAP-123',
    quantity: 10,
  };

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [InventoryCardComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(InventoryCardComponent);
    component = fixture.componentInstance;
    component.item = mockItem;
    fixture.detectChanges();
  });

  it('should display item information', () => {
    const compiled = fixture.nativeElement;
    expect(compiled.querySelector('.item-name').textContent).toContain('Laptop');
    expect(compiled.querySelector('.item-barcode').textContent).toContain('LAP-123');
    expect(compiled.querySelector('.item-quantity').textContent).toContain('10');
  });

  it('should emit click event when card is clicked', () => {
    spyOn(component.itemClick, 'emit');

    const card = fixture.debugElement.query(By.css('.inventory-card'));
    card.triggerEventHandler('click', null);

    expect(component.itemClick.emit).toHaveBeenCalledWith('1');
  });
});
```

### 3. Integration Test Example
```typescript
// src/app/integration/inventory-page.integration.spec.ts
import { TestBed } from '@angular/core/testing';
import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { InventoryService } from '../services/inventory.service';
import { InventoryItem } from '../models/inventory-item.model';

describe('InventoryService Integration', () => {
  let service: InventoryService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [HttpClientTestingModule],
      providers: [InventoryService],
    });
    service = TestBed.inject(InventoryService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should fetch inventory items from API', async () => {
    // Arrange
    const mockItems: InventoryItem[] = [
      { id: '1', name: 'Laptop', barcode: 'LAP-1', quantity: 10 },
      { id: '2', name: 'Mouse', barcode: 'MOU-1', quantity: 25 },
    ];

    // Act
    service.getAllItems().subscribe((items) => {
      expect(items).toEqual(mockItems);
    });

    // Assert
    const req = httpMock.expectOne('/api/inventory');
    expect(req.request.method).toBe('GET');
    req.flush(mockItems);
  });

  it('should handle API errors', async () => {
    // Act
    service.getAllItems().subscribe(
      () => fail('should have failed'),
      (error) => {
        expect(error.status).toBe(500);
      }
    );

    // Assert
    const req = httpMock.expectOne('/api/inventory');
    req.flush('Server error', { status: 500, statusText: 'Internal Server Error' });
  });
});
```

---

## Node.js/Express

### Stack Overview
- **Unit Testing**: Jest, Mocha
- **Integration Testing**: Supertest
- **E2E Testing**: Supertest or dedicated E2E framework

### Setup
```bash
npm install --save-dev jest supertest @types/jest @types/supertest
```

### 1. Unit Test Example
```javascript
// services/inventoryService.test.js
const InventoryService = require('./inventoryService');
const InventoryRepository = require('./inventoryRepository');

jest.mock('./inventoryRepository');

describe('InventoryService', () => {
  let service;
  let mockRepository;

  beforeEach(() => {
    mockRepository = new InventoryRepository();
    service = new InventoryService(mockRepository);
  });

  describe('incrementQuantity', () => {
    it('should increment item quantity', async () => {
      // Arrange
      const item = {
        id: '1',
        name: 'Test Item',
        barcode: 'TEST-123',
        quantity: 5,
      };
      mockRepository.getItem.mockResolvedValue(item);
      mockRepository.updateQuantity.mockResolvedValue(true);

      // Act
      await service.incrementQuantity('1');

      // Assert
      expect(mockRepository.updateQuantity).toHaveBeenCalledWith('1', 6);
    });

    it('should throw error when item not found', async () => {
      // Arrange
      mockRepository.getItem.mockResolvedValue(null);

      // Act & Assert
      await expect(service.incrementQuantity('999')).rejects.toThrow('Item not found');
    });
  });
});
```

### 2. Integration Test Example
```javascript
// routes/inventoryRoutes.test.js
const request = require('supertest');
const express = require('express');
const inventoryRoutes = require('./inventoryRoutes');
const InventoryService = require('../services/inventoryService');

jest.mock('../services/inventoryService');

const app = express();
app.use(express.json());
app.use('/api/inventory', inventoryRoutes);

describe('Inventory Routes', () => {
  let mockService;

  beforeEach(() => {
    mockService = new InventoryService();
  });

  describe('GET /api/inventory', () => {
    it('should return all inventory items', async () => {
      // Arrange
      const mockItems = [
        { id: '1', name: 'Laptop', barcode: 'LAP-1', quantity: 10 },
        { id: '2', name: 'Mouse', barcode: 'MOU-1', quantity: 25 },
      ];
      mockService.getAllItems.mockResolvedValue(mockItems);

      // Act
      const response = await request(app).get('/api/inventory');

      // Assert
      expect(response.status).toBe(200);
      expect(response.body).toEqual(mockItems);
    });

    it('should handle service errors', async () => {
      // Arrange
      mockService.getAllItems.mockRejectedValue(new Error('Database connection failed'));

      // Act
      const response = await request(app).get('/api/inventory');

      // Assert
      expect(response.status).toBe(500);
      expect(response.body.error).toBe('Failed to fetch inventory');
    });
  });

  describe('POST /api/inventory', () => {
    it('should create new inventory item', async () => {
      // Arrange
      const newItem = {
        name: 'Keyboard',
        barcode: 'KEY-1',
        quantity: 15,
      };
      const createdItem = { id: '3', ...newItem };
      mockService.addItem.mockResolvedValue(createdItem);

      // Act
      const response = await request(app).post('/api/inventory').send(newItem);

      // Assert
      expect(response.status).toBe(201);
      expect(response.body).toEqual(createdItem);
    });

    it('should validate required fields', async () => {
      // Act
      const response = await request(app).post('/api/inventory').send({
        name: 'Invalid Item',
        // Missing required fields
      });

      // Assert
      expect(response.status).toBe(400);
      expect(response.body.error).toContain('Validation failed');
    });
  });
});
```

### 3. E2E Test Example
```javascript
// test/e2e/smoke.test.js
const request = require('supertest');
const app = require('../../app');

describe('E2E Smoke Tests', () => {
  describe('Complete User Journey', () => {
    it('should perform full inventory management cycle', async () => {
      // 1. Get initial inventory (should be empty)
      let response = await request(app).get('/api/inventory');
      expect(response.status).toBe(200);
      expect(response.body).toEqual([]);

      // 2. Add first item
      const firstItem = {
        name: 'E2E Test Item',
        barcode: 'E2E-123',
        quantity: 5,
      };
      response = await request(app).post('/api/inventory').send(firstItem);
      expect(response.status).toBe(201);
      const itemId = response.body.id;

      // 3. Verify item in list
      response = await request(app).get('/api/inventory');
      expect(response.status).toBe(200);
      expect(response.body).toHaveLength(1);
      expect(response.body[0].name).toBe('E2E Test Item');

      // 4. Update quantity
      response = await request(app)
        .patch(`/api/inventory/${itemId}/quantity`)
        .send({ quantity: 10 });
      expect(response.status).toBe(200);

      // 5. Verify update
      response = await request(app).get(`/api/inventory/${itemId}`);
      expect(response.body.quantity).toBe(10);

      // 6. Delete item
      response = await request(app).delete(`/api/inventory/${itemId}`);
      expect(response.status).toBe(204);

      // 7. Verify deletion
      response = await request(app).get('/api/inventory');
      expect(response.body).toEqual([]);
    });

    it('should handle concurrent updates correctly', async () => {
      // Create item
      const item = {
        name: 'Concurrent Test Item',
        barcode: 'CONC-123',
        quantity: 10,
      };
      let response = await request(app).post('/api/inventory').send(item);
      const itemId = response.body.id;

      // Simulate concurrent updates
      const updates = [
        request(app).patch(`/api/inventory/${itemId}/quantity`).send({ quantity: 15 }),
        request(app).patch(`/api/inventory/${itemId}/quantity`).send({ quantity: 20 }),
        request(app).patch(`/api/inventory/${itemId}/quantity`).send({ quantity: 25 }),
      ];

      const results = await Promise.all(updates);

      // All should succeed
      expect(results.every(r => r.status === 200)).toBe(true);

      // Final quantity should be consistent (last write wins)
      response = await request(app).get(`/api/inventory/${itemId}`);
      expect(response.body.quantity).toBe(25);
    });
  });
});
```

---

## .NET/C#

### Stack Overview
- **Unit Testing**: xUnit, NUnit, MSTest
- **Integration Testing**: WebApplicationFactory
- **Component Testing**: bUnit for Blazor
- **E2E Testing**: Playwright for .NET, Selenium

### Setup
```bash
dotnet add package xunit
dotnet add package Xunit.Analyzers
dotnet add package Moq
dotnet add package Microsoft.AspNetCore.Mvc.Testing
```

### 1. Unit Test Example
```csharp
// tests/InventoryServiceTests.cs
using Xunit;
using Moq;
using MyApp.Services;
using MyApp.Repositories;
using MyApp.Models;

public class InventoryServiceTests
{
    private readonly InventoryService _service;
    private readonly Mock<IInventoryRepository> _mockRepository;

    public InventoryServiceTests()
    {
        _mockRepository = new Mock<IInventoryRepository>();
        _service = new InventoryService(_mockRepository.Object);
    }

    [Fact]
    public async Task IncrementQuantity_WhenItemExists_IncrementsQuantity()
    {
        // Arrange
        var item = new InventoryItem
        {
            Id = "1",
            Name = "Test Item",
            Barcode = "TEST-123",
            Quantity = 5
        };
        _mockRepository.Setup(r => r.GetItem("1")).ReturnsAsync(item);
        _mockRepository.Setup(r => r.UpdateQuantity("1", 6)).ReturnsAsync(true);

        // Act
        await _service.IncrementQuantity("1");

        // Assert
        _mockRepository.Verify(r => r.UpdateQuantity("1", 6), Times.Once);
    }

    [Fact]
    public async Task IncrementQuantity_WhenItemDoesNotExist_ThrowsException()
    {
        // Arrange
        _mockRepository.Setup(r => r.GetItem("999")).ReturnsAsync((InventoryItem)null);

        // Act & Assert
        await Assert.ThrowsAsync<ItemNotFoundException>(
            () => _service.IncrementQuantity("999")
        );
    }
}
```

### 2. Integration Test Example
```csharp
// tests/InventoryApiTests.cs
using Xunit;
using Microsoft.AspNetCore.Mvc.Testing;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;
using MyApp.Models;

public class InventoryApiTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;

    public InventoryApiTests(WebApplicationFactory<Program> factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task GetInventory_ReturnsItems()
    {
        // Act
        var response = await _client.GetAsync("/api/inventory");

        // Assert
        response.EnsureSuccessStatusCode();
        var items = await response.Content.ReadFromJsonAsync<InventoryItem[]>();
        Assert.NotNull(items);
        Assert.NotEmpty(items);
    }

    [Fact]
    public async Task PostInventory_CreatesNewItem()
    {
        // Arrange
        var newItem = new
        {
            Name = "Integration Test Item",
            Barcode = "INT-123",
            Quantity = 5
        };

        // Act
        var response = await _client.PostAsJsonAsync("/api/inventory", newItem);

        // Assert
        response.EnsureSuccessStatusCode();
        var createdItem = await response.Content.ReadFromJsonAsync<InventoryItem>();
        Assert.NotNull(createdItem.Id);
        Assert.Equal("Integration Test Item", createdItem.Name);
    }
}
```

### 3. Blazor Component Test Example
```csharp
// tests/InventoryCardTests.razor
@using MyApp.Components
@using MyApp.Models
@using Bunit
@using Xunit

@code {
    [Fact]
    public void InventoryCard_RendersItemCorrectly()
    {
        // Arrange
        using var ctx = new TestContext();
        var item = new InventoryItem
        {
            Id = "1",
            Name = "Laptop",
            Barcode = "LAP-123",
            Quantity = 10
        };

        // Act
        var cut = ctx.RenderComponent<InventoryCard>(
            parameters => parameters.Add(p => p.Item, item)
        );

        // Assert
        cut.Find(".item-name").TextContent.MarkupMatches("Laptop");
        cut.Find(".item-barcode").TextContent.MarkupMatches("Barcode: LAP-123");
        cut.Find(".item-quantity").TextContent.MarkupMatches("10");
    }

    [Fact]
    public void ClickingCard_TriggersOnClickEvent()
    {
        // Arrange
        using var ctx = new TestContext();
        var item = new InventoryItem { Id = "1", Name = "Test", Quantity = 5 };
        var wasClicked = false;
        InventoryItem clickedItem = null;

        // Act
        var cut = ctx.RenderComponent<InventoryCard>(
            parameters => parameters
                .Add(p => p.Item, item)
                .Add(p => p.OnClick, (i) => { wasClicked = true; clickedItem = i; })
        );

        cut.Find(".inventory-card").Click();

        // Assert
        Assert.True(wasClicked);
        Assert.Equal(item, clickedItem);
    }
}
```

---

## Test Type Comparison by Technology

| Test Type | Flutter | React | Vue | Angular | Node.js | .NET |
|-----------|---------|-------|-----|---------|---------|------|
| **Unit** | `flutter_test` | Jest | Vitest | Jasmine | Jest | xUnit |
| **Component** | Widget Tests | RTL | Vue Test Utils | Angular TL | - | bUnit |
| **Integration** | `integration_test` | Jest + MSW | Vitest + MSW | TestBed | Supertest | WebAppFactory |
| **Workflow** | Flutter Driver | Cypress | Cypress | Protractor | - | Playwright |
| **System** | Native | Performance APIs | Performance APIs | Performance APIs | - | Performance Counters |
| **E2E** | Patrol | Cypress/Playwright | Cypress/Playwright | Protractor | Supertest | Playwright |

---

## 🎯 Implementation Guidelines by Tech Stack

### **React/Vue/Angular (Frontend)**
- **Unit Tests**: Test all business logic, hooks, composables, services
- **Component Tests**: Test rendering, user interactions, state management
- **Integration Tests**: Test API calls, state management, routing
- **Workflow Tests**: Test complete user journeys with E2E tools
- **System Tests**: Performance, accessibility, security testing
- **E2E Tests**: Critical paths only, real browser, real API

### **Flutter (Mobile)**
- **Unit Tests**: Test all Dart logic, models, services
- **Widget Tests**: Test every widget, state changes, animations
- **Integration Tests**: Test database, API calls, platform features
- **Workflow Tests**: Test navigation, user flows, multi-screen journeys
- **System Tests**: Performance benchmarks, memory usage
- **E2E Tests**: Real device testing, camera, location, critical paths

### **Node.js/.NET (Backend)**
- **Unit Tests**: Test all business logic, services, utilities
- **Integration Tests**: Test database operations, API endpoints
- **Feature Tests**: Test complete business operations
- **System Tests**: Load testing, security testing, stress testing
- **E2E Tests**: API contract testing, full request-response cycles

---

## 📊 Test Coverage Standards by Technology

| Technology | Unit | Component | Integration | Feature | Workflow | System | E2E | Total |
|------------|------|-----------|-------------|---------|----------|--------|-----|-------|
| **Flutter** | 90% | 80% | 70% | 70% | 60% | 50% | 40% | 85% |
| **React** | 90% | 85% | 75% | 70% | 65% | 50% | 40% | 85% |
| **Vue** | 90% | 85% | 75% | 70% | 65% | 50% | 40% | 85% |
| **Angular** | 90% | 85% | 75% | 70% | 65% | 50% | 40% | 85% |
| **Node.js** | 90% | N/A | 80% | 75% | N/A | 60% | 50% | 85% |
| **.NET** | 90% | N/A | 80% | 75% | N/A | 60% | 50% | 85% |

---

## 🔧 CI/CD Integration by Technology

### **GitHub Actions - Multi-Framework**
```yaml
name: Multi-Framework Tests

on: [push, pull_request]

jobs:
  flutter-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: subosito/flutter-action@v2
      - run: flutter pub get
      - run: flutter analyze
      - run: flutter test --coverage
      - run: flutter test integration_test/

  react-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
      - run: npm ci
      - run: npm run test:ci
      - run: npm run test:e2e

  dotnet-tests:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-dotnet@v3
      - run: dotnet restore
      - run: dotnet build
      - run: dotnet test --collect:"XPlat Code Coverage"
```

---

## Python/FastAPI

### Stack Overview
- **Unit Testing**: pytest, unittest
- **Integration Testing**: pytest, httpx
- **E2E Testing**: pytest, Playwright

### Setup
```bash
pip install pytest pytest-cov httpx pytest-asyncio pytest-playwright
```

```python
# pytest.ini or setup.cfg
[tool:pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = --cov=. --cov-report=html --cov-report=term-missing
```

### 1. Unit Test Example
```python
# tests/unit/test_inventory_service.py
import pytest
from unittest.mock import Mock
from app.services.inventory_service import InventoryService
from app.repositories.inventory_repository import InventoryRepository
from app.models.inventory_item import InventoryItem

def test_increment_quantity_when_item_exists():
    # Arrange
    mock_repository = Mock(spec=InventoryRepository)
    service = InventoryService(mock_repository)
    
    item = InventoryItem(
        id="1",
        name="Test Item",
        barcode="TEST-123",
        quantity=5
    )
    mock_repository.get_item.return_value = item
    mock_repository.update_quantity.return_value = True
    
    # Act
    service.increment_quantity("1")
    
    # Assert
    mock_repository.update_quantity.assert_called_once_with("1", 6)

def test_increment_quantity_when_item_not_found():
    # Arrange
    mock_repository = Mock(spec=InventoryRepository)
    service = InventoryService(mock_repository)
    mock_repository.get_item.return_value = None
    
    # Act & Assert
    with pytest.raises(ItemNotFoundException):
        service.increment_quantity("999")
```

### 2. API/Component Test Example (FastAPI)
```python
# tests/component/test_inventory_api.py
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_get_inventory_items():
    # Act
    response = client.get("/api/inventory")
    
    # Assert
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 0

def test_create_inventory_item():
    # Arrange
    new_item = {
        "name": "Test Item",
        "barcode": "TEST-123",
        "quantity": 5
    }
    
    # Act
    response = client.post("/api/inventory", json=new_item)
    
    # Assert
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "Test Item"
    assert data["quantity"] == 5
    assert "id" in data
```

### 3. Integration Test Example
```python
# tests/integration/test_database_integration.py
import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session
from app.database.models import Base, InventoryItemDB
from app.database.database import get_db

@pytest.fixture
def db_engine():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)

@pytest.fixture
def db_session(db_engine):
    connection = db_engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection)
    yield session
    session.close()
    transaction.rollback()
    connection.close()

def test_complete_crud_flow(db_session):
    # Create
    item = InventoryItemDB(
        barcode="TEST-123",
        name="Integration Test Item",
        quantity=5
    )
    db_session.add(item)
    db_session.commit()
    db_session.refresh(item)
    assert item.id is not None
    item_id = item.id
    
    # Read
    saved_item = db_session.query(InventoryItemDB).filter_by(id=item_id).first()
    assert saved_item.name == "Integration Test Item"
    assert saved_item.quantity == 5
    
    # Update
    saved_item.quantity = 10
    db_session.commit()
    
    updated_item = db_session.query(InventoryItemDB).filter_by(id=item_id).first()
    assert updated_item.quantity == 10
    
    # Delete
    db_session.delete(updated_item)
    db_session.commit()
    
    deleted_item = db_session.query(InventoryItemDB).filter_by(id=item_id).first()
    assert deleted_item is None
```

### 4. Feature Test Example
```python
# tests/integration/test_item_management_feature.py
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_complete_item_lifecycle():
    # Create item
    new_item = {
        "name": "Feature Test Item",
        "barcode": "FEATURE-123",
        "quantity": 5
    }
    response = client.post("/api/inventory", json=new_item)
    assert response.status_code == 201
    item_data = response.json()
    item_id = item_data["id"]
    
    # Read item
    response = client.get(f"/api/inventory/{item_id}")
    assert response.status_code == 200
    assert response.json()["name"] == "Feature Test Item"
    
    # Update quantity
    response = client.put(
        f"/api/inventory/{item_id}/quantity",
        json={"quantity": 10}
    )
    assert response.status_code == 200
    
    # Verify update
    response = client.get(f"/api/inventory/{item_id}")
    assert response.json()["quantity"] == 10
    
    # Update details
    response = client.put(
        f"/api/inventory/{item_id}",
        json={"name": "Updated Item"}
    )
    assert response.status_code == 200
    
    # Delete item
    response = client.delete(f"/api/inventory/{item_id}")
    assert response.status_code == 204
    
    # Verify deletion
    response = client.get(f"/api/inventory/{item_id}")
    assert response.status_code == 404
```

### 5. Workflow Test Example
```python
# tests/e2e/test_onboarding_workflow.py
import pytest
from playwright.sync_api import Page, expect

def test_new_user_onboarding(page: Page):
    # Step 1: Visit homepage
    page.goto("/")
    expect(page).to_have_title("Inventory Management")
    
    # Step 2: See empty state
    expect(page.get_by_text("No items yet")).to_be_visible()
    
    # Step 3: Click add button
    page.get_by_role("button", name="Add Item").click()
    
    # Step 4: Fill form
    page.get_by_label("Name").fill("First Item")
    page.get_by_label("Barcode").fill("123456")
    page.get_by_label("Quantity").fill("5")
    
    # Step 5: Submit form
    page.get_by_role("button", name="Save").click()
    
    # Step 6: Verify success message
    expect(page.get_by_text("Item added successfully")).to_be_visible()
    
    # Step 7: Verify item in list
    expect(page.get_by_text("First Item")).to_be_visible()
    expect(page.get_by_text("Barcode: 123456")).to_be_visible()
```

### 6. Performance Test Example
```python
# tests/system/test_performance.py
import pytest
import time
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_api_response_time():
    # Arrange
    start_time = time.time()
    
    # Act
    response = client.get("/api/inventory")
    
    # Assert
    end_time = time.time()
    assert response.status_code == 200
    assert (end_time - start_time) < 1.0  # Should respond in under 1 second

def test_database_query_performance(db_session):
    # Add test data
    for i in range(100):
        item = InventoryItemDB(
            barcode=f"PERF-{i}",
            name=f"Performance Test {i}",
            quantity=i
        )
        db_session.add(item)
    db_session.commit()
    
    # Measure query time
    start_time = time.time()
    result = db_session.query(InventoryItemDB).count()
    end_time = time.time()
    
    assert result == 100
    assert (end_time - start_time) < 0.5  # Should count in under 0.5 seconds
```

### 7. E2E Test Example
```python
# tests/e2e/test_smoke.py
import pytest
from playwright.sync_api import Page, expect

def test_complete_smoke_scenario(page: Page):
    # Scenario: Add item, search, update, delete
    
    # 1. Navigate to app
    page.goto("/")
    
    # 2. Add new item
    page.get_by_role("button", name="Add Item").click()
    page.get_by_label("Name").fill("Smoke Test Item")
    page.get_by_label("Barcode").fill("SMOKE-123")
    page.get_by_label("Quantity").fill("10")
    page.get_by_role("button", name="Save").click()
    
    # 3. Verify item added
    expect(page.get_by_text("Item added successfully")).to_be_visible()
    
    # 4. Search for item
    page.get_by_placeholder("Search inventory").fill("Smoke Test")
    expect(page.get_by_text("Smoke Test Item")).to_be_visible()
    
    # 5. Update quantity
    page.get_by_text("Smoke Test Item").click()
    page.get_by_label("Quantity").fill("15")
    page.get_by_role("button", name="Update").click()
    expect(page.get_by_text("15")).to_be_visible()
    
    # 6. Delete item
    page.get_by_role("button", name="Delete").click()
    page.get_by_role("button", name="Confirm").click()
    
    # 7. Verify deletion
    page.get_by_placeholder("Search inventory").fill("Smoke Test")
    expect(page.get_by_text("No items found")).to_be_visible()
```

---

**Version**: [TEMPLATE_VERSION]  
**Last Updated**: [CURRENT_DATE]  
**Maintainer**: [MAINTAINER_NAME]

---

*This guide provides concrete, production-ready test implementations for each major technology stack. Adapt the examples to your project's specific requirements and coding standards.*