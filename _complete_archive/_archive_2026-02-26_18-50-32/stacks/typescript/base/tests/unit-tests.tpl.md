# TypeScript Unit Testing Template
# Comprehensive unit testing patterns for TypeScript projects with Jest and full type safety

/**
 * TypeScript Unit Test Patterns
 * Advanced unit testing with Jest, TypeScript, type-safe mocking, and comprehensive coverage
 */

import { describe, it, expect, beforeEach, afterEach, jest, beforeAll, afterAll } from '@jest/globals';
import { Mocked, MockedFunction, MockedClass } from 'jest-mock';
import { UserService } from '@/services/UserService';
import { UserRepository } from '@/repositories/UserRepository';
import { EmailService } from '@/services/EmailService';
import { User, CreateUserRequest, UserRole } from '@/models/User';
import { ValidationError, NotFoundError, BusinessRuleError } from '@/utils/errors';

// ====================
// BASIC UNIT TEST PATTERNS
// ====================

describe('Basic Function Tests', () => {
  
  test('square function with positive numbers', () => {
    const result = square(5);
    expect(result).toBe(25);
  });
  
  test('square function with zero', () => {
    const result = square(0);
    expect(result).toBe(0);
  });
  
  test('square function with negative numbers', () => {
    const result = square(-3);
    expect(result).toBe(9);
  });
  
  test('square function with large numbers', () => {
    const result = square(100);
    expect(result).toBe(10000);
  });

  test('square function with decimal numbers', () => {
    const result = square(2.5);
    expect(result).toBe(6.25);
  });

  test('square function handles type safety', () => {
    // TypeScript compile-time type checking
    const num: number = 5;
    const result: number = square(num);
    expect(result).toBe(25);
  });
});

describe('Table-Driven Tests', () => {
  test.each([
    ['regular customer', 'regular', 100.0, 0.0],
    ['premium customer small purchase', 'premium', 50.0, 2.5],
    ['premium customer large purchase', 'premium', 200.0, 20.0],
    ['vip customer', 'vip', 100.0, 15.0],
    ['vip customer large purchase', 'vip', 1000.0, 150.0],
  ])('calculate discount: %s', (description, customerType, amount, expected) => {
    const discount = calculateDiscount(customerType, amount);
    expect(Math.abs(discount - expected)).toBeLessThan(0.01);
  });

  test.each([
    [1, 1, 2],
    [2, 3, 5],
    [-1, 1, 0],
    [0, 0, 0],
    [100, 200, 300],
  ])('add function: %d + %d = %d', (a, b, expected) => {
    expect(add(a, b)).toBe(expected);
  });
});

// ====================
// TYPE-SAFE MOCK TESTING PATTERNS
// ====================

describe('Mock Testing Patterns with Type Safety', () => {
  
  test('service with mock repository', async () => {
    // Create type-safe mock repository
    const mockRepository: Mocked<UserRepository> = {
      findById: jest.fn(),
      findByEmail: jest.fn(),
      save: jest.fn(),
      delete: jest.fn(),
      findAll: jest.fn(),
      count: jest.fn(),
    };
    
    // Setup expectations with proper typing
    const expectedUser: User = {
      id: '123',
      name: 'John Doe',
      email: 'john@example.com',
      passwordHash: 'hashed_password',
      roles: [UserRole.USER],
      isActive: true,
      createdAt: new Date('2023-01-01'),
      updatedAt: new Date('2023-01-01'),
    };
    
    mockRepository.findById.mockResolvedValue(expectedUser);
    mockRepository.save.mockResolvedValue(expectedUser);
    
    // Create service with mock
    const service = new UserService(mockRepository);
    
    // Execute and assert
    const user = await service.getUserById('123');
    expect(user).toEqual(expectedUser);
    expect(mockRepository.findById).toHaveBeenCalledWith('123');
    expect(mockRepository.save).not.toHaveBeenCalled();
  });
  
  test('API call with mock axios', async () => {
    // Mock axios with proper typing
    interface AxiosResponse<T = any> {
      data: T;
      status: number;
      statusText: string;
      headers: any;
      config: any;
    }
    
    interface AxiosInstance {
      get: MockedFunction<(url: string) => Promise<AxiosResponse>>;
      post: MockedFunction<(url: string, data?: any) => Promise<AxiosResponse>>;
    }
    
    const mockAxios: AxiosInstance = {
      get: jest.fn(),
      post: jest.fn(),
    };
    
    // Setup mock response with proper typing
    const mockResponse: AxiosResponse = {
      data: { id: '1', name: 'John Doe', email: 'john@example.com' },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    };
    
    mockAxios.get.mockResolvedValue(mockResponse);
    
    // Execute
    const result = await fetchUserAPI(mockAxios as any, '1');
    
    // Assert
    expect(result.name).toBe('John Doe');
    expect(mockAxios.get).toHaveBeenCalledWith('/api/users/1');
  });

  test('mock external service with error handling', async () => {
    const mockEmailService: Mocked<EmailService> = {
      sendWelcomeEmail: jest.fn(),
      sendPasswordResetEmail: jest.fn(),
      sendOrderConfirmation: jest.fn(),
      validateEmail: jest.fn(),
    };
    
    // Mock successful email
    mockEmailService.sendWelcomeEmail.mockResolvedValue(true);
    
    // Mock failed email
    mockEmailService.sendPasswordResetEmail.mockRejectedValue(
      new Error('SMTP connection failed')
    );
    
    const service = new UserService(mockEmailService as any);
    
    // Test successful email
    await expect(service.sendWelcomeEmail('test@example.com')).resolves.toBe(true);
    
    // Test failed email
    await expect(service.sendPasswordResetEmail('test@example.com')).rejects.toThrow(
      'SMTP connection failed'
    );
  });
});

// ====================
// CLASS AND SERVICE TESTING
// ====================

describe('UserService Class Testing', () => {
  let userService: UserService;
  let mockUserRepository: Mocked<UserRepository>;
  let mockEmailService: Mocked<EmailService>;

  beforeEach(() => {
    // Create fresh mocks for each test
    mockUserRepository = {
      findById: jest.fn(),
      findByEmail: jest.fn(),
      save: jest.fn(),
      delete: jest.fn(),
      findAll: jest.fn(),
      count: jest.fn(),
    };
    
    mockEmailService = {
      sendWelcomeEmail: jest.fn(),
      sendPasswordResetEmail: jest.fn(),
      sendOrderConfirmation: jest.fn(),
      validateEmail: jest.fn(),
    };
    
    userService = new UserService(mockUserRepository, mockEmailService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('createUser', () => {
    it('should create a user with valid data', async () => {
      // Arrange
      const userData: CreateUserRequest = {
        name: 'John Doe',
        email: 'john@example.com',
        password: 'SecureP@ssw0rd123',
        roles: [UserRole.USER],
      };

      const expectedUser: User = {
        id: '123',
        name: userData.name,
        email: userData.email,
        passwordHash: 'hashed_password',
        roles: userData.roles || [UserRole.USER],
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      mockUserRepository.findByEmail.mockResolvedValue(null);
      mockUserRepository.save.mockResolvedValue(expectedUser);
      mockEmailService.sendWelcomeEmail.mockResolvedValue(true);

      // Act
      const result = await userService.createUser(userData);

      // Assert
      expect(result).toEqual(expectedUser);
      expect(mockUserRepository.findByEmail).toHaveBeenCalledWith(userData.email);
      expect(mockUserRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          name: userData.name,
          email: userData.email,
        })
      );
      expect(mockEmailService.sendWelcomeEmail).toHaveBeenCalledWith(expectedUser);
    });

    it('should throw error for duplicate email', async () => {
      // Arrange
      const userData: CreateUserRequest = {
        name: 'John Doe',
        email: 'existing@example.com',
        password: 'SecureP@ssw0rd123',
      };

      const existingUser: User = {
        id: '456',
        name: 'Existing User',
        email: userData.email,
        passwordHash: 'hashed_password',
        roles: [UserRole.USER],
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      mockUserRepository.findByEmail.mockResolvedValue(existingUser);

      // Act & Assert
      await expect(userService.createUser(userData)).rejects.toThrow(
        BusinessRuleError
      );
      await expect(userService.createUser(userData)).rejects.toThrow(
        'User with this email already exists'
      );

      expect(mockUserRepository.save).not.toHaveBeenCalled();
      expect(mockEmailService.sendWelcomeEmail).not.toHaveBeenCalled();
    });

    it('should validate email format', async () => {
      // Arrange
      const userData: CreateUserRequest = {
        name: 'John Doe',
        email: 'invalid-email-format',
        password: 'SecureP@ssw0rd123',
      };

      // Act & Assert
      await expect(userService.createUser(userData)).rejects.toThrow(
        ValidationError
      );
      await expect(userService.createUser(userData)).rejects.toThrow(
        'Invalid email format'
      );

      expect(mockUserRepository.findByEmail).not.toHaveBeenCalled();
      expect(mockUserRepository.save).not.toHaveBeenCalled();
    });
  });

  describe('getUserById', () => {
    it('should return user when found', async () => {
      // Arrange
      const expectedUser: User = {
        id: '123',
        name: 'John Doe',
        email: 'john@example.com',
        passwordHash: 'hashed_password',
        roles: [UserRole.USER],
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      mockUserRepository.findById.mockResolvedValue(expectedUser);

      // Act
      const result = await userService.getUserById('123');

      // Assert
      expect(result).toEqual(expectedUser);
      expect(mockUserRepository.findById).toHaveBeenCalledWith('123');
    });

    it('should throw NotFoundError when user not found', async () => {
      // Arrange
      mockUserRepository.findById.mockResolvedValue(null);

      // Act & Assert
      await expect(userService.getUserById('nonexistent')).rejects.toThrow(
        NotFoundError
      );
      await expect(userService.getUserById('nonexistent')).rejects.toThrow(
        'User not found'
      );

      expect(mockUserRepository.findById).toHaveBeenCalledWith('nonexistent');
    });
  });
});

// ====================
// UTILITY FUNCTION TESTING
// ====================

describe('Utility Function Testing', () => {
  
  describe('Validation Utils', () => {
    test('validateEmail with valid emails', () => {
      const validEmails = [
        'user@example.com',
        'test.email+tag@domain.co.uk',
        'user123@test-domain.com',
        'john.doe@company.org',
      ];

      validEmails.forEach(email => {
        expect(validateEmail(email)).toBe(true);
      });
    });

    test('validateEmail with invalid emails', () => {
      const invalidEmails = [
        'invalid-email',
        '@domain.com',
        'user@',
        'user..name@domain.com',
        '',
        null,
        undefined,
      ];

      invalidEmails.forEach(email => {
        expect(validateEmail(email as string)).toBe(false);
      });
    });
  });

  describe('Password Validation Utils', () => {
    test('validatePassword with strong passwords', () => {
      const strongPasswords = [
        'StrongP@ssw0rd123',
        'C0mpl3x!PassWord',
        'S3cur3P@ss!',
      ];

      strongPasswords.forEach(password => {
        const result = validatePassword(password);
        expect(result.isValid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });
    });

    test('validatePassword with weak passwords', () => {
      const weakPasswords = [
        'weak',
        '123456',
        'password',
        'PASSWORD',
        'Pass Word',
      ];

      weakPasswords.forEach(password => {
        const result = validatePassword(password);
        expect(result.isValid).toBe(false);
        expect(result.errors.length).toBeGreaterThan(0);
      });
    });
  });

  describe('Date Utils', () => {
    test('formatDate with different formats', () => {
      const date = new Date('2023-12-25T10:30:00');
      
      expect(formatDate(date, 'YYYY-MM-DD')).toBe('2023-12-25');
      expect(formatDate(date, 'DD/MM/YYYY')).toBe('25/12/2023');
      expect(formatDate(date, 'MM-DD-YYYY')).toBe('12-25-2023');
      expect(formatDate(date, 'DD MMM YYYY')).toBe('25 Dec 2023');
    });

    test('isValidDate with various inputs', () => {
      expect(isValidDate(new Date())).toBe(true);
      expect(isValidDate(new Date('2023-01-01'))).toBe(true);
      expect(isValidDate(new Date('invalid'))).toBe(false);
      expect(isValidDate(null as any)).toBe(false);
      expect(isValidDate(undefined as any)).toBe(false);
      expect(isValidDate('2023-01-01' as any)).toBe(false);
    });
  });
});

// ====================
// ASYNC FUNCTION TESTING
// ====================

describe('Async Function Testing', () => {
  
  test('handles promises correctly', async () => {
    const promise = Promise.resolve('test data');
    
    await expect(promise).resolves.toBe('test data');
    await expect(Promise.reject('error')).rejects.toBe('error');
  });

  test('handles timeout scenarios', async () => {
    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error('Timeout')), 100);
    });

    await expect(timeoutPromise).rejects.toThrow('Timeout');
  }, 200); // Test timeout

  test('handles concurrent operations', async () => {
    const operations = [
      Promise.resolve(1),
      Promise.resolve(2),
      Promise.resolve(3),
    ];

    const results = await Promise.all(operations);
    expect(results).toHaveLength(3);
    expect(results).toEqual([1, 2, 3]);
  });

  test('handles race conditions', async () => {
    const fastPromise = new Promise(resolve => setTimeout(() => resolve('fast'), 10));
    const slowPromise = new Promise(resolve => setTimeout(() => resolve('slow'), 100));

    const result = await Promise.race([fastPromise, slowPromise]);
    expect(result).toBe('fast');
  });
});

// ====================
// ERROR HANDLING TESTING
// ====================

describe('Error Handling Testing', () => {
  
  test('handles custom errors correctly', () => {
    const validationError = new ValidationError('Invalid input');
    const notFoundError = new NotFoundError('Resource not found');
    const businessRuleError = new BusinessRuleError('Business rule violated');

    expect(validationError).toBeInstanceOf(ValidationError);
    expect(validationError.message).toBe('Invalid input');
    expect(validationError.name).toBe('ValidationError');

    expect(notFoundError).toBeInstanceOf(NotFoundError);
    expect(notFoundError.message).toBe('Resource not found');

    expect(businessRuleError).toBeInstanceOf(BusinessRuleError);
    expect(businessRuleError.message).toBe('Business rule violated');
  });

  test('error propagation in async functions', async () => {
    const mockRepository = {
      findById: jest.fn().mockRejectedValue(new Error('Database connection failed')),
    };

    const service = new UserService(mockRepository as any);

    await expect(service.getUserById('123')).rejects.toThrow('Database connection failed');
  });

  test('error handling with try-catch', async () => {
    const errorMessage = 'Test error';
    
    try {
      throw new Error(errorMessage);
    } catch (error) {
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).message).toBe(errorMessage);
    }
  });
});

// ====================
// PROPERTY-BASED TESTING
// ====================

describe('Property-Based Testing', () => {
  
  test('mathematical properties', () => {
    // Test commutative property
    for (let i = 0; i < 100; i++) {
      const a = Math.floor(Math.random() * 1000);
      const b = Math.floor(Math.random() * 1000);
      expect(add(a, b)).toBe(add(b, a));
    }

    // Test associative property
    for (let i = 0; i < 100; i++) {
      const a = Math.floor(Math.random() * 100);
      const b = Math.floor(Math.random() * 100);
      const c = Math.floor(Math.random() * 100);
      expect(add(add(a, b), c)).toBe(add(a, add(b, c)));
    }

    // Test identity property
    for (let i = 0; i < 100; i++) {
      const a = Math.floor(Math.random() * 1000);
      expect(add(a, 0)).toBe(a);
      expect(add(0, a)).toBe(a);
    }
  });

  test('string validation properties', () => {
    // Test that valid emails always pass validation
    const validEmailPatterns = [
      'user@domain.com',
      'test.email+tag@domain.co.uk',
      'user123@sub.domain.com',
    ];

    validEmailPatterns.forEach(pattern => {
      expect(validateEmail(pattern)).toBe(true);
    });
  });
});

// ====================
// CUSTOM MATCHERS AND UTILITIES
// ====================

// Custom matchers for TypeScript
declare global {
  namespace jest {
    interface Matchers<R> {
      toBeValidUser(): R;
      toBeValidEmail(): R;
      toBeValidUuid(): R;
      toBeWithinRange(min: number, max: number): R;
    }
  }
}

expect.extend({
  toBeValidUser(received: any) {
    const pass = received && 
      typeof received.id === 'string' &&
      typeof received.name === 'string' &&
      typeof received.email === 'string' &&
      Array.isArray(received.roles) &&
      typeof received.isActive === 'boolean';

    if (pass) {
      return {
        message: () => `expected ${received} not to be a valid user`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected ${received} to be a valid user`,
        pass: false,
      };
    }
  },

  toBeValidEmail(received: any) {
    const pass = typeof received === 'string' && 
      /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(received);

    if (pass) {
      return {
        message: () => `expected ${received} not to be a valid email`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected ${received} to be a valid email`,
        pass: false,
      };
    }
  },

  toBeValidUuid(received: any) {
    const pass = typeof received === 'string' && 
      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(received);

    if (pass) {
      return {
        message: () => `expected ${received} not to be a valid UUID`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected ${received} to be a valid UUID`,
        pass: false,
      };
    }
  },

  toBeWithinRange(received: any, floor: number, ceiling: number) {
    const pass = typeof received === 'number' && received >= floor && received <= ceiling;
    
    if (pass) {
      return {
        message: () => `expected ${received} not to be within range ${floor} - ${ceiling}`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected ${received} to be within range ${floor} - ${ceiling}`,
        pass: false,
      };
    }
  },
});

// ====================
// TEST DATA FACTORIES
// ====================

class UserFactory {
  static create(overrides: Partial<User> = {}): User {
    return {
      id: 'user-' + Math.random().toString(36).substr(2, 9),
      name: 'Test User',
      email: 'test@example.com',
      passwordHash: 'hashed_password',
      roles: [UserRole.USER],
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
      ...overrides,
    };
  }

  static createMany(count: number, overrides: Partial<User> = {}): User[] {
    return Array.from({ length: count }, () => this.create(overrides));
  }

  static withRole(role: UserRole): User {
    return this.create({ roles: [role] });
  }

  static inactive(): User {
    return this.create({ isActive: false });
  }
}

class CreateUserRequestFactory {
  static create(overrides: Partial<CreateUserRequest> = {}): CreateUserRequest {
    return {
      name: 'Test User',
      email: 'test@example.com',
      password: 'SecureP@ssw0rd123',
      roles: [UserRole.USER],
      ...overrides,
    };
  }
}

// ====================
// PERFORMANCE AND BENCHMARK TESTING
// ====================

describe('Performance Testing', () => {
  
  test('function execution time', async () => {
    const startTime = Date.now();
    
    // Execute function multiple times
    for (let i = 0; i < 1000; i++) {
      square(i);
    }
    
    const endTime = Date.now();
    const executionTime = endTime - startTime;
    
    // Should complete within reasonable time
    expect(executionTime).toBeLessThan(100); // 100ms
  });

  test('memory usage patterns', () => {
    const initialMemory = process.memoryUsage().heapUsed;
    
    // Create large array
    const largeArray = Array.from({ length: 10000 }, (_, i) => ({
      id: i,
      name: `Item ${i}`,
      data: Math.random().toString(36),
    }));
    
    // Process array
    const processed = largeArray.map(item => ({
      ...item,
      processed: true,
    }));
    
    const finalMemory = process.memoryUsage().heapUsed;
    const memoryIncrease = finalMemory - initialMemory;
    
    // Memory increase should be reasonable
    expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024); // 50MB
    expect(processed).toHaveLength(10000);
  });
});

// ====================
// HELPER FUNCTIONS FOR TESTS
// ====================

// Mock implementations for testing
function square(n: number): number {
  return n * n;
}

function add(a: number, b: number): number {
  return a + b;
}

function calculateDiscount(customerType: string, amount: number): number {
  switch (customerType) {
    case 'premium':
      return amount * 0.1; // 10% discount
    case 'vip':
      return amount * 0.15; // 15% discount
    default:
      return 0;
  }
}

function validateEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

function validatePassword(password: string): { isValid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  if (password.length < 8) {
    errors.push('Password must be at least 8 characters long');
  }
  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }
  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }
  if (!/[0-9]/.test(password)) {
    errors.push('Password must contain at least one number');
  }
  if (!/[!@#$%^&*]/.test(password)) {
    errors.push('Password must contain at least one special character');
  }
  
  return {
    isValid: errors.length === 0,
    errors,
  };
}

function formatDate(date: Date, format: string): string {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  
  switch (format) {
    case 'YYYY-MM-DD':
      return `${year}-${month}-${day}`;
    case 'DD/MM/YYYY':
      return `${day}/${month}/${year}`;
    case 'MM-DD-YYYY':
      return `${month}-${day}-${year}`;
    case 'DD MMM YYYY':
      const monthNames = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
      return `${day} ${monthNames[date.getMonth()]} ${year}`;
    default:
      return `${year}-${month}-${day}`;
  }
}

function isValidDate(date: any): date is Date {
  return date instanceof Date && !isNaN(date.getTime());
}

async function fetchUserAPI(axios: any, userId: string): Promise<any> {
  const response = await axios.get(`/api/users/${userId}`);
  return response.data;
}

// Export factories and utilities for use in other test files
export { UserFactory, CreateUserRequestFactory };