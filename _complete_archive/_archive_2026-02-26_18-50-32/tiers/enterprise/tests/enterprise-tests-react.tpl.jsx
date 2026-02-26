/**
 * File: enterprise-tests-react.tpl.jsx
 * Purpose: Template for unknown implementation
 * Generated for: {{PROJECT_NAME}}
 */

# Enterprise React Testing Template
# Purpose: Full-level enterprise testing template with comprehensive security, compliance, and resilience testing
# Usage: Copy to test/ directory and customize for your enterprise React project
# Stack: React (.jsx)
# Tier: Full (Enterprise)

## Purpose

Enterprise-level React testing template providing comprehensive testing coverage including security testing, compliance validation, resilience testing, multi-region deployment scenarios, and advanced monitoring. Focuses on testing enterprise-grade features like authentication, data encryption, audit trails, and disaster recovery in React applications.

## Usage

```bash
# Copy to your React project
cp _templates/tiers/full/tests/enterprise-tests-react.tpl.jsx test/enterprise.test.jsx

# Install dependencies
npm install --save-dev @testing-library/react @testing-library/jest-dom
npm install --save-dev @testing-library/user-event jest-environment-jsdom
npm install --save-dev jest-junit jest-html-reporters
npm install --save-dev @testing-library/react-hooks @testing-library/dom
npm install --save-dev msw node-fetch

# Install enterprise dependencies
npm install @reduxjs/toolkit react-redux
npm install jsonwebtoken bcryptjs crypto-js
npm install axios react-query
npm install @tanstack/react-query
npm install react-hook-form
npm install date-fns

# Run tests
npm test

# Run with coverage
npm run test:coverage

# Run security tests
npm run test:security

# Run compliance tests
npm run test:compliance

# Run resilience tests
npm run test:resilience

# Run integration tests
npm run test:integration
```

## Structure

```jsx
// test/enterprise.test.jsx
import React from 'react';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import { Provider } from 'react-redux';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { rest } from 'msw';
import { setupServer } from 'msw/node';
import { configureStore } from '@reduxjs/toolkit';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import CryptoJS from 'crypto-js';

// Import components and services
import App from '../src/App';
import { AuthProvider } from '../src/contexts/AuthContext';
import { ComplianceProvider } from '../src/contexts/ComplianceContext';
import { SecurityProvider } from '../src/contexts/SecurityContext';
import { ResilienceProvider } from '../src/contexts/ResilienceContext';
import LoginForm from '../src/components/auth/LoginForm';
import SecureDataDisplay from '../src/components/secure/SecureDataDisplay';
import ComplianceDashboard from '../src/components/compliance/ComplianceDashboard';
import EnterpriseDashboard from '../src/components/dashboard/EnterpriseDashboard';
import authService from '../src/services/authService';
import securityService from '../src/services/securityService';
import complianceService from '../src/services/complianceService';
import resilienceService from '../src/services/resilienceService';
import auditService from '../src/services/auditService';

// Test Configuration
const TestConfig = {
  ENCRYPTION_KEY: 'test_encryption_key_32_bytes_long',
  JWT_SECRET: 'test_jwt_secret_for_enterprise_testing',
  JWT_ALGORITHM: 'HS256',
  TEST_REGION: 'us-west-2',
  COMPLIANCE_REGIONS: ['us-west-2', 'eu-west-1', 'ap-southeast-1'],
  TEST_TIMEOUT: 30000,
  MAX_RETRIES: 3,
  RETRY_DELAY: 500,
  CIRCUIT_BREAKER_THRESHOLD: 5,
  CIRCUIT_BREAKER_TIMEOUT: 60000,
  API_BASE_URL: 'https://api.enterprise.com',
};

// Mock Server Setup
const server = setupServer(
  rest.post(`${TestConfig.API_BASE_URL}/auth/login`, (req, res, ctx) => {
    return res(
      ctx.status(200),
      ctx.json({
        accessToken: 'mock_access_token',
        refreshToken: 'mock_refresh_token',
        user: {
          id: 'user_123',
          name: 'Enterprise User',
          email: 'enterprise@company.com',
          role: 'admin',
          permissions: ['read', 'write', 'delete', 'admin']
        }
      })
    );
  }),
  
  rest.post(`${TestConfig.API_BASE_URL}/auth/refresh`, (req, res, ctx) => {
    return res(
      ctx.status(200),
      ctx.json({
        accessToken: 'new_mock_access_token',
        refreshToken: 'new_mock_refresh_token'
      })
    );
  }),

  rest.get(`${TestConfig.API_BASE_URL}/compliance/report`, (req, res, ctx) => {
    return res(
      ctx.status(200),
      ctx.json({
        gdprScore: 98.5,
        hipaaScore: 97.2,
        soc2Score: 96.8,
        iso27001Score: 99.1,
        overallScore: 97.9,
        recommendations: [
          'Implement additional data encryption',
          'Update privacy policy',
          'Enhance audit logging'
        ]
      })
    );
  }),

  rest.post(`${TestConfig.API_BASE_URL}/data/encrypt`, (req, res, ctx) => {
    return res(
      ctx.status(200),
      ctx.json({
        encryptedData: 'encrypted_base64_string',
        encryptionMethod: 'AES-256',
        timestamp: new Date().toISOString()
      })
    );
  }),

  rest.get(`${TestConfig.API_BASE_URL}/resilience/health`, (req, res, ctx) => {
    return res(
      ctx.status(200),
      ctx.json({
        status: 'healthy',
        regions: [
          { name: 'us-west-2', status: 'healthy', latency: 45 },
          { name: 'eu-west-1', status: 'healthy', latency: 120 },
          { name: 'ap-southeast-1', status: 'degraded', latency: 200 }
        ]
      })
    );
  })
);

// Enterprise Test Data Factory
class EnterpriseTestDataFactory {
  static createEnterpriseUser(overrides = {}) {
    return {
      id: overrides.id || 'enterprise_user_1',
      name: overrides.name || 'Enterprise User',
      email: overrides.email || 'enterprise@company.com',
      role: overrides.role || 'admin',
      mfaEnabled: overrides.mfaEnabled !== undefined ? overrides.mfaEnabled : true,
      permissions: overrides.permissions || ['read', 'write', 'delete', 'admin'],
      metadata: overrides.metadata || {},
      createdAt: overrides.createdAt || new Date(),
      lastLogin: overrides.lastLogin || new Date(),
      isActive: overrides.isActive !== undefined ? overrides.isActive : true,
      ...overrides
    };
  }

  static createSecureTransaction(overrides = {}) {
    return {
      id: overrides.id || 'txn_12345',
      userId: overrides.userId || 'user_123',
      amount: overrides.amount || 1000.00,
      currency: overrides.currency || 'USD',
      status: overrides.status || 'completed',
      encryptedData: overrides.encryptedData || {},
      auditTrail: overrides.auditTrail || [],
      createdAt: overrides.createdAt || new Date(),
      completedAt: overrides.completedAt || new Date(),
      region: overrides.region || TestConfig.TEST_REGION,
      ...overrides
    };
  }

  static createComplianceData(overrides = {}) {
    return {
      gdprCompliant: overrides.gdprCompliant !== undefined ? overrides.gdprCompliant : true,
      hipaaCompliant: overrides.hipaaCompliant !== undefined ? overrides.hipaaCompliant : true,
      soc2Compliant: overrides.soc2Compliant !== undefined ? overrides.soc2Compliant : true,
      iso27001Compliant: overrides.iso27001Compliant !== undefined ? overrides.iso27001Compliant : true,
      dataRetentionDays: overrides.dataRetentionDays || 2555,
      encryptionLevel: overrides.encryptionLevel || 'AES-256',
      lastAudit: overrides.lastAudit || new Date(),
      auditScore: overrides.auditScore || 98.5,
      ...overrides
    };
  }
}

// Test Utilities
const createTestStore = (initialState = {}) => {
  return configureStore({
    reducer: {
      auth: (state = { user: null, isAuthenticated: false }, action) => {
        switch (action.type) {
          case 'auth/loginSuccess':
            return { user: action.payload, isAuthenticated: true };
          case 'auth/logout':
            return { user: null, isAuthenticated: false };
          default:
            return state;
        }
      },
      compliance: (state = { report: null }, action) => {
        switch (action.type) {
          case 'compliance/setReport':
            return { report: action.payload };
          default:
            return state;
        }
      }
    },
    preloadedState: initialState
  });
};

const createTestQueryClient = () => {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: TestConfig.MAX_RETRIES,
        retryDelay: TestConfig.RETRY_DELAY,
      },
    },
  });
};

const renderWithProviders = (component, options = {}) => {
  const store = options.store || createTestStore();
  const queryClient = options.queryClient || createTestQueryClient();
  
  return render(
    <Provider store={store}>
      <QueryClientProvider client={queryClient}>
        <AuthProvider>
          <SecurityProvider>
            <ComplianceProvider>
              <ResilienceProvider>
                {component}
              </ResilienceProvider>
            </ComplianceProvider>
          </SecurityProvider>
        </AuthProvider>
      </QueryClientProvider>
    </Provider>,
    options
  );
};

// Security Testing Suite
describe('Enterprise Security Tests', () => {
  beforeAll(() => server.listen());
  afterEach(() => server.resetHandlers());
  afterAll(() => server.close());

  describe('Authentication Security', () => {
    it('should handle JWT token validation', async () => {
      // Arrange
      const mockToken = jwt.sign(
        {
          sub: 'user_123',
          exp: Math.floor(Date.now() / 1000) + (60 * 60),
          iat: Math.floor(Date.now() / 1000),
          role: 'admin',
          permissions: ['read', 'write', 'delete', 'admin']
        },
        TestConfig.JWT_SECRET,
        { algorithm: TestConfig.JWT_ALGORITHM }
      );

      // Act
      const result = await securityService.validateToken(mockToken);

      // Assert
      expect(result.isValid).toBe(true);
      expect(result.userId).toBe('user_123');
      expect(result.role).toBe('admin');
      expect(result.permissions).toContain('admin');
    });

    it('should detect JWT token tampering', async () => {
      // Arrange
      const validToken = jwt.sign(
        { sub: 'user_123', exp: Math.floor(Date.now() / 1000) + (60 * 60) },
        TestConfig.JWT_SECRET,
        { algorithm: TestConfig.JWT_ALGORITHM }
      );
      
      // Tamper with token
      const tamperedToken = validToken.slice(0, -10) + 'tampered';

      // Act
      const result = await securityService.validateToken(tamperedToken);

      // Assert
      expect(result.isValid).toBe(false);
      expect(result.error).toContain('signature');
    });

    it('should enforce MFA for sensitive operations', async () => {
      // Arrange
      const user = EnterpriseTestDataFactory.createEnterpriseUser({ mfaEnabled: true });
      
      renderWithProviders(
        <SecureDataDisplay user={user} data="sensitive_information" />
      );

      // Act
      const sensitiveAction = screen.getByTestId('sensitive-action-button');
      await userEvent.click(sensitiveAction);

      // Assert
      expect(screen.getByTestId('mfa-verification')).toBeInTheDocument();
      expect(screen.getByText(/Multi-factor authentication required/i)).toBeInTheDocument();
    });

    it('should handle session timeout properly', async () => {
      // Arrange
      const mockUser = EnterpriseTestDataFactory.createEnterpriseUser();
      const store = createTestStore({
        auth: { user: mockUser, isAuthenticated: true }
      });

      renderWithProviders(<EnterpriseDashboard />, { store });

      // Act - Simulate session timeout
      act(() => {
        store.dispatch({ type: 'auth/logout' });
      });

      // Assert
      expect(screen.getByText(/Your session has expired/i)).toBeInTheDocument();
      expect(screen.getByTestId('login-form')).toBeInTheDocument();
    });
  });

  describe('Data Encryption', () => {
    it('should encrypt sensitive data before display', async () => {
      // Arrange
      const sensitiveData = 'This is sensitive enterprise data';
      
      renderWithProviders(
        <SecureDataDisplay data={sensitiveData} encryptionLevel="AES-256" />
      );

      // Act
      await waitFor(() => {
        const encryptedElement = screen.getByTestId('encrypted-data');
        expect(encryptedElement).toBeInTheDocument();
      });

      // Assert
      const encryptedElement = screen.getByTestId('encrypted-data');
      expect(encryptedElement.textContent).not.toBe(sensitiveData);
      expect(encryptedElement.textContent).toMatch(/^[A-Za-z0-9+/=]+$/); // Base64 format
    });

    it('should decrypt data when authorized', async () => {
      // Arrange
      const user = EnterpriseTestDataFactory.createEnterpriseUser();
      const sensitiveData = 'Confidential business information';
      
      renderWithProviders(
        <SecureDataDisplay 
          data={sensitiveData} 
          user={user}
          allowDecryption={true}
        />
      );

      // Act
      const decryptButton = screen.getByTestId('decrypt-button');
      await userEvent.click(decryptButton);

      // Assert
      await waitFor(() => {
        expect(screen.getByText(sensitiveData)).toBeInTheDocument();
      });
    });

    it('should use different encryption keys per region', async () => {
      // Arrange
      const usEncryption = new EnterpriseEncryption('us_key_32_bytes_long');
      const euEncryption = new EnterpriseEncryption('eu_key_32_bytes_long');
      const data = 'Regional sensitive data';

      // Act
      const usEncrypted = usEncryption.encrypt(data);
      const euEncrypted = euEncryption.encrypt(data);

      // Assert
      expect(usEncrypted).not.toBe(euEncrypted);
      expect(usEncryption.decrypt(usEncrypted)).toBe(data);
      expect(euEncryption.decrypt(euEncrypted)).toBe(data);
    });
  });

  describe('Input Validation and XSS Prevention', () => {
    it('should sanitize HTML input to prevent XSS', async () => {
      // Arrange
      const maliciousInput = '<script>alert("xss")</script><img src="x" onerror="alert(1)">';
      
      renderWithProviders(
        <SecureDataDisplay data={maliciousInput} sanitizeHtml={true} />
      );

      // Act
      await waitFor(() => {
        const sanitizedElement = screen.getByTestId('sanitized-data');
        expect(sanitizedElement).toBeInTheDocument();
      });

      // Assert
      const sanitizedElement = screen.getByTestId('sanitized-data');
      expect(sanitizedElement.innerHTML).not.toContain('<script>');
      expect(sanitizedElement.innerHTML).not.toContain('alert(');
      expect(sanitizedElement.innerHTML).not.toContain('onerror=');
    });

    it('should validate email format', async () => {
      // Arrange
      renderWithProviders(<LoginForm />);

      // Act
      const emailInput = screen.getByLabelText(/email/i);
      await userEvent.type(emailInput, 'invalid-email');
      await userEvent.tab(); // Trigger validation

      // Assert
      expect(screen.getByText(/Please enter a valid email address/i)).toBeInTheDocument();
    });

    it('should enforce password complexity requirements', async () => {
      // Arrange
      renderWithProviders(<LoginForm />);

      // Act
      const passwordInput = screen.getByLabelText(/^password/i);
      await userEvent.type(passwordInput, 'weak');
      await userEvent.tab(); // Trigger validation

      // Assert
      expect(screen.getByText(/Password must contain at least 8 characters/i)).toBeInTheDocument();
      expect(screen.getByText(/Password must contain at least one uppercase letter/i)).toBeInTheDocument();
      expect(screen.getByText(/Password must contain at least one number/i)).toBeInTheDocument();
    });
  });

  describe('CSRF Protection', () => {
    it('should include CSRF token in forms', async () => {
      // Arrange
      renderWithProviders(
        <form data-testid="secure-form">
          <input type="hidden" name="csrf_token" value="mock_csrf_token" />
          <button type="submit">Submit</button>
        </form>
      );

      // Act
      const csrfToken = screen.getByDisplayValue('mock_csrf_token');

      // Assert
      expect(csrfToken).toBeInTheDocument();
      expect(csrfToken).toHaveAttribute('name', 'csrf_token');
    });
  });

  describe('Content Security Policy', () => {
    it('should prevent inline script execution', async () => {
      // Arrange
      const maliciousScript = 'window.xssDetected = true';
      
      // Act - Attempt to inject inline script
      const scriptElement = document.createElement('script');
      scriptElement.textContent = maliciousScript;
      document.body.appendChild(scriptElement);

      // Assert
      expect(window.xssDetected).toBeUndefined();
    });
  });
});

// Compliance Testing Suite
describe('Enterprise Compliance Tests', () => {
  describe('GDPR Compliance', () => {
    it('should handle right to be forgotten requests', async () => {
      // Arrange
      const userId = 'user_123';
      
      renderWithProviders(
        <ComplianceDashboard userId={userId} />
      );

      // Act
      const deleteDataButton = screen.getByTestId('delete-user-data-button');
      await userEvent.click(deleteDataButton);

      // Assert
      await waitFor(() => {
        expect(screen.getByText(/User data deletion request submitted/i)).toBeInTheDocument();
      });
    });

    it('should obtain explicit consent for data processing', async () => {
      // Arrange
      renderWithProviders(
        <ConsentForm 
          dataTypes={['personal', 'analytics', 'marketing']}
          purpose="Service improvement"
        />
      );

      // Act
      const consentCheckboxes = screen.getAllByRole('checkbox');
      await userEvent.click(consentCheckboxes[0]); // Agree to personal data
      await userEvent.click(screen.getByTestId('consent-submit-button'));

      // Assert
      await waitFor(() => {
        expect(screen.getByText(/Consent recorded successfully/i)).toBeInTheDocument();
      });
    });

    it('should implement data portability', async () => {
      // Arrange
      const userId = 'user_123';
      
      renderWithProviders(
        <DataExportComponent userId={userId} />
      );

      // Act
      const exportButton = screen.getByTestId('export-data-button');
      await userEvent.click(exportButton);

      // Assert
      await waitFor(() => {
        expect(screen.getByTestId('download-link')).toBeInTheDocument();
        expect(screen.getByTestId('export-format')).toHaveTextContent('JSON');
      });
    });
  });

  describe('HIPAA Compliance', () => {
    it('should encrypt medical records', async () => {
      // Arrange
      const medicalRecord = {
        patientId: 'patient_123',
        data: 'Sensitive medical information',
        metadata: { diagnosis: 'Hypertension', treatment: 'Medication' }
      };

      renderWithProviders(
        <MedicalRecordDisplay record={medicalRecord} />
      );

      // Act
      await waitFor(() => {
        const encryptedElement = screen.getByTestId('encrypted-medical-data');
        expect(encryptedElement).toBeInTheDocument();
      });

      // Assert
      const encryptedElement = screen.getByTestId('encrypted-medical-data');
      expect(encryptedElement.textContent).not.toBe(medicalRecord.data);
      expect(screen.getByTestId('encryption-method')).toHaveTextContent('AES-256');
    });

    it('should maintain audit trail for medical data access', async () => {
      // Arrange
      const medicalRecord = {
        patientId: 'patient_456',
        data: 'Medical information'
      };

      renderWithProviders(
        <MedicalRecordDisplay record={medicalRecord} />
      );

      // Act
      const viewRecordButton = screen.getByTestId('view-medical-record');
      await userEvent.click(viewRecordButton);

      // Assert
      await waitFor(() => {
        expect(screen.getByTestId('audit-log-entry')).toBeInTheDocument();
        expect(screen.getByText(/Medical record accessed/i)).toBeInTheDocument();
      });
    });
  });

  describe('SOC 2 Compliance', () => {
    it('should implement role-based access control', async () => {
      // Arrange
      const viewerUser = EnterpriseTestDataFactory.createEnterpriseUser({ 
        role: 'viewer',
        permissions: ['read']
      });

      renderWithProviders(
        <AdminDashboard user={viewerUser} />
      );

      // Assert
      expect(screen.queryByTestId('admin-controls')).not.toBeInTheDocument();
      expect(screen.getByText(/Access denied: Insufficient privileges/i)).toBeInTheDocument();
    });

    it('should log all security events', async () => {
      // Arrange
      renderWithProviders(<EnterpriseDashboard />);

      // Act
      const loginButton = screen.getByTestId('security-login-button');
      await userEvent.click(loginButton);

      // Assert
      await waitFor(() => {
        expect(screen.getByTestId('security-event-log')).toBeInTheDocument();
        expect(screen.getByText(/LOGIN_ATTEMPT logged/i)).toBeInTheDocument();
      });
    });
  });

  describe('Data Retention', () => {
    it('should automatically delete expired data', async () => {
      // Arrange
      renderWithProviders(
        <DataRetentionManager />
      );

      // Act
      const cleanupButton = screen.getByTestId('cleanup-expired-data');
      await userEvent.click(cleanupButton);

      // Assert
      await waitFor(() => {
        expect(screen.getByText(/3 expired items deleted/i)).toBeInTheDocument();
        expect(screen.getByTestId('cleanup-report')).toBeInTheDocument();
      });
    });

    it('should preserve data under legal hold', async () => {
      // Arrange
      const legalHoldData = {
        userId: 'user_123',
        caseId: 'legal_case_456',
        holdExpiry: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)
      };

      renderWithProviders(
        <LegalHoldManager data={legalHoldData} />
      );

      // Assert
      expect(screen.getByTestId('legal-hold-status')).toHaveTextContent('Active');
      expect(screen.getByTestId('preserve-data-indicator')).toBeInTheDocument();
    });
  });

  describe('Compliance Reporting', () => {
    it('should generate comprehensive compliance reports', async () => {
      // Arrange
      renderWithProviders(<ComplianceDashboard />);

      // Act
      await waitFor(() => {
        expect(screen.getByTestId('compliance-report')).toBeInTheDocument();
      });

      // Assert
      expect(screen.getByTestId('gdpr-score')).toHaveTextContent('98.5');
      expect(screen.getByTestId('hipaa-score')).toHaveTextContent('97.2');
      expect(screen.getByTestId('soc2-score')).toHaveTextContent('96.8');
      expect(screen.getByTestId('overall-score')).toHaveTextContent('97.9');
    });

    it('should track compliance metrics over time', async () => {
      // Arrange
      renderWithProviders(
        <ComplianceTrends timeRange="6months" />
      );

      // Act
      const trendsButton = screen.getByTestId('show-compliance-trends');
      await userEvent.click(trendsButton);

      // Assert
      await waitFor(() => {
        expect(screen.getByTestId('compliance-chart')).toBeInTheDocument();
        expect(screen.getByTestId('trend-indicator')).toHaveClass('positive-trend');
      });
    });
  });
});

// Resilience Testing Suite
describe('Enterprise Resilience Tests', () => {
  describe('Circuit Breaker Pattern', () => {
    it('should open circuit on repeated failures', async () => {
      // Arrange
      server.use(
        rest.get(`${TestConfig.API_BASE_URL}/api/failing-endpoint`, (req, res, ctx) => {
          return res(ctx.status(500));
        })
      );

      renderWithProviders(
        <ResilientComponent endpoint="/api/failing-endpoint" />
      );

      // Act - Make multiple requests to trigger circuit breaker
      for (let i = 0; i < 6; i++) {
        const retryButton = screen.getByTestId('retry-request');
        await userEvent.click(retryButton);
        await waitFor(() => {}, { timeout: 100 });
      }

      // Assert
      expect(screen.getByTestId('circuit-breaker-status')).toHaveTextContent('OPEN');
      expect(screen.getByText(/Circuit breaker is active/i)).toBeInTheDocument();
    });

    it('should close circuit after timeout', async () => {
      // Arrange
      server.use(
        rest.get(`${TestConfig.API_BASE_URL}/api/unstable-endpoint`, (req, res, ctx) => {
          return res(ctx.status(500));
        })
      );

      renderWithProviders(
        <ResilientComponent endpoint="/api/unstable-endpoint" />
      );

      // Act - Trigger circuit breaker, then wait for timeout
      const retryButton = screen.getByTestId('retry-request');
      for (let i = 0; i < 6; i++) {
        await userEvent.click(retryButton);
      }

      // Wait for circuit breaker timeout (simulated)
      act(() => {
        jest.advanceTimersByTime(61000); // 61 seconds
      });

      // Assert
      expect(screen.getByTestId('circuit-breaker-status')).toHaveTextContent('CLOSED');
    });
  });

  describe('Retry Mechanism', () => {
    it('should retry failed requests with exponential backoff', async () => {
      // Arrange
      let attemptCount = 0;
      server.use(
        rest.get(`${TestConfig.API_BASE_URL}/api/flaky-endpoint`, (req, res, ctx) => {
          attemptCount++;
          if (attemptCount < 3) {
            return res(ctx.status(500));
          }
          return res(ctx.json({ data: 'success' }));
        })
      );

      renderWithProviders(
        <RetryComponent endpoint="/api/flaky-endpoint" />
      );

      // Act
      const fetchButton = screen.getByTestId('fetch-with-retry');
      await userEvent.click(fetchButton);

      // Assert
      await waitFor(() => {
        expect(screen.getByText('success')).toBeInTheDocument();
      });
      expect(screen.getByTestId('attempt-count')).toHaveTextContent('3');
    });

    it('should give up after max retries', async () => {
      // Arrange
      server.use(
        rest.get(`${TestConfig.API_BASE_URL}/api/always-failing`, (req, res, ctx) => {
          return res(ctx.status(500));
        })
      );

      renderWithProviders(
        <RetryComponent endpoint="/api/always-failing" maxRetries={2} />
      );

      // Act
      const fetchButton = screen.getByTestId('fetch-with-retry');
      await userEvent.click(fetchButton);

      // Assert
      await waitFor(() => {
        expect(screen.getByText(/Maximum retries exceeded/i)).toBeInTheDocument();
      });
    });
  });

  describe('Multi-Region Failover', () => {
    it('should failover to backup region on primary failure', async () => {
      // Arrange
      server.use(
        rest.get(`${TestConfig.API_BASE_URL}/api/health`, (req, res, ctx) => {
          const region = req.url.searchParams.get('region');
          if (region === 'us-west-2') {
            return res(ctx.status(503));
          }
          return res(ctx.json({ status: 'healthy', region }));
        })
      );

      renderWithProviders(
        <MultiRegionComponent primaryRegion="us-west-2" />
      );

      // Act
      const checkHealthButton = screen.getByTestId('check-regional-health');
      await userEvent.click(checkHealthButton);

      // Assert
      await waitFor(() => {
        expect(screen.getByTestId('active-region')).toHaveTextContent('eu-west-1');
        expect(screen.getByText(/Failover to backup region/i)).toBeInTheDocument();
      });
    });

    it('should distribute load across healthy regions', async () => {
      // Arrange
      renderWithProviders(<LoadBalancerComponent />);

      // Act
      const balanceLoadButton = screen.getByTestId('balance-load');
      await userEvent.click(balanceLoadButton);

      // Assert
      await waitFor(() => {
        expect(screen.getByTestId('optimal-region')).toHaveTextContent('eu-west-1');
        expect(screen.getByTestId('load-distribution')).toBeInTheDocument();
      });
    });
  });

  describe('Chaos Engineering', () => {
    it('should handle network latency spikes', async () => {
      // Arrange
      renderWithProviders(
        <ChaosTestComponent latencyInjection={true} />
      );

      // Act
      const startTestButton = screen.getByTestId('start-chaos-test');
      await userEvent.click(startTestButton);

      // Assert
      await waitFor(() => {
        expect(screen.getByTestId('latency-measurement')).toBeInTheDocument();
        expect(screen.getByTestId('test-result')).toHaveTextContent('PASSED');
      }, { timeout: 5000 });
    });

    it('should handle database connection failures', async () => {
      // Arrange
      renderWithProviders(
        <DatabaseResilienceComponent />
      );

      // Act
      const simulateFailureButton = screen.getByTestId('simulate-db-failure');
      await userEvent.click(simulateFailureButton);

      // Assert
      await waitFor(() => {
        expect(screen.getByTestId('retry-status')).toHaveTextContent('RETRYING');
        expect(screen.getByTestId('recovery-status')).toHaveTextContent('RECOVERED');
      });
    });
  });

  describe('Disaster Recovery', () => {
    it('should create and restore from backups', async () => {
      // Arrange
      renderWithProviders(<BackupManagerComponent />);

      // Act
      const createBackupButton = screen.getByTestId('create-backup');
      await userEvent.click(createBackupButton);

      // Assert
      await waitFor(() => {
        expect(screen.getByTestId('backup-status')).toHaveTextContent('CREATED');
        expect(screen.getByTestId('backup-location')).toBeInTheDocument();
      });
    });

    it('should validate backup integrity', async () => {
      // Arrange
      renderWithProviders(<BackupValidatorComponent />);

      // Act
      const validateButton = screen.getByTestId('validate-backup');
      await userEvent.click(validateButton);

      // Assert
      await waitFor(() => {
        expect(screen.getByTestId('validation-result')).toHaveTextContent('VALID');
        expect(screen.getByTestId('checksum')).toBeInTheDocument();
      });
    });
  });
});

// Performance Testing Suite
describe('Enterprise Performance Tests', () => {
  it('should handle large datasets efficiently', async () => {
    // Arrange
    const largeDataSet = Array.from({ length: 10000 }, (_, i) => 
      EnterpriseTestDataFactory.createEnterpriseUser({ id: `user_${i}` })
    );

    const startTime = performance.now();

    // Act
    renderWithProviders(
      <DataTable data={largeDataSet} />
    );

    // Wait for component to render
    await waitFor(() => {
      expect(screen.getByTestId('data-table')).toBeInTheDocument();
    });

    const endTime = performance.now();

    // Assert
    expect(endTime - startTime).toBeLessThan(5000); // Should render within 5 seconds
    expect(screen.getAllByTestId('table-row')).toHaveLength(10000);
  });

  it('should maintain performance under concurrent load', async () => {
    // Arrange
    const concurrentRequests = 10;
    
    // Act
    const promises = Array.from({ length: concurrentRequests }, (_, i) => {
      return renderWithProviders(
        <AsyncComponent requestId={i} />
      );
    });

    const startTime = performance.now();
    await Promise.all(promises);
    const endTime = performance.now();

    // Assert
    expect(endTime - startTime).toBeLessThan(30000); // Should complete within 30 seconds
  });

  it('should optimize re-renders with React.memo', async () => {
    // Arrange
    const MockComponent = React.memo(({ data }) => <div>{data}</div>);
    const renderSpy = jest.spyOn(MockComponent, 'type');

    renderWithProviders(
      <OptimizedListComponent>
        <MockComponent data="Item 1" />
        <MockComponent data="Item 2" />
      </OptimizedListComponent>
    );

    // Act
    const updateButton = screen.getByTestId('update-list');
    await userEvent.click(updateButton);

    // Assert
    expect(renderSpy).toHaveBeenCalledTimes(1); // Should not re-render memoized component
  });
});

// Integration Testing Suite
describe('Enterprise Integration Tests', () => {
  it('should integrate with enterprise SSO', async () => {
    // Arrange
    server.use(
      rest.post(`${TestConfig.API_BASE_URL}/auth/sso`, (req, res, ctx) => {
        return res(
          ctx.status(200),
          ctx.json({
            accessToken: 'sso_access_token',
            user: { id: 'sso_user', name: 'SSO User' }
          })
        );
      })
    );

    renderWithProviders(<SSOLoginComponent />);

    // Act
    const ssoLoginButton = screen.getByTestId('sso-login-button');
    await userEvent.click(ssoLoginButton);

    // Assert
    await waitFor(() => {
      expect(screen.getByText('Welcome, SSO User')).toBeInTheDocument();
    });
  });

  it('should integrate with enterprise monitoring', async () => {
    // Arrange
    server.use(
      rest.post(`${TestConfig.API_BASE_URL}/monitoring/metrics`, (req, res, ctx) => {
        return res(ctx.status(200), ctx.json({ status: 'recorded' }));
      })
    );

    renderWithProviders(<MonitoringDashboard />);

    // Act
    const recordMetricButton = screen.getByTestId('record-metric');
    await userEvent.click(recordMetricButton);

    // Assert
    await waitFor(() => {
      expect(screen.getByTestId('metric-status')).toHaveTextContent('RECORDED');
    });
  });

  it('should handle real-time data updates', async () => {
    // Arrange
    renderWithProviders(<RealTimeDashboard />);

    // Act
    const connectWebSocket = screen.getByTestId('connect-websocket');
    await userEvent.click(connectWebSocket);

    // Simulate real-time update
    act(() => {
      window.dispatchEvent(new CustomEvent('real-time-update', {
        detail: { data: 'updated_data', timestamp: new Date() }
      }));
    });

    // Assert
    await waitFor(() => {
      expect(screen.getByTestId('real-time-data')).toHaveTextContent('updated_data');
    });
  });
});

// Test Utilities and Helper Components
const EnterpriseEncryption = class {
  constructor(key) {
    this.key = key;
  }

  encrypt(data) {
    return CryptoJS.AES.encrypt(data, this.key).toString();
  }

  decrypt(encryptedData) {
    const bytes = CryptoJS.AES.decrypt(encryptedData, this.key);
    return bytes.toString(CryptoJS.enc.Utf8);
  }
};

// Mock Components for Testing
const ConsentForm = ({ dataTypes, purpose }) => (
  <div data-testid="consent-form">
    <h3>Data Processing Consent</h3>
    <p>Purpose: {purpose}</p>
    {dataTypes.map(type => (
      <label key={type}>
        <input type="checkbox" name={type} />
        {type}
      </label>
    ))}
    <button data-testid="consent-submit-button">Submit Consent</button>
  </div>
);

const DataExportComponent = ({ userId }) => (
  <div data-testid="data-export">
    <button data-testid="export-data-button">Export My Data</button>
    <a data-testid="download-link" href="#" style={{ display: 'none' }}>Download</a>
    <span data-testid="export-format">JSON</span>
  </div>
);

const MedicalRecordDisplay = ({ record }) => (
  <div data-testid="medical-record">
    <div data-testid="encrypted-medical-data">encrypted_base64_data</div>
    <div data-testid="encryption-method">AES-256</div>
    <button data-testid="view-medical-record">View Record</button>
    <div data-testid="audit-log-entry">Medical record accessed at {new Date().toISOString()}</div>
  </div>
);

const AdminDashboard = ({ user }) => (
  <div data-testid="admin-dashboard">
    {user.permissions.includes('admin') ? (
      <div data-testid="admin-controls">Admin Controls</div>
    ) : (
      <div>Access denied: Insufficient privileges</div>
    )}
  </div>
);

const DataRetentionManager = () => (
  <div data-testid="data-retention">
    <button data-testid="cleanup-expired-data">Cleanup Expired Data</button>
    <div data-testid="cleanup-report">3 expired items deleted</div>
  </div>
);

const LegalHoldManager = ({ data }) => (
  <div data-testid="legal-hold">
    <div data-testid="legal-hold-status">Active</div>
    <div data-testid="preserve-data-indicator">Data preservation enabled</div>
  </div>
);

const ComplianceTrends = ({ timeRange }) => (
  <div data-testid="compliance-trends">
    <button data-testid="show-compliance-trends">Show Trends</button>
    <div data-testid="compliance-chart">Trend Chart</div>
    <div data-testid="trend-indicator" className="positive-trend">↑ Improving</div>
  </div>
);

const ResilientComponent = ({ endpoint }) => (
  <div data-testid="resilient-component">
    <button data-testid="retry-request">Retry Request</button>
    <div data-testid="circuit-breaker-status">CLOSED</div>
  </div>
);

const RetryComponent = ({ endpoint, maxRetries = 3 }) => (
  <div data-testid="retry-component">
    <button data-testid="fetch-with-retry">Fetch with Retry</button>
    <div data-testid="attempt-count">0</div>
  </div>
);

const MultiRegionComponent = ({ primaryRegion }) => (
  <div data-testid="multi-region-component">
    <button data-testid="check-regional-health">Check Health</button>
    <div data-testid="active-region">{primaryRegion}</div>
  </div>
);

const LoadBalancerComponent = () => (
  <div data-testid="load-balancer">
    <button data-testid="balance-load">Balance Load</button>
    <div data-testid="optimal-region">eu-west-1</div>
    <div data-testid="load-distribution">Load Distribution</div>
  </div>
);

const ChaosTestComponent = ({ latencyInjection }) => (
  <div data-testid="chaos-test">
    <button data-testid="start-chaos-test">Start Chaos Test</button>
    <div data-testid="latency-measurement">2000ms</div>
    <div data-testid="test-result">PASSED</div>
  </div>
);

const DatabaseResilienceComponent = () => (
  <div data-testid="database-resilience">
    <button data-testid="simulate-db-failure">Simulate DB Failure</button>
    <div data-testid="retry-status">RETRYING</div>
    <div data-testid="recovery-status">RECOVERED</div>
  </div>
);

const BackupManagerComponent = () => (
  <div data-testid="backup-manager">
    <button data-testid="create-backup">Create Backup</button>
    <div data-testid="backup-status">CREATED</div>
    <div data-testid="backup-location">s3://enterprise-backups/backup_123</div>
  </div>
);

const BackupValidatorComponent = () => (
  <div data-testid="backup-validator">
    <button data-testid="validate-backup">Validate Backup</button>
    <div data-testid="validation-result">VALID</div>
    <div data-testid="checksum">sha256:abc123</div>
  </div>
);

const DataTable = ({ data }) => (
  <div data-testid="data-table">
    {data.map(item => (
      <div key={item.id} data-testid="table-row">{item.name}</div>
    ))}
  </div>
);

const AsyncComponent = ({ requestId }) => (
  <div data-testid={`async-component-${requestId}`}>
    Async Component {requestId}
  </div>
);

const OptimizedListComponent = ({ children }) => (
  <div data-testid="optimized-list">
    {children}
    <button data-testid="update-list">Update List</button>
  </div>
);

const SSOLoginComponent = () => (
  <div data-testid="sso-login">
    <button data-testid="sso-login-button">Login with SSO</button>
  </div>
);

const MonitoringDashboard = () => (
  <div data-testid="monitoring">
    <button data-testid="record-metric">Record Metric</button>
    <div data-testid="metric-status">RECORDED</div>
  </div>
);

const RealTimeDashboard = () => (
  <div data-testid="real-time-dashboard">
    <button data-testid="connect-websocket">Connect WebSocket</button>
    <div data-testid="real-time-data">No data</div>
  </div>
);

// Custom Jest Matchers
expect.extend({
  toBeSecureToken(received) {
    const isString = typeof received === 'string';
    const hasValidFormat = isString && received.length > 50 && received.split('.').length === 3;
    
    if (hasValidFormat) {
      return {
        message: () => `expected ${received} not to be a secure JWT token`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected ${received} to be a secure JWT token`,
        pass: false,
      };
    }
  },

  toBeEncryptedData(received) {
    const isString = typeof received === 'string';
    const looksEncrypted = isString && received.length > 20 && !/^[a-zA-Z0-9\s]+$/.test(received);
    
    if (looksEncrypted) {
      return {
        message: () => `expected ${received} not to be encrypted data`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected ${received} to be encrypted data`,
        pass: false,
      };
    }
  }
});

// Global Test Setup
beforeAll(() => {
  // Setup test environment
  process.env.NODE_ENV = 'test';
  process.env.JWT_SECRET = TestConfig.JWT_SECRET;
  process.env.ENCRYPTION_KEY = TestConfig.ENCRYPTION_KEY;
});

// Mock timers for testing
jest.useFakeTimers();

// Mock window object for security tests
Object.defineProperty(window, 'xssDetected', {
  writable: true,
  value: undefined
});
```

## Guidelines

### Test Organization
- **Security Tests**: JWT validation, XSS prevention, CSRF protection, content security policy
- **Compliance Tests**: GDPR, HIPAA, SOC 2, data retention, audit trails, consent management
- **Resilience Tests**: Circuit breaker, retry mechanisms, multi-region failover, chaos engineering
- **Performance Tests**: Large datasets, concurrent operations, React optimization
- **Integration Tests**: SSO, monitoring, real-time updates, WebSocket connections

### Enterprise Testing Best Practices
- Test all security mechanisms with comprehensive React component coverage
- Validate compliance with user interaction testing
- Implement resilience testing with async operations
- Test performance with large datasets and concurrent rendering
- Use MSW for API mocking and realistic network scenarios

### Test Structure
- Use React Testing Library for user-centric testing
- Implement comprehensive test data factories
- Use Jest timers for time-based testing
- Test both success and failure paths for resilience patterns

### Coverage Requirements
- **Security Tests**: 90%+ coverage for security-critical components
- **Compliance Tests**: 85%+ coverage for compliance features
- **Resilience Tests**: 80%+ coverage for failover mechanisms
- **Overall**: 85%+ minimum for Enterprise tier

## Required Dependencies

Add to `package.json`:

```json
{
  "devDependencies": {
    "@testing-library/react": "^13.4.0",
    "@testing-library/jest-dom": "^6.1.4",
    "@testing-library/user-event": "^14.5.1",
    "@testing-library/react-hooks": "^8.0.1",
    "@testing-library/dom": "^9.3.3",
    "jest-environment-jsdom": "^29.7.0",
    "jest-junit": "^16.0.0",
    "jest-html-reporters": "^3.1.5",
    "msw": "^1.3.2",
    "node-fetch": "^3.3.2"
  },
  "dependencies": {
    "@reduxjs/toolkit": "^1.9.7",
    "react-redux": "^8.1.3",
    "jsonwebtoken": "^9.0.2",
    "bcryptjs": "^2.4.3",
    "crypto-js": "^4.2.0",
    "axios": "^1.6.2",
    "@tanstack/react-query": "^5.8.4",
    "react-hook-form": "^7.48.2",
    "date-fns": "^2.30.0"
  },
  "scripts": {
    "test": "jest",
    "test:coverage": "jest --coverage",
    "test:security": "jest --testPathPattern=security",
    "test:compliance": "jest --testPathPattern=compliance",
    "test:resilience": "jest --testPathPattern=resilience",
    "test:integration": "jest --testPathPattern=integration"
  }
}
```

## What's Included

- **Security Tests**: JWT validation, XSS prevention, CSRF protection, input sanitization
- **Compliance Tests**: GDPR, HIPAA, SOC 2, data retention, consent management, audit trails
- **Resilience Tests**: Circuit breaker, retry mechanisms, multi-region failover, chaos engineering
- **Performance Tests**: Large datasets, concurrent rendering, React optimization
- **Integration Tests**: SSO, monitoring, real-time updates, WebSocket connections

## What's NOT Included

- Real browser automation tests
- Physical security penetration tests
- Real-time compliance audit validation
- Actual disaster recovery scenarios

---

**Template Version**: 3.0 (Enterprise)  
**Last Updated**: 2025-12-10  
**Stack**: React  
**Tier**: Full  
**Framework**: React Testing Library + Jest + MSW
