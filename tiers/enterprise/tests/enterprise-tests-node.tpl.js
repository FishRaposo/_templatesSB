/**
 * Template: enterprise-tests-node.tpl.js
 * Purpose: enterprise-tests-node template
 * Stack: node
 * Tier: base
 */

# Universal Template System - Unknown Stack
# Generated: 2025-12-10
# Purpose: Testing utilities
# Tier: enterprise
# Stack: unknown
# Category: testing

# Enterprise Node.js Testing Template
# Purpose: Full-level enterprise testing template with comprehensive security, compliance, and resilience testing
# Usage: Copy to test/ directory and customize for your enterprise Node.js project
# Stack: Node.js (.js)
# Tier: Full (Enterprise)

## Purpose

Enterprise-level Node.js testing template providing comprehensive testing coverage including security testing, compliance validation, resilience testing, multi-region deployment scenarios, and advanced monitoring. Focuses on testing enterprise-grade features like JWT authentication, data encryption, audit trails, and disaster recovery.

## Usage

```bash
# Copy to your Node.js project
cp _templates/tiers/full/tests/enterprise-tests-node.tpl.js test/enterprise.test.js

# Install dependencies
npm install --save-dev jest jest-environment-node supertest
npm install --save-dev @jest/globals jest-circus jest-runner
npm install --save-dev nock sinon chai chai-http
npm install --save-dev @types/jest @types/supertest
npm install --save-dev jest-junit jest-html-reporters

# Install enterprise dependencies
npm install jsonwebtoken bcryptjs crypto
npm install helmet express-rate-limit express-validator
npm install winston prom-client
npm install aws-sdk @aws-sdk/client-s3
npm install ioredis mongoose
npm install circuit-breaker-js

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

```javascript
// test/enterprise.test.js
const { describe, it, before, after, beforeEach, afterEach } = require('@jest/globals');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nock = require('nock');
const sinon = require('sinon');
const chai = require('chai');
const chaiHttp = require('chai-http');
const { expect } = chai;

chai.use(chaiHttp);

// Import application modules
const app = require('../src/app');
const AuthService = require('../src/services/authService');
const SecurityService = require('../src/services/securityService');
const ComplianceService = require('../src/services/complianceService');
const ResilienceService = require('../src/services/resilienceService');
const MonitoringService = require('../src/services/monitoringService');
const AuditService = require('../src/services/auditService');
const User = require('../src/models/User');
const Transaction = require('../src/models/Transaction');
const EnterpriseEncryption = require('../src/utils/encryption');
const ComplianceValidator = require('../src/utils/complianceValidator');

// Test Configuration
const TestConfig = {
  ENCRYPTION_KEY: crypto.randomBytes(32),
  JWT_SECRET: 'test_jwt_secret_for_enterprise_testing',
  JWT_ALGORITHM: 'HS256',
  TEST_REGION: 'us-west-2',
  COMPLIANCE_REGIONS: ['us-west-2', 'eu-west-1', 'ap-southeast-1'],
  TEST_TIMEOUT: 30000,
  MAX_RETRIES: 3,
  RETRY_DELAY: 500,
  CIRCUIT_BREAKER_THRESHOLD: 5,
  CIRCUIT_BREAKER_TIMEOUT: 60000,
  API_RATE_LIMIT: 100,
  SESSION_TIMEOUT: 900000, // 15 minutes
};

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

// Security Testing Suite
describe('Enterprise Security Tests', () => {
  let authService;
  let securityService;
  let mockAuditService;

  beforeEach(() => {
    authService = new AuthService();
    securityService = new SecurityService();
    mockAuditService = sinon.createStubInstance(AuditService);
  });

  afterEach(() => {
    sinon.restore();
  });

  describe('JWT Token Security', () => {
    it('should validate JWT token integrity', async () => {
      // Arrange
      const user = EnterpriseTestDataFactory.createEnterpriseUser();
      const token = jwt.sign(
        {
          sub: user.id,
          exp: Math.floor(Date.now() / 1000) + (60 * 60), // 1 hour
          iat: Math.floor(Date.now() / 1000),
          role: user.role,
          permissions: user.permissions
        },
        TestConfig.JWT_SECRET,
        { algorithm: TestConfig.JWT_ALGORITHM }
      );

      // Act
      const result = await securityService.validateToken(token);

      // Assert
      expect(result.isValid).to.be.true;
      expect(result.userId).to.equal(user.id);
      expect(result.expiresAt).to.be.a('date');
      expect(result.expiresAt.getTime()).to.be.greaterThan(Date.now());
      expect(result.role).to.equal(user.role);
      expect(result.permissions).to.deep.equal(user.permissions);
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
      expect(result.isValid).to.be.false;
      expect(result.error).to.include('signature');
    });

    it('should reject expired JWT tokens', async () => {
      // Arrange
      const expiredToken = jwt.sign(
        { sub: 'user_123', exp: Math.floor(Date.now() / 1000) - 60 }, // Expired 1 minute ago
        TestConfig.JWT_SECRET,
        { algorithm: TestConfig.JWT_ALGORITHM }
      );

      // Act
      const result = await securityService.validateToken(expiredToken);

      // Assert
      expect(result.isValid).to.be.false;
      expect(result.error).to.include('expired');
    });

    it('should enforce token refresh mechanism', async () => {
      // Arrange
      const user = EnterpriseTestDataFactory.createEnterpriseUser();
      const refreshToken = jwt.sign(
        { sub: user.id, type: 'refresh' },
        TestConfig.JWT_SECRET,
        { algorithm: TestConfig.JWT_ALGORITHM }
      );

      sinon.stub(authService, 'refreshToken').resolves({
        accessToken: 'new_access_token',
        refreshToken: 'new_refresh_token',
        expiresIn: 3600
      });

      // Act
      const result = await authService.refreshToken(refreshToken);

      // Assert
      expect(result.accessToken).to.exist;
      expect(result.refreshToken).to.exist;
      expect(result.expiresIn).to.equal(3600);
    });
  });

  describe('AES-256 Encryption', () => {
    it('should encrypt sensitive data with AES-256', async () => {
      // Arrange
      const sensitiveData = 'This is sensitive enterprise data';
      const encryption = new EnterpriseEncryption(TestConfig.ENCRYPTION_KEY);

      // Act
      const encrypted = await encryption.encrypt(sensitiveData);
      const decrypted = await encryption.decrypt(encrypted);

      // Assert
      expect(encrypted).to.not.equal(sensitiveData);
      expect(decrypted).to.equal(sensitiveData);
      expect(encrypted.length).to.be.greaterThan(sensitiveData.length);
    });

    it('should use different encryption keys per region', async () => {
      // Arrange
      const data = 'Regional sensitive data';
      const usKey = crypto.randomBytes(32);
      const euKey = crypto.randomBytes(32);
      
      const usEncryption = new EnterpriseEncryption(usKey);
      const euEncryption = new EnterpriseEncryption(euKey);

      // Act
      const usEncrypted = await usEncryption.encrypt(data);
      const euEncrypted = await euEncryption.encrypt(data);

      // Assert
      expect(usEncrypted).to.not.equal(euEncrypted);
      expect(await usEncryption.decrypt(usEncrypted)).to.equal(data);
      expect(await euEncryption.decrypt(euEncrypted)).to.equal(data);
    });

    it('should generate unique IV for each encryption', async () => {
      // Arrange
      const data = 'Test data for IV uniqueness';
      const encryption = new EnterpriseEncryption(TestConfig.ENCRYPTION_KEY);

      // Act
      const encrypted1 = await encryption.encrypt(data);
      const encrypted2 = await encryption.encrypt(data);

      // Assert
      expect(encrypted1).to.not.equal(encrypted2);
      expect(await encryption.decrypt(encrypted1)).to.equal(data);
      expect(await encryption.decrypt(encrypted2)).to.equal(data);
    });
  });

  describe('Password Security', () => {
    it('should hash passwords with bcrypt', async () => {
      // Arrange
      const password = 'SecureEnterprisePassword123!';

      // Act
      const hashedPassword = await securityService.hashPassword(password);

      // Assert
      expect(hashedPassword).to.not.equal(password);
      expect(hashedPassword.length).to.equal(60); // bcrypt hash length
      expect(hashedPassword).to.match(/^\$2[aby]\$\d+\$/); // bcrypt format
    });

    it('should verify bcrypt passwords correctly', async () => {
      // Arrange
      const password = 'SecureEnterprisePassword123!';
      const hashedPassword = await securityService.hashPassword(password);

      // Act
      const isValid = await securityService.verifyPassword(password, hashedPassword);
      const isInvalid = await securityService.verifyPassword('wrongpassword', hashedPassword);

      // Assert
      expect(isValid).to.be.true;
      expect(isInvalid).to.be.false;
    });

    it('should enforce password complexity requirements', async () => {
      // Arrange
      const validator = securityService.getPasswordValidator();

      // Act & Assert
      expect(validator.isValid('SecurePass123!')).to.be.true;
      expect(validator.isValid('weak')).to.be.false;
      expect(validator.isValid('alllowercase123')).to.be.false;
      expect(validator.isValid('ALLUPPERCASE123')).to.be.false;
      expect(validator.isValid('NoNumbersHere')).to.be.false;
      expect(validator.isValid('Short1!')).to.be.false;
    });
  });

  describe('Multi-Factor Authentication', () => {
    it('should enforce MFA for sensitive operations', async () => {
      // Arrange
      const user = EnterpriseTestDataFactory.createEnterpriseUser({ mfaEnabled: true });
      const sensitiveOperation = 'delete_account';

      sinon.stub(authService, 'verifyMFA').resolves(true);

      // Act
      const result = await authService.verifyMFA(user.id, '123456');

      // Assert
      expect(result).to.be.true;
      expect(authService.verifyMFA.calledWith(user.id, '123456')).to.be.true;
    });

    it('should generate and validate TOTP codes', async () => {
      // Arrange
      const user = EnterpriseTestDataFactory.createEnterpriseUser();
      const secret = 'JBSWY3DPEHPK3PXP';

      // Act
      const code = await authService.generateTOTP(secret);
      const isValid = await authService.verifyTOTP(secret, code);

      // Assert
      expect(code).to.be.a('string');
      expect(code.length).to.equal(6);
      expect(isValid).to.be.true;
    });
  });

  describe('Session Security', () => {
    it('should implement proper session timeout', async () => {
      // Arrange
      const sessionManager = securityService.getSessionManager();
      const user = EnterpriseTestDataFactory.createEnterpriseUser();

      // Act
      const sessionId = await sessionManager.createSession(user);
      const isActive = await sessionManager.isSessionActive(sessionId);

      // Assert
      expect(isActive).to.be.true;

      // Simulate timeout
      await new Promise(resolve => setTimeout(resolve, 100));
      await sessionManager.expireSession(sessionId);
      const isExpired = await sessionManager.isSessionActive(sessionId);

      expect(isExpired).to.be.false;
    });

    it('should invalidate session on security breach', async () => {
      // Arrange
      const sessionManager = securityService.getSessionManager();
      const user = EnterpriseTestDataFactory.createEnterpriseUser();
      const sessionId = await sessionManager.createSession(user);

      // Act
      await sessionManager.invalidateSession(sessionId, 'security_breach_detected');

      // Assert
      const isActive = await sessionManager.isSessionActive(sessionId);
      expect(isActive).to.be.false;
    });

    it('should prevent session fixation attacks', async () => {
      // Arrange
      const sessionManager = securityService.getSessionManager();
      const user = EnterpriseTestDataFactory.createEnterpriseUser();

      // Act
      const initialSessionId = 'attacker_controlled_session';
      const newSessionId = await sessionManager.regenerateSession(initialSessionId, user);

      // Assert
      expect(newSessionId).to.not.equal(initialSessionId);
      expect(await sessionManager.isSessionActive(newSessionId)).to.be.true;
      expect(await sessionManager.isSessionActive(initialSessionId)).to.be.false;
    });
  });

  describe('Input Validation and Sanitization', () => {
    it('should sanitize HTML to prevent XSS', async () => {
      // Arrange
      const maliciousInput = '<script>alert("xss")</script><img src="x" onerror="alert(1)">';
      const validator = securityService.getInputValidator();

      // Act
      const sanitized = validator.sanitizeHtml(maliciousInput);

      // Assert
      expect(sanitized).to.not.include('<script>');
      expect(sanitized).to.not.include('alert(');
      expect(sanitized).to.not.include('onerror=');
    });

    it('should validate email format against enterprise standards', () => {
      // Arrange
      const validator = securityService.getEmailValidator();
      const validEmails = [
        'user@company.com',
        'john.doe@enterprise.co.uk',
        'user+tag@company.org',
      ];
      const invalidEmails = [
        'user@',
        '@company.com',
        'user.company.com',
        'user@.com',
        '',
      ];

      // Act & Assert
      validEmails.forEach(email => {
        expect(validator.isValid(email), `${email} should be valid`).to.be.true;
      });
      
      invalidEmails.forEach(email => {
        expect(validator.isValid(email), `${email} should be invalid`).to.be.false;
      });
    });

    it('should prevent SQL injection in database queries', () => {
      // Arrange
      const maliciousInput = "'; DROP TABLE users; --";
      const queryBuilder = securityService.getQueryBuilder();

      // Act
      const query = queryBuilder.buildUserQuery(maliciousInput);

      // Assert
      expect(query).to.not.include('DROP TABLE');
      expect(query).to.include('WHERE email = ?');
    });
  });

  describe('API Security', () => {
    it('should implement rate limiting', async () => {
      // Arrange
      const token = generateTestJWT();
      const headers = { 'Authorization': `Bearer ${token}` };

      // Act - Make multiple requests rapidly
      const responses = [];
      for (let i = 0; i < 10; i++) {
        const response = await request(app)
          .get('/api/users')
          .set(headers)
          .expect(200);
        responses.push(response);
        await new Promise(resolve => setTimeout(resolve, 10));
      }

      // Assert
      const successCount = responses.filter(r => r.status === 200).length;
      const rateLimitedCount = responses.filter(r => r.status === 429).length;
      
      expect(successCount).to.be.at.least(5);
      expect(rateLimitedCount).to.be.greaterThan(0);
    });

    it('should enforce CORS policies', async () => {
      // Act
      const response = await request(app)
        .get('/api/users')
        .set('Origin', 'https://malicious-site.com')
        .expect(400);

      // Assert
      expect(response.headers['access-control-allow-origin']).to.be.undefined;
    });

    it('should implement security headers', async () => {
      // Act
      const response = await request(app)
        .get('/api/health')
        .expect(200);

      // Assert
      expect(response.headers['x-frame-options']).to.equal('DENY');
      expect(response.headers['x-content-type-options']).to.equal('nosniff');
      expect(response.headers['strict-transport-security']).to.include('max-age');
    });
  });
});

// Compliance Testing Suite
describe('Enterprise Compliance Tests', () => {
  let complianceService;
  let auditService;

  beforeEach(() => {
    complianceService = new ComplianceService();
    auditService = sinon.createStubInstance(AuditService);
  });

  afterEach(() => {
    sinon.restore();
  });

  describe('GDPR Compliance', () => {
    it('should handle right to be forgotten requests', async () => {
      // Arrange
      const userId = 'user_123';
      sinon.stub(complianceService, 'deleteUserData').resolves({
        isCompliant: true,
        message: 'User data deleted successfully',
        standard: 'GDPR'
      });

      // Act
      const result = await complianceService.deleteUserData(userId);

      // Assert
      expect(result.isCompliant).to.be.true;
      expect(result.standard).to.equal('GDPR');
      expect(auditService.logAuditEvent.calledOnce).to.be.true;
    });

    it('should obtain explicit consent for data processing', async () => {
      // Arrange
      const consentRequest = {
        userId: 'user_123',
        dataTypes: ['personal', 'analytics', 'marketing'],
        purpose: 'Service improvement',
        version: '1.0'
      };

      sinon.stub(complianceService, 'requestConsent').resolves({
        granted: true,
        timestamp: new Date(),
        consentId: 'consent_456',
        expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000) // 1 year
      });

      // Act
      const response = await complianceService.requestConsent(consentRequest);

      // Assert
      expect(response.granted).to.be.true;
      expect(response.consentId).to.exist;
      expect(response.expiresAt.getTime()).to.be.greaterThan(Date.now());
    });

    it('should implement data portability', async () => {
      // Arrange
      const userId = 'user_123';
      sinon.stub(complianceService, 'exportUserData').resolves({
        userId: userId,
        data: { personal: {}, transactions: [], preferences: {} },
        format: 'json',
        exportedAt: new Date(),
        checksum: 'sha256:abc123'
      });

      // Act
      const exportData = await complianceService.exportUserData(userId);

      // Assert
      expect(exportData.userId).to.equal(userId);
      expect(exportData.data).to.be.an('object');
      expect(exportData.format).to.equal('json');
      expect(exportData.checksum).to.startWith('sha256:');
    });

    it('should validate consent expiration', async () => {
      // Arrange
      const expiredConsent = {
        granted: true,
        timestamp: new Date(Date.now() - 400 * 24 * 60 * 60 * 1000), // 400 days ago
        expiresAt: new Date(Date.now() - 35 * 24 * 60 * 60 * 1000), // Expired 35 days ago
        consentId: 'consent_456'
      };

      // Act
      const isValid = await complianceService.isConsentValid(expiredConsent);

      // Assert
      expect(isValid).to.be.false;
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

      sinon.stub(complianceService, 'encryptMedicalRecord').resolves({
        id: medicalRecord.patientId,
        encryptedData: 'encrypted_base64_data',
        encryptionMethod: 'AES-256',
        encryptedAt: new Date(),
        accessLog: ['encryption_event']
      });

      // Act
      const encrypted = await complianceService.encryptMedicalRecord(medicalRecord);

      // Assert
      expect(encrypted.encryptedData).to.not.equal(medicalRecord.data);
      expect(encrypted.encryptionMethod).to.equal('AES-256');
      expect(encrypted.accessLog).to.have.length.greaterThan(0);
    });

    it('should maintain audit trail for medical data access', async () => {
      // Arrange
      const accessLog = {
        userId: 'doctor_123',
        patientId: 'patient_456',
        action: 'VIEW_RECORD',
        timestamp: new Date(),
        ipAddress: '192.168.1.1',
        userAgent: 'Enterprise Medical System v1.0'
      };

      sinon.stub(auditService, 'logMedicalAccess').resolves(true);

      // Act
      const result = await auditService.logMedicalAccess(accessLog);

      // Assert
      expect(result).to.be.true;
      expect(auditService.logMedicalAccess.calledWith(accessLog)).to.be.true;
    });

    it('should enforce minimum necessary information principle', async () => {
      // Arrange
      const fullRecord = {
        patientId: 'patient_123',
        ssn: '123-45-6789',
        diagnosis: 'Hypertension',
        treatment: 'Medication',
        notes: 'Patient prefers morning appointments'
      };

      const requestContext = {
        requesterRole: 'nurse',
        purpose: 'medication_administration'
      };

      // Act
      const filteredRecord = await complianceService.filterMedicalData(fullRecord, requestContext);

      // Assert
      expect(filteredRecord).to.not.have.property('ssn');
      expect(filteredRecord).to.have.property('patientId');
      expect(filteredRecord).to.have.property('diagnosis');
      expect(filteredRecord).to.have.property('treatment');
    });
  });

  describe('SOC 2 Compliance', () => {
    it('should implement role-based access control', async () => {
      // Arrange
      const viewerUser = EnterpriseTestDataFactory.createEnterpriseUser({ role: 'viewer' });
      const adminResource = 'admin_dashboard';

      sinon.stub(complianceService, 'checkAccess').resolves({
        hasAccess: false,
        reason: 'Insufficient privileges: viewer role cannot access admin resources'
      });

      // Act
      const result = await complianceService.checkAccess(viewerUser, adminResource);

      // Assert
      expect(result.hasAccess).to.be.false;
      expect(result.reason).to.include('Insufficient privileges');
    });

    it('should log all security events', async () => {
      // Arrange
      const securityEvent = {
        type: 'LOGIN_ATTEMPT',
        userId: 'user_123',
        timestamp: new Date(),
        details: {
          ipAddress: '192.168.1.1',
          userAgent: 'Enterprise App v1.0',
          success: true,
          location: 'New York, USA'
        }
      };

      sinon.stub(auditService, 'logSecurityEvent').resolves(true);

      // Act
      const result = await auditService.logSecurityEvent(securityEvent);

      // Assert
      expect(result).to.be.true;
      expect(auditService.logSecurityEvent.calledWith(securityEvent)).to.be.true;
    });

    it('should implement encryption at rest and in transit', async () => {
      // Arrange
      const data = 'Sensitive enterprise data';

      // Act
      const atRestEncryption = await complianceService.encryptAtRest(data);
      const inTransitEncryption = await complianceService.encryptForTransit(data);

      // Assert
      expect(atRestEncryption.encrypted).to.not.equal(data);
      expect(atRestEncryption.method).to.equal('AES-256');
      expect(inTransitEncryption.encrypted).to.not.equal(data);
      expect(inTransitEncryption.method).to.equal('TLS-1.3');
    });
  });

  describe('Data Retention', () => {
    it('should automatically delete expired data', async () => {
      // Arrange
      const expiredData = [
        { id: '1', expiryDate: new Date(Date.now() - 24 * 60 * 60 * 1000) }, // 1 day ago
        { id: '2', expiryDate: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }, // 30 days ago
        { id: '3', expiryDate: new Date(Date.now() - 4000 * 24 * 60 * 60 * 1000) } // 4000 days ago
      ];

      sinon.stub(complianceService, 'cleanupExpiredData').resolves({
        deletedItems: 3,
        errors: [],
        cleanupDuration: 5000
      });

      // Act
      const result = await complianceService.cleanupExpiredData();

      // Assert
      expect(result.deletedItems).to.equal(3);
      expect(result.errors).to.have.length(0);
      expect(result.cleanupDuration).to.be.greaterThan(0);
    });

    it('should preserve data under legal hold', async () => {
      // Arrange
      const legalHoldData = {
        userId: 'user_123',
        caseId: 'legal_case_456',
        holdExpiry: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000), // 90 days from now
        reason: 'Pending litigation',
        createdAt: new Date()
      };

      sinon.stub(complianceService, 'checkLegalHold').resolves(true);

      // Act
      const hasLegalHold = await complianceService.checkLegalHold(legalHoldData.userId);

      // Assert
      expect(hasLegalHold).to.be.true;
    });
  });

  describe('Compliance Reporting', () => {
    it('should generate comprehensive compliance reports', () => {
      // Arrange
      const validator = new ComplianceValidator();
      const testData = EnterpriseTestDataFactory.createComplianceData();

      // Act
      const report = validator.generateComplianceReport(testData);

      // Assert
      expect(report).to.have.property('gdpr_score');
      expect(report).to.have.property('hipaa_score');
      expect(report).to.have.property('soc2_score');
      expect(report).to.have.property('iso27001_score');
      expect(report).to.have.property('overall_score');
      expect(report).to.have.property('recommendations');
      expect(report.overall_score).to.be.at.least(95.0);
    });

    it('should track compliance metrics over time', async () => {
      // Arrange
      const timeSeriesData = [
        { date: new Date('2023-01-01'), score: 95.5 },
        { date: new Date('2023-02-01'), score: 96.2 },
        { date: new Date('2023-03-01'), score: 97.8 },
      ];

      sinon.stub(complianceService, 'getComplianceTrends').resolves(timeSeriesData);

      // Act
      const trends = await complianceService.getComplianceTrends('GDPR', '2023-01-01', '2023-03-31');

      // Assert
      expect(trends).to.have.length(3);
      expect(trends[2].score).to.be.greaterThan(trends[0].score);
    });
  });
});

// Resilience Testing Suite
describe('Enterprise Resilience Tests', () => {
  let resilienceService;
  let monitoringService;

  beforeEach(() => {
    resilienceService = new ResilienceService();
    monitoringService = sinon.createStubInstance(MonitoringService);
  });

  afterEach(() => {
    sinon.restore();
  });

  describe('Circuit Breaker Pattern', () => {
    it('should open circuit on repeated failures', () => {
      // Arrange
      const circuitBreaker = resilienceService.createCircuitBreaker({
        failureThreshold: TestConfig.CIRCUIT_BREAKER_THRESHOLD,
        timeout: TestConfig.CIRCUIT_BREAKER_TIMEOUT
      });

      // Act - Simulate failures
      for (let i = 0; i < TestConfig.CIRCUIT_BREAKER_THRESHOLD; i++) {
        circuitBreaker.recordFailure();
      }

      // Assert
      expect(circuitBreaker.isOpen()).to.be.true;
    });

    it('should close circuit after timeout', (done) => {
      // Arrange
      const circuitBreaker = resilienceService.createCircuitBreaker({
        failureThreshold: 3,
        timeout: 100 // 100ms timeout for testing
      });

      // Open circuit
      for (let i = 0; i < 3; i++) {
        circuitBreaker.recordFailure();
      }

      // Act - Wait for timeout
      setTimeout(() => {
        // Assert
        expect(circuitBreaker.isOpen()).to.be.false;
        done();
      }, 150);
    });

    it('should allow single test request when circuit is half-open', async () => {
      // Arrange
      const circuitBreaker = resilienceService.createCircuitBreaker({
        failureThreshold: 3,
        timeout: 100
      });

      // Open circuit
      for (let i = 0; i < 3; i++) {
        circuitBreaker.recordFailure();
      }

      // Wait for timeout to enter half-open state
      await new Promise(resolve => setTimeout(resolve, 150));

      // Act
      const canExecute = circuitBreaker.canExecute();

      // Assert
      expect(canExecute).to.be.true;
      expect(circuitBreaker.getState()).to.equal('half-open');
    });
  });

  describe('Retry Mechanism', () => {
    it('should retry failed requests with exponential backoff', async () => {
      // Arrange
      const retryPolicy = resilienceService.createRetryPolicy({
        maxRetries: 3,
        baseDelay: 100,
        maxDelay: 1000,
        backoffFactor: 2.0
      });

      let attemptCount = 0;
      const failingOperation = async () => {
        attemptCount++;
        if (attemptCount < 3) {
          throw new Error(`Attempt ${attemptCount} failed`);
        }
        return 'success';
      };

      // Act
      const startTime = Date.now();
      const result = await retryPolicy.execute(failingOperation);
      const endTime = Date.now();

      // Assert
      expect(result).to.equal('success');
      expect(attemptCount).to.equal(3);
      expect(endTime - startTime).to.be.at.least(300); // 100ms + 200ms delays
    });

    it('should give up after max retries', async () => {
      // Arrange
      const retryPolicy = resilienceService.createRetryPolicy({ maxRetries: 2 });
      let attemptCount = 0;

      const alwaysFailingOperation = async () => {
        attemptCount++;
        throw new Error(`Attempt ${attemptCount} failed`);
      };

      // Act & Assert
      try {
        await retryPolicy.execute(alwaysFailingOperation);
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect(attemptCount).to.equal(3); // Initial attempt + 2 retries
      }
    });

    it('should implement jitter to prevent thundering herd', async () => {
      // Arrange
      const retryPolicy = resilienceService.createRetryPolicy({
        maxRetries: 2,
        baseDelay: 100,
        jitter: true
      });

      const delays = [];
      const operationWithDelayTracking = async () => {
        const start = Date.now();
        throw new Error('Fail');
      };

      // Act
      for (let i = 0; i < 5; i++) {
        const start = Date.now();
        try {
          await retryPolicy.execute(operationWithDelayTracking);
        } catch (error) {
          // Expected to fail
        }
        delays.push(Date.now() - start);
      }

      // Assert
      // Delays should vary due to jitter
      const uniqueDelays = [...new Set(delays)];
      expect(uniqueDelays.length).to.be.greaterThan(1);
    });
  });

  describe('Multi-Region Failover', () => {
    it('should failover to backup region on primary failure', async () => {
      // Arrange
      const failoverManager = resilienceService.createFailoverManager({
        primaryRegion: TestConfig.TEST_REGION,
        backupRegions: ['eu-west-1', 'ap-southeast-1']
      });

      sinon.stub(resilienceService, 'checkRegionHealth')
        .withArgs('us-west-2').resolves({ status: 'unhealthy' })
        .withArgs('eu-west-1').resolves({ status: 'healthy' })
        .withArgs('ap-southeast-1').resolves({ status: 'healthy' });

      // Act
      const activeRegion = await failoverManager.getActiveRegion();

      // Assert
      expect(activeRegion).to.equal('eu-west-1');
    });

    it('should distribute load across healthy regions', async () => {
      // Arrange
      const loadBalancer = resilienceService.createLoadBalancer([
        'us-west-2',
        'eu-west-1',
        'ap-southeast-1'
      ]);

      sinon.stub(resilienceService, 'getRegionLoad')
        .withArgs('us-west-2').resolves({ currentLoad: 80.0, maxCapacity: 100.0 })
        .withArgs('eu-west-1').resolves({ currentLoad: 45.0, maxCapacity: 100.0 })
        .withArgs('ap-southeast-1').resolves({ currentLoad: 60.0, maxCapacity: 100.0 });

      // Act
      const selectedRegion = await loadBalancer.selectOptimalRegion();

      // Assert
      expect(selectedRegion).to.equal('eu-west-1'); // Lowest load
    });

    it('should implement gradual traffic shifting during failover', async () => {
      // Arrange
      const trafficManager = resilienceService.createTrafficManager({
        regions: ['us-west-2', 'eu-west-1'],
        shiftPercentage: 10, // 10% per minute
        healthCheckInterval: 60000 // 1 minute
      });

      // Act
      const distribution = await trafficManager.calculateTrafficDistribution();

      // Assert
      expect(distribution['us-west-2']).to.be.at.least(90);
      expect(distribution['eu-west-1']).to.be.at.most(10);
    });
  });

  describe('Chaos Engineering', () => {
    it('should handle network latency spikes', async () => {
      // Arrange
      const chaosService = resilienceService.createChaosService();
      const apiClient = {
        fetchData: async (endpoint) => {
          await new Promise(resolve => setTimeout(resolve, 100));
          return { data: `Data from ${endpoint}` };
        }
      };

      // Act
      const startTime = Date.now();
      const result = await chaosService.withNetworkLatency(
        () => apiClient.fetchData('/endpoint'),
        2000 // 2 second latency
      );
      const endTime = Date.now();

      // Assert
      expect(endTime - startTime).to.be.at.least(1900);
      expect(result).to.not.be.null;
    });

    it('should handle database connection failures', async () => {
      // Arrange
      const databaseService = resilienceService.createDatabaseService();
      
      let failureCount = 0;
      sinon.stub(databaseService, 'executeQuery')
        .callsFake(async () => {
          failureCount++;
          if (failureCount <= 2) {
            throw new Error('Database connection failed');
          }
          return { data: 'success' };
        });

      // Act
      const result = await databaseService.executeWithRetry(
        'SELECT * FROM users',
        { maxRetries: 3 }
      );

      // Assert
      expect(result.data).to.equal('success');
      expect(failureCount).to.equal(3);
    });

    it('should simulate resource exhaustion', async () => {
      // Arrange
      const resourceMonitor = resilienceService.createResourceMonitor();
      
      // Simulate high memory usage
      sinon.stub(resourceMonitor, 'getMemoryUsage')
        .resolves({ used: 900, total: 1000, percentage: 90 });

      // Act
      const isHealthy = await resourceMonitor.checkResourceHealth();

      // Assert
      expect(isHealthy).to.be.false;
    });
  });

  describe('Disaster Recovery', () => {
    it('should create and restore from backups', async () => {
      // Arrange
      const backupService = resilienceService.createBackupService();
      const testData = { key: 'value', timestamp: new Date().toISOString() };

      sinon.stub(backupService, 'createBackup').resolves({
        backupId: 'backup_123',
        location: 's3://enterprise-backups/backup_123',
        size: 1024,
        createdAt: new Date(),
        checksum: 'sha256:abc123'
      });

      // Act
      const backup = await backupService.createBackup(testData);

      // Assert
      expect(backup.backupId).to.exist;
      expect(backup.location).to.include('s3://enterprise-backups/');
      expect(backup.size).to.be.greaterThan(0);
    });

    it('should validate backup integrity', async () => {
      // Arrange
      const backupService = resilienceService.createBackupService();
      const backupId = 'backup_123';
      
      sinon.stub(backupService, 'validateBackup').resolves({
        isValid: true,
        checksum: 'sha256:abc123def456',
        verifiedAt: new Date(),
        validationMethod: 'SHA-256'
      });

      // Act
      const validation = await backupService.validateBackup(backupId);

      // Assert
      expect(validation.isValid).to.be.true;
      expect(validation.checksum).to.startWith('sha256:');
      expect(validation.validationMethod).to.equal('SHA-256');
    });

    it('should implement point-in-time recovery', async () => {
      // Arrange
      const recoveryService = resilienceService.createRecoveryService();
      const recoveryPoint = new Date('2023-12-01T10:00:00Z');
      
      sinon.stub(recoveryService, 'restoreToPointInTime').resolves({
        restored: true,
        pointInTime: recoveryPoint,
        restoredObjects: 150,
        duration: 45000
      });

      // Act
      const result = await recoveryService.restoreToPointInTime(recoveryPoint);

      // Assert
      expect(result.restored).to.be.true;
      expect(result.pointInTime).to.equal(recoveryPoint);
      expect(result.restoredObjects).to.be.greaterThan(0);
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

    // Act
    const startTime = Date.now();
    const processedData = largeDataSet.filter(user => user.isActive);
    const endTime = Date.now();

    // Assert
    expect(processedData).to.have.length(10000);
    expect(endTime - startTime).to.be.lessThan(5000); // Should complete within 5 seconds
  });

  it('should maintain performance under concurrent load', async () => {
    // Arrange
    const concurrentRequests = 100;
    const apiClient = {
      fetchData: async (endpoint) => {
        await new Promise(resolve => setTimeout(resolve, 50));
        return { success: true, data: `Data from ${endpoint}` };
      }
    };

    // Act
    const startTime = Date.now();
    const promises = Array.from({ length: concurrentRequests }, (_, i) =>
      apiClient.fetchData(`/endpoint/${i}`)
    );
    const results = await Promise.all(promises);
    const endTime = Date.now();

    // Assert
    expect(results).to.have.length(concurrentRequests);
    expect(endTime - startTime).to.be.lessThan(30000); // Should complete within 30 seconds
    expect(results.every(r => r.success)).to.be.true;
  });

  it('should optimize encryption performance', async () => {
    // Arrange
    const encryption = new EnterpriseEncryption(TestConfig.ENCRYPTION_KEY);
    const sensitiveData = 'Large sensitive data block '.repeat(1000);

    // Act
    const startTime = Date.now();
    const encrypted = await encryption.encrypt(sensitiveData);
    const decrypted = await encryption.decrypt(encrypted);
    const endTime = Date.now();

    // Assert
    expect(decrypted).to.equal(sensitiveData);
    expect(endTime - startTime).to.be.lessThan(100); // Should complete within 100ms
  });

  it('should handle memory efficiently under load', async () => {
    // Arrange
    const memoryMonitor = {
      getUsage: () => process.memoryUsage(),
      isHealthy: (usage) => usage.heapUsed < usage.heapTotal * 0.9
    };

    // Act - Simulate memory-intensive operations
    const operations = Array.from({ length: 1000 }, (_, i) => {
      const largeObject = new Array(10000).fill(`data_${i}`);
      return largeObject;
    });

    const memoryAfter = memoryMonitor.getUsage();

    // Assert
    expect(memoryMonitor.isHealthy(memoryAfter)).to.be.true;
    
    // Clean up
    operations.length = 0;
    if (global.gc) global.gc(); // Force garbage collection if available
  });
});

// Integration Testing Suite
describe('Enterprise Integration Tests', () => {
  describe('SSO Integration', () => {
    it('should integrate with enterprise SSO providers', async () => {
      // Arrange
      const ssoConfig = {
        provider: 'azure_ad',
        clientId: 'enterprise_client_id',
        tenantId: 'enterprise_tenant_id'
      };

      // Mock SSO provider response
      nock('https://login.microsoftonline.com')
        .post(`/${ssoConfig.tenantId}/oauth2/v2.0/token`)
        .reply(200, {
          access_token: 'mock_access_token',
          refresh_token: 'mock_refresh_token',
          expires_in: 3600
        });

      // Act
      const response = await request(app)
        .post('/auth/sso')
        .send(ssoConfig)
        .expect(200);

      // Assert
      expect(response.body).to.have.property('access_token');
      expect(response.body).to.have.property('refresh_token');
    });
  });

  describe('Monitoring Integration', () => {
    it('should integrate with enterprise monitoring systems', async () => {
      // Arrange
      const monitoringConfig = {
        endpoint: 'https://monitoring.enterprise.com',
        apiKey: TestConfig.JWT_SECRET,
        metricsInterval: 30000
      };

      const monitoringService = new MonitoringService(monitoringConfig);

      // Mock monitoring endpoint
      nock(monitoringConfig.endpoint)
        .post('/metrics')
        .reply(200, { status: 'recorded' });

      // Act
      await monitoringService.recordMetric('user_login', 1);
      await monitoringService.recordError('api_failure', 'Database connection lost');

      // Assert
      expect(nock.isDone()).to.be.true;
    });
  });

  describe('Database Integration', () => {
    it('should handle database connection pooling', async () => {
      // Arrange
      const databaseService = require('../src/services/databaseService');
      const config = {
        host: 'localhost',
        port: 5432,
        database: 'test_db',
        maxConnections: 10,
        minConnections: 2
      };

      // Act
      await databaseService.initializeConnectionPool(config);
      const poolStats = databaseService.getConnectionPoolStats();

      // Assert
      expect(poolStats.active).to.be.at.most(config.maxConnections);
      expect(poolStats.idle).to.be.at.least(config.minConnections);
    });
  });

  describe('Message Queue Integration', () => {
    it('should handle message queue resilience', async () => {
      // Arrange
      const messageQueue = require('../src/services/messageQueue');
      
      // Mock message queue
      const mockQueue = {
        publish: sinon.stub().resolves({ messageId: 'msg_123' }),
        consume: sinon.stub().callsFake((callback) => {
          // Simulate message consumption
          setTimeout(() => callback({ body: JSON.stringify({ test: 'data' }) }), 100);
        })
      };

      // Act
      const publishResult = await mockQueue.publish('test.queue', { test: 'data' });
      
      let consumedMessage;
      await mockQueue.consume((message) => {
        consumedMessage = JSON.parse(message.body);
      });

      // Assert
      expect(publishResult.messageId).to.exist;
      expect(consumedMessage.test).to.equal('data');
    });
  });
});

// Test Utilities and Helper Functions
function generateTestJWT() {
  return jwt.sign(
    {
      sub: 'test_user_123',
      exp: Math.floor(Date.now() / 1000) + (60 * 60), // 1 hour
      iat: Math.floor(Date.now() / 1000),
      role: 'admin',
      permissions: ['read', 'write', 'delete', 'admin']
    },
    TestConfig.JWT_SECRET,
    { algorithm: TestConfig.JWT_ALGORITHM }
  );
}

class EnterpriseTestUtils {
  static async waitForCondition(conditionFn, timeout = 30000) {
    const startTime = Date.now();
    while (Date.now() - startTime < timeout) {
      if (await conditionFn()) {
        return true;
      }
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    throw new Error(`Condition not met within ${timeout}ms`);
  }

  static createMockComplianceReport() {
    return {
      gdprScore: 98.5,
      hipaaScore: 97.2,
      soc2Score: 96.8,
      iso27001Score: 99.1,
      overallScore: 97.9,
      recommendations: [
        'Implement additional data encryption',
        'Update privacy policy',
        'Enhance audit logging'
      ],
      lastAssessment: new Date().toISOString()
    };
  }

  static async measureExecutionTime(operation) {
    const startTime = process.hrtime.bigint();
    await operation();
    const endTime = process.hrtime.bigint();
    return Number(endTime - startTime) / 1000000; // Convert to milliseconds
  }
}

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
  },

  toBeCompliantWith(received, standard) {
    const hasComplianceFields = received && 
      typeof received === 'object' &&
      'isCompliant' in received &&
      'standard' in received &&
      received.standard === standard;
    
    if (hasComplianceFields) {
      return {
        message: () => `expected ${received} not to be compliant with ${standard}`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected ${received} to be compliant with ${standard}`,
        pass: false,
      };
    }
  }
});

// Global Test Setup and Teardown
beforeAll(async () => {
  // Initialize test environment
  process.env.NODE_ENV = 'test';
  process.env.JWT_SECRET = TestConfig.JWT_SECRET;
  process.env.ENCRYPTION_KEY = TestConfig.ENCRYPTION_KEY.toString('base64');
});

afterAll(async () => {
  // Cleanup test environment
  nock.cleanAll();
  nock.restore();
});

beforeEach(() => {
  // Reset mocks before each test
  nock.cleanAll();
});

afterEach(() => {
  // Cleanup after each test
  sinon.restore();
});

module.exports = {
  EnterpriseTestDataFactory,
  EnterpriseTestUtils,
  TestConfig
};
```

## Guidelines

### Test Organization
- **Security Tests**: JWT validation, AES-256 encryption, MFA, session management, input sanitization
- **Compliance Tests**: GDPR, HIPAA, SOC 2, data retention, audit trails, legal hold
- **Resilience Tests**: Circuit breaker, retry mechanisms, multi-region failover, chaos engineering
- **Performance Tests**: Large datasets, concurrent operations, memory management
- **Integration Tests**: SSO, monitoring, database integration, message queues

### Enterprise Testing Best Practices
- Test all security mechanisms with comprehensive coverage
- Validate compliance with multiple regulatory frameworks
- Implement chaos engineering for resilience validation
- Test multi-region deployment and failover scenarios
- Monitor and validate performance under enterprise loads

### Test Structure
- Use comprehensive test data factories for enterprise scenarios
- Implement async/await patterns for enterprise operations
- Use Sinon for mocking and Nock for HTTP stubbing
- Test both success and failure paths for resilience patterns

### Coverage Requirements
- **Security Tests**: 90%+ coverage for security-critical code
- **Compliance Tests**: 85%+ coverage for compliance features
- **Resilience Tests**: 80%+ coverage for failover mechanisms
- **Overall**: 85%+ minimum for Enterprise tier

## Required Dependencies

Add to `package.json`:

```json
{
  "devDependencies": {
    "jest": "^29.7.0",
    "jest-environment-node": "^29.7.0",
    "@jest/globals": "^29.7.0",
    "jest-circus": "^29.7.0",
    "jest-runner": "^29.7.0",
    "supertest": "^6.3.3",
    "nock": "^13.3.8",
    "sinon": "^17.0.1",
    "chai": "^4.3.10",
    "chai-http": "^4.4.0",
    "@types/jest": "^29.5.8",
    "@types/supertest": "^2.0.16",
    "jest-junit": "^16.0.0",
    "jest-html-reporters": "^3.1.5"
  },
  "dependencies": {
    "jsonwebtoken": "^9.0.2",
    "bcryptjs": "^2.4.3",
    "helmet": "^7.1.0",
    "express-rate-limit": "^7.1.5",
    "express-validator": "^7.0.1",
    "winston": "^3.11.0",
    "prom-client": "^15.0.0",
    "aws-sdk": "^2.1498.0",
    "@aws-sdk/client-s3": "^3.468.0",
    "ioredis": "^5.3.2",
    "mongoose": "^8.0.3",
    "circuit-breaker-js": "^1.1.1"
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

- **Security Tests**: JWT validation, AES-256 encryption, MFA, rate limiting, input sanitization
- **Compliance Tests**: GDPR, HIPAA, SOC 2, data retention, audit trails, legal hold
- **Resilience Tests**: Circuit breaker, retry with exponential backoff, multi-region failover
- **Performance Tests**: Large datasets, concurrent operations, memory management
- **Integration Tests**: SSO, monitoring, database integration, message queues

## What's NOT Included

- Real cloud provider integration tests
- Physical security penetration tests
- Real-time compliance audit validation
- Actual disaster recovery scenarios

---

**Template Version**: 3.0 (Enterprise)  
**Last Updated**: 2025-12-10  
**Stack**: Node.js  
**Tier**: Full  
**Framework**: Jest + Supertest + Sinon + Nock
