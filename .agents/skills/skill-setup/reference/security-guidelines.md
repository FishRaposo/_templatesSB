# Security Guidelines for AI Agent Skills

This document provides comprehensive security guidelines for creating and maintaining secure AI agent skills.

## Security Principles

### 1. Principle of Least Privilege
Skills should only request the minimum permissions necessary to function.

```yaml
# Good: Minimal permissions
permissions:
  file_system:
    read: true
    write: false
  network: false
  code_execution: false

# Bad: Overly broad permissions
permissions:
  file_system: true  # Full access
  network: true     # Unrestricted
  code_execution: true  # All languages
```

### 2. Input Validation
Always validate and sanitize all inputs before processing.

```javascript
// Example: Secure input validation
function validateInput(input) {
  // Check for dangerous patterns
  const dangerous = ['<script', 'javascript:', 'data:', 'vbscript:'];
  const inputLower = input.toLowerCase();
  
  for (const pattern of dangerous) {
    if (inputLower.includes(pattern)) {
      throw new Error('Potentially dangerous input detected');
    }
  }
  
  // Sanitize input
  return input.replace(/[^a-zA-Z0-9 .,-]/g, '');
}
```

### 3. Secure Default Configuration
Skills should be secure by default.

```json
{
  "security": {
    "validate_inputs": true,
    "sanitize_outputs": true,
    "check_permissions": true,
    "audit_logging": true,
    "default_deny": true
  }
}
```

## Common Security Vulnerabilities

### 1. Command Injection
Never pass unsanitized user input to shell commands.

```javascript
// Vulnerable
function processFile(filename) {
  exec(`cat ${filename}`, callback); // Dangerous!
}

// Secure
function processFile(filename) {
  // Validate filename
  if (!/^[a-zA-Z0-9._-]+$/.test(filename)) {
    throw new Error('Invalid filename');
  }
  
  // Use parameterized commands
  execFile('cat', [filename], callback);
}
```

### 2. Path Traversal
Prevent directory traversal attacks.

```javascript
// Vulnerable
function readFile(path) {
  return fs.readFile(path); // Can access any file!
}

// Secure
function readFile(path) {
  const resolvedPath = path.resolve(path);
  const allowedDir = path.resolve('/allowed/directory');
  
  if (!resolvedPath.startsWith(allowedDir)) {
    throw new Error('Access denied');
  }
  
  return fs.readFile(resolvedPath);
}
```

### 3. Code Injection
Avoid evaluating user input as code.

```javascript
// Very dangerous
eval(userInput); // Never do this!

// Also dangerous
new Function(userInput)(); // Don't do this either!

// Safe alternative
function processUserInput(input) {
  // Use a whitelist of allowed operations
  const allowed = JSON.parse(input);
  return processSafely(allowed);
}
```

## Secure Coding Practices

### 1. Environment Variables for Secrets
Never hardcode sensitive information.

```javascript
// Bad
const apiKey = 'sk-1234567890abcdef';

// Good
const apiKey = process.env.API_KEY;
if (!apiKey) {
  throw new Error('API_KEY environment variable required');
}
```

### 2. Secure File Handling
```javascript
import fs from 'fs/promises';
import path from 'path';

class SecureFileHandler {
  constructor(allowedDir) {
    this.allowedDir = path.resolve(allowedDir);
  }
  
  async readFile(filename) {
    // Validate filename
    if (!this.isValidFilename(filename)) {
      throw new Error('Invalid filename');
    }
    
    const fullPath = path.join(this.allowedDir, filename);
    
    // Ensure path is within allowed directory
    if (!path.resolve(fullPath).startsWith(this.allowedDir)) {
      throw new Error('Access denied: path traversal attempt');
    }
    
    return await fs.readFile(fullPath, 'utf-8');
  }
  
  isValidFilename(filename) {
    // Allow only alphanumeric, dots, hyphens, and underscores
    return /^[a-zA-Z0-9._-]+$/.test(filename) && 
           !filename.startsWith('.') &&
           filename.length <= 255;
  }
}
```

### 3. Secure Network Requests
```javascript
import https from 'https';
import { URL } from 'url';

class SecureHTTPClient {
  constructor(allowedDomains) {
    this.allowedDomains = new Set(allowedDomains);
  }
  
  async fetch(url) {
    const parsedUrl = new URL(url);
    
    // Validate domain
    if (!this.allowedDomains.has(parsedUrl.hostname)) {
      throw new Error('Domain not allowed');
    }
    
    // Enforce HTTPS
    if (parsedUrl.protocol !== 'https:') {
      throw new Error('Only HTTPS is allowed');
    }
    
    // Set secure headers
    const options = {
      hostname: parsedUrl.hostname,
      path: parsedUrl.pathname + parsedUrl.search,
      method: 'GET',
      headers: {
        'User-Agent': 'Skill/1.0',
        'Accept': 'application/json',
        'Accept-Encoding': 'gzip, deflate'
      },
      timeout: 30000
    };
    
    return new Promise((resolve, reject) => {
      const req = https.request(options, (res) => {
        if (res.statusCode !== 200) {
          reject(new Error(`HTTP ${res.statusCode}`));
          return;
        }
        
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => resolve(data));
      });
      
      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Request timeout'));
      });
      
      req.end();
    });
  }
}
```

## Permission Management

### 1. Permission Scopes
```yaml
permissions:
  file_system:
    read: true
    write: false
    execute: false
    allowed_paths:
      - "/safe/directory"
      - "./data"
    denied_paths:
      - "/etc"
      - "~/.ssh"
      - "/var/secrets"
  
  network:
    outbound: true
    inbound: false
    allowed_domains:
      - "api.example.com"
      - "cdn.trusted.com"
    denied_domains:
      - "*.malicious.com"
      - "suspicious-site.org"
  
  code_execution:
    python: true
    javascript: false
    shell: false
    sandboxed: true
  
  external_apis:
    - name: "github_api"
      endpoint: "https://api.github.com"
      rate_limit: 5000
      required_scopes: ["public_repo"]
```

### 2. Runtime Security
```javascript
class SecureExecutor {
  constructor() {
    this.allowedModules = new Set(['fs', 'path', 'crypto']);
    this.timeout = 30000; // 30 seconds
    this.memoryLimit = 512 * 1024 * 1024; // 512MB
  }
  
  async execute(code, context = {}) {
    // Create sandbox
    const sandbox = {
      console: {
        log: (...args) => this.safeLog(args)
      },
      require: (module) => this.requireModule(module),
      ...context
    };
    
    // Set timeout
    const timeoutId = setTimeout(() => {
      throw new Error('Execution timeout');
    }, this.timeout);
    
    try {
      // Execute in sandbox
      const func = new Function(...Object.keys(sandbox), code);
      const result = func(...Object.values(sandbox));
      
      clearTimeout(timeoutId);
      return result;
    } catch (error) {
      clearTimeout(timeoutId);
      throw error;
    }
  }
  
  requireModule(module) {
    if (!this.allowedModules.has(module)) {
      throw new Error(`Module '${module}' not allowed`);
    }
    return require(module);
  }
  
  safeLog(args) {
    // Sanitize log output
    const sanitized = args.map(arg => {
      if (typeof arg === 'string') {
        return arg.replace(/password/i, '[REDACTED]');
      }
      return arg;
    });
    console.log(...sanitized);
  }
}
```

## Data Protection

### 1. Sensitive Data Handling
```javascript
class DataProtection {
  static sanitizeForLogging(data) {
    const sensitive = ['password', 'token', 'key', 'secret', 'auth'];
    
    const sanitize = (obj) => {
      if (typeof obj !== 'object' || obj === null) {
        return obj;
      }
      
      if (Array.isArray(obj)) {
        return obj.map(sanitize);
      }
      
      const sanitized = {};
      for (const [key, value] of Object.entries(obj)) {
        const keyLower = key.toLowerCase();
        if (sensitive.some(s => keyLower.includes(s))) {
          sanitized[key] = '[REDACTED]';
        } else {
          sanitized[key] = sanitize(value);
        }
      }
      
      return sanitized;
    };
    
    return sanitize(data);
  }
  
  static encryptSensitiveData(data, key) {
    // Use proper encryption for sensitive data
    const crypto = require('crypto');
    const cipher = crypto.createCipher('aes-256-gcm', key);
    let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return {
      data: encrypted,
      tag: cipher.getAuthTag().toString('hex')
    };
  }
}
```

### 2. Secure Storage
```javascript
import fs from 'fs/promises';
import crypto from 'crypto';

class SecureStorage {
  constructor(keyFile) {
    this.keyFile = keyFile;
  }
  
  async getKey() {
    try {
      const key = await fs.readFile(this.keyFile);
      return key;
    } catch {
      // Generate new key
      const key = crypto.randomBytes(32);
      await fs.writeFile(this.keyFile, key, { mode: 0o600 }); // Owner read only
      return key;
    }
  }
  
  async store(data, filePath) {
    const key = await this.getKey();
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipher('aes-256-gcm', key);
    cipher.setAAD(Buffer.from('skill-data'));
    
    let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const stored = {
      iv: iv.toString('hex'),
      data: encrypted,
      tag: cipher.getAuthTag().toString('hex')
    };
    
    await fs.writeFile(filePath, JSON.stringify(stored), { mode: 0o600 });
  }
  
  async retrieve(filePath) {
    const key = await this.getKey();
    const stored = JSON.parse(await fs.readFile(filePath, 'utf8'));
    
    const decipher = crypto.createDecipher('aes-256-gcm', key);
    decipher.setAAD(Buffer.from('skill-data'));
    decipher.setAuthTag(Buffer.from(stored.tag, 'hex'));
    
    let decrypted = decipher.update(stored.data, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return JSON.parse(decrypted);
  }
}
```

## Audit and Monitoring

### 1. Security Audit Log
```javascript
class SecurityAuditLogger {
  constructor(logFile) {
    this.logFile = logFile;
  }
  
  async log(event, details = {}) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      event,
      details: DataProtection.sanitizeForLogging(details),
      user: process.env.USER || 'unknown',
      pid: process.pid
    };
    
    await fs.appendFile(
      this.logFile,
      JSON.stringify(logEntry) + '\n',
      { flag: 'a' }
    );
  }
  
  async logAccess(resource, granted) {
    await this.log('access_check', {
      resource,
      granted,
      ip: process.env.REMOTE_ADDR || 'local'
    });
  }
  
  async logCommand(command, user) {
    await this.log('command_execution', {
      command: DataProtection.sanitizeForLogging(command),
      user
    });
  }
  
  async logSecurityEvent(event, severity, details) {
    await this.log('security_event', {
      security_event: event,
      severity,
      details
    });
  }
}
```

### 2. Security Monitoring
```javascript
class SecurityMonitor {
  constructor() {
    this.failedAttempts = new Map();
    this.blockedIPs = new Set();
    this.maxAttempts = 5;
    this.blockDuration = 15 * 60 * 1000; // 15 minutes
  }
  
  recordFailure(identifier) {
    const attempts = this.failedAttempts.get(identifier) || 0;
    this.failedAttempts.set(identifier, attempts + 1);
    
    if (attempts + 1 >= this.maxAttempts) {
      this.block(identifier);
    }
  }
  
  block(identifier) {
    this.blockedIPs.add(identifier);
    setTimeout(() => {
      this.blockedIPs.delete(identifier);
      this.failedAttempts.delete(identifier);
    }, this.blockDuration);
  }
  
  isBlocked(identifier) {
    return this.blockedIPs.has(identifier);
  }
  
  checkRateLimit(identifier, limit = 100, window = 60000) {
    const now = Date.now();
    const key = `rate_limit:${identifier}`;
    
    // Implement rate limiting logic
    // This is a simplified example
    return true;
  }
}
```

## Security Checklist

### Development Phase
- [ ] Input validation implemented
- [ ] Output encoding/sanitization
- [ ] Error messages don't leak information
- [ ] No hardcoded secrets
- [ ] Principle of least privilege applied
- [ ] Secure defaults configured
- [ ] Dependencies scanned for vulnerabilities

### Testing Phase
- [ ] Security unit tests written
- [ ] Penetration testing performed
- [ ] Dependency vulnerability scan
- [ ] Static code analysis completed
- [ ] fuzz testing for inputs

### Deployment Phase
- [ ] Environment variables configured
- [ ] File permissions set correctly
- [ ] Audit logging enabled
- [ ] Rate limiting configured
- [ ] Security headers set
- [ ] HTTPS enforced
- [ ] Backup encryption enabled

### Maintenance Phase
- [ ] Regular security updates
- [ ] Dependency updates
- [ ] Audit log review
- [ ] Security monitoring alerts
- [ ] Incident response plan

## Common Attack Vectors and Mitigations

### 1. Prompt Injection
```javascript
// Detect and prevent prompt injection
function detectPromptInjection(input) {
  const injectionPatterns = [
    /ignore\s+previous\s+instructions/i,
    /system\s*:/i,
    /assistant\s*:/i,
    /\[BEGIN\s+INSTRUCTIONS\]/i,
    /\[END\s+INSTRUCTIONS\]/i
  ];
  
  return injectionPatterns.some(pattern => pattern.test(input));
}
```

### 2. Resource Exhaustion
```javascript
// Prevent resource exhaustion
class ResourceLimiter {
  constructor() {
    this.maxMemory = 512 * 1024 * 1024; // 512MB
    this.maxExecutionTime = 30000; // 30 seconds
    this.maxFileSize = 100 * 1024 * 1024; // 100MB
  }
  
  checkMemoryUsage() {
    const usage = process.memoryUsage();
    if (usage.heapUsed > this.maxMemory) {
      throw new Error('Memory limit exceeded');
    }
  }
  
  enforceFileSizeLimit(size) {
    if (size > this.maxFileSize) {
      throw new Error('File size limit exceeded');
    }
  }
}
```

### 3. Data Exfiltration
```javascript
// Prevent data exfiltration
class DataExfiltrationGuard {
  constructor(allowedDomains) {
    this.allowedDomains = new Set(allowedDomains);
  }
  
  checkNetworkRequest(url) {
    const parsed = new URL(url);
    
    // Block external domains unless explicitly allowed
    if (!this.allowedDomains.has(parsed.hostname)) {
      throw new Error('External network access blocked');
    }
    
    // Block sensitive file patterns
    const sensitivePatterns = [
      /\.env$/,
      /private\.key$/,
      /secrets?.json$/,
      /\.pem$/
    ];
    
    if (sensitivePatterns.some(pattern => pattern.test(parsed.pathname))) {
      throw new Error('Access to sensitive files blocked');
    }
  }
}
```

## Incident Response

### 1. Security Incident Response Plan
1. **Detection**: Monitor alerts and logs
2. **Assessment**: Determine scope and impact
3. **Containment**: Isolate affected systems
4. **Eradication**: Remove threats
5. **Recovery**: Restore operations
6. **Lessons Learned**: Document and improve

### 2. Emergency Procedures
```javascript
class EmergencyProcedures {
  async handleSecurityIncident(incident) {
    // Log incident
    await this.logIncident(incident);
    
    // Block malicious actor
    if (incident.source) {
      await this.blockIP(incident.source);
    }
    
    // Notify administrators
    await this.notifyAdmins(incident);
    
    // Preserve evidence
    await this.preserveEvidence(incident);
    
    // Initiate response plan
    await this.initiateResponse(incident);
  }
}
```

Following these security guidelines helps ensure your AI agent skills are secure, reliable, and trustworthy. Remember that security is an ongoing process, not a one-time consideration.
