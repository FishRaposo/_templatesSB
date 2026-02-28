# Node.js and CLI Patterns for Skills

This guide covers common patterns and best practices for using Node.js and command-line tools within AI agent skills.

## Why Node.js for Skills?

- **Universal Runtime**: Available on all platforms
- **Rich Ecosystem**: npm provides extensive package library
- **JSON Native**: Perfect for API interactions
- **Async/Await**: Handles concurrent operations well
- **Cross-Platform**: Works consistently across OS

## Setting Up Node.js Projects

### Project Structure
```
skill-directory/
├── SKILL.md
├── package.json          # Node.js dependencies
├── scripts/
│   ├── index.js         # Main script
│   ├── utils.js         # Utility functions
│   └── config.js        # Configuration
└── node_modules/        # Installed packages
```

### package.json Template
```json
{
  "name": "skill-name",
  "version": "1.0.0",
  "description": "Skill description",
  "type": "module",
  "main": "scripts/index.js",
  "bin": {
    "skill-command": "scripts/index.js"
  },
  "scripts": {
    "start": "node scripts/index.js",
    "test": "node scripts/test.js"
  },
  "dependencies": {
    "axios": "^1.6.0",
    "commander": "^11.0.0",
    "inquirer": "^9.2.0",
    "chalk": "^5.3.0"
  },
  "devDependencies": {
    "jest": "^29.7.0"
  },
  "keywords": ["ai", "skill", "automation"],
  "author": "Your Name",
  "license": "MIT"
}
```

## Essential Node.js Patterns

### 1. File Operations
```javascript
// scripts/utils.js
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export class FileHandler {
  static async readFile(filePath) {
    try {
      const absolutePath = path.resolve(__dirname, '..', filePath);
      return await fs.readFile(absolutePath, 'utf-8');
    } catch (error) {
      throw new Error(`Failed to read file ${filePath}: ${error.message}`);
    }
  }

  static async writeFile(filePath, content) {
    try {
      const absolutePath = path.resolve(__dirname, '..', filePath);
      await fs.writeFile(absolutePath, content, 'utf-8');
      return true;
    } catch (error) {
      throw new Error(`Failed to write file ${filePath}: ${error.message}`);
    }
  }

  static async fileExists(filePath) {
    try {
      await fs.access(path.resolve(__dirname, '..', filePath));
      return true;
    } catch {
      return false;
    }
  }
}
```

### 2. CLI Command Execution
```javascript
// scripts/cli.js
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

export class CLIHelper {
  static async runCommand(command, options = {}) {
    try {
      const { stdout, stderr } = await execAsync(command, {
        timeout: 30000,
        maxBuffer: 1024 * 1024,
        ...options
      });
      
      return {
        success: true,
        stdout: stdout.trim(),
        stderr: stderr.trim()
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
        code: error.code
      };
    }
  }

  static async runScript(scriptPath, args = []) {
    const command = `node ${scriptPath} ${args.join(' ')}`;
    return await this.runCommand(command);
  }

  static async checkCommand(command) {
    const result = await this.runCommand(`which ${command} || whereis ${command}`);
    return result.success && result.stdout.length > 0;
  }
}
```

### 3. HTTP Requests
```javascript
// scripts/api.js
import axios from 'axios';

export class APIClient {
  constructor(baseURL, options = {}) {
    this.client = axios.create({
      baseURL,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      }
    });
  }

  async get(endpoint, params = {}) {
    try {
      const response = await this.client.get(endpoint, { params });
      return response.data;
    } catch (error) {
      throw new Error(`GET request failed: ${error.message}`);
    }
  }

  async post(endpoint, data = {}) {
    try {
      const response = await this.client.post(endpoint, data);
      return response.data;
    } catch (error) {
      throw new Error(`POST request failed: ${error.message}`);
    }
  }

  async downloadFile(url, outputPath) {
    try {
      const response = await this.client.get(url, {
        responseType: 'stream'
      });
      
      const writer = fs.createWriteStream(outputPath);
      response.data.pipe(writer);
      
      return new Promise((resolve, reject) => {
        writer.on('finish', resolve);
        writer.on('error', reject);
      });
    } catch (error) {
      throw new Error(`Download failed: ${error.message}`);
    }
  }
}
```

### 4. Data Processing
```javascript
// scripts/processor.js
export class DataProcessor {
  static processCSV(csvData) {
    const lines = csvData.split('\n');
    const headers = lines[0].split(',').map(h => h.trim());
    
    return lines.slice(1)
      .filter(line => line.trim())
      .map(line => {
        const values = line.split(',').map(v => v.trim());
        return headers.reduce((obj, header, index) => {
          obj[header] = values[index] || null;
          return obj;
        }, {});
      });
  }

  static processJSON(jsonData) {
    try {
      return JSON.parse(jsonData);
    } catch (error) {
      throw new Error(`Invalid JSON: ${error.message}`);
    }
  }

  static async processLargeFile(filePath, processor) {
    const stream = fs.createReadStream(filePath);
    const results = [];
    
    return new Promise((resolve, reject) => {
      stream.on('data', chunk => {
        // Process chunk
        const result = processor(chunk.toString());
        results.push(result);
      });
      
      stream.on('end', () => resolve(results));
      stream.on('error', reject);
    });
  }
}
```

## CLI Tool Patterns

### 1. GitHub CLI Integration
```javascript
// scripts/github.js
export class GitHubHelper {
  static async getRepoInfo(owner, repo) {
    const result = await CLIHelper.runCommand(
      `gh repo view ${owner}/${repo} --json name,description,stars,language`
    );
    
    if (result.success) {
      return JSON.parse(result.stdout);
    }
    throw new Error(`Failed to get repo info: ${result.error}`);
  }

  static async listIssues(owner, repo, state = 'open') {
    const result = await CLIHelper.runCommand(
      `gh issue list --repo ${owner}/${repo} --state ${state} --json number,title,body`
    );
    
    return result.success ? JSON.parse(result.stdout) : [];
  }

  static async createIssue(owner, repo, title, body) {
    const result = await CLIHelper.runCommand(
      `gh issue create --repo ${owner}/${repo} --title "${title}" --body "${body}"`
    );
    
    return result.success;
  }
}
```

### 2. AWS CLI Integration
```javascript
// scripts/aws.js
export class AWSHelper {
  static async listS3Buckets() {
    const result = await CLIHelper.runCommand('aws s3 ls');
    
    if (result.success) {
      return result.stdout
        .split('\n')
        .filter(line => line.trim())
        .map(line => line.split(' ').pop());
    }
    return [];
  }

  static async getEC2Instances() {
    const result = await CLIHelper.runCommand(
      'aws ec2 describe-instances --output json'
    );
    
    if (result.success) {
      const data = JSON.parse(result.stdout);
      return data.Reservations.flatMap(r => r.Instances);
    }
    return [];
  }

  static async invokeLambda(functionName, payload = {}) {
    const result = await CLIHelper.runCommand(
      `aws lambda invoke --function-name ${functionName} --payload '${JSON.stringify(payload)}' output.json`
    );
    
    if (result.success) {
      const output = await FileHandler.readFile('output.json');
      return JSON.parse(output);
    }
    throw new Error(`Lambda invocation failed: ${result.error}`);
  }
}
```

### 3. Docker Integration
```javascript
// scripts/docker.js
export class DockerHelper {
  static async buildImage(dockerfilePath, imageName) {
    const result = await CLIHelper.runCommand(
      `docker build -f ${dockerfilePath} -t ${imageName} .`
    );
    
    return result.success;
  }

  static async runContainer(imageName, options = {}) {
    const ports = options.ports ? 
      options.ports.map(p => `-p ${p}`).join(' ') : '';
    
    const volumes = options.volumes ? 
      options.volumes.map(v => `-v ${v}`).join(' ') : '';
    
    const command = `docker run ${ports} ${volumes} ${imageName}`;
    const result = await CLIHelper.runCommand(command);
    
    return result.success ? result.stdout : null;
  }

  static async listContainers(all = false) {
    const flag = all ? '-a' : '';
    const result = await CLIHelper.runCommand(`docker ps ${flag} --format "{{.ID}}\t{{.Names}}\t{{.Status}}"`);
    
    if (result.success) {
      return result.stdout
        .split('\n')
        .filter(line => line.trim())
        .map(line => {
          const [id, name, status] = line.split('\t');
          return { id, name, status };
        });
    }
    return [];
  }
}
```

## Common Skill Patterns

### 1. Batch Processing
```javascript
// scripts/batch.js
export class BatchProcessor {
  constructor(processor, options = {}) {
    this.processor = processor;
    this.concurrency = options.concurrency || 5;
    this.retryCount = options.retryCount || 3;
  }

  async process(items) {
    const results = [];
    const batches = this.createBatches(items, this.concurrency);
    
    for (const batch of batches) {
      const batchResults = await Promise.allSettled(
        batch.map(item => this.processWithRetry(item))
      );
      
      results.push(...batchResults);
    }
    
    return results;
  }

  async processWithRetry(item, attempt = 1) {
    try {
      return await this.processor(item);
    } catch (error) {
      if (attempt < this.retryCount) {
        console.log(`Retrying item ${attempt}/${this.retryCount}`);
        return await this.processWithRetry(item, attempt + 1);
      }
      throw error;
    }
  }

  createBatches(items, batchSize) {
    const batches = [];
    for (let i = 0; i < items.length; i += batchSize) {
      batches.push(items.slice(i, i + batchSize));
    }
    return batches;
  }
}
```

### 2. Progress Tracking
```javascript
// scripts/progress.js
import chalk from 'chalk';

export class ProgressTracker {
  constructor(total, options = {}) {
    this.total = total;
    this.current = 0;
    this.width = options.width || 40;
    this.showPercentage = options.showPercentage !== false;
  }

  update(message = '') {
    this.current++;
    const percentage = Math.round((this.current / this.total) * 100);
    const filled = Math.round((this.width * this.current) / this.total);
    const empty = this.width - filled;
    
    const bar = chalk.green('█'.repeat(filled)) + 
                chalk.gray('█'.repeat(empty));
    
    const output = [
      `\r[${bar}]`,
      this.showPercentage ? `${percentage}%` : '',
      `(${this.current}/${this.total})`,
      message
    ].filter(Boolean).join(' ');
    
    process.stdout.write(output);
    
    if (this.current === this.total) {
      process.stdout.write('\n');
    }
  }

  complete(message = 'Done!') {
    this.current = this.total;
    this.update(message);
  }
}
```

### 3. Configuration Management
```javascript
// scripts/config.js
export class ConfigManager {
  static async load(configPath = './config.json') {
    try {
      const configData = await FileHandler.readFile(configPath);
      return JSON.parse(configData);
    } catch (error) {
      console.warn(`Config file not found, using defaults: ${error.message}`);
      return this.getDefaults();
    }
  }

  static getDefaults() {
    return {
      timeout: 30000,
      retries: 3,
      output: {
        format: 'json',
        pretty: true
      },
      logging: {
        level: 'info',
        file: 'skill.log'
      }
    };
  }

  static merge(userConfig, defaults = this.getDefaults()) {
    return {
      ...defaults,
      ...userConfig,
      output: { ...defaults.output, ...userConfig.output },
      logging: { ...defaults.logging, ...userConfig.logging }
    };
  }
}
```

## Error Handling Patterns

### 1. Graceful Degradation
```javascript
// scripts/errors.js
export class ErrorHandler {
  static async withFallback(primary, fallback, errorContext = '') {
    try {
      return await primary();
    } catch (primaryError) {
      console.warn(`Primary method failed${errorContext}: ${primaryError.message}`);
      
      try {
        return await fallback();
      } catch (fallbackError) {
        throw new Error(`Both primary and fallback failed: ${fallbackError.message}`);
      }
    }
  }

  static async withRetry(operation, maxRetries = 3, delay = 1000) {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        return await operation();
      } catch (error) {
        if (attempt === maxRetries) {
          throw error;
        }
        
        console.log(`Attempt ${attempt} failed, retrying in ${delay}ms...`);
        await new Promise(resolve => setTimeout(resolve, delay));
        delay *= 2; // Exponential backoff
      }
    }
  }
}
```

### 2. Validation
```javascript
// scripts/validation.js
export class Validator {
  static required(value, name) {
    if (value === undefined || value === null || value === '') {
      throw new Error(`${name} is required`);
    }
    return value;
  }

  static fileExists(filePath, name = 'file') {
    if (!fs.existsSync(filePath)) {
      throw new Error(`${name} does not exist: ${filePath}`);
    }
    return filePath;
  }

  static range(value, min, max, name) {
    if (value < min || value > max) {
      throw new Error(`${name} must be between ${min} and ${max}`);
    }
    return value;
  }

  static oneOf(value, allowedValues, name) {
    if (!allowedValues.includes(value)) {
      throw new Error(`${name} must be one of: ${allowedValues.join(', ')}`);
    }
    return value;
  }
}
```

## Testing Patterns

### 1. Unit Tests
```javascript
// scripts/test.js
import assert from 'assert';

export class TestRunner {
  static async runTests() {
    const tests = [
      this.testFileOperations,
      this.testCLIExecution,
      this.testDataProcessing
    ];
    
    let passed = 0;
    let failed = 0;
    
    for (const test of tests) {
      try {
        await test();
        console.log(`✓ ${test.name}`);
        passed++;
      } catch (error) {
        console.log(`✗ ${test.name}: ${error.message}`);
        failed++;
      }
    }
    
    console.log(`\nTests: ${passed} passed, ${failed} failed`);
    return failed === 0;
  }

  static async testFileOperations() {
    const testContent = 'Test content';
    await FileHandler.writeFile('test.txt', testContent);
    const content = await FileHandler.readFile('test.txt');
    assert.equal(content, testContent);
    await fs.unlink('test.txt');
  }

  static async testCLIExecution() {
    const result = await CLIHelper.runCommand('echo "test"');
    assert.equal(result.success, true);
    assert.equal(result.stdout, 'test');
  }

  static async testDataProcessing() {
    const csv = 'name,age\nJohn,30\nJane,25';
    const data = DataProcessor.processCSV(csv);
    assert.equal(data.length, 2);
    assert.equal(data[0].name, 'John');
  }
}
```

## Best Practices

### 1. Script Organization
- Use ES modules (`import`/`export`)
- Keep scripts focused on single responsibilities
- Use classes for related functionality
- Export utilities for reuse

### 2. Error Handling
- Always handle promise rejections
- Provide meaningful error messages
- Use try/catch for async operations
- Implement graceful fallbacks

### 3. Performance
- Use streams for large files
- Implement batching for bulk operations
- Cache results when appropriate
- Use async/await for concurrency

### 4. Security
- Validate all inputs
- Sanitize command arguments
- Use environment variables for secrets
- Avoid eval() and similar functions

### 5. Cross-Platform Compatibility
- Use `path.join()` for paths
- Check command availability before use
- Handle different shell behaviors
- Test on multiple platforms

## Integration with Skills

### Example Skill Integration
```markdown
## Using Node.js Scripts

This skill includes Node.js scripts for enhanced functionality:

### Installation
```bash
npm install
```

### Usage Examples

**Process data with script:**
```bash
node scripts/process.js --input data.csv --output result.json
```

**Batch processing:**
```bash
node scripts/batch.js --directory ./files --concurrency 5
```

**CLI integration:**
```bash
# Using GitHub CLI
gh api repos/owner/repo | node scripts/analyze.js

# Using AWS CLI
aws s3 ls s3://bucket/ | node scripts/s3-analyzer.js
```
```

These patterns provide a solid foundation for building robust, cross-platform skills using Node.js and CLI tools.
