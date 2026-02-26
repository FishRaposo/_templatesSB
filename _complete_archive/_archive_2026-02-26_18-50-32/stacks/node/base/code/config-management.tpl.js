/**
 * File: config-management.tpl.js
 * Purpose: Template for unknown implementation
 * Generated for: {{PROJECT_NAME}}
 */

#!/usr/bin/env node
/**
 * Node.js Configuration Management Template
 * Purpose: Reusable configuration management for Node.js projects
 * Usage: Import and adapt for environment-specific settings
 */

const fs = require('fs').promises;
const path = require('path');
const { promisify } = require('util');

class ConfigManager {
    constructor(options = {}) {
        this.env = options.env || process.env.NODE_ENV || 'development';
        this.configDir = options.configDir || './config';
        this.config = {};
        this.watchers = new Map();
    }

    /**
     * Load configuration from files and environment variables
     */
    async load() {
        try {
            // Load base configuration
            await this.loadBaseConfig();
            
            // Load environment-specific configuration
            await this.loadEnvConfig();
            
            // Override with environment variables
            this.loadFromEnv();
            
            // Validate required configuration
            this.validateConfig();
            
            return this.config;
        } catch (error) {
            throw new Error(`Failed to load configuration: ${error.message}`);
        }
    }

    /**
     * Load base configuration file
     */
    async loadBaseConfig() {
        const baseConfigPath = path.join(this.configDir, 'base.json');
        try {
            const baseConfig = await this.readConfigFile(baseConfigPath);
            this.config = { ...baseConfig };
        } catch (error) {
            // Base config is optional
            console.warn(`Base config not found at ${baseConfigPath}`);
        }
    }

    /**
     * Load environment-specific configuration
     */
    async loadEnvConfig() {
        const envConfigPath = path.join(this.configDir, `${this.env}.json`);
        try {
            const envConfig = await this.readConfigFile(envConfigPath);
            this.config = { ...this.config, ...envConfig };
        } catch (error) {
            if (this.env !== 'test') {
                console.warn(`Environment config not found at ${envConfigPath}`);
            }
        }
    }

    /**
     * Read configuration file (JSON or JS)
     */
    async readConfigFile(filePath) {
        const ext = path.extname(filePath);
        
        if (ext === '.js') {
            delete require.cache[require.resolve(filePath)];
            return require(filePath);
        } else if (ext === '.json') {
            const content = await fs.readFile(filePath, 'utf8');
            return JSON.parse(content);
        } else {
            throw new Error(`Unsupported config file format: ${ext}`);
        }
    }

    /**
     * Load configuration from environment variables
     */
    loadFromEnv() {
        const envMappings = {
            // Database
            'DB_HOST': 'database.host',
            'DB_PORT': 'database.port',
            'DB_NAME': 'database.name',
            'DB_USER': 'database.user',
            'DB_PASSWORD': 'database.password',
            'DB_SSL': 'database.ssl',
            
            // Server
            'PORT': 'server.port',
            'HOST': 'server.host',
            'DEBUG': 'server.debug',
            'LOG_LEVEL': 'server.logLevel',
            
            // Application
            'APP_NAME': 'app.name',
            'APP_VERSION': 'app.version',
            'SECRET_KEY': 'app.secretKey',
            
            // External services
            'API_KEY': 'external.apiKey',
            'API_URL': 'external.apiUrl',
            'REDIS_URL': 'external.redisUrl'
        };

        Object.entries(envMappings).forEach(([envVar, configPath]) => {
            const value = process.env[envVar];
            if (value !== undefined) {
                this.setNestedValue(configPath, this.parseEnvValue(value));
            }
        });
    }

    /**
     * Parse environment variable value to appropriate type
     */
    parseEnvValue(value) {
        // Try to parse as JSON
        try {
            return JSON.parse(value);
        } catch {
            // Try to parse as number
            if (/^\d+$/.test(value)) {
                return parseInt(value, 10);
            }
            if (/^\d+\.\d+$/.test(value)) {
                return parseFloat(value);
            }
            // Try to parse as boolean
            if (value.toLowerCase() === 'true') return true;
            if (value.toLowerCase() === 'false') return false;
            // Return as string
            return value;
        }
    }

    /**
     * Set nested configuration value
     */
    setNestedValue(path, value) {
        const keys = path.split('.');
        let current = this.config;
        
        for (let i = 0; i < keys.length - 1; i++) {
            if (!current[keys[i]]) {
                current[keys[i]] = {};
            }
            current = current[keys[i]];
        }
        
        current[keys[keys.length - 1]] = value;
    }

    /**
     * Get configuration value
     */
    get(path, defaultValue = undefined) {
        const keys = path.split('.');
        let current = this.config;
        
        for (const key of keys) {
            if (current && typeof current === 'object' && key in current) {
                current = current[key];
            } else {
                return defaultValue;
            }
        }
        
        return current;
    }

    /**
     * Set configuration value
     */
    set(path, value) {
        this.setNestedValue(path, value);
    }

    /**
     * Validate required configuration
     */
    validateConfig() {
        const required = [
            'app.name',
            'server.port'
        ];

        const missing = required.filter(path => this.get(path) === undefined);
        
        if (missing.length > 0) {
            throw new Error(`Missing required configuration: ${missing.join(', ')}`);
        }
    }

    /**
     * Watch configuration file for changes
     */
    async watchConfigFile(filePath, callback) {
        if (this.watchers.has(filePath)) {
            return;
        }

        try {
            const watcher = fs.watch(filePath, async (eventType) => {
                if (eventType === 'change') {
                    try {
                        await this.load();
                        callback(this.config);
                    } catch (error) {
                        console.error(`Error reloading config: ${error.message}`);
                    }
                }
            });

            this.watchers.set(filePath, watcher);
        } catch (error) {
            console.warn(`Cannot watch config file ${filePath}: ${error.message}`);
        }
    }

    /**
     * Stop watching all configuration files
     */
    stopWatching() {
        for (const [filePath, watcher] of this.watchers) {
            watcher.close();
        }
        this.watchers.clear();
    }

    /**
     * Get configuration as plain object
     */
    toObject() {
        return { ...this.config };
    }

    /**
     * Save configuration to file
     */
    async save(filePath) {
        const configJson = JSON.stringify(this.config, null, 2);
        await fs.writeFile(filePath, configJson, 'utf8');
    }
}

/**
 * Database configuration class
 */
class DatabaseConfig {
    constructor(options = {}) {
        this.host = options.host || 'localhost';
        this.port = options.port || 5432;
        this.name = options.name || 'myapp';
        this.user = options.user || 'postgres';
        this.password = options.password || '';
        this.ssl = options.ssl || false;
        this.pool = {
            min: options.poolMin || 2,
            max: options.poolMax || 10,
            idleTimeoutMillis: options.idleTimeout || 30000
        };
    }

    /**
     * Get database connection URL
     */
    getUrl() {
        const ssl = this.ssl ? '?ssl=true' : '';
        return `postgresql://${this.user}:${this.password}@${this.host}:${this.port}/${this.name}${ssl}`;
    }

    /**
     * Get configuration for database client
     */
    getClientConfig() {
        return {
            host: this.host,
            port: this.port,
            database: this.name,
            user: this.user,
            password: this.password,
            ssl: this.ssl,
            pool: this.pool
        };
    }
}

/**
 * Server configuration class
 */
class ServerConfig {
    constructor(options = {}) {
        this.host = options.host || '0.0.0.0';
        this.port = options.port || 3000;
        this.debug = options.debug || false;
        this.logLevel = options.logLevel || 'info';
        this.cors = {
            enabled: options.corsEnabled !== false,
            origin: options.corsOrigin || '*',
            credentials: options.corsCredentials || false
        };
        this.rateLimit = {
            enabled: options.rateLimitEnabled !== false,
            windowMs: options.rateLimitWindow || 900000, // 15 minutes
            max: options.rateLimitMax || 100
        };
    }
}

/**
 * Create sample configuration files
 */
async function createSampleConfigs() {
    const configDir = './config';
    
    // Create config directory
    try {
        await fs.mkdir(configDir, { recursive: true });
    } catch (error) {
        // Directory might already exist
    }

    // Development configuration
    const devConfig = {
        app: {
            name: 'MyApp',
            version: '1.0.0',
            secretKey: 'dev-secret-key'
        },
        database: new DatabaseConfig({
            name: 'myapp_dev',
            user: 'dev_user',
            password: 'dev_password'
        }).getClientConfig(),
        server: new ServerConfig({
            port: 3000,
            debug: true,
            logLevel: 'debug'
        }),
        external: {
            apiUrl: 'http://localhost:4000',
            apiKey: 'dev-api-key'
        }
    };

    // Production configuration
    const prodConfig = {
        app: {
            name: 'MyApp',
            version: '1.0.0'
        },
        database: new DatabaseConfig({
            host: 'prod-db.example.com',
            name: 'myapp_prod',
            user: 'prod_user',
            ssl: true
        }).getClientConfig(),
        server: new ServerConfig({
            port: 8080,
            debug: false,
            logLevel: 'info',
            corsEnabled: true,
            rateLimitEnabled: true
        }),
        external: {
            apiUrl: 'https://api.example.com'
        }
    };

    // Test configuration
    const testConfig = {
        app: {
            name: 'MyApp-Test',
            version: '1.0.0-test',
            secretKey: 'test-secret-key'
        },
        database: new DatabaseConfig({
            host: 'localhost',
            name: 'myapp_test',
            user: 'test_user'
        }).getClientConfig(),
        server: new ServerConfig({
            port: 3001,
            debug: true,
            logLevel: 'error'
        }),
        external: {
            apiUrl: 'http://localhost:4001',
            apiKey: 'test-api-key'
        }
    };

    // Write configuration files
    await fs.writeFile(
        path.join(configDir, 'development.json'),
        JSON.stringify(devConfig, null, 2)
    );

    await fs.writeFile(
        path.join(configDir, 'production.json'),
        JSON.stringify(prodConfig, null, 2)
    );

    await fs.writeFile(
        path.join(configDir, 'test.json'),
        JSON.stringify(testConfig, null, 2)
    );

    console.log('Sample configuration files created:');
    console.log('- config/development.json');
    console.log('- config/production.json');
    console.log('- config/test.json');
}

/**
 * Express middleware for configuration
 */
function configMiddleware(configManager) {
    return (req, res, next) => {
        req.config = configManager;
        next();
    };
}

// Example usage
if (require.main === module) {
    async function main() {
        try {
            // Create sample configurations
            await createSampleConfigs();

            // Initialize configuration manager
            const configManager = new ConfigManager();
            await configManager.load();

            console.log('Configuration loaded successfully:');
            console.log(`App: ${configManager.get('app.name')} v${configManager.get('app.version')}`);
            console.log(`Server: ${configManager.get('server.host')}:${configManager.get('server.port')}`);
            console.log(`Database: ${configManager.get('database.host')}:${configManager.get('database.port')}/${configManager.get('database.name')}`);

        } catch (error) {
            console.error('Configuration error:', error.message);
            process.exit(1);
        }
    }

    main();
}

module.exports = {
    ConfigManager,
    DatabaseConfig,
    ServerConfig,
    configMiddleware,
    createSampleConfigs
};
