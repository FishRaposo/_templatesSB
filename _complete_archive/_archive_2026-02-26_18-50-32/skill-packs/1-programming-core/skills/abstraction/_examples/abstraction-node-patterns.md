# Abstraction Node.js Patterns

## Abstract Factory Pattern

```javascript
#!/usr/bin/env node
class AbstractFactory {
    static create(type, ...args) {
        const factories = {
            database: DatabaseFactory,
            cache: CacheFactory,
            logger: LoggerFactory
        };
        
        const Factory = factories[type];
        if (!Factory) throw new Error(`Unknown factory type: ${type}`);
        return Factory.create(...args);
    }
}

class DatabaseFactory {
    static create(type, config) {
        const databases = {
            mysql: () => new MySQLDatabase(config),
            postgres: () => new PostgreSQLDatabase(config),
            mongodb: () => new MongoDBDatabase(config)
        };
        
        const createDb = databases[type];
        if (!createDb) throw new Error(`Unknown database type: ${type}`);
        return createDb();
    }
}
```

## Higher-Order Functions for Abstraction

```javascript
#!/usr/bin/env node
function withErrorHandling(fn) {
    return async (...args) => {
        try {
            return await fn(...args);
        } catch (error) {
            console.error('Error:', error.message);
            throw error;
        }
    };
}

function withLogging(fn, logger) {
    return async (...args) => {
        logger.info(`Calling ${fn.name} with args:`, args);
        const result = await fn(...args);
        logger.info(`${fn.name} returned:`, result);
        return result;
    };
}

const safeLoggedFetch = withLogging(
    withErrorHandling(fetch),
    console
);
```

## Module Pattern for Abstraction

```javascript
#!/usr/bin/env node
function createModule(name, dependencies = {}) {
    let instance = null;
    
    const mod = {
        name,
        
        getInstance(...args) {
            if (!instance) {
                instance = mod.create(...args);
            }
            return instance;
        },
        
        create(...args) {
            throw new Error('Create method must be implemented');
        },
        
        inject(deps) {
            Object.assign(dependencies, deps);
        }
    };
    
    return mod;
}
```
