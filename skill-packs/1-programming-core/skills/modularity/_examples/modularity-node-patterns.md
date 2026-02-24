# Modularity Node.js Patterns

## CommonJS Module Pattern

```javascript
// user.module.js
class UserService {
    constructor(database) {
        this.db = database;
    }
    
    async create(userData) {
        // Implementation
    }
}

module.exports = UserService;
module.exports.UserService = UserService;
```

## Module Registry Pattern

```javascript
#!/usr/bin/env node
class ModuleRegistry {
    constructor() {
        this.modules = new Map();
        this.loaded = new Set();
    }
    
    register(name, moduleFactory) {
        this.modules.set(name, {
            factory: moduleFactory,
            instance: null,
            loaded: false
        });
    }
    
    async load(name) {
        if (this.loaded.has(name)) return this.get(name);
        
        const module = this.modules.get(name);
        if (!module) throw new Error(`Module ${name} not registered`);
        
        module.instance = await module.factory();
        module.loaded = true;
        this.loaded.add(name);
        
        return module.instance;
    }
    
    get(name) {
        const module = this.modules.get(name);
        return module ? module.instance : null;
    }
    
    async loadAll() {
        for (const name of this.modules.keys()) {
            await this.load(name);
        }
    }
}

// Usage
const registry = new ModuleRegistry();

registry.register('database', async () => {
    const { default: Database } = await import('./database.module.js');
    return new Database();
});

registry.register('userService', async () => {
    const db = await registry.load('database');
    const { default: UserService } = await import('./user.module.js');
    return new UserService(db);
});
```
