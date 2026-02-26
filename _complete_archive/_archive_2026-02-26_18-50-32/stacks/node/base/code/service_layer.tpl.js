/*
File: service_layer.tpl.js
Purpose: Service layer pattern with dependency injection
Generated for: {{PROJECT_NAME}}
*/

// Result pattern for service operations
class Result {
    constructor(success, data = null, error = null, errorCode = null) {
        this.success = success;
        this.data = data;
        this.error = error;
        this.errorCode = errorCode;
    }

    static ok(data) {
        return new Result(true, data);
    }

    static fail(error, errorCode = 'ERROR') {
        return new Result(false, null, error, errorCode);
    }

    isOk() {
        return this.success;
    }

    isFail() {
        return !this.success;
    }
}

// Base service class
class BaseService {
    constructor(repository) {
        this.repository = repository;
    }

    async get(id) {
        const entity = await this.repository.findById(id);
        if (!entity) {
            return Result.fail('Entity not found', 'NOT_FOUND');
        }
        return Result.ok(entity);
    }

    async list(options = {}) {
        const result = await this.repository.findAll(options);
        return Result.ok(result);
    }

    async create(data) {
        try {
            const entity = await this.repository.create(data);
            return Result.ok(entity);
        } catch (error) {
            return Result.fail(error.message, 'CREATE_FAILED');
        }
    }

    async update(id, data) {
        try {
            const entity = await this.repository.update(id, data);
            return Result.ok(entity);
        } catch (error) {
            return Result.fail(error.message, 'UPDATE_FAILED');
        }
    }

    async delete(id) {
        try {
            await this.repository.delete(id);
            return Result.ok({ deleted: true });
        } catch (error) {
            return Result.fail(error.message, 'DELETE_FAILED');
        }
    }
}

// Event emitter for domain events
const { EventEmitter } = require('events');

class EventBus extends EventEmitter {
    constructor() {
        super();
        this.setMaxListeners(100);
    }

    async publish(eventType, payload) {
        this.emit(eventType, {
            type: eventType,
            payload,
            occurredAt: new Date(),
        });
    }

    subscribe(eventType, handler) {
        this.on(eventType, handler);
        return () => this.off(eventType, handler);
    }
}

// Simple dependency injection container
class Container {
    constructor() {
        this.services = new Map();
        this.factories = new Map();
        this.singletons = new Map();
    }

    register(name, instance) {
        this.services.set(name, instance);
        return this;
    }

    registerFactory(name, factory, singleton = true) {
        this.factories.set(name, { factory, singleton });
        return this;
    }

    resolve(name) {
        // Check if already instantiated
        if (this.services.has(name)) {
            return this.services.get(name);
        }

        // Check singletons
        if (this.singletons.has(name)) {
            return this.singletons.get(name);
        }

        // Check factories
        if (this.factories.has(name)) {
            const { factory, singleton } = this.factories.get(name);
            const instance = factory(this);

            if (singleton) {
                this.singletons.set(name, instance);
            }

            return instance;
        }

        throw new Error(`Service '${name}' not registered`);
    }

    has(name) {
        return this.services.has(name) || this.factories.has(name) || this.singletons.has(name);
    }
}

// Example user service
class UserService extends BaseService {
    constructor(repository, eventBus, passwordService) {
        super(repository);
        this.eventBus = eventBus;
        this.passwordService = passwordService;
    }

    async register(email, password, username) {
        // Check if email exists
        const existingEmail = await this.repository.findByEmail(email);
        if (existingEmail) {
            return Result.fail('Email already registered', 'EMAIL_EXISTS');
        }

        // Check if username exists
        const existingUsername = await this.repository.findByUsername(username);
        if (existingUsername) {
            return Result.fail('Username already taken', 'USERNAME_EXISTS');
        }

        // Hash password
        const passwordHash = await this.passwordService.hash(password);

        // Create user
        const user = await this.repository.create({
            email,
            username,
            passwordHash,
        });

        // Publish event
        await this.eventBus.publish('user.registered', {
            userId: user.id,
            email: user.email,
        });

        return Result.ok(user);
    }

    async authenticate(email, password) {
        const user = await this.repository.findByEmail(email);
        if (!user) {
            return Result.fail('Invalid credentials', 'INVALID_CREDENTIALS');
        }

        const isValid = await this.passwordService.verify(password, user.passwordHash);
        if (!isValid) {
            return Result.fail('Invalid credentials', 'INVALID_CREDENTIALS');
        }

        await this.repository.updateLastLogin(user.id);

        await this.eventBus.publish('user.authenticated', {
            userId: user.id,
            email: user.email,
        });

        return Result.ok(user);
    }

    async changePassword(userId, currentPassword, newPassword) {
        const result = await this.get(userId);
        if (result.isFail()) return result;

        const user = result.data;
        const isValid = await this.passwordService.verify(currentPassword, user.passwordHash);
        if (!isValid) {
            return Result.fail('Current password is incorrect', 'INVALID_PASSWORD');
        }

        const newHash = await this.passwordService.hash(newPassword);
        await this.repository.update(userId, { passwordHash: newHash });

        await this.eventBus.publish('user.password_changed', { userId });

        return Result.ok({ changed: true });
    }
}

// Password service
class PasswordService {
    constructor(bcrypt) {
        this.bcrypt = bcrypt;
        this.rounds = 12;
    }

    async hash(password) {
        return this.bcrypt.hash(password, this.rounds);
    }

    async verify(password, hash) {
        return this.bcrypt.compare(password, hash);
    }
}

// Setup container
function setupContainer(dependencies = {}) {
    const container = new Container();

    // Register event bus
    container.register('eventBus', new EventBus());

    // Register bcrypt
    container.register('bcrypt', dependencies.bcrypt || require('bcrypt'));

    // Register password service
    container.registerFactory('passwordService', (c) => {
        return new PasswordService(c.resolve('bcrypt'));
    });

    // Register repositories (pass in from dependencies)
    if (dependencies.userRepository) {
        container.register('userRepository', dependencies.userRepository);
    }

    // Register services
    container.registerFactory('userService', (c) => {
        return new UserService(
            c.resolve('userRepository'),
            c.resolve('eventBus'),
            c.resolve('passwordService')
        );
    });

    return container;
}

module.exports = {
    Result,
    BaseService,
    EventBus,
    Container,
    UserService,
    PasswordService,
    setupContainer,
};
