# Async Control Flow Examples

## Sequential Async Operations

```javascript
// Sequential execution with async/await
async function fetchUserData(userId) {
    try {
        const user = await fetch(`/api/users/${userId}`).then(r => r.json());
        const profile = await fetch(`/api/profiles/${userId}`).then(r => r.json());
        const preferences = await fetch(`/api/preferences/${userId}`).then(r => r.json());
        
        return { user, profile, preferences };
    } catch (error) {
        console.error('Failed to fetch user data:', error);
        throw error;
    }
}

// Sequential with error handling for each step
async function processOrder(orderId) {
    let order;
    try {
        order = await getOrder(orderId);
    } catch (error) {
        throw new Error(`Order not found: ${orderId}`);
    }
    
    let payment;
    try {
        payment = await processPayment(order.paymentId);
    } catch (error) {
        order.status = 'payment_failed';
        await updateOrder(order);
        throw new Error('Payment processing failed');
    }
    
    try {
        await shipOrder(orderId);
        order.status = 'shipped';
    } catch (error) {
        order.status = 'shipping_failed';
        await updateOrder(order);
        throw new Error('Shipping failed');
    }
    
    return order;
}
```

## Parallel Async Operations

```javascript
// Parallel execution with Promise.all
async function fetchDashboardData(userId) {
    const [
        user,
        notifications,
        recentActivity,
        recommendations
    ] = await Promise.all([
        fetchUser(userId),
        fetchNotifications(userId),
        fetchRecentActivity(userId),
        fetchRecommendations(userId)
    ]);
    
    return { user, notifications, recentActivity, recommendations };
}

// Parallel with error isolation
async function fetchMultipleSources(urls) {
    const results = await Promise.allSettled(
        urls.map(url => fetch(url).then(r => r.json()))
    );
    
    const successful = results
        .filter(r => r.status === 'fulfilled')
        .map(r => r.value);
    
    const failed = results
        .filter(r => r.status === 'rejected')
        .map(r => r.reason);
    
    return { successful, failed };
}

// Batch processing with concurrency limit
async function processBatch(items, processor, concurrency = 5) {
    const results = [];
    const executing = [];
    
    for (const item of items) {
        const promise = processor(item).then(result => {
            executing.splice(executing.indexOf(promise), 1);
            return result;
        });
        
        results.push(promise);
        executing.push(promise);
        
        if (executing.length >= concurrency) {
            await Promise.race(executing);
        }
    }
    
    return Promise.all(results);
}
```

## Conditional Async Flow

```javascript
// Async ternary pattern
async function getUserData(userId, includeProfile = false) {
    const user = await fetchUser(userId);
    const profile = includeProfile ? await fetchProfile(userId) : null;
    return { user, profile };
}

// Async conditional chain
async function authenticateUser(credentials) {
    const user = await findUser(credentials.email);
    
    if (!user) {
        throw new Error('User not found');
    }
    
    const isValid = await verifyPassword(user, credentials.password);
    
    if (!isValid) {
        throw new Error('Invalid password');
    }
    
    const token = user.twoFactorEnabled 
        ? await generate2FAToken(user)
        : await generateJWT(user);
    
    return { user, token };
}

// Async switch pattern
async function processRequest(request) {
    switch (request.type) {
        case 'CREATE':
            return await createResource(request.data);
        case 'UPDATE':
            return await updateResource(request.id, request.data);
        case 'DELETE':
            return await deleteResource(request.id);
        case 'BATCH':
            return await processBatch(request.operations);
        default:
            throw new Error(`Unknown request type: ${request.type}`);
    }
}
```

## Async Iteration Patterns

```javascript
// Async generator for pagination
async function* paginatedFetch(url, pageSize = 100) {
    let page = 1;
    let hasMore = true;
    
    while (hasMore) {
        const response = await fetch(`${url}?page=${page}&size=${pageSize}`);
        const data = await response.json();
        
        yield* data.items;
        
        hasMore = data.hasMore;
        page++;
    }
}

// Using async iteration
async function processAllUsers() {
    for await (const user of paginatedFetch('/api/users')) {
        await processUser(user);
    }
}

// Async reduce
async function asyncReduce(asyncIterable, reducer, initialValue) {
    let result = initialValue;
    
    for await (const item of asyncIterable) {
        result = await reducer(result, item);
    }
    
    return result;
}

// Usage
const totalUsers = await asyncReduce(
    paginatedFetch('/api/users'),
    async (total, user) => total + 1,
    0
);
```

## Async State Machine

```javascript
// Async state machine for order processing
class AsyncStateMachine {
    constructor(initialState, transitions) {
        this.state = initialState;
        this.transitions = transitions;
    }
    
    async transition(event, data) {
        const stateTransitions = this.transitions[this.state];
        const transition = stateTransitions?.[event];
        
        if (!transition) {
            throw new Error(`Invalid transition: ${this.state} -> ${event}`);
        }
        
        // Execute async transition
        this.state = await transition.call(this, data);
        return this.state;
    }
}

// Order processing state machine
const orderMachine = new AsyncStateMachine('pending', {
    pending: {
        submit: async function(order) {
            await validateOrder(order);
            await saveOrder(order);
            return 'submitted';
        }
    },
    submitted: {
        payment: async function(payment) {
            const result = await processPayment(payment);
            return result.success ? 'paid' : 'payment_failed';
        },
        cancel: async function(reason) {
            await cancelOrder(this.orderId);
            return 'cancelled';
        }
    },
    paid: {
        ship: async function(shippingInfo) {
            await createShipment(shippingInfo);
            return 'shipped';
        }
    }
});

// Usage
await orderMachine.transition('submit', orderData);
await orderMachine.transition('payment', paymentData);
await orderMachine.transition('ship', shippingInfo);
```

## Async Retry Pattern

```javascript
// Retry with exponential backoff
async function retry(fn, options = {}) {
    const {
        times = 3,
        delay = 1000,
        backoff = 2,
        condition = () => true
    } = options;
    
    let lastError;
    
    for (let i = 0; i < times; i++) {
        try {
            return await fn();
        } catch (error) {
            lastError = error;
            
            if (i === times - 1 || !condition(error)) {
                throw error;
            }
            
            const waitTime = delay * Math.pow(backoff, i);
            await new Promise(resolve => setTimeout(resolve, waitTime));
        }
    }
    
    throw lastError;
}

// Usage with different strategies
await retry(
    () => fetch('/api/data').then(r => r.json()),
    {
        times: 5,
        delay: 1000,
        backoff: 2,
        condition: error => error.status >= 500 // Retry on server errors
    }
);
```

## When to Use

- Handle multiple API calls efficiently
- Process data streams asynchronously
- Implement robust error handling in async flows
- Manage complex async dependencies
- Create responsive user interfaces with async operations
