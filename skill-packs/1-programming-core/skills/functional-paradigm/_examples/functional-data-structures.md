# Functional Data Structures and Utilities

## Immutable List

```javascript
#!/usr/bin/env node
class ImmutableList {
    constructor(head = null, tail = null) {
        this.head = head;
        this.tail = tail;
        this.length = tail ? tail.length + 1 : 0;
    }
    
    static of(...items) {
        return items.reduceRight(
            (list, item) => new ImmutableList(item, list),
            new ImmutableList()
        );
    }
    
    push(value) { return new ImmutableList(value, this); }
    
    map(fn) {
        return this.tail ? 
            new ImmutableList(fn(this.head), this.tail.map(fn)) :
            new ImmutableList();
    }
    
    filter(predicate) {
        if (!this.tail) return new ImmutableList();
        const filteredTail = this.tail.filter(predicate);
        return predicate(this.head) ?
            new ImmutableList(this.head, filteredTail) : filteredTail;
    }
    
    toArray() {
        const result = [];
        let current = this;
        while (current.head !== null) {
            result.push(current.head);
            current = current.tail;
        }
        return result;
    }
}
```

## Maybe Monad

```javascript
#!/usr/bin/env node
class Maybe {
    static of(value) {
        return value !== null && value !== undefined ?
            new Just(value) : new Nothing();
    }
    map(fn) { return this; }
    chain(fn) { return this; }
    getOrElse(defaultValue) { return defaultValue; }
}

class Just extends Maybe {
    constructor(value) { super(); this._value = value; }
    map(fn) { return Maybe.of(fn(this._value)); }
    chain(fn) { return fn(this._value); }
    getOrElse() { return this._value; }
}

class Nothing extends Maybe {
    map() { return this; }
    chain() { return this; }
}
```

## Either Monad

```javascript
#!/usr/bin/env node
class Either {
    static left(value) { return new Left(value); }
    static right(value) { return new Right(value); }
}

class Left extends Either {
    constructor(value) { super(); this._value = value; }
    map() { return this; }
    chain() { return this; }
}

class Right extends Either {
    constructor(value) { super(); this._value = value; }
    map(fn) { return Either.right(fn(this._value)); }
    chain(fn) { return fn(this._value); }
}
```

## Functional Utilities

```javascript
#!/usr/bin/env node
const Functional = {
    compose: (...fns) => x => fns.reduceRight((acc, fn) => fn(acc), x),
    pipe: (...fns) => x => fns.reduce((acc, fn) => fn(acc), x),
    curry: fn => {
        return function curried(...args) {
            return args.length >= fn.length ?
                fn.apply(this, args) : curried.bind(this, ...args);
        };
    },
    partial: (fn, ...presetArgs) => (...laterArgs) => fn(...presetArgs, ...laterArgs),
    memoize: fn => {
        const cache = new Map();
        return (...args) => {
            const key = JSON.stringify(args);
            return cache.has(key) ? cache.get(key) : cache.set(key, fn(...args)).get(key);
        };
    },
    always: value => () => value,
    complement: predicate => (...args) => !predicate(...args),
    flip: fn => (a, b, ...rest) => fn(b, a, ...rest)
};
```
