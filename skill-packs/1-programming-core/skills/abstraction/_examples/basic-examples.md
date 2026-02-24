# Abstraction Examples

## Abstract Interface

**JavaScript:**
```javascript
class DataSource {
    async get(id) { throw new Error('Must implement'); }
    async save(item) { throw new Error('Must implement'); }
}

class DatabaseSource extends DataSource {
    async get(id) { return db.query('SELECT * FROM items WHERE id = ?', [id]); }
    async save(item) { return db.query('INSERT INTO items SET ?', [item]); }
}
```

**Python:**
```python
from abc import ABC, abstractmethod

class DataSource(ABC):
    @abstractmethod
    async def get(self, id): ...
    @abstractmethod
    async def save(self, item): ...

class DatabaseSource(DataSource):
    async def get(self, id):
        return await db.fetch_one("SELECT * FROM items WHERE id = $1", id)
    async def save(self, item):
        return await db.execute("INSERT INTO items VALUES ($1)", item)
```

## Layered Abstraction

**JavaScript:**
```javascript
// Low-level
function fetchFromDB(id) { return db.query('SELECT * FROM users WHERE id=?', [id]); }
// Mid-level
function getUser(id) { return fetchFromDB(id); }
// High-level
function getUserProfile(id) {
    const user = getUser(id);
    return { id: user.id, name: user.name, email: user.email };
}
```

**Python:**
```python
# Low-level
def fetch_from_db(id): return db.execute("SELECT * FROM users WHERE id=%s", (id,))
# Mid-level
def get_user(id): return fetch_from_db(id)
# High-level
def get_user_profile(id):
    user = get_user(id)
    return {"id": user["id"], "name": user["name"], "email": user["email"]}
```

## When to Use
- Create an abstraction for this complex operation
- Hide implementation details behind an interface
- Design a reusable component