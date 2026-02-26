# Integration Testing Examples

## API Integration Testing

### JavaScript (Supertest)

```javascript
const request = require('supertest');
const app = require('../app');

describe('User API Integration', () => {
  test('GET /users returns user list', async () => {
    const response = await request(app)
      .get('/users')
      .expect('Content-Type', /json/)
      .expect(200);
    
    expect(response.body).toBeInstanceOf(Array);
    expect(response.body[0]).toHaveProperty('id');
    expect(response.body[0]).toHaveProperty('name');
  });
  
  test('POST /users creates user', async () => {
    const newUser = {
      name: 'John Doe',
      email: 'john@example.com'
    };
    
    const response = await request(app)
      .post('/users')
      .send(newUser)
      .expect(201);
    
    expect(response.body.name).toBe('John Doe');
    expect(response.body).toHaveProperty('id');
  });
  
  test('GET /users/:id returns 404 for non-existent', async () => {
    await request(app)
      .get('/users/999999')
      .expect(404);
  });
});
```

### Python (requests + pytest)

```python
import requests
import pytest

BASE_URL = 'http://localhost:8000'

class TestUserAPI:
    def test_get_users_returns_list(self):
        response = requests.get(f'{BASE_URL}/users')
        assert response.status_code == 200
        
        data = response.json()
        assert isinstance(data, list)
        assert 'id' in data[0]
    
    def test_create_user(self):
        new_user = {
            'name': 'John Doe',
            'email': 'john@example.com'
        }
        
        response = requests.post(
            f'{BASE_URL}/users',
            json=new_user
        )
        
        assert response.status_code == 201
        assert response.json()['name'] == 'John Doe'
    
    def test_get_nonexistent_user_returns_404(self):
        response = requests.get(f'{BASE_URL}/users/999999')
        assert response.status_code == 404
```

## Database Integration Testing

### JavaScript (Testcontainers)

```javascript
const { GenericContainer } = require('testcontainers');

describe('UserRepository Integration', () => {
  let container;
  let db;
  let repo;
  
  beforeAll(async () => {
    container = await new GenericContainer('postgres:15')
      .withExposedPorts(5432)
      .withEnvironment({
        POSTGRES_USER: 'test',
        POSTGRES_PASSWORD: 'test',
        POSTGRES_DB: 'testdb'
      })
      .start();
    
    db = new Database({
      host: 'localhost',
      port: container.getMappedPort(5432),
      user: 'test',
      password: 'test',
      database: 'testdb'
    });
    
    await db.migrate();
    repo = new UserRepository(db);
  }, 30000);
  
  afterAll(async () => {
    await db.close();
    await container.stop();
  });
  
  beforeEach(async () => {
    await db.truncate('users');
  });
  
  test('saves and retrieves user', async () => {
    const user = {
      name: 'John',
      email: 'john@example.com'
    };
    
    const id = await repo.save(user);
    const found = await repo.findById(id);
    
    expect(found.name).toBe('John');
    expect(found.email).toBe('john@example.com');
  });
  
  test('finds user by email', async () => {
    await repo.save({
      name: 'Jane',
      email: 'jane@example.com'
    });
    
    const found = await repo.findByEmail('jane@example.com');
    expect(found.name).toBe('Jane');
  });
});
```

### Python (pytest-postgresql)

```python
import pytest
from sqlalchemy import create_engine
from myapp.models import Base, User
from myapp.repository import UserRepository

@pytest.fixture(scope='session')
def database():
    from testing.postgresql import Postgresql
    with Postgresql() as postgresql:
        engine = create_engine(postgresql.url())
        Base.metadata.create_all(engine)
        yield engine

@pytest.fixture
def db_session(database):
    connection = database.connect()
    transaction = connection.begin()
    session = Session(bind=connection)
    yield session
    session.close()
    transaction.rollback()
    connection.close()

class TestUserRepository:
    def test_saves_and_retrieves_user(self, db_session):
        repo = UserRepository(db_session)
        
        user_id = repo.save(
            name='John',
            email='john@example.com'
        )
        
        user = repo.find_by_id(user_id)
        assert user.name == 'John'
        assert user.email == 'john@example.com'
    
    def test_finds_by_email(self, db_session):
        repo = UserRepository(db_session)
        repo.save(name='Jane', email='jane@example.com')
        
        user = repo.find_by_email('jane@example.com')
        assert user is not None
        assert user.name == 'Jane'
```

## End-to-End Workflow Test

### JavaScript (Complete Flow)

```javascript
describe('Order Workflow Integration', () => {
  test('complete purchase flow', async () => {
    // 1. Create user
    const user = await createUser({
      name: 'Customer',
      email: 'customer@example.com'
    });
    
    // 2. Create products
    const products = await createProducts([
      { name: 'Widget', price: 29.99, stock: 100 },
      { name: 'Gadget', price: 19.99, stock: 50 }
    ]);
    
    // 3. Create cart and add items
    const cart = await createCart(user.id);
    await addToCart(cart.id, products[0].id, 2);
    await addToCart(cart.id, products[1].id, 1);
    
    // 4. Checkout
    const order = await checkout(cart.id, {
      paymentMethod: 'card',
      cardToken: 'tok_visa'
    });
    
    // 5. Verify
    expect(order.status).toBe('confirmed');
    expect(order.total).toBeCloseTo(79.97, 2);
    
    // 6. Verify side effects
    const updatedProduct = await getProduct(products[0].id);
    expect(updatedProduct.stock).toBe(98);  // Reduced by 2
    
    const userOrders = await getUserOrders(user.id);
    expect(userOrders).toHaveLength(1);
  });
});
```

## Best Practices

- Use real services, not mocks
- Clean state between tests
- Test complete workflows
- Verify side effects
