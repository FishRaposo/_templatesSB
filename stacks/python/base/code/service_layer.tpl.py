"""
File: service_layer.tpl.py
Purpose: Service layer pattern with dependency injection
Generated for: {{PROJECT_NAME}}
"""

from abc import ABC, abstractmethod
from typing import Generic, TypeVar, Optional, List, Any
from dataclasses import dataclass
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

T = TypeVar("T")
ID = TypeVar("ID")


# Base repository interface
class IRepository(ABC, Generic[T, ID]):
    """Abstract repository interface"""

    @abstractmethod
    async def get_by_id(self, id: ID) -> Optional[T]:
        pass

    @abstractmethod
    async def get_all(self, limit: int = 100, offset: int = 0) -> List[T]:
        pass

    @abstractmethod
    async def create(self, entity: T) -> T:
        pass

    @abstractmethod
    async def update(self, entity: T) -> T:
        pass

    @abstractmethod
    async def delete(self, id: ID) -> bool:
        pass


# Base service class
class BaseService(Generic[T, ID]):
    """Base service with common CRUD operations"""

    def __init__(self, repository: IRepository[T, ID]):
        self.repository = repository
        self.logger = logging.getLogger(self.__class__.__name__)

    async def get(self, id: ID) -> Optional[T]:
        """Get entity by ID"""
        self.logger.debug(f"Getting entity with id={id}")
        return await self.repository.get_by_id(id)

    async def list(self, limit: int = 100, offset: int = 0) -> List[T]:
        """List entities with pagination"""
        self.logger.debug(f"Listing entities: limit={limit}, offset={offset}")
        return await self.repository.get_all(limit=limit, offset=offset)

    async def create(self, entity: T) -> T:
        """Create new entity"""
        self.logger.info(f"Creating new entity")
        return await self.repository.create(entity)

    async def update(self, entity: T) -> T:
        """Update existing entity"""
        self.logger.info(f"Updating entity")
        return await self.repository.update(entity)

    async def delete(self, id: ID) -> bool:
        """Delete entity by ID"""
        self.logger.info(f"Deleting entity with id={id}")
        return await self.repository.delete(id)


# Result pattern for service operations
@dataclass
class Result(Generic[T]):
    """Result wrapper for service operations"""
    success: bool
    data: Optional[T] = None
    error: Optional[str] = None
    error_code: Optional[str] = None

    @staticmethod
    def ok(data: T) -> "Result[T]":
        return Result(success=True, data=data)

    @staticmethod
    def fail(error: str, error_code: str = "ERROR") -> "Result[T]":
        return Result(success=False, error=error, error_code=error_code)


# Event system for domain events
@dataclass
class DomainEvent:
    """Base domain event"""
    occurred_at: datetime
    aggregate_id: Any
    event_type: str
    payload: dict


class EventBus:
    """Simple event bus for domain events"""

    def __init__(self):
        self._handlers: dict[str, List[callable]] = {}

    def subscribe(self, event_type: str, handler: callable):
        """Subscribe to an event type"""
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        self._handlers[event_type].append(handler)

    async def publish(self, event: DomainEvent):
        """Publish an event to all subscribers"""
        handlers = self._handlers.get(event.event_type, [])
        for handler in handlers:
            try:
                await handler(event)
            except Exception as e:
                logger.error(f"Error handling event {event.event_type}: {e}")


# Unit of Work pattern
class IUnitOfWork(ABC):
    """Unit of Work interface for transaction management"""

    @abstractmethod
    async def __aenter__(self):
        pass

    @abstractmethod
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

    @abstractmethod
    async def commit(self):
        pass

    @abstractmethod
    async def rollback(self):
        pass


# Example concrete service
class UserService(BaseService):
    """User service with business logic"""

    def __init__(self, repository, event_bus: EventBus):
        super().__init__(repository)
        self.event_bus = event_bus

    async def register(self, email: str, password: str) -> Result:
        """Register a new user"""
        # Check if user exists
        existing = await self.repository.get_by_email(email)
        if existing:
            return Result.fail("Email already registered", "USER_EXISTS")

        # Create user
        user = await self.repository.create({
            "email": email,
            "password_hash": self._hash_password(password),
        })

        # Publish event
        await self.event_bus.publish(DomainEvent(
            occurred_at=datetime.utcnow(),
            aggregate_id=user.id,
            event_type="user.registered",
            payload={"email": email},
        ))

        return Result.ok(user)

    def _hash_password(self, password: str) -> str:
        """Hash password (implement with bcrypt/argon2)"""
        import hashlib
        return hashlib.sha256(password.encode()).hexdigest()


# Dependency injection container
class Container:
    """Simple DI container"""

    def __init__(self):
        self._services: dict[str, Any] = {}
        self._factories: dict[str, callable] = {}

    def register(self, name: str, service: Any):
        """Register a service instance"""
        self._services[name] = service

    def register_factory(self, name: str, factory: callable):
        """Register a factory function"""
        self._factories[name] = factory

    def resolve(self, name: str) -> Any:
        """Resolve a service by name"""
        if name in self._services:
            return self._services[name]
        if name in self._factories:
            service = self._factories[name](self)
            self._services[name] = service
            return service
        raise KeyError(f"Service '{name}' not registered")


# Usage:
# container = Container()
# container.register("event_bus", EventBus())
# container.register_factory("user_service", lambda c: UserService(
#     repository=UserRepository(db),
#     event_bus=c.resolve("event_bus")
# ))
# user_service = container.resolve("user_service")
