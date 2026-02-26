"""
File: repository.tpl.py
Purpose: Generic repository pattern for SQLAlchemy
Generated for: {{PROJECT_NAME}}
"""

from typing import Generic, List, Optional, Type, TypeVar
from sqlalchemy import select, update, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase
from pydantic import BaseModel

ModelType = TypeVar("ModelType", bound=DeclarativeBase)
CreateSchemaType = TypeVar("CreateSchemaType", bound=BaseModel)
UpdateSchemaType = TypeVar("UpdateSchemaType", bound=BaseModel)


class BaseRepository(Generic[ModelType, CreateSchemaType, UpdateSchemaType]):
    """Generic repository with CRUD operations"""

    def __init__(self, model: Type[ModelType], session: AsyncSession):
        self.model = model
        self.session = session

    async def get(self, id: int) -> Optional[ModelType]:
        """Get a single record by ID"""
        result = await self.session.execute(
            select(self.model).where(self.model.id == id)
        )
        return result.scalar_one_or_none()

    async def get_by(self, **kwargs) -> Optional[ModelType]:
        """Get a single record by arbitrary fields"""
        query = select(self.model)
        for key, value in kwargs.items():
            query = query.where(getattr(self.model, key) == value)
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def list(
        self,
        skip: int = 0,
        limit: int = 100,
        order_by: Optional[str] = None,
        **filters,
    ) -> List[ModelType]:
        """Get a list of records with pagination and filtering"""
        query = select(self.model)

        for key, value in filters.items():
            if value is not None:
                query = query.where(getattr(self.model, key) == value)

        if order_by:
            desc = order_by.startswith("-")
            field = order_by.lstrip("-")
            column = getattr(self.model, field)
            query = query.order_by(column.desc() if desc else column)

        query = query.offset(skip).limit(limit)
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def count(self, **filters) -> int:
        """Count records matching filters"""
        from sqlalchemy import func

        query = select(func.count()).select_from(self.model)
        for key, value in filters.items():
            if value is not None:
                query = query.where(getattr(self.model, key) == value)
        result = await self.session.execute(query)
        return result.scalar() or 0

    async def create(self, obj_in: CreateSchemaType) -> ModelType:
        """Create a new record"""
        obj = self.model(**obj_in.model_dump())
        self.session.add(obj)
        await self.session.commit()
        await self.session.refresh(obj)
        return obj

    async def update(
        self,
        id: int,
        obj_in: UpdateSchemaType,
    ) -> Optional[ModelType]:
        """Update an existing record"""
        obj = await self.get(id)
        if not obj:
            return None

        update_data = obj_in.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(obj, field, value)

        await self.session.commit()
        await self.session.refresh(obj)
        return obj

    async def delete(self, id: int) -> bool:
        """Delete a record by ID"""
        result = await self.session.execute(
            delete(self.model).where(self.model.id == id)
        )
        await self.session.commit()
        return result.rowcount > 0

    async def bulk_create(self, objs_in: List[CreateSchemaType]) -> List[ModelType]:
        """Create multiple records"""
        objs = [self.model(**obj.model_dump()) for obj in objs_in]
        self.session.add_all(objs)
        await self.session.commit()
        for obj in objs:
            await self.session.refresh(obj)
        return objs


# Example usage:
# from models import User
# from schemas import UserCreate, UserUpdate
#
# class UserRepository(BaseRepository[User, UserCreate, UserUpdate]):
#     async def get_by_email(self, email: str) -> Optional[User]:
#         return await self.get_by(email=email)
#
# async with get_session() as session:
#     repo = UserRepository(User, session)
#     user = await repo.create(UserCreate(email="test@example.com", name="Test"))
