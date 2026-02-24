"""
File: validators.tpl.py
Purpose: Common validation patterns with Pydantic
Generated for: {{PROJECT_NAME}}
"""

import re
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, field_validator, model_validator
from pydantic import EmailStr, HttpUrl, Field
from datetime import datetime, date


# Common regex patterns
PHONE_PATTERN = re.compile(r"^\+?[1-9]\d{1,14}$")
SLUG_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{3,32}$")


class BaseSchema(BaseModel):
    """Base schema with common configuration"""

    model_config = ConfigDict(
        from_attributes=True,
        str_strip_whitespace=True,
        validate_default=True,
    )


class TimestampMixin(BaseModel):
    """Mixin for created/updated timestamps"""

    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class PaginationParams(BaseSchema):
    """Pagination parameters"""

    page: int = Field(default=1, ge=1)
    per_page: int = Field(default=20, ge=1, le=100)
    order_by: Optional[str] = None
    order_dir: str = Field(default="asc", pattern="^(asc|desc)$")

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.per_page

    @property
    def limit(self) -> int:
        return self.per_page


class UserCreate(BaseSchema):
    """User creation with validation"""

    email: EmailStr
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=8, max_length=128)
    full_name: Optional[str] = Field(default=None, max_length=100)

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not USERNAME_PATTERN.match(v):
            raise ValueError(
                "Username must be 3-32 characters, alphanumeric with _ or -"
            )
        return v.lower()

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v


class PhoneNumber(BaseSchema):
    """Phone number with E.164 validation"""

    number: str

    @field_validator("number")
    @classmethod
    def validate_phone(cls, v: str) -> str:
        v = re.sub(r"[\s\-\(\)]", "", v)
        if not PHONE_PATTERN.match(v):
            raise ValueError("Invalid phone number format")
        return v


class DateRange(BaseSchema):
    """Date range with validation"""

    start_date: date
    end_date: date

    @model_validator(mode="after")
    def validate_date_range(self):
        if self.end_date < self.start_date:
            raise ValueError("end_date must be after start_date")
        return self


class Address(BaseSchema):
    """Address with common fields"""

    street: str = Field(max_length=200)
    city: str = Field(max_length=100)
    state: Optional[str] = Field(default=None, max_length=100)
    postal_code: str = Field(max_length=20)
    country: str = Field(max_length=2, pattern="^[A-Z]{2}$")  # ISO 3166-1 alpha-2


class Slug(BaseSchema):
    """URL slug validation"""

    slug: str = Field(max_length=100)

    @field_validator("slug")
    @classmethod
    def validate_slug(cls, v: str) -> str:
        v = v.lower()
        if not SLUG_PATTERN.match(v):
            raise ValueError("Slug must be lowercase with hyphens only")
        return v


class Money(BaseSchema):
    """Monetary amount with currency"""

    amount: int = Field(ge=0)  # Store in cents
    currency: str = Field(default="USD", pattern="^[A-Z]{3}$")

    @property
    def display_amount(self) -> float:
        return self.amount / 100


# Validation utilities
def validate_model(model_class: type[BaseModel], data: dict) -> tuple[bool, Any]:
    """
    Validate data against a Pydantic model.
    Returns (success, result_or_errors)
    """
    try:
        instance = model_class.model_validate(data)
        return True, instance
    except Exception as e:
        return False, str(e)


# Usage:
# user_data = {"email": "test@example.com", "username": "john_doe", "password": "Password123"}
# success, result = validate_model(UserCreate, user_data)
# if success:
#     print(result.email)
