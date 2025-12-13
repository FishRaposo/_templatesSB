"""
File: validation.tpl.py
Purpose: Input validation patterns with Pydantic and custom validators
Generated for: {{PROJECT_NAME}}
"""

import re
from datetime import date, datetime
from decimal import Decimal
from typing import Annotated, Any, Callable, List, Optional, TypeVar
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    HttpUrl,
    SecretStr,
    field_validator,
    model_validator,
    validator,
)
from pydantic.functional_validators import AfterValidator, BeforeValidator


# ============================================================================
# Custom Types with Validation
# ============================================================================

# Username: alphanumeric, 3-30 chars
def validate_username(v: str) -> str:
    if not re.match(r"^[a-zA-Z0-9_-]{3,30}$", v):
        raise ValueError(
            "Username must be 3-30 characters, alphanumeric with _ or -"
        )
    return v.lower()


Username = Annotated[str, AfterValidator(validate_username)]


# Slug: URL-safe string
def validate_slug(v: str) -> str:
    if not re.match(r"^[a-z0-9]+(?:-[a-z0-9]+)*$", v):
        raise ValueError("Invalid slug format")
    return v


Slug = Annotated[str, AfterValidator(validate_slug)]


# Phone number with formatting
def validate_phone(v: str) -> str:
    # Remove all non-digits
    digits = re.sub(r"\D", "", v)
    if len(digits) < 10 or len(digits) > 15:
        raise ValueError("Phone number must have 10-15 digits")
    return digits


PhoneNumber = Annotated[str, AfterValidator(validate_phone)]


# Strong password validation
def validate_strong_password(v: str) -> str:
    if len(v) < 8:
        raise ValueError("Password must be at least 8 characters")
    if not re.search(r"[A-Z]", v):
        raise ValueError("Password must contain uppercase letter")
    if not re.search(r"[a-z]", v):
        raise ValueError("Password must contain lowercase letter")
    if not re.search(r"\d", v):
        raise ValueError("Password must contain a digit")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
        raise ValueError("Password must contain a special character")
    return v


StrongPassword = Annotated[str, AfterValidator(validate_strong_password)]


# Positive integer
def validate_positive(v: int) -> int:
    if v <= 0:
        raise ValueError("Value must be positive")
    return v


PositiveInt = Annotated[int, AfterValidator(validate_positive)]


# Money amount (positive Decimal with 2 decimal places)
def validate_money(v: Decimal) -> Decimal:
    if v < 0:
        raise ValueError("Amount cannot be negative")
    return v.quantize(Decimal("0.01"))


Money = Annotated[Decimal, AfterValidator(validate_money)]


# Sanitized string (strips and removes excess whitespace)
def sanitize_string(v: str) -> str:
    return " ".join(v.split())


SanitizedString = Annotated[str, BeforeValidator(sanitize_string)]


# ============================================================================
# Base Models with Common Configuration
# ============================================================================

class StrictModel(BaseModel):
    """Base model with strict validation."""
    
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra="forbid",
        frozen=False,
    )


class ImmutableModel(BaseModel):
    """Base model for immutable data."""
    
    model_config = ConfigDict(
        str_strip_whitespace=True,
        frozen=True,
        extra="forbid",
    )


# ============================================================================
# Common Schema Patterns
# ============================================================================

class TimestampMixin(BaseModel):
    """Mixin for timestamp fields."""
    
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class IDMixin(BaseModel):
    """Mixin for ID field."""
    
    id: int


class UUIDMixin(BaseModel):
    """Mixin for UUID field."""
    
    id: UUID


# ============================================================================
# Request Validators
# ============================================================================

class PaginationRequest(StrictModel):
    """Pagination request parameters."""
    
    page: int = Field(default=1, ge=1, le=1000)
    per_page: int = Field(default=20, ge=1, le=100)
    
    @property
    def offset(self) -> int:
        return (self.page - 1) * self.per_page


class SortRequest(StrictModel):
    """Sorting request parameters."""
    
    sort_by: str = Field(default="created_at")
    sort_order: str = Field(default="desc", pattern="^(asc|desc)$")
    
    @field_validator("sort_by")
    @classmethod
    def validate_sort_field(cls, v: str) -> str:
        allowed_fields = {"id", "created_at", "updated_at", "name", "title"}
        if v not in allowed_fields:
            raise ValueError(f"Sort by must be one of: {allowed_fields}")
        return v


class DateRangeRequest(StrictModel):
    """Date range request parameters."""
    
    start_date: Optional[date] = None
    end_date: Optional[date] = None
    
    @model_validator(mode="after")
    def validate_date_range(self):
        if self.start_date and self.end_date:
            if self.start_date > self.end_date:
                raise ValueError("Start date must be before end date")
        return self


# ============================================================================
# User Schemas
# ============================================================================

class UserRegistration(StrictModel):
    """User registration request."""
    
    email: EmailStr
    username: Username
    password: StrongPassword
    password_confirm: str
    full_name: Optional[SanitizedString] = Field(None, max_length=100)
    
    @model_validator(mode="after")
    def validate_passwords_match(self):
        if self.password != self.password_confirm:
            raise ValueError("Passwords do not match")
        return self


class UserLogin(StrictModel):
    """User login request."""
    
    email: EmailStr
    password: str = Field(..., min_length=1)
    remember_me: bool = False


class PasswordChange(StrictModel):
    """Password change request."""
    
    current_password: str = Field(..., min_length=1)
    new_password: StrongPassword
    new_password_confirm: str
    
    @model_validator(mode="after")
    def validate_passwords(self):
        if self.new_password != self.new_password_confirm:
            raise ValueError("New passwords do not match")
        if self.current_password == self.new_password:
            raise ValueError("New password must be different from current")
        return self


class UserProfile(StrictModel):
    """User profile update request."""
    
    full_name: Optional[SanitizedString] = Field(None, max_length=100)
    bio: Optional[str] = Field(None, max_length=500)
    website: Optional[HttpUrl] = None
    phone: Optional[PhoneNumber] = None
    birth_date: Optional[date] = None
    
    @field_validator("birth_date")
    @classmethod
    def validate_birth_date(cls, v: Optional[date]) -> Optional[date]:
        if v:
            today = date.today()
            age = today.year - v.year - ((today.month, today.day) < (v.month, v.day))
            if age < 13:
                raise ValueError("Must be at least 13 years old")
            if age > 150:
                raise ValueError("Invalid birth date")
        return v


# ============================================================================
# Content Schemas
# ============================================================================

class PostCreate(StrictModel):
    """Post creation request."""
    
    title: SanitizedString = Field(..., min_length=5, max_length=200)
    content: str = Field(..., min_length=10, max_length=50000)
    excerpt: Optional[str] = Field(None, max_length=500)
    slug: Optional[Slug] = None
    status: str = Field(default="draft", pattern="^(draft|published|archived)$")
    tags: List[str] = Field(default_factory=list, max_length=10)
    
    @field_validator("tags")
    @classmethod
    def validate_tags(cls, v: List[str]) -> List[str]:
        # Normalize tags
        normalized = [tag.strip().lower() for tag in v if tag.strip()]
        # Remove duplicates while preserving order
        seen = set()
        unique = []
        for tag in normalized:
            if tag not in seen:
                seen.add(tag)
                unique.append(tag)
        return unique


class CommentCreate(StrictModel):
    """Comment creation request."""
    
    content: SanitizedString = Field(..., min_length=1, max_length=5000)
    parent_id: Optional[int] = None
    
    @field_validator("content")
    @classmethod
    def validate_content(cls, v: str) -> str:
        # Basic content moderation
        forbidden = ["spam", "advertisement"]  # Add more as needed
        content_lower = v.lower()
        for word in forbidden:
            if word in content_lower:
                raise ValueError("Content contains forbidden words")
        return v


# ============================================================================
# Business Schemas
# ============================================================================

class OrderCreate(StrictModel):
    """Order creation request."""
    
    items: List["OrderItem"] = Field(..., min_length=1)
    shipping_address_id: int
    billing_address_id: Optional[int] = None
    coupon_code: Optional[str] = Field(None, pattern="^[A-Z0-9]{4,20}$")
    notes: Optional[str] = Field(None, max_length=500)
    
    @model_validator(mode="after")
    def set_billing_address(self):
        if not self.billing_address_id:
            self.billing_address_id = self.shipping_address_id
        return self


class OrderItem(StrictModel):
    """Order item."""
    
    product_id: int
    quantity: int = Field(..., ge=1, le=99)
    options: dict = Field(default_factory=dict)


class PaymentRequest(StrictModel):
    """Payment request."""
    
    amount: Money
    currency: str = Field(default="USD", pattern="^[A-Z]{3}$")
    payment_method_id: str
    description: Optional[str] = Field(None, max_length=200)
    
    @field_validator("amount")
    @classmethod
    def validate_minimum_amount(cls, v: Decimal) -> Decimal:
        if v < Decimal("0.50"):
            raise ValueError("Minimum amount is 0.50")
        return v


# ============================================================================
# Validation Utilities
# ============================================================================

def create_validator(
    validate_fn: Callable[[Any], bool],
    error_message: str,
) -> Callable[[Any], Any]:
    """Create a validator function from a predicate."""
    
    def validator(v: Any) -> Any:
        if not validate_fn(v):
            raise ValueError(error_message)
        return v
    
    return validator


def validate_enum_value(enum_class):
    """Create a validator for enum values."""
    
    def validator(v: str) -> str:
        valid_values = [e.value for e in enum_class]
        if v not in valid_values:
            raise ValueError(f"Must be one of: {', '.join(valid_values)}")
        return v
    
    return validator


# Update forward references
OrderCreate.model_rebuild()
