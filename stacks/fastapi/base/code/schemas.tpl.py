"""
File: schemas.tpl.py
Purpose: Pydantic models for request/response validation and serialization
Generated for: {{PROJECT_NAME}}
Tier: base
Stack: fastapi
Category: schemas
"""

from pydantic import BaseModel, Field, EmailStr, ConfigDict, field_validator
from typing import Optional, List
from datetime import datetime
from enum import Enum


# ============================================================================
# Common Schemas
# ============================================================================

class ResponseStatus(str, Enum):
    """Standard response status values"""
    SUCCESS = "success"
    ERROR = "error"
    PENDING = "pending"


class MessageResponse(BaseModel):
    """Standard message response"""
    message: str
    status: ResponseStatus = ResponseStatus.SUCCESS
    
    model_config = ConfigDict(from_attributes=True)


class PaginatedResponse(BaseModel):
    """Standard paginated response wrapper"""
    items: List[BaseModel]
    total: int
    skip: int
    limit: int
    has_more: bool
    
    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# User Schemas
# ============================================================================

class UserBase(BaseModel):
    """Base user schema with common fields"""
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    full_name: Optional[str] = Field(None, max_length=100)
    
    @field_validator('username')
    @classmethod
    def validate_username(cls, v: str) -> str:
        """Validate username format"""
        if not v.isalnum() and '_' not in v:
            raise ValueError('Username must be alphanumeric or contain underscores')
        return v.lower()


class UserCreate(UserBase):
    """Schema for user creation"""
    password: str = Field(..., min_length=8, max_length=100)
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v: str) -> str:
        """Validate password strength"""
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        return v


class UserUpdate(BaseModel):
    """Schema for user updates (all fields optional)"""
    email: Optional[EmailStr] = None
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    full_name: Optional[str] = Field(None, max_length=100)
    
    model_config = ConfigDict(from_attributes=True)


class UserResponse(UserBase):
    """Schema for user responses (excludes sensitive data)"""
    id: int
    is_active: bool = True
    is_admin: bool = False
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    model_config = ConfigDict(from_attributes=True)


class UserInDB(UserResponse):
    """Schema for user in database (includes hashed password)"""
    hashed_password: str


# ============================================================================
# Authentication Schemas
# ============================================================================

class Token(BaseModel):
    """OAuth2 token response"""
    access_token: str
    token_type: str = "bearer"
    expires_in: Optional[int] = None
    refresh_token: Optional[str] = None


class TokenData(BaseModel):
    """Data stored in JWT token"""
    user_id: int
    username: str
    scopes: List[str] = []


class LoginRequest(BaseModel):
    """User login request"""
    username: str
    password: str


class RefreshTokenRequest(BaseModel):
    """Token refresh request"""
    refresh_token: str


# ============================================================================
# Item Schemas (Example Resource)
# ============================================================================

class ItemBase(BaseModel):
    """Base item schema"""
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    price: float = Field(..., gt=0)
    tax: Optional[float] = Field(None, ge=0)
    tags: List[str] = Field(default_factory=list)


class ItemCreate(ItemBase):
    """Schema for item creation"""
    pass


class ItemUpdate(BaseModel):
    """Schema for item updates (all fields optional)"""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    price: Optional[float] = Field(None, gt=0)
    tax: Optional[float] = Field(None, ge=0)
    tags: Optional[List[str]] = None
    
    model_config = ConfigDict(from_attributes=True)


class ItemResponse(ItemBase):
    """Schema for item responses"""
    id: int
    owner_id: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# Error Schemas
# ============================================================================

class ErrorDetail(BaseModel):
    """Detailed error information"""
    field: Optional[str] = None
    message: str
    code: Optional[str] = None


class ErrorResponse(BaseModel):
    """Standard error response"""
    detail: str
    errors: Optional[List[ErrorDetail]] = None
    status_code: int
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# Health Check Schema
# ============================================================================

class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    service: str
    version: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    dependencies: Optional[dict] = None
    
    model_config = ConfigDict(from_attributes=True)
