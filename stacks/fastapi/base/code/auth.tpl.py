"""
File: auth.tpl.py
Purpose: JWT authentication and password hashing utilities
Generated for: {{PROJECT_NAME}}
Tier: base
Stack: fastapi
Category: authentication
"""

from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status

# Configuration (should come from settings)
SECRET_KEY = "{{SECRET_KEY}}"  # Change this in production!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ============================================================================
# Password Utilities
# ============================================================================

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain password against a hashed password.
    
    Args:
        plain_password: Plain text password
        hashed_password: Hashed password from database
        
    Returns:
        bool: True if password matches
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """
    Hash a plain password.
    
    Args:
        password: Plain text password
        
    Returns:
        str: Hashed password
    """
    return pwd_context.hash(password)


# ============================================================================
# JWT Token Utilities
# ============================================================================

def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create a JWT access token.
    
    Args:
        data: Data to encode in token (typically {"sub": user_id})
        expires_delta: Optional custom expiration time
        
    Returns:
        str: Encoded JWT token
        
    Example:
        token = create_access_token({"sub": str(user.id)})
    """
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    
    return encoded_jwt


def create_refresh_token(
    data: dict,
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create a JWT refresh token with longer expiration.
    
    Args:
        data: Data to encode in token
        expires_delta: Optional custom expiration time
        
    Returns:
        str: Encoded JWT refresh token
    """
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    
    to_encode.update({"exp": expire, "iat": datetime.utcnow(), "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    
    return encoded_jwt


def decode_token(token: str) -> dict:
    """
    Decode and validate a JWT token.
    
    Args:
        token: JWT token string
        
    Returns:
        dict: Decoded token payload
        
    Raises:
        HTTPException: If token is invalid or expired
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


def get_user_id_from_token(token: str) -> int:
    """
    Extract user ID from JWT token.
    
    Args:
        token: JWT token string
        
    Returns:
        int: User ID from token
        
    Raises:
        HTTPException: If token is invalid or missing user ID
    """
    payload = decode_token(token)
    user_id: Optional[str] = payload.get("sub")
    
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return int(user_id)


# ============================================================================
# Token Validation
# ============================================================================

def validate_token_type(token: str, expected_type: str = "access") -> bool:
    """
    Validate that token is of expected type (access or refresh).
    
    Args:
        token: JWT token string
        expected_type: Expected token type ("access" or "refresh")
        
    Returns:
        bool: True if token type matches
        
    Raises:
        HTTPException: If token type doesn't match
    """
    payload = decode_token(token)
    token_type = payload.get("type", "access")
    
    if token_type != expected_type:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token type. Expected {expected_type}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return True


# ============================================================================
# Authentication Helper
# ============================================================================

async def authenticate_user(username: str, password: str, db):
    """
    Authenticate a user with username and password.
    
    Args:
        username: Username or email
        password: Plain text password
        db: Database session
        
    Returns:
        User: Authenticated user object or None
        
    Example:
        user = await authenticate_user("john", "password123", db)
        if user:
            token = create_access_token({"sub": str(user.id)})
    """
    # This is a placeholder - implement with actual User model
    # from sqlalchemy import select
    # from .models import User
    # 
    # # Try to find user by username or email
    # result = await db.execute(
    #     select(User).where(
    #         (User.username == username) | (User.email == username)
    #     )
    # )
    # user = result.scalar_one_or_none()
    # 
    # if not user:
    #     return None
    # 
    # if not verify_password(password, user.hashed_password):
    #     return None
    # 
    # return user
    return None
