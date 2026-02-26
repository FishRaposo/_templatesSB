"""
Security - Authentication, JWT, Password Hashing
"""

from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Union

import jwt
from passlib.context import CryptContext

from app.config import settings


# ============================================================================
# Password Hashing
# ============================================================================

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=settings.security.bcrypt_rounds,
)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against a hash."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password."""
    return pwd_context.hash(password)


# ============================================================================
# JWT Token Management
# ============================================================================

ALGORITHM = settings.security.algorithm
SECRET_KEY = settings.security.secret_key.get_secret_value()


def create_access_token(
    subject: Union[str, int],
    expires_delta: Optional[timedelta] = None,
    additional_claims: Optional[Dict[str, Any]] = None,
) -> str:
    """Create an access token."""
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(
            minutes=settings.security.access_token_expire_minutes
        )
    
    to_encode = {
        "sub": str(subject),
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "access",
    }
    
    if additional_claims:
        to_encode.update(additional_claims)
    
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(
    subject: Union[str, int],
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a refresh token."""
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(
            days=settings.security.refresh_token_expire_days
        )
    
    to_encode = {
        "sub": str(subject),
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "refresh",
    }
    
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> Dict[str, Any]:
    """Decode and validate a JWT token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired")
    except jwt.InvalidTokenError as e:
        raise ValueError(f"Invalid token: {str(e)}")


def create_verification_token(user_id: int) -> str:
    """Create an email verification token."""
    expire = datetime.utcnow() + timedelta(hours=24)
    
    to_encode = {
        "sub": str(user_id),
        "exp": expire,
        "type": "verification",
    }
    
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_password_reset_token(user_id: int) -> str:
    """Create a password reset token."""
    expire = datetime.utcnow() + timedelta(hours=1)
    
    to_encode = {
        "sub": str(user_id),
        "exp": expire,
        "type": "password_reset",
    }
    
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_token_type(token: str, expected_type: str) -> Dict[str, Any]:
    """Verify token and check its type."""
    payload = decode_token(token)
    
    if payload.get("type") != expected_type:
        raise ValueError(f"Invalid token type. Expected {expected_type}")
    
    return payload


# ============================================================================
# API Key Generation
# ============================================================================

import secrets
import hashlib


def generate_api_key() -> tuple[str, str, str]:
    """
    Generate an API key.
    Returns: (full_key, key_prefix, key_hash)
    """
    # Generate a random key
    key = secrets.token_urlsafe(32)
    prefix = key[:8]
    
    # Hash the key for storage
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    
    return key, prefix, key_hash


def verify_api_key(key: str, key_hash: str) -> bool:
    """Verify an API key against its hash."""
    computed_hash = hashlib.sha256(key.encode()).hexdigest()
    return secrets.compare_digest(computed_hash, key_hash)


# ============================================================================
# Security Headers
# ============================================================================

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}


# ============================================================================
# Rate Limiting
# ============================================================================

class RateLimiter:
    """Simple in-memory rate limiter (use Redis in production)."""
    
    def __init__(self, requests_per_minute: int = 60):
        self.requests_per_minute = requests_per_minute
        self._requests: Dict[str, list] = {}
    
    def is_allowed(self, key: str) -> bool:
        """Check if request is allowed."""
        now = datetime.utcnow()
        window_start = now - timedelta(minutes=1)
        
        # Get existing requests for this key
        if key not in self._requests:
            self._requests[key] = []
        
        # Filter to only include requests in the current window
        self._requests[key] = [
            ts for ts in self._requests[key]
            if ts > window_start
        ]
        
        # Check limit
        if len(self._requests[key]) >= self.requests_per_minute:
            return False
        
        # Add current request
        self._requests[key].append(now)
        return True
    
    def get_remaining(self, key: str) -> int:
        """Get remaining requests in current window."""
        if key not in self._requests:
            return self.requests_per_minute
        
        now = datetime.utcnow()
        window_start = now - timedelta(minutes=1)
        
        current_requests = len([
            ts for ts in self._requests[key]
            if ts > window_start
        ])
        
        return max(0, self.requests_per_minute - current_requests)


# ============================================================================
# Input Sanitization
# ============================================================================

import re
import html


def sanitize_html(text: str) -> str:
    """Escape HTML entities in text."""
    return html.escape(text)


def sanitize_filename(filename: str) -> str:
    """Sanitize a filename to prevent path traversal."""
    # Remove path separators
    filename = filename.replace("/", "_").replace("\\", "_")
    # Remove potentially dangerous characters
    filename = re.sub(r'[<>:"|?*]', "", filename)
    # Remove leading dots
    filename = filename.lstrip(".")
    return filename


def is_safe_url(url: str, allowed_hosts: list[str]) -> bool:
    """Check if URL is safe for redirect."""
    from urllib.parse import urlparse
    
    if not url:
        return False
    
    parsed = urlparse(url)
    
    # Allow relative URLs
    if not parsed.scheme and not parsed.netloc:
        return True
    
    # Check if host is allowed
    return parsed.netloc in allowed_hosts
