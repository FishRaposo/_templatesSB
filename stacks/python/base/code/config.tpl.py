"""
File: config.tpl.py
Purpose: Application configuration management using Pydantic Settings
Generated for: {{PROJECT_NAME}}
"""

import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# ============================================================================
# Base Settings
# ============================================================================

class BaseConfig(BaseSettings):
    """Base configuration with common settings."""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


# ============================================================================
# App Settings
# ============================================================================

class AppSettings(BaseConfig):
    """Application settings."""
    
    # Application
    app_name: str = Field(default="{{PROJECT_NAME}}")
    app_version: str = Field(default="1.0.0")
    environment: str = Field(default="development")
    debug: bool = Field(default=False)
    
    # Server
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8000)
    workers: int = Field(default=1)
    
    # Logging
    log_level: str = Field(default="INFO")
    log_format: str = Field(default="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    
    @property
    def is_production(self) -> bool:
        return self.environment == "production"
    
    @property
    def is_development(self) -> bool:
        return self.environment == "development"
    
    @property
    def is_testing(self) -> bool:
        return self.environment == "testing"


# ============================================================================
# Database Settings
# ============================================================================

class DatabaseSettings(BaseConfig):
    """Database configuration."""
    
    model_config = SettingsConfigDict(env_prefix="DB_")
    
    # Connection
    host: str = Field(default="localhost")
    port: int = Field(default=5432)
    name: str = Field(default="app_db")
    user: str = Field(default="postgres")
    password: SecretStr = Field(default=SecretStr(""))
    
    # Pool settings
    pool_size: int = Field(default=5)
    max_overflow: int = Field(default=10)
    pool_timeout: int = Field(default=30)
    pool_recycle: int = Field(default=1800)
    
    # Options
    echo: bool = Field(default=False)
    ssl_mode: str = Field(default="prefer")
    
    @property
    def async_url(self) -> str:
        """Get async database URL."""
        password = self.password.get_secret_value()
        return f"postgresql+asyncpg://{self.user}:{password}@{self.host}:{self.port}/{self.name}"
    
    @property
    def sync_url(self) -> str:
        """Get sync database URL."""
        password = self.password.get_secret_value()
        return f"postgresql+psycopg2://{self.user}:{password}@{self.host}:{self.port}/{self.name}"
    
    @property
    def url(self) -> str:
        """Alias for async_url."""
        return self.async_url


# ============================================================================
# Redis Settings
# ============================================================================

class RedisSettings(BaseConfig):
    """Redis configuration."""
    
    model_config = SettingsConfigDict(env_prefix="REDIS_")
    
    host: str = Field(default="localhost")
    port: int = Field(default=6379)
    db: int = Field(default=0)
    password: Optional[SecretStr] = Field(default=None)
    
    # Pool settings
    max_connections: int = Field(default=10)
    
    # Timeouts
    socket_timeout: int = Field(default=5)
    socket_connect_timeout: int = Field(default=5)
    
    @property
    def url(self) -> str:
        """Get Redis URL."""
        if self.password:
            return f"redis://:{self.password.get_secret_value()}@{self.host}:{self.port}/{self.db}"
        return f"redis://{self.host}:{self.port}/{self.db}"


# ============================================================================
# Security Settings
# ============================================================================

class SecuritySettings(BaseConfig):
    """Security configuration."""
    
    model_config = SettingsConfigDict(env_prefix="SECURITY_")
    
    # JWT
    secret_key: SecretStr = Field(default=SecretStr("change-me-in-production"))
    algorithm: str = Field(default="HS256")
    access_token_expire_minutes: int = Field(default=30)
    refresh_token_expire_days: int = Field(default=7)
    
    # Password hashing
    bcrypt_rounds: int = Field(default=12)
    
    # Session
    session_cookie_name: str = Field(default="session")
    session_max_age: int = Field(default=86400)
    
    # CORS
    cors_origins: List[str] = Field(default=["*"])
    cors_allow_credentials: bool = Field(default=True)
    
    # Rate limiting
    rate_limit_per_minute: int = Field(default=60)
    
    @field_validator("secret_key")
    @classmethod
    def validate_secret_key(cls, v: SecretStr) -> SecretStr:
        if v.get_secret_value() == "change-me-in-production":
            import warnings
            warnings.warn("Using default secret key. Change in production!")
        return v


# ============================================================================
# Storage Settings
# ============================================================================

class StorageSettings(BaseConfig):
    """File storage configuration."""
    
    model_config = SettingsConfigDict(env_prefix="STORAGE_")
    
    # Provider (local, s3, gcs)
    provider: str = Field(default="local")
    
    # Local storage
    local_path: Path = Field(default=Path("./uploads"))
    
    # S3
    s3_bucket: Optional[str] = Field(default=None)
    s3_region: str = Field(default="us-east-1")
    s3_access_key: Optional[SecretStr] = Field(default=None)
    s3_secret_key: Optional[SecretStr] = Field(default=None)
    s3_endpoint_url: Optional[str] = Field(default=None)
    
    # Upload limits
    max_file_size: int = Field(default=10 * 1024 * 1024)  # 10 MB
    allowed_extensions: List[str] = Field(
        default=["jpg", "jpeg", "png", "gif", "pdf", "doc", "docx"]
    )


# ============================================================================
# Email Settings
# ============================================================================

class EmailSettings(BaseConfig):
    """Email configuration."""
    
    model_config = SettingsConfigDict(env_prefix="EMAIL_")
    
    # Provider (smtp, sendgrid, ses, mailgun)
    provider: str = Field(default="smtp")
    
    # SMTP
    smtp_host: str = Field(default="smtp.gmail.com")
    smtp_port: int = Field(default=587)
    smtp_user: Optional[str] = Field(default=None)
    smtp_password: Optional[SecretStr] = Field(default=None)
    smtp_tls: bool = Field(default=True)
    
    # SendGrid
    sendgrid_api_key: Optional[SecretStr] = Field(default=None)
    
    # Common
    from_email: str = Field(default="noreply@example.com")
    from_name: str = Field(default="{{PROJECT_NAME}}")


# ============================================================================
# External Services Settings
# ============================================================================

class ExternalServicesSettings(BaseConfig):
    """External services configuration."""
    
    # Stripe
    stripe_secret_key: Optional[SecretStr] = Field(default=None)
    stripe_publishable_key: Optional[str] = Field(default=None)
    stripe_webhook_secret: Optional[SecretStr] = Field(default=None)
    
    # Sentry
    sentry_dsn: Optional[str] = Field(default=None)
    
    # Analytics
    google_analytics_id: Optional[str] = Field(default=None)
    mixpanel_token: Optional[str] = Field(default=None)


# ============================================================================
# Feature Flags
# ============================================================================

class FeatureFlags(BaseConfig):
    """Feature flags configuration."""
    
    model_config = SettingsConfigDict(env_prefix="FEATURE_")
    
    enable_registration: bool = Field(default=True)
    enable_social_login: bool = Field(default=False)
    enable_api_keys: bool = Field(default=True)
    enable_webhooks: bool = Field(default=True)
    maintenance_mode: bool = Field(default=False)


# ============================================================================
# Unified Settings
# ============================================================================

class Settings(BaseSettings):
    """Unified application settings."""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )
    
    app: AppSettings = Field(default_factory=AppSettings)
    db: DatabaseSettings = Field(default_factory=DatabaseSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)
    email: EmailSettings = Field(default_factory=EmailSettings)
    services: ExternalServicesSettings = Field(default_factory=ExternalServicesSettings)
    features: FeatureFlags = Field(default_factory=FeatureFlags)


# ============================================================================
# Settings Provider
# ============================================================================

@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


# Alias for convenience
settings = get_settings()
