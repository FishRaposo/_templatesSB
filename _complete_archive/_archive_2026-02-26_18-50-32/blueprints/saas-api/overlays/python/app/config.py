"""
Configuration Management
Using Pydantic Settings for type-safe configuration
"""

from functools import lru_cache
from typing import List, Optional

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# ============================================================================
# Settings Classes
# ============================================================================

class AppSettings(BaseSettings):
    """Application settings."""
    
    model_config = SettingsConfigDict(
        env_prefix="APP_",
        case_sensitive=False,
    )
    
    app_name: str = "SaaS API"
    app_version: str = "1.0.0"
    environment: str = Field(default="development", description="development, staging, production")
    debug: bool = True
    host: str = "0.0.0.0"
    port: int = 8000
    
    @property
    def is_production(self) -> bool:
        return self.environment == "production"


class DatabaseSettings(BaseSettings):
    """Database settings."""
    
    model_config = SettingsConfigDict(
        env_prefix="DB_",
        case_sensitive=False,
    )
    
    host: str = "localhost"
    port: int = 5432
    name: str = "app_db"
    user: str = "postgres"
    password: SecretStr = SecretStr("password")
    
    pool_size: int = 10
    pool_max_overflow: int = 20
    pool_timeout: int = 30
    echo: bool = False
    
    @property
    def async_url(self) -> str:
        pswd = self.password.get_secret_value()
        return f"postgresql+asyncpg://{self.user}:{pswd}@{self.host}:{self.port}/{self.name}"
    
    @property
    def sync_url(self) -> str:
        pswd = self.password.get_secret_value()
        return f"postgresql://{self.user}:{pswd}@{self.host}:{self.port}/{self.name}"


class RedisSettings(BaseSettings):
    """Redis settings."""
    
    model_config = SettingsConfigDict(
        env_prefix="REDIS_",
        case_sensitive=False,
    )
    
    host: str = "localhost"
    port: int = 6379
    db: int = 0
    password: Optional[SecretStr] = None
    
    cache_ttl: int = 3600  # 1 hour
    session_ttl: int = 86400  # 24 hours
    
    @property
    def url(self) -> str:
        if self.password:
            pswd = self.password.get_secret_value()
            return f"redis://:{pswd}@{self.host}:{self.port}/{self.db}"
        return f"redis://{self.host}:{self.port}/{self.db}"


class SecuritySettings(BaseSettings):
    """Security settings."""
    
    model_config = SettingsConfigDict(
        env_prefix="SECURITY_",
        case_sensitive=False,
    )
    
    secret_key: SecretStr = SecretStr("change-me-in-production-please")
    algorithm: str = "HS256"
    
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    
    bcrypt_rounds: int = 12
    
    cors_origins: List[str] = ["http://localhost:3000"]
    cors_allow_credentials: bool = True
    
    rate_limit_per_minute: int = 60
    
    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v):
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v


class ServicesSettings(BaseSettings):
    """External services settings."""
    
    model_config = SettingsConfigDict(
        env_prefix="",
        case_sensitive=False,
    )
    
    # Stripe
    stripe_secret_key: Optional[SecretStr] = Field(None, alias="STRIPE_SECRET_KEY")
    stripe_publishable_key: Optional[str] = Field(None, alias="STRIPE_PUBLISHABLE_KEY")
    stripe_webhook_secret: Optional[SecretStr] = Field(None, alias="STRIPE_WEBHOOK_SECRET")
    
    # Email (SendGrid or other)
    email_provider: str = Field("console", description="console, sendgrid, ses")
    sendgrid_api_key: Optional[SecretStr] = Field(None, alias="SENDGRID_API_KEY")
    email_from_address: str = "noreply@example.com"
    email_from_name: str = "SaaS App"
    
    # Sentry
    sentry_dsn: Optional[str] = Field(None, alias="SENTRY_DSN")
    
    # OpenAI (if using AI features)
    openai_api_key: Optional[SecretStr] = Field(None, alias="OPENAI_API_KEY")


class CelerySettings(BaseSettings):
    """Celery/Task queue settings."""
    
    model_config = SettingsConfigDict(
        env_prefix="CELERY_",
        case_sensitive=False,
    )
    
    broker_url: str = "redis://localhost:6379/1"
    result_backend: str = "redis://localhost:6379/2"
    
    task_serializer: str = "json"
    result_serializer: str = "json"
    accept_content: List[str] = ["json"]
    
    timezone: str = "UTC"
    enable_utc: bool = True
    
    task_track_started: bool = True
    task_time_limit: int = 300  # 5 minutes
    worker_prefetch_multiplier: int = 4


# ============================================================================
# Combined Settings
# ============================================================================

class Settings(BaseSettings):
    """Combined application settings."""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )
    
    app: AppSettings = AppSettings()
    db: DatabaseSettings = DatabaseSettings()
    redis: RedisSettings = RedisSettings()
    security: SecuritySettings = SecuritySettings()
    services: ServicesSettings = ServicesSettings()
    celery: CelerySettings = CelerySettings()


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


# Global settings instance
settings = get_settings()


# ============================================================================
# Feature Flags
# ============================================================================

class FeatureFlags:
    """Feature flags for gradual rollouts."""
    
    def __init__(self):
        self._flags = {
            "new_billing_flow": False,
            "ai_features": False,
            "dark_mode": True,
            "beta_features": settings.app.environment != "production",
        }
    
    def is_enabled(self, flag: str, user_id: Optional[int] = None) -> bool:
        """Check if a feature flag is enabled."""
        base_enabled = self._flags.get(flag, False)
        
        # Add percentage rollout or user-specific logic here
        return base_enabled
    
    def set_flag(self, flag: str, enabled: bool):
        """Set a feature flag (for testing)."""
        self._flags[flag] = enabled


feature_flags = FeatureFlags()
