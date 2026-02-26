"""
File: config.tpl.py
Purpose: FastAPI application configuration using Pydantic Settings
Generated for: {{PROJECT_NAME}}
Tier: base
Stack: fastapi
Category: configuration
"""

from pydantic import Field, field_validator, PostgresDsn, RedisDsn
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional, List
from functools import lru_cache


class DatabaseSettings(BaseSettings):
    """Database configuration"""
    
    host: str = Field("localhost", description="Database host")
    port: int = Field(5432, description="Database port")
    user: str = Field("postgres", description="Database user")
    password: str = Field("", description="Database password")
    name: str = Field("{{PROJECT_NAME}}", description="Database name")
    echo: bool = Field(False, description="Echo SQL queries")
    pool_size: int = Field(5, description="Connection pool size")
    max_overflow: int = Field(10, description="Max overflow connections")
    
    @property
    def url(self) -> str:
        """Construct database URL"""
        return f"postgresql+asyncpg://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"
    
    model_config = SettingsConfigDict(env_prefix="DB_")


class RedisSettings(BaseSettings):
    """Redis configuration"""
    
    host: str = Field("localhost", description="Redis host")
    port: int = Field(6379, description="Redis port")
    db: int = Field(0, description="Redis database number")
    password: Optional[str] = Field(None, description="Redis password")
    
    @property
    def url(self) -> str:
        """Construct Redis URL"""
        if self.password:
            return f"redis://:{self.password}@{self.host}:{self.port}/{self.db}"
        return f"redis://{self.host}:{self.port}/{self.db}"
    
    model_config = SettingsConfigDict(env_prefix="REDIS_")


class AuthSettings(BaseSettings):
    """Authentication configuration"""
    
    secret_key: str = Field(..., description="Secret key for JWT")
    algorithm: str = Field("HS256", description="JWT algorithm")
    access_token_expire_minutes: int = Field(30, description="Access token expiration")
    refresh_token_expire_days: int = Field(7, description="Refresh token expiration")
    
    @field_validator('secret_key')
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        """Ensure secret key is strong enough"""
        if len(v) < 32:
            raise ValueError('Secret key must be at least 32 characters long')
        return v
    
    model_config = SettingsConfigDict(env_prefix="AUTH_")


class CORSSettings(BaseSettings):
    """CORS configuration"""
    
    origins: List[str] = Field(
        default_factory=lambda: ["http://localhost:3000"],
        description="Allowed origins"
    )
    credentials: bool = Field(True, description="Allow credentials")
    methods: List[str] = Field(
        default_factory=lambda: ["*"],
        description="Allowed methods"
    )
    headers: List[str] = Field(
        default_factory=lambda: ["*"],
        description="Allowed headers"
    )
    
    model_config = SettingsConfigDict(env_prefix="CORS_")


class ServerSettings(BaseSettings):
    """Server configuration"""
    
    host: str = Field("0.0.0.0", description="Server host")
    port: int = Field(8000, description="Server port")
    workers: int = Field(1, description="Number of worker processes")
    reload: bool = Field(False, description="Enable auto-reload")
    log_level: str = Field("info", description="Logging level")
    
    model_config = SettingsConfigDict(env_prefix="SERVER_")


class AppSettings(BaseSettings):
    """Main application settings"""
    
    # Application info
    name: str = Field("{{PROJECT_NAME}}", description="Application name")
    version: str = Field("{{VERSION}}", description="Application version")
    description: str = Field("{{PROJECT_DESCRIPTION}}", description="Application description")
    
    # Environment
    environment: str = Field("development", description="Environment (development/staging/production)")
    debug: bool = Field(False, description="Debug mode")
    testing: bool = Field(False, description="Testing mode")
    
    # API settings
    api_prefix: str = Field("/api/v1", description="API route prefix")
    docs_url: str = Field("/docs", description="OpenAPI docs URL")
    redoc_url: str = Field("/redoc", description="ReDoc URL")
    
    # Rate limiting
    rate_limit_enabled: bool = Field(True, description="Enable rate limiting")
    rate_limit_calls: int = Field(100, description="Max calls per period")
    rate_limit_period: int = Field(60, description="Rate limit period in seconds")
    
    # Monitoring
    enable_metrics: bool = Field(True, description="Enable metrics collection")
    enable_tracing: bool = Field(False, description="Enable distributed tracing")
    
    @property
    def is_production(self) -> bool:
        """Check if running in production"""
        return self.environment == "production"
    
    @property
    def is_development(self) -> bool:
        """Check if running in development"""
        return self.environment == "development"
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )


class Settings(BaseSettings):
    """Complete application settings"""
    
    app: AppSettings = Field(default_factory=AppSettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    auth: AuthSettings = Field(default_factory=AuthSettings)
    cors: CORSSettings = Field(default_factory=CORSSettings)
    server: ServerSettings = Field(default_factory=ServerSettings)
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        case_sensitive=False,
        extra="ignore"
    )


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance.
    
    Returns:
        Settings: Application settings
        
    Example:
        from app.config import get_settings
        
        settings = get_settings()
        print(settings.database.url)
    """
    return Settings()


# Export settings instance
settings = get_settings()
