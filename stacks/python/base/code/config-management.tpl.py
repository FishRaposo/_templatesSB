"""
File: config-management.tpl.py
Purpose: Configuration management using pydantic-settings
Generated for: {{PROJECT_NAME}}
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, PostgresDsn, computed_field
from typing import Optional

class DatabaseSettings(BaseSettings):
    host: str = Field("localhost", alias="DB_HOST")
    port: int = Field(5432, alias="DB_PORT")
    user: str = Field("postgres", alias="DB_USER")
    password: str = Field("", alias="DB_PASSWORD")
    name: str = Field("myapp", alias="DB_NAME")
    
    @computed_field
    @property
    def url(self) -> PostgresDsn:
        return PostgresDsn.build(
            scheme="postgresql",
            username=self.user,
            password=self.password,
            host=self.host,
            port=self.port,
            path=self.name,
        )

class ServerSettings(BaseSettings):
    host: str = Field("0.0.0.0", alias="HOST")
    port: int = Field(8000, alias="PORT")
    debug: bool = Field(False, alias="DEBUG")
    log_level: str = Field("INFO", alias="LOG_LEVEL")

class Settings(BaseSettings):
    environment: str = Field("development", alias="ENVIRONMENT")
    database: DatabaseSettings = DatabaseSettings()
    server: ServerSettings = ServerSettings()

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        case_sensitive=True,
        extra="ignore"
    )

# Singleton instance
settings = Settings()

if __name__ == "__main__":
    print(f"Loaded config for environment: {settings.environment}")
    print(f"Database URL: {settings.database.url}")
