# Universal Template System - Python Stack
# Generated: 2025-12-10
# Purpose: Configuration management utilities
# Tier: base
# Stack: python
# Category: utilities

#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# FILE: config-management.tpl.py
# PURPOSE: Comprehensive configuration management system for Python projects
# USAGE: Import and adapt for environment-specific settings, feature flags, and runtime configuration
# DEPENDENCIES: os, json, yaml, pathlib for configuration handling
# AUTHOR: [[.Author]]
# VERSION: [[.Version]]
# SINCE: [[.Version]]
# -----------------------------------------------------------------------------

"""
Python Configuration Management Template
Purpose: Reusable configuration management for Python projects
Usage: Import and adapt for environment-specific settings
"""

import os
import json
import yaml
from typing import Dict, Any, Optional
from pathlib import Path
from dataclasses import dataclass, asdict

@dataclass
class DatabaseConfig:
    """Database configuration settings"""
    host: str = "localhost"
    port: int = 5432
    name: str = "myapp"
    user: str = "postgres"
    password: str = ""
    ssl_mode: str = "prefer"

@dataclass
class ServerConfig:
    """Server configuration settings"""
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False
    workers: int = 1
    log_level: str = "INFO"

@dataclass
class AppConfig:
    """Main application configuration"""
    environment: str = "development"
    database: DatabaseConfig = None
    server: ServerConfig = None
    
    def __post_init__(self):
        if self.database is None:
            self.database = DatabaseConfig()
        if self.server is None:
            self.server = ServerConfig()

class ConfigManager:
    """Configuration management utility"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or self._find_config_file()
        self.config = self._load_config()
    
    def _find_config_file(self) -> Optional[str]:
        """Find configuration file in common locations"""
        locations = [
            "config.yaml",
            "config.yml", 
            "config.json",
            ".config.yaml",
            ".config.json",
            os.path.expanduser("~/.config/myapp/config.yaml")
        ]
        
        for location in locations:
            if os.path.exists(location):
                return location
        return None
    
    def _load_config(self) -> AppConfig:
        """Load configuration from file and environment variables"""
        config = AppConfig()
        
        # Load from file if exists
        if self.config_file:
            config = self._load_from_file(config)
        
        # Override with environment variables
        config = self._load_from_env(config)
        
        return config
    
    def _load_from_file(self, config: AppConfig) -> AppConfig:
        """Load configuration from YAML or JSON file"""
        try:
            with open(self.config_file, 'r') as f:
                if self.config_file.endswith(('.yaml', '.yml')):
                    data = yaml.safe_load(f)
                else:
                    data = json.load(f)
            
            # Update config with file data
            if 'environment' in data:
                config.environment = data['environment']
            
            if 'database' in data:
                for key, value in data['database'].items():
                    if hasattr(config.database, key):
                        setattr(config.database, key, value)
            
            if 'server' in data:
                for key, value in data['server'].items():
                    if hasattr(config.server, key):
                        setattr(config.server, key, value)
                        
        except Exception as e:
            print(f"Warning: Could not load config file {self.config_file}: {e}")
        
        return config
    
    def _load_from_env(self, config: AppConfig) -> AppConfig:
        """Load configuration from environment variables"""
        # Environment variables
        config.environment = os.getenv('ENVIRONMENT', config.environment)
        
        # Database settings
        config.database.host = os.getenv('DB_HOST', config.database.host)
        config.database.port = int(os.getenv('DB_PORT', config.database.port))
        config.database.name = os.getenv('DB_NAME', config.database.name)
        config.database.user = os.getenv('DB_USER', config.database.user)
        config.database.password = os.getenv('DB_PASSWORD', config.database.password)
        
        # Server settings
        config.server.host = os.getenv('HOST', config.server.host)
        config.server.port = int(os.getenv('PORT', config.server.port))
        config.server.debug = os.getenv('DEBUG', 'false').lower() == 'true'
        config.server.workers = int(os.getenv('WORKERS', config.server.workers))
        config.server.log_level = os.getenv('LOG_LEVEL', config.server.log_level)
        
        return config
    
    def get_config(self) -> AppConfig:
        """Get the loaded configuration"""
        return self.config
    
    def get_dict(self) -> Dict[str, Any]:
        """Get configuration as dictionary"""
        return asdict(self.config)
    
    def save_config(self, filename: str):
        """Save current configuration to file"""
        config_dict = self.get_dict()
        
        with open(filename, 'w') as f:
            if filename.endswith(('.yaml', '.yml')):
                yaml.dump(config_dict, f, default_flow_style=False)
            else:
                json.dump(config_dict, f, indent=2)

# Example usage and configuration templates
def create_sample_configs():
    """Create sample configuration files"""
    
    # Development configuration
    dev_config = {
        'environment': 'development',
        'database': {
            'host': 'localhost',
            'port': 5432,
            'name': 'myapp_dev',
            'user': 'dev_user',
            'password': 'dev_password'
        },
        'server': {
            'host': '127.0.0.1',
            'port': 8000,
            'debug': True,
            'workers': 1,
            'log_level': 'DEBUG'
        }
    }
    
    # Production configuration
    prod_config = {
        'environment': 'production',
        'database': {
            'host': 'prod-db.example.com',
            'port': 5432,
            'name': 'myapp_prod',
            'user': 'prod_user',
            'ssl_mode': 'require'
        },
        'server': {
            'host': '0.0.0.0',
            'port': 8080,
            'debug': False,
            'workers': 4,
            'log_level': 'INFO'
        }
    }
    
    # Save sample configs
    with open('config.dev.yaml', 'w') as f:
        yaml.dump(dev_config, f, default_flow_style=False)
    
    with open('config.prod.yaml', 'w') as f:
        yaml.dump(prod_config, f, default_flow_style=False)

# Usage example
if __name__ == "__main__":
    # Initialize configuration manager
    config_manager = ConfigManager()
    config = config_manager.get_config()
    
    print(f"Environment: {config.environment}")
    print(f"Database: {config.database.host}:{config.database.port}/{config.database.name}")
    print(f"Server: {config.server.host}:{config.server.port}")
    
    # Create sample configuration files
    create_sample_configs()
    print("Sample configuration files created: config.dev.yaml, config.prod.yaml")
