<!--
File: config-management-pattern.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# ----------------------------------------------------------------------------- 
# FILE: config-management-pattern.tpl.md
# PURPOSE: Generic configuration management design pattern
# USAGE: Adapt this pattern for your specific technology stack
# AUTHOR: [[.Author]]
# VERSION: [[.Version]]
# SINCE: [[.Version]]
# -----------------------------------------------------------------------------

# Configuration Management Pattern

## Overview
Configuration management is essential for separating application settings from code, enabling different environments, and managing application behavior without code changes.

## Core Design Pattern

### 1. Configuration Hierarchy
```
Default Values → Environment Variables → Config Files → Runtime Overrides
```

**Priority Order** (highest to lowest):
1. Runtime/Command-line arguments
2. Environment variables  
3. Configuration files (JSON/YAML/INI)
4. Default hardcoded values

### 2. Configuration Categories

#### Application Settings
- Environment (development/staging/production)
- Debug mode
- Log level
- Application name/version

#### Database Configuration  
- Connection string/URL
- Pool settings
- Timeout values
- SSL settings

#### Server Configuration
- Host/port binding
- Worker processes
- CORS settings
- Rate limiting

#### External Services
- API keys and tokens
- Third-party URLs
- Service credentials
- Feature flags

### 3. Pseudocode Implementation

```pseudocode
class ConfigManager:
    function __init__(config_file=None):
        self.config = self.load_defaults()
        self.config = self.merge_config_file(config_file)
        self.config = self.merge_environment_variables()
        self.config = self.validate_config()
    
    function load_defaults():
        return {
            "app": {
                "name": "myapp",
                "environment": "development", 
                "debug": false,
                "log_level": "INFO"
            },
            "database": {
                "host": "localhost",
                "port": 5432,
                "name": "myapp",
                "ssl": false
            },
            "server": {
                "host": "0.0.0.0",
                "port": 8000,
                "workers": 1
            }
        }
    
    function merge_config_file(file_path):
        if file_exists(file_path):
            file_config = parse_file(file_path)  # JSON/YAML/INI
            return deep_merge(self.config, file_config)
        return self.config
    
    function merge_environment_variables():
        # Map environment variables to config keys
        env_mappings = {
            "APP_ENV": "app.environment",
            "DEBUG": "app.debug", 
            "DB_HOST": "database.host",
            "DB_PORT": "database.port",
            "SERVER_PORT": "server.port"
        }
        
        for env_var, config_path in env_mappings:
            if environment_exists(env_var):
                value = get_environment(env_var)
                self.set_nested_value(config_path, value)
        
        return self.config
    
    function validate_config():
        # Validate required fields, data types, ranges
        assert self.config.database.port > 0
        assert self.config.server.workers > 0
        assert self.config.app.log_level in valid_log_levels
        return self.config
    
    function get(key_path, default=None):
        return self.get_nested_value(key_path, default)
    
    function set(key_path, value):
        self.set_nested_value(key_path, value)
```

### 4. Configuration File Formats

#### YAML Example
```yaml
app:
  environment: production
  debug: false
  log_level: INFO

database:
  host: prod-db.example.com
  port: 5432
  name: myapp_prod
  ssl: true
  pool_size: 20

server:
  host: 0.0.0.0
  port: 8080
  workers: 4
```

#### JSON Example
```json
{
  "app": {
    "environment": "production",
    "debug": false,
    "log_level": "INFO"
  },
  "database": {
    "host": "prod-db.example.com",
    "port": 5432,
    "name": "myapp_prod"
  }
}
```

## Technology-Specific Implementations

### Node.js (JavaScript/TypeScript)
```javascript
class ConfigManager {
  constructor(configFile) {
    this.config = this.loadDefaults();
    this.config = this.mergeConfigFile(configFile);
    this.config = this.mergeEnvironmentVariables();
    this.validate();
  }
  
  loadDefaults() {
    return {
      app: { environment: 'development', debug: false },
      database: { host: 'localhost', port: 5432 }
    };
  }
  
  mergeEnvironmentVariables() {
    return {
      ...this.config,
      app: {
        ...this.config.app,
        environment: process.env.NODE_ENV || this.config.app.environment,
        debug: process.env.DEBUG === 'true'
      },
      database: {
        ...this.config.database,
        host: process.env.DB_HOST || this.config.database.host,
        port: parseInt(process.env.DB_PORT) || this.config.database.port
      }
    };
  }
}

// Usage
const config = new ConfigManager('./config.yaml');
console.log(config.get('database.host'));
```

### Python
```python
import os
import yaml
from typing import Dict, Any

class ConfigManager:
    def __init__(self, config_file: str = None):
        self.config = self._load_defaults()
        self.config = self._merge_config_file(config_file)
        self.config = self._merge_environment_variables()
        self._validate()
    
    def _load_defaults(self) -> Dict[str, Any]:
        return {
            'app': {'environment': 'development', 'debug': False},
            'database': {'host': 'localhost', 'port': 5432}
        }
    
    def _merge_environment_variables(self) -> Dict[str, Any]:
        self.config['app']['environment'] = os.getenv('APP_ENV', self.config['app']['environment'])
        self.config['app']['debug'] = os.getenv('DEBUG', 'false').lower() == 'true'
        self.config['database']['host'] = os.getenv('DB_HOST', self.config['database']['host'])
        self.config['database']['port'] = int(os.getenv('DB_PORT', str(self.config['database']['port'])))
        return self.config

# Usage
config = ConfigManager('./config.yaml')
print(config['database']['host'])
```

### Go
```go
type Config struct {
    App struct {
        Environment string `yaml:"environment"`
        Debug       bool   `yaml:"debug"`
    } `yaml:"app"`
    Database struct {
        Host string `yaml:"host"`
        Port int    `yaml:"port"`
    } `yaml:"database"`
}

func LoadConfig(configFile string) (*Config, error) {
    config := &Config{}
    
    // Load defaults
    config.App.Environment = "development"
    config.Database.Host = "localhost"
    config.Database.Port = 5432
    
    // Load from file if exists
    if configFile != "" {
        data, err := ioutil.ReadFile(configFile)
        if err == nil {
            yaml.Unmarshal(data, config)
        }
    }
    
    // Override with environment variables
    if env := os.Getenv("APP_ENV"); env != "" {
        config.App.Environment = env
    }
    if env := os.Getenv("DB_HOST"); env != "" {
        config.Database.Host = env
    }
    
    return config, nil
}
```

## Best Practices

### 1. Security
- Never commit secrets to version control
- Use environment variables for sensitive data
- Implement encryption for stored secrets
- Rotate credentials regularly

### 2. Validation
- Validate all configuration values
- Provide clear error messages for invalid config
- Use schema validation for config files
- Set sensible defaults

### 3. Environment Management
- Separate configs per environment
- Use naming conventions for environment variables
- Document all configuration options
- Implement configuration hot-reloading if needed

### 4. Testing
- Test with different configuration scenarios
- Mock environment variables in tests
- Validate configuration loading in CI/CD
- Test default values and edge cases

## Adaptation Checklist

- [ ] Choose appropriate configuration file format for your stack
- [ ] Implement configuration class/struct for your language
- [ ] Set up environment variable mappings
- [ ] Add configuration validation
- [ ] Create sample configuration files
- [ ] Document all configuration options
- [ ] Test configuration loading in different environments
- [ ] Set up secret management for production

## Common Pitfalls

1. **Hardcoding values** - Always use configuration for changeable values
2. **Missing validation** - Invalid config can cause runtime errors
3. **Secrets in config files** - Use environment variables for sensitive data
4. **No defaults** - Provide sensible defaults for all options
5. **Complex nesting** - Keep configuration structure simple and flat

---

*Generic Configuration Management Pattern - Adapt to your technology stack*
