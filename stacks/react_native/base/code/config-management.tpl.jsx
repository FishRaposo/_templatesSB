/**
 * File: config-management.tpl.jsx
 * Purpose: Template for unknown implementation
 * Generated for: {{PROJECT_NAME}}
 */

// -----------------------------------------------------------------------------
// FILE: config-management.tpl.jsx
// PURPOSE: Comprehensive configuration management system for React Native projects
// USAGE: Import and adapt for environment-specific settings, feature flags, and runtime configuration
// DEPENDENCIES: React Native (createContext, useContext, useState, useEffect, useCallback)
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

/**
 * React Native Configuration Management Template
 * Purpose: Reusable configuration management for React Native projects
 * Usage: Import and adapt for environment-specific settings
 */

import React Native, { createContext, useContext, useState, useEffect, useCallback } from 'react_native';

/**
 * Configuration context for React Native components
 */
const ConfigContext = createContext();

/**
 * Configuration provider component
 */
export const ConfigProvider = ({ children, initialConfig = {} }) => {
  const [config, setConfig] = useState(initialConfig);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  /**
   * Load configuration from various sources
   */
  const loadConfig = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      // Load environment variables
      const envConfig = loadEnvironmentConfig();
      
      // Load API configuration
      const apiConfig = await loadAPIConfig();
      
      // Load user preferences
      const userConfig = await loadUserConfig();

      // Merge all configurations
      const mergedConfig = {
        ...envConfig,
        ...apiConfig,
        ...userConfig,
        ...initialConfig
      };

      setConfig(mergedConfig);
    } catch (err) {
      setError(err.message);
      console.error('Failed to load configuration:', err);
    } finally {
      setLoading(false);
    }
  }, [initialConfig]);

  /**
   * Update configuration value
   */
  const updateConfig = useCallback((key, value) => {
    setConfig(prev => ({
      ...prev,
      [key]: value
    }));
  }, []);

  /**
   * Get configuration value by path
   */
  const getConfig = useCallback((path, defaultValue = undefined) => {
    const keys = path.split('.');
    let current = config;
    
    for (const key of keys) {
      if (current && typeof current === 'object' && key in current) {
        current = current[key];
      } else {
        return defaultValue;
      }
    }
    
    return current;
  }, [config]);

  /**
   * Set nested configuration value
   */
  const setNestedConfig = useCallback((path, value) => {
    const keys = path.split('.');
    setConfig(prev => {
      const newConfig = { ...prev };
      let current = newConfig;
      
      for (let i = 0; i < keys.length - 1; i++) {
        const key = keys[i];
        if (!current[key] || typeof current[key] !== 'object') {
          current[key] = {};
        }
        current = current[key];
      }
      
      current[keys[keys.length - 1]] = value;
      return newConfig;
    });
  }, []);

  // Load configuration on mount
  useEffect(() => {
    loadConfig();
  }, [loadConfig]);

  const value = {
    config,
    loading,
    error,
    updateConfig,
    getConfig,
    setNestedConfig,
    reloadConfig: loadConfig
  };

  return (
    <ConfigContext.Provider value={value}>
      {children}
    </ConfigContext.Provider>
  );
};

/**
 * Hook to use configuration in components
 */
export const useConfig = () => {
  const context = useContext(ConfigContext);
  if (!context) {
    throw new Error('useConfig must be used within a ConfigProvider');
  }
  return context;
};

/**
 * Load environment-based configuration
 */
function loadEnvironmentConfig() {
  const env = process.env.NODE_ENV || 'development';
  
  const baseConfig = {
    environment: env,
    isDevelopment: env === 'development',
    isProduction: env === 'production',
    isTest: env === 'test'
  };

  const environmentConfigs = {
    development: {
      apiURL: process.env.REACT_APP_DEV_API_URL || 'http://localhost:3001',
      debug: true,
      logLevel: 'debug',
      enableHotReload: true,
      mockData: true
    },
    production: {
      apiURL: process.env.REACT_APP_PROD_API_URL || 'https://api.example.com',
      debug: false,
      logLevel: 'error',
      enableHotReload: false,
      mockData: false
    },
    test: {
      apiURL: process.env.REACT_APP_TEST_API_URL || 'http://localhost:3002',
      debug: true,
      logLevel: 'silent',
      enableHotReload: false,
      mockData: true
    }
  };

  return {
    ...baseConfig,
    ...environmentConfigs[env]
  };
}

/**
 * Load API configuration
 */
async function loadAPIConfig() {
  try {
    // In a real app, this would fetch from your API
    const response = await fetch('/api/config');
    if (!response.ok) {
      throw new Error('Failed to fetch API configuration');
    }
    return await response.json();
  } catch (error) {
    console.warn('Could not load API config, using defaults');
    return {
      features: {
        darkMode: true,
        notifications: true,
        analytics: false
      },
      limits: {
        maxFileSize: 10485760, // 10MB
        maxUploads: 5
      }
    };
  }
}

/**
 * Load user preferences from localStorage
 */
async function loadUserConfig() {
  try {
    const stored = localStorage.getItem('userConfig');
    if (stored) {
      return JSON.parse(stored);
    }
  } catch (error) {
    console.warn('Could not load user config from localStorage');
  }
  
  return {
    theme: 'light',
    language: 'en',
    timezone: 'UTC',
    notifications: {
      email: true,
      push: false,
      sms: false
    }
  };
}

/**
 * Save user preferences to localStorage
 */
export const saveUserConfig = async (config) => {
  try {
    localStorage.setItem('userConfig', JSON.stringify(config));
  } catch (error) {
    console.error('Failed to save user config:', error);
  }
};

/**
 * Configuration validation
 */
export const validateConfig = (config) => {
  const errors = [];
  
  if (!config.apiURL) {
    errors.push('API URL is required');
  }
  
  if (!config.environment) {
    errors.push('Environment is required');
  }
  
  if (config.apiURL && !isValidURL(config.apiURL)) {
    errors.push('API URL is not valid');
  }
  
  return {
    isValid: errors.length === 0,
    errors
  };
};

/**
 * URL validation helper
 */
function isValidURL(string) {
  try {
    new URL(string);
    return true;
  } catch (_) {
    return false;
  }
}

/**
 * Higher-order component for configuration-based rendering
 */
export const withConfig = (Component) => {
  return function ConfiguredComponent(props) {
    const config = useConfig();
    
    if (config.loading) {
      return <div>Loading configuration...</div>;
    }
    
    if (config.error) {
      return <div>Error loading configuration: {config.error}</div>;
    }
    
    return <Component {...props} config={config} />;
  };
};

/**
 * Configuration-aware hooks
 */
export const useFeatureFlag = (featureName) => {
  const { getConfig } = useConfig();
  return getConfig(`features.${featureName}`, false);
};

export const useAPILimit = (limitName) => {
  const { getConfig } = useConfig();
  return getConfig(`limits.${limitName}`, 0);
};

export const useTheme = () => {
  const { config, updateConfig } = useConfig();
  
  const setTheme = useCallback((theme) => {
    updateConfig('theme', theme);
    saveUserConfig({ ...config, theme });
  }, [config, updateConfig]);
  
  return {
    theme: config.theme || 'light',
    setTheme,
    isDarkMode: config.theme === 'dark'
  };
};

/**
 * Configuration management component
 */
export const ConfigManager = () => {
  const { config, updateConfig, reloadConfig } = useConfig();
  const [editing, setEditing] = useState(false);
  const [tempConfig, setTempConfig] = useState(config);

  const handleSave = async () => {
    const validation = validateConfig(tempConfig);
    
    if (!validation.isValid) {
      alert(`Configuration errors: ${validation.errors.join(', ')}`);
      return;
    }

    // Update all config values
    Object.keys(tempConfig).forEach(key => {
      updateConfig(key, tempConfig[key]);
    });

    // Save to localStorage
    await saveUserConfig(tempConfig);
    setEditing(false);
  };

  const handleReset = () => {
    setTempConfig(config);
    setEditing(false);
  };

  const handleReload = async () => {
    await reloadConfig();
    setTempConfig(config);
  };

  if (!editing) {
    return (
      <div className="config-manager">
        <h3>Configuration</h3>
        <div className="config-display">
          <pre>{JSON.stringify(config, null, 2)}</pre>
        </div>
        <div className="config-actions">
          <button onClick={() => setEditing(true)}>Edit</button>
          <button onClick={handleReload}>Reload</button>
        </div>
      </div>
    );
  }

  return (
    <div className="config-manager">
      <h3>Edit Configuration</h3>
      <div className="config-editor">
        <textarea
          value={JSON.stringify(tempConfig, null, 2)}
          onChange={(e) => setTempConfig(JSON.parse(e.target.value))}
          rows={20}
          cols={80}
        />
      </div>
      <div className="config-actions">
        <button onClick={handleSave}>Save</button>
        <button onClick={handleReset}>Cancel</button>
      </div>
    </div>
  );
};

/**
 * Environment-specific component rendering
 */
export const EnvironmentRenderer = ({ children, development, production, test }) => {
  const { getConfig } = useConfig();
  const environment = getConfig('environment');

  switch (environment) {
    case 'development':
      return development || children;
    case 'production':
      return production || children;
    case 'test':
      return test || children;
    default:
      return children;
  }
};

/**
 * Configuration provider setup example
 */
export const setupConfig = (App) => {
  return () => (
    <ConfigProvider>
      <App />
    </ConfigProvider>
  );
};

// Example usage component
export const ExampleComponent = () => {
  const { config, getConfig, updateConfig } = useConfig();
  const darkModeEnabled = useFeatureFlag('darkMode');
  const maxFileSize = useAPILimit('maxFileSize');
  const { theme, setTheme } = useTheme();

  return (
    <div className={`example-component theme-${theme}`}>
      <h2>Configuration Example</h2>
      <p>Environment: {config.environment}</p>
      <p>API URL: {config.apiURL}</p>
      <p>Dark Mode: {darkModeEnabled ? 'Enabled' : 'Disabled'}</p>
      <p>Max File Size: {maxFileSize} bytes</p>
      
      <div className="theme-switcher">
        <button onClick={() => setTheme('light')}>Light Theme</button>
        <button onClick={() => setTheme('dark')}>Dark Theme</button>
      </div>
      
      <ConfigManager />
    </div>
  );
};

export default {
  ConfigProvider,
  useConfig,
  withConfig,
  useFeatureFlag,
  useAPILimit,
  useTheme,
  ConfigManager,
  EnvironmentRenderer,
  setupConfig,
  validateConfig,
  saveUserConfig
};
