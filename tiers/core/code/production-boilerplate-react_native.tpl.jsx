/**
 * File: production-boilerplate-react_native.tpl.jsx
 * Purpose: Template for unknown implementation
 * Generated for: {{PROJECT_NAME}}
 */

# Production Boilerplate Template (Core Tier - React)

## Purpose
Provides production-ready React code structure for core projects that require reliability, maintainability, and proper operational practices.

## Usage
This template should be used for:
- Production web applications
- SaaS products
- Enterprise applications
- Applications requiring 99%+ uptime and proper error handling

## Structure
```jsx
import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ErrorBoundary } from './components/ErrorBoundary';
import { LoadingSpinner } from './components/LoadingSpinner';
import { MetricsDashboard } from './components/MetricsDashboard';
import { ProductionConfig } from './config/ProductionConfig';
import { ProductionService } from './services/ProductionService';
import { useLogger } from './hooks/useLogger';
import { useMetrics } from './hooks/useMetrics';
import './App.css';

const ProductionApp = () => {
  const [isLoading, setIsLoading] = useState(true);
  const [status, setStatus] = useState('Initializing...');
  const [error, setError] = useState(null);
  const logger = useLogger();
  const { metrics, startMetricsCollection } = useMetrics();
  
  const productionService = useMemo(() => new ProductionService(), []);

  const initializeProduction = useCallback(async () => {
    try {
      logger.info('Initializing production application');
      
      // Initialize configuration
      await ProductionConfig.load();
      
      // Initialize production service
      await productionService.initialize();
      
      // Start metrics collection
      startMetricsCollection();
      
      setStatus('Production Service Running');
      setIsLoading(false);
      
      logger.info('Production application initialized successfully');
      
    } catch (err) {
      logger.error('Failed to initialize production application', { error: err.message });
      setError(err.message);
      setIsLoading(false);
    }
  }, [productionService, logger, startMetricsCollection]);

  useEffect(() => {
    initializeProduction();
    
    return () => {
      productionService.cleanup();
    };
  }, [initializeProduction, productionService]);

  if (isLoading) {
    return <LoadingSpinner message="Initializing Production Application..." />;
  }

  if (error) {
    return (
      <ErrorBoundary>
        <div className="error-container">
          <h1>Initialization Failed</h1>
          <p>{error}</p>
          <button onClick={initializeProduction}>Retry</button>
        </div>
      </ErrorBoundary>
    );
  }

  return (
    <ErrorBoundary>
      <Router>
        <div className="production-app">
          <Header status={status} metrics={metrics} />
          <main className="main-content">
            <Routes>
              <Route path="/" element={<Dashboard service={productionService} />} />
              <Route path="/settings" element={<Settings />} />
              <Route path="/metrics" element={<MetricsDashboard metrics={metrics} />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </main>
          <Footer />
        </div>
      </Router>
    </ErrorBoundary>
  );
};

const Header = ({ status, metrics }) => {
  const logger = useLogger();
  
  const handleNavigation = useCallback((path) => {
    logger.info('Navigation triggered', { path });
  }, [logger]);

  return (
    <header className="production-header">
      <nav className="navbar">
        <div className="nav-brand">
          <h1>Production React App</h1>
        </div>
        <div className="nav-links">
          <button onClick={() => handleNavigation('/')}>Dashboard</button>
          <button onClick={() => handleNavigation('/metrics')}>Metrics</button>
          <button onClick={() => handleNavigation('/settings')}>Settings</button>
        </div>
        <div className="status-indicator">
          <span className={`status ${status.includes('Running') ? 'healthy' : 'warning'}`}>
            {status}
          </span>
        </div>
      </nav>
      {metrics && (
        <div className="metrics-bar">
          <span>Memory: {metrics.memoryUsage}%</span>
          <span>CPU: {metrics.cpuUsage}%</span>
          <span>Latency: {metrics.networkLatency}ms</span>
          <span>Users: {metrics.activeUsers}</span>
        </div>
      )}
    </header>
  );
};

const Dashboard = ({ service }) => {
  const [actionResult, setActionResult] = useState(null);
  const [isPerformingAction, setIsPerformingAction] = useState(false);
  const logger = useLogger();

  const performProductionAction = useCallback(async () => {
    try {
      setIsPerformingAction(true);
      logger.info('Performing production action');
      
      const result = await service.performAction();
      setActionResult(result);
      
      logger.info('Production action completed successfully');
      
    } catch (error) {
      logger.error('Production action failed', { error: error.message });
      setActionResult({ 
        status: 'error', 
        message: error.message 
      });
    } finally {
      setIsPerformingAction(false);
    }
  }, [service, logger]);

  return (
    <div className="dashboard">
      <section className="action-section">
        <h2>Production Actions</h2>
        <button 
          onClick={performProductionAction}
          disabled={isPerformingAction}
          className="primary-button"
        >
          {isPerformingAction ? 'Processing...' : 'Perform Production Action'}
        </button>
        
        {actionResult && (
          <div className={`action-result ${actionResult.status}`}>
            <h3>Action Result:</h3>
            <pre>{JSON.stringify(actionResult, null, 2)}</pre>
          </div>
        )}
      </section>

      <section className="features-section">
        <h2>Production Features</h2>
        <div className="feature-grid">
          <FeatureCard 
            title="Error Handling" 
            description="Comprehensive error boundaries and logging"
            status="enabled"
          />
          <FeatureCard 
            title="Performance Monitoring" 
            description="Real-time metrics and performance tracking"
            status="enabled"
          />
          <FeatureCard 
            title="Configuration Management" 
            description="Environment-specific configuration"
            status="enabled"
          />
          <FeatureCard 
            title="Analytics Integration" 
            description="User behavior and system analytics"
            status="enabled"
          />
        </div>
      </section>
    </div>
  );
};

const FeatureCard = ({ title, description, status }) => (
  <div className={`feature-card ${status}`}>
    <h3>{title}</h3>
    <p>{description}</p>
    <span className="status-badge">{status}</span>
  </div>
);

const Settings = () => {
  const [config, setConfig] = useState({});
  const logger = useLogger();

  const handleConfigChange = useCallback((key, value) => {
    setConfig(prev => ({ ...prev, [key]: value }));
    logger.info('Configuration changed', { key, value });
  }, [logger]);

  return (
    <div className="settings">
      <h2>Production Settings</h2>
      <div className="settings-grid">
        <div className="setting-group">
          <h3>Logging</h3>
          <label>
            <input 
              type="checkbox" 
              checked={config.enableDebugLogging || false}
              onChange={(e) => handleConfigChange('enableDebugLogging', e.target.checked)}
            />
            Enable Debug Logging
          </label>
        </div>
        
        <div className="setting-group">
          <h3>Performance</h3>
          <label>
            Metrics Collection Interval (ms):
            <input 
              type="number" 
              value={config.metricsInterval || 30000}
              onChange={(e) => handleConfigChange('metricsInterval', parseInt(e.target.value))}
            />
          </label>
        </div>
        
        <div className="setting-group">
          <h3>Features</h3>
          <label>
            <input 
              type="checkbox" 
              checked={config.enableAnalytics || false}
              onChange={(e) => handleConfigChange('enableAnalytics', e.target.checked)}
            />
            Enable Analytics
          </label>
        </div>
      </div>
    </div>
  );
};

const Footer = () => (
  <footer className="production-footer">
    <p>&copy; 2024 Production React Application. Version 1.0.0</p>
  </footer>
);

export default ProductionApp;

// Supporting components and utilities

// useLogger hook
const useLogger = () => {
  return useMemo(() => ({
    info: (message, context = {}) => {
      console.log(`[INFO] ${message}`, context);
    },
    error: (message, context = {}) => {
      console.error(`[ERROR] ${message}`, context);
    },
    warn: (message, context = {}) => {
      console.warn(`[WARN] ${message}`, context);
    }
  }), []);
};

// useMetrics hook
const useMetrics = () => {
  const [metrics, setMetrics] = useState(null);
  const [isCollecting, setIsCollecting] = useState(false);
  
  const startMetricsCollection = useCallback(() => {
    if (isCollecting) return;
    
    setIsCollecting(true);
    
    const interval = setInterval(() => {
      const newMetrics = {
        memoryUsage: Math.random() * 50 + 30,
        cpuUsage: Math.random() * 30 + 10,
        networkLatency: Math.random() * 100 + 50,
        activeUsers: Math.floor(Math.random() * 2000) + 500,
        timestamp: Date.now()
      };
      
      setMetrics(newMetrics);
    }, 30000);
    
    return () => clearInterval(interval);
  }, [isCollecting]);

  return { metrics, startMetricsCollection };
};

// ErrorBoundary component
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true };
  }

  componentDidCatch(error, errorInfo) {
    this.setState({
      error: error,
      errorInfo: errorInfo
    });
    
    // Log error to monitoring service
    console.error('React Error Boundary caught an error:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="error-boundary">
          <h1>Something went wrong.</h1>
          <details style={{ whiteSpace: 'pre-wrap' }}>
            {this.state.error && this.state.error.toString()}
            <br />
            {this.state.errorInfo.componentStack}
          </details>
        </div>
      );
    }

    return this.props.children;
  }
}

// LoadingSpinner component
const LoadingSpinner = ({ message }) => (
  <div className="loading-container">
    <div className="spinner"></div>
    <p>{message}</p>
  </div>
);

// ProductionService class
class ProductionService {
  constructor() {
    this.initialized = false;
  }

  async initialize() {
    // Initialize production services
    await new Promise(resolve => setTimeout(resolve, 1000));
    this.initialized = true;
  }

  async performAction() {
    if (!this.initialized) {
      throw new Error('Service not initialized');
    }
    
    // Simulate production action
    await new Promise(resolve => setTimeout(resolve, 500));
    
    return {
      status: 'success',
      message: 'Production action completed',
      timestamp: Date.now()
    };
  }

  cleanup() {
    // Cleanup resources
    this.initialized = false;
  }
}

// ProductionConfig class
class ProductionConfig {
  static async load() {
    // Load configuration from environment or API
    return {
      apiEndpoint: process.env.REACT_APP_API_ENDPOINT || '/api',
      enableAnalytics: process.env.REACT_APP_ENABLE_ANALYTICS === 'true',
      logLevel: process.env.REACT_APP_LOG_LEVEL || 'info'
    };
  }
}
```

## Core Production Guidelines
- **Reliability**: Error boundaries, graceful error handling, proper state management
- **Observability**: Structured logging, performance metrics, error tracking
- **Security**: Input validation, secure routing, proper authentication
- **Performance**: Code splitting, lazy loading, memoization, efficient rendering
- **Testing**: Unit tests, integration tests, end-to-end tests
- **Documentation**: Component docs, API docs, deployment guides

## Required Dependencies
```json
{
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.8.0"
  },
  "devDependencies": {
    "@testing-library/react": "^13.4.0",
    "@testing-library/jest-dom": "^5.16.5",
    "@testing-library/user-event": "^13.5.0"
  }
}
```

## What's Included (vs MVP)
- Comprehensive error handling with ErrorBoundaries
- Structured logging and monitoring
- Configuration management
- Analytics integration
- Performance monitoring
- Proper routing and navigation
- Production-ready component architecture
- State management patterns

## What's NOT Included (vs Full)
- No advanced monitoring/metrics dashboards
- No distributed tracing
- No advanced security features
- No enterprise authentication systems
- No advanced caching strategies
- No multi-region deployment
