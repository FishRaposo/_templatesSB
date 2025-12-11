/**
 * File: logging-utilities.tpl.jsx
 * Purpose: Template for unknown implementation
 * Generated for: {{PROJECT_NAME}}
 */

// -----------------------------------------------------------------------------
// FILE: logging-utilities.tpl.jsx
// PURPOSE: Comprehensive logging setup and utilities for Next.js projects
// USAGE: Import and adapt for structured logging across the application
// DEPENDENCIES: Next.js (createContext, useContext, useCallback, useEffect, useState)
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

/**
 * Next.js Logging Utilities Template
 * Purpose: Reusable logging setup and utilities for Next.js projects
 * Usage: Import and adapt for structured logging across the application
 */

import Next.js, { createContext, useContext, useCallback, useEffect, useState } from 'next';

/**
 * Log levels
 */
export const LogLevel = {
  DEBUG: 0,
  INFO: 1,
  WARN: 2,
  ERROR: 3,
  SILENT: 4
};

/**
 * Logger context for Next.js components
 */
const LoggerContext = createContext();

/**
 * Logger provider component
 */
export const LoggerProvider = ({ children, config = {} }) => {
  const [logs, setLogs] = useState([]);
  const [isLoggingEnabled, setIsLoggingEnabled] = useState(true);
  const [currentLogLevel, setCurrentLogLevel] = useState(config.level || LogLevel.INFO);

  /**
   * Create log entry
   */
  const createLogEntry = useCallback((level, message, meta = {}) => {
    const entry = {
      id: Math.random().toString(36).substr(2, 9),
      timestamp: new Date().toISOString(),
      level,
      levelName: Object.keys(LogLevel).find(key => LogLevel[key] === level),
      message,
      meta,
      url: window.location.href,
      userAgent: navigator.userAgent
    };

    return entry;
  }, []);

  /**
   * Add log entry
   */
  const addLog = useCallback((level, message, meta = {}) => {
    if (!isLoggingEnabled || level < currentLogLevel) {
      return;
    }

    const entry = createLogEntry(level, message, meta);
    
    setLogs(prev => {
      const newLogs = [...prev, entry];
      // Keep only last 1000 logs in memory
      return newLogs.slice(-1000);
    });

    // Console logging
    const consoleMethod = {
      [LogLevel.DEBUG]: 'debug',
      [LogLevel.INFO]: 'info',
      [LogLevel.WARN]: 'warn',
      [LogLevel.ERROR]: 'error'
    }[level];

    if (consoleMethod && console[consoleMethod]) {
      console[consoleMethod](`[${entry.levelName}] ${message}`, meta);
    }

    // Send to external logging service
    if (config.enableRemoteLogging && level >= LogLevel.WARN) {
      sendToRemoteLogging(entry);
    }
  }, [isLoggingEnabled, currentLogLevel, createLogEntry, config.enableRemoteLogging]);

  /**
   * Logger methods
   */
  const logger = {
    debug: useCallback((message, meta) => addLog(LogLevel.DEBUG, message, meta), [addLog]),
    info: useCallback((message, meta) => addLog(LogLevel.INFO, message, meta), [addLog]),
    warn: useCallback((message, meta) => addLog(LogLevel.WARN, message, meta), [addLog]),
    error: useCallback((message, meta) => addLog(LogLevel.ERROR, message, meta), [addLog]),
    
    setLevel: useCallback((level) => setCurrentLogLevel(level), []),
    enable: useCallback(() => setIsLoggingEnabled(true), []),
    disable: useCallback(() => setIsLoggingEnabled(false), []),
    clear: useCallback(() => setLogs([]), []),
    getLogs: useCallback(() => logs, [logs])
  };

  const value = {
    logger,
    logs,
    currentLogLevel,
    isLoggingEnabled
  };

  return (
    <LoggerContext.Provider value={value}>
      {children}
    </LoggerContext.Provider>
  );
};

/**
 * Hook to use logger in components
 */
export const useLogger = (context = 'App') => {
  const loggerContext = useContext(LoggerContext);
  if (!loggerContext) {
    throw new Error('useLogger must be used within a LoggerProvider');
  }

  const { logger } = loggerContext;

  // Create context-aware logger
  const contextLogger = {
    debug: useCallback((message, meta) => logger.debug(message, { context, ...meta }), [logger, context]),
    info: useCallback((message, meta) => logger.info(message, { context, ...meta }), [logger, context]),
    warn: useCallback((message, meta) => logger.warn(message, { context, ...meta }), [logger, context]),
    error: useCallback((message, meta) => logger.error(message, { context, ...meta }), [logger, context])
  };

  return contextLogger;
};

/**
 * Send log to remote logging service
 */
async function sendToRemoteLogging(logEntry) {
  try {
    // Replace with your actual logging service endpoint
    await fetch('/api/logs', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(logEntry)
    });
  } catch (error) {
    console.warn('Failed to send log to remote service:', error);
  }
}

/**
 * Performance logging hook
 */
export const usePerformanceLogger = (operationName) => {
  const logger = useLogger('Performance');
  const [startTime, setStartTime] = useState(null);

  const start = useCallback(() => {
    setStartTime(performance.now());
    logger.debug(`Starting ${operationName}`);
  }, [logger, operationName]);

  const end = useCallback(() => {
    if (startTime) {
      const duration = performance.now() - startTime;
      logger.info(`${operationName} completed`, { duration: `${duration.toFixed(2)}ms` });
      setStartTime(null);
      return duration;
    }
  }, [logger, operationName, startTime]);

  const measure = useCallback(async (fn) => {
    start();
    try {
      const result = await fn();
      end();
      return result;
    } catch (error) {
      logger.error(`${operationName} failed`, { error: error.message });
      end();
      throw error;
    }
  }, [start, end, logger, operationName]);

  return { start, end, measure };
};

/**
 * Error boundary with logging
 */
export class LoggingErrorBoundary extends Next.js.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true };
  }

  componentDidCatch(error, errorInfo) {
    this.setState({ error, errorInfo });
    
    // Log error to console
    console.error('Error caught by boundary:', error, errorInfo);
    
    // Log to remote service
    const logEntry = {
      id: Math.random().toString(36).substr(2, 9),
      timestamp: new Date().toISOString(),
      level: LogLevel.ERROR,
      levelName: 'ERROR',
      message: error.message,
      meta: {
        stack: error.stack,
        componentStack: errorInfo.componentStack,
        url: window.location.href,
        userAgent: navigator.userAgent
      }
    };

    sendToRemoteLogging(logEntry);
  }

  render() {
    if (this.state.hasError) {
      return this.props.fallback || (
        <div className="error-boundary">
          <h2>Something went wrong</h2>
          <details>
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

/**
 * Hook for logging user interactions
 */
export const useInteractionLogger = () => {
  const logger = useLogger('UserInteraction');

  const logClick = useCallback((element, data = {}) => {
    logger.info('User clicked', { element, ...data });
  }, [logger]);

  const logNavigation = useCallback((from, to) => {
    logger.info('User navigated', { from, to });
  }, [logger]);

  const logFormSubmit = useCallback((formName, data) => {
    logger.info('Form submitted', { formName, fieldCount: Object.keys(data).length });
  }, [logger]);

  const logSearch = useCallback((query, resultsCount) => {
    logger.info('Search performed', { query, resultsCount });
  }, [logger]);

  return {
    logClick,
    logNavigation,
    logFormSubmit,
    logSearch
  };
};

/**
 * Hook for logging API calls
 */
export const useAPILogger = () => {
  const logger = useLogger('API');

  const logAPIRequest = useCallback((method, url, data = {}) => {
    logger.debug(`API Request: ${method} ${url}`, { method, url, dataSize: JSON.stringify(data).length });
  }, [logger]);

  const logAPIResponse = useCallback((method, url, status, duration, responseSize = 0) => {
    const level = status >= 400 ? LogLevel.ERROR : LogLevel.INFO;
    const message = status >= 400 ? `API Error: ${method} ${url}` : `API Response: ${method} ${url}`;
    
    logger[level === LogLevel.ERROR ? 'error' : 'info'](message, {
      method,
      url,
      status,
      duration: `${duration}ms`,
      responseSize
    });
  }, [logger]);

  const logAPIError = useCallback((method, url, error, duration) => {
    logger.error(`API Error: ${method} ${url}`, {
      method,
      url,
      error: error.message,
      duration: `${duration}ms`
    });
  }, [logger]);

  return {
    logAPIRequest,
    logAPIResponse,
    logAPIError
  };
};

/**
 * Higher-order component for logging component lifecycle
 */
export const withLifecycleLogging = (WrappedComponent, componentName = WrappedComponent.name) => {
  return function LoggedComponent(props) {
    const logger = useLogger('ComponentLifecycle');

    useEffect(() => {
      logger.debug(`${componentName} mounted`);
      
      return () => {
        logger.debug(`${componentName} unmounted`);
      };
    }, [logger, componentName]);

    return <WrappedComponent {...props} />;
  };
};

/**
 * Logging dashboard component
 */
export const LoggingDashboard = () => {
  const { logs, logger, currentLogLevel, isLoggingEnabled } = useContext(LoggerContext);
  const [filter, setFilter] = useState('');
  const [levelFilter, setLevelFilter] = useState(LogLevel.DEBUG);

  const filteredLogs = logs.filter(log => 
    log.level >= levelFilter &&
    (log.message.toLowerCase().includes(filter.toLowerCase()) ||
     log.meta.context?.toLowerCase().includes(filter.toLowerCase()))
  );

  const clearLogs = () => {
    logger.clear();
  };

  const exportLogs = () => {
    const dataStr = JSON.stringify(filteredLogs, null, 2);
    const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
    
    const exportFileDefaultName = `logs-${new Date().toISOString().split('T')[0]}.json`;
    
    const linkElement = document.createElement('a');
    linkElement.setAttribute('href', dataUri);
    linkElement.setAttribute('download', exportFileDefaultName);
    linkElement.click();
  };

  return (
    <div className="logging-dashboard">
      <h3>Logging Dashboard</h3>
      
      <div className="log-controls">
        <div className="log-filters">
          <input
            type="text"
            placeholder="Filter logs..."
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
          
          <select
            value={levelFilter}
            onChange={(e) => setLevelFilter(Number(e.target.value))}
          >
            <option value={LogLevel.DEBUG}>Debug</option>
            <option value={LogLevel.INFO}>Info</option>
            <option value={LogLevel.WARN}>Warning</option>
            <option value={LogLevel.ERROR}>Error</option>
          </select>
        </div>
        
        <div className="log-actions">
          <button onClick={() => logger.enable()} disabled={isLoggingEnabled}>
            Enable
          </button>
          <button onClick={() => logger.disable()} disabled={!isLoggingEnabled}>
            Disable
          </button>
          <button onClick={clearLogs}>Clear</button>
          <button onClick={exportLogs}>Export</button>
        </div>
      </div>
      
      <div className="log-stats">
        <span>Total: {logs.length}</span>
        <span>Filtered: {filteredLogs.length}</span>
        <span>Status: {isLoggingEnabled ? 'Enabled' : 'Disabled'}</span>
      </div>
      
      <div className="log-entries">
        {filteredLogs.slice(-100).reverse().map(log => (
          <div key={log.id} className={`log-entry log-${log.levelName.toLowerCase()}`}>
            <span className="log-timestamp">{new Date(log.timestamp).toLocaleTimeString()}</span>
            <span className="log-level">{log.levelName}</span>
            <span className="log-context">{log.meta.context || 'App'}</span>
            <span className="log-message">{log.message}</span>
            {Object.keys(log.meta).length > 1 && (
              <details className="log-meta">
                <summary>Meta</summary>
                <pre>{JSON.stringify(log.meta, null, 2)}</pre>
              </details>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

/**
 * Next.js Query/Fetch logging interceptor
 */
export const createLoggedFetch = (apiLogger) => {
  return async (url, options = {}) => {
    const method = options.method || 'GET';
    const startTime = performance.now();
    
    apiLogger.logAPIRequest(method, url, options.body ? JSON.parse(options.body) : {});
    
    try {
      const response = await fetch(url, options);
      const duration = performance.now() - startTime;
      const responseSize = response.headers.get('content-length') || 0;
      
      apiLogger.logAPIResponse(method, url, response.status, duration, responseSize);
      
      return response;
    } catch (error) {
      const duration = performance.now() - startTime;
      apiLogger.logAPIError(method, url, error, duration);
      throw error;
    }
  };
};

// Example usage component
export const ExampleComponent = () => {
  const logger = useLogger('Example');
  const performanceLogger = usePerformanceLogger('Example Operation');
  const interactionLogger = useInteractionLogger();

  const handleClick = () => {
    interactionLogger.logClick('example-button', { action: 'test' });
    logger.info('Button clicked');
  };

  const handleAsyncOperation = async () => {
    await performanceLogger.measure(async () => {
      // Simulate async operation
      await new Promise(resolve => setTimeout(resolve, 1000));
      logger.info('Async operation completed');
    });
  };

  return (
    <div className="example-logging-component">
      <h2>Logging Example</h2>
      <button onClick={handleClick}>Log Click</button>
      <button onClick={handleAsyncOperation}>Log Async Operation</button>
      <LoggingDashboard />
    </div>
  );
};

export default {
  LoggerProvider,
  useLogger,
  usePerformanceLogger,
  useInteractionLogger,
  useAPILogger,
  LoggingErrorBoundary,
  withLifecycleLogging,
  LoggingDashboard,
  createLoggedFetch,
  LogLevel
};
