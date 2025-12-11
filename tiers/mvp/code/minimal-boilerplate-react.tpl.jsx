/**
 * Template: minimal-boilerplate-react.tpl.jsx
 * Purpose: minimal-boilerplate-react template
 * Stack: react
 * Tier: base
 */

# Universal Template System - Unknown Stack
# Generated: 2025-12-10
# Purpose: unknown template utilities
# Tier: mvp
# Stack: unknown
# Category: utilities

# Minimal Boilerplate Template (MVP Tier - React)

## Purpose
Provides the absolute minimum React code structure for MVP projects following the minimal viable product approach.

## Usage
This template should be used for:
- Prototype web applications
- Proof of concepts
- Early-stage startup web apps
- Internal tools with limited scope

## Structure
```jsx
// [[.ProjectName]] - MVP React Application
// Author: [[.Author]]
// Version: [[.Version]]

import React, { useState, useEffect } from 'react';
import './App.css';

/**
 * MVP Application Component
 * 
 * A minimal React component demonstrating MVP approach with:
 * - Basic state management using useState
 * - Lifecycle management with useEffect
 * - Simple user interaction handling
 * - No external dependencies beyond React core
 * 
 * @component
 * @returns {JSX.Element} The rendered MVP application
 */
function MVPApp() {
  // State management for application status
  const [status, setStatus] = useState('MVP Application Starting...');
  
  // Loading state to show/hide loading indicator
  const [loading, setLoading] = useState(true);

  /**
   * Initialize core functionality when component mounts
   * 
   * MVP approach: Simulated initialization with basic error handling.
   * In production, this would include:
   * - API client initialization
   * - Basic configuration loading
   * - Essential service setup
   * No advanced features like caching, retry logic, or analytics.
   */
  useEffect(() => {
    // Initialize core functionality only
    // No advanced configuration, no optional features
    const initializeCore = async () => {
      try {
        // Only essential initialization
        // Simulate async operation (API call, config load, etc.)
        await new Promise(resolve => setTimeout(resolve, 1000));
        setStatus('MVP Service Running');
      } catch (error) {
        setStatus('MVP Service Error');
        console.error('Initialization failed:', error);
        // MVP: Basic error handling, no retry or fallback mechanisms
      } finally {
        setLoading(false);
      }
    };

    initializeCore();
  }, []); // Empty dependency array = run once on mount

  /**
   * Handles basic user action
   * 
   * MVP approach: Simple alert and console log.
   * In production, this would contain core business logic:
   * - API calls
   * - State updates
   * - Navigation logic
   * No advanced features like loading states or error boundaries.
   */
  const performBasicAction = () => {
    // Basic functionality
    alert('MVP Action Performed');
    console.log('Basic action triggered');
    
    // MVP: Simple user feedback, no sophisticated notification system
  };

  if (loading) {
    return (
      <div className="App">
        <header className="App-header">
          <h1>Loading MVP Application...</h1>
        </header>
      </div>
    );
  }

  return (
    <div className="App">
      <header className="App-header">
        <h1>MVP React Application</h1>
        <p>{status}</p>
        <div className="action-section">
          <button 
            onClick={performBasicAction}
            className="basic-button"
          >
            Perform Basic Action
          </button>
        </div>
        <div className="feature-list">
          <h3>Core Features:</h3>
          <ul>
            <li>Basic component structure</li>
            <li>Simple state management</li>
            <li>Event handling</li>
            <li>Conditional rendering</li>
          </ul>
        </div>
      </header>
    </div>
  );
}

export default MVPApp;

// Basic CSS (App.css)
const basicStyles = `
.App {
  text-align: center;
}

.App-header {
  background-color: #282c34;
  padding: 20px;
  color: white;
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  font-size: calc(10px + 2vmin);
}

.basic-button {
  background-color: #61dafb;
  border: none;
  color: #282c34;
  padding: 10px 20px;
  font-size: 16px;
  border-radius: 5px;
  cursor: pointer;
  margin: 10px;
}

.basic-button:hover {
  background-color: #21a1f1;
}

.feature-list {
  margin-top: 30px;
  text-align: left;
}

.feature-list ul {
  list-style-type: none;
  padding: 0;
}

.feature-list li {
  margin: 5px 0;
}
`;
```

## MVP Guidelines
- **Focus**: Core functionality only
- **Complexity**: Keep it simple and direct
- **Dependencies**: React and basic CSS only
- **State Management**: useState and useEffect only
- **Routing**: Single page application
- **Styling**: Basic CSS or inline styles

## What's NOT Included (Compared to Core/Full)
- No advanced state management (Redux, Context API)
- No routing library (React Router)
- No comprehensive error handling
- No form validation libraries
- No API integration patterns
- No automated testing framework
- No component libraries (Material-UI, Ant Design)
- No build optimization
- No TypeScript support
- No internationalization
