/**
 * Template: basic-tests-react_native.tpl.jsx
 * Purpose: basic-tests-react_native template
 * Stack: react
 * Tier: base
 */

# Universal Template System - Unknown Stack
# Generated: 2025-12-10
# Purpose: Testing utilities
# Tier: mvp
# Stack: unknown
# Category: testing

# Basic React Native Testing Template
# Purpose: MVP-level testing template with component and interaction tests for React Native applications
# Usage: Copy to __tests__/ directory and customize for your [[.ProjectName]] React Native project
# Stack: React Native (.jsx)
# Tier: MVP (Minimal Viable Product)

## Purpose

Essential React Native testing scaffold covering rendering, navigation, and interaction flows with a light footprint so MVP builds stay fast.

## Usage

```bash
# Copy to your React Native project
cp _templates/tiers/mvp/tests/basic-tests-react_native.tpl.jsx __tests__/Basic.test.jsx

# Install dependencies
npm install --save-dev @testing-library/react-native @testing-library/jest-native jest

# Run tests
npm test
```

## Structure

```jsx
// __tests__/Basic.test.jsx
import React from 'react';
import { render, fireEvent } from '@testing-library/react-native';
import App from '../App';

describe('App root', () => {
  it('renders the home screen', () => {
    const { getByText } = render(<App />);
    expect(getByText('Welcome')).toBeTruthy();
  });

  it('navigates on button press', () => {
    const { getByText } = render(<App />);
    fireEvent.press(getByText('Continue'));
    expect(getByText('Next Screen')).toBeTruthy();
  });
});
```
