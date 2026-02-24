// React Stack Dependencies Template
// Complete package management and tooling configurations for React projects

{
  "name": "{{PROJECT_NAME}}",
  "version": "1.0.0",
  "private": true,
  "description": "{{PROJECT_DESCRIPTION}}",
  "scripts": {
    // Development Scripts
    "start": "react-scripts start",
    "dev": "react-scripts start",
    "build": "react-scripts build",
    "build:profile": "react-scripts build --profile",
    "build:analyze": "npm run build && npm run analyze",
    "analyze": "source-map-explorer build/static/js/*.js",
    "test": "react-scripts test",
    "test:ci": "CI=true npm test -- --coverage --watchAll=false",
    "test:watch": "npm test -- --watch",
    "test:unit": "npm test -- --testPathPattern=unit/",
    "test:integration": "npm test -- --testPathPattern=integration/",
    "test:e2e": "cypress run",
    "test:e2e:open": "cypress open",
    
    // Code Quality
    "lint": "eslint src/**/*.{js,jsx,ts,tsx}",
    "lint:fix": "eslint src/**/*.{js,jsx,ts,tsx} --fix",
    "format": "prettier --write \"src/**/*.{js,jsx,ts,tsx,json,css,md}\"",
    "format:check": "prettier --check \"src/**/*.{js,jsx,ts,tsx,json,css,md}\"",
    "type-check": "tsc --noEmit",
    "validate": "npm run type-check && npm run lint && npm run format:check && npm run test:ci",
    
    // Utilities
    "clean": "rimraf build coverage",
    "eject": "react-scripts eject",
    "serve": "serve -s build",
    "serve:prod": "serve -s build -l 3000",
    
    // Storybook (for component development)
    "storybook": "storybook dev -p 6006",
    "build-storybook": "storybook build",
    
    // Performance Monitoring
    "perf": "react-scripts build && npx lighthouse http://localhost:3000 --view",
    
    // Security
    "security-audit": "npm audit && npm audit --audit-level=moderate",
    "security-fix": "npm audit fix",
    
    // Git Hooks
    "prepare": "husky install"
  },
  "dependencies": {
    // React Core
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-scripts": "5.0.1",
    
    // React Router
    "react-router-dom": "^6.18.0",
    "@remix-run/router": "^1.11.0",
    
    // State Management
    "@reduxjs/toolkit": "^1.9.7",
    "react-redux": "^8.1.3",
    "zustand": "^4.4.6",
    "zod": "^3.22.4",
    "jotai": "^2.5.1",
    
    // Form Handling
    "react-hook-form": "^7.48.2",
    "@hookform/resolvers": "^3.3.2",
    "formik": "^2.4.5",
    "yup": "^1.3.3",
    
    // UI Components
    "@mui/material": "^5.14.18",
    "@mui/icons-material": "^5.14.18",
    "@mui/lab": "^5.0.0-alpha.153",
    "@emotion/react": "^11.11.1",
    "@emotion/styled": "^11.11.0",
    "@ant-design/icons": "^5.2.6",
    "antd": "^5.11.1",
    
    // Data Visualization
    "recharts": "^2.8.0",
    "chart.js": "^4.4.0",
    "react-chartjs-2": "^5.2.0",
    "d3": "^7.8.5",
    
    // HTTP Client
    "axios": "^1.6.0",
    "@tanstack/react-query": "^5.8.2",
    "@tanstack/react-query-devtools": "^5.8.2",
    
    // Authentication
    "@auth0/auth0-react": "^2.2.3",
    "aws-amplify": "^6.0.5",
    
    // Date & Time
    "dayjs": "^1.11.10",
    "date-fns": "^2.30.0",
    "react-datepicker": "^4.21.0",
    
    // Styling
    "styled-components": "^6.1.1",
    "tailwindcss": "^3.3.5",
    "classnames": "^2.3.2",
    "clsx": "^2.0.0",
    
    // Icons
    "@fortawesome/react-fontawesome": "^0.2.0",
    "@fortawesome/free-solid-svg-icons": "^6.4.2",
    "@fortawesome/free-brands-svg-icons": "^6.4.2",
    
    // Internationalization
    "react-i18next": "^13.5.0",
    "i18next": "^23.7.6",
    "i18next-browser-languagedetector": "^7.2.0",
    
    // File Upload
    "react-dropzone": "^14.2.3",
    "file-saver": "^2.0.5",
    
    // Utilities
    "lodash": "^4.17.21",
    "ramda": "^0.29.1",
    "clsx": "^2.0.0",
    
    // Performance
    "web-vitals": "^3.5.0",
    "react-window": "^1.8.9",
    "react-virtualized": "^9.22.5",
    
    // Analytics
    "react-ga4": "^2.1.0",
    "@segment/analytics-next": "^1.61.0",
    
    // Error Boundaries
    "react-error-boundary": "^4.0.11",
    "@sentry/react": "^7.80.1",
    
    // PWA Support
    "workbox-background-sync": "^7.0.0",
    "workbox-broadcast-update": "^7.0.0",
    "workbox-cacheable-response": "^7.0.0",
    "workbox-core": "^7.0.0",
    "workbox-expiration": "^7.0.0",
    "workbox-google-analytics": "^7.0.0",
    "workbox-navigation-preload": "^7.0.0",
    "workbox-precaching": "^7.0.0",
    "workbox-range-requests": "^7.0.0",
    "workbox-routing": "^7.0.0",
    "workbox-strategies": "^7.0.0",
    "workbox-streams": "^7.0.0"
  },
  "devDependencies": {
    // TypeScript
    "@types/node": "^20.8.0",
    "@types/react": "^18.2.34",
    "@types/react-dom": "^18.2.14",
    "@types/lodash": "^4.14.201",
    "typescript": "^5.2.2",
    
    // Testing
    "@testing-library/jest-dom": "^6.1.4",
    "@testing-library/react": "^14.1.0",
    "@testing-library/user-event": "^14.5.1",
    "@testing-library/react-hooks": "^8.0.1",
    "jest-environment-jsdom": "^29.7.0",
    "msw": "^2.0.4",
    
    // E2E Testing
    "cypress": "^13.5.0",
    "@cypress/react": "^8.0.0",
    "@cypress/webpack-dev-server": "^3.7.0",
    
    // Linting & Formatting
    "eslint": "^8.52.0",
    "@typescript-eslint/eslint-plugin": "^6.9.1",
    "@typescript-eslint/parser": "^6.9.1",
    "eslint-plugin-react": "^7.33.2",
    "eslint-plugin-react-hooks": "^4.6.0",
    "eslint-plugin-jsx-a11y": "^6.7.1",
    "eslint-plugin-import": "^2.29.0",
    "prettier": "^3.0.3",
    "@types/prettier": "^3.0.0",
    "eslint-config-prettier": "^9.0.0",
    "eslint-plugin-prettier": "^5.0.1",
    
    // Git Hooks
    "husky": "^8.0.3",
    "lint-staged": "^15.0.2",
    
    // Storybook
    "@storybook/react": "^7.6.6",
    "@storybook/react-webpack5": "^7.6.6",
    "@storybook/addon-essentials": "^7.6.6",
    "@storybook/addon-interactions": "^7.6.6",
    "@storybook/addon-links": "^7.6.6",
    "@storybook/addon-onboarding": "^1.0.10",
    "@storybook/blocks": "^7.6.6",
    "@storybook/testing-library": "^0.2.2",
    "storybook": "^7.6.6",
    
    // Bundle Analysis
    "source-map-explorer": "^2.5.3",
    "@bundle-analyzer/webpack-plugin": "^0.7.0",
    
    // Utilities
    "rimraf": "^5.0.5",
    "concurrently": "^8.2.2",
    "serve": "^14.2.1",
    "cross-env": "^7.0.3",
    
    // Performance Testing
    "@lhci/cli": "^0.13.0",
    "lighthouse": "^11.3.0"
  },
  
  // ====================
  // BROWSER SUPPORT
  // ====================
  "browserslist": {
    "production": [
      ">0.2%",
      "not dead",
      "not op_mini all"
    ],
    "development": [
      "last 1 chrome version",
      "last 1 firefox version",
      "last 1 safari version"
    ]
  },
  
  // ====================
  // ESLINT CONFIGURATION
  // ====================
  "eslintConfig": {
    "extends": [
      "react-app",
      "react-app/jest",
      "plugin:react/recommended",
      "plugin:react-hooks/recommended",
      "plugin:jsx-a11y/recommended",
      "plugin:import/recommended",
      "plugin:import/typescript",
      "@typescript-eslint/recommended",
      "prettier"
    ],
    "parser": "@typescript-eslint/parser",
    "parserOptions": {
      "ecmaVersion": 2020,
      "sourceType": "module",
      "ecmaFeatures": {
        "jsx": true
      }
    },
    "plugins": [
      "react",
      "react-hooks",
      "jsx-a11y",
      "import",
      "@typescript-eslint",
      "prettier"
    ],
    "rules": {
      "prettier/prettier": "error",
      "react/react-in-jsx-scope": "off",
      "react/prop-types": "off",
      "react/jsx-uses-react": "off",
      "@typescript-eslint/no-unused-vars": "error",
      "@typescript-eslint/explicit-function-return-type": "warn",
      "@typescript-eslint/no-explicit-any": "warn",
      "import/order": [
        "error",
        {
          "groups": [
            ["builtin", "external"],
            ["internal", "parent", "sibling", "index"]
          ],
          "alphabetize": {
            "order": "asc",
            "caseInsensitive": true
          }
        }
      ]
    },
    "settings": {
      "react": {
        "version": "detect"
      },
      "import/resolver": {
        "typescript": {}
      }
    }
  },
  
  // ====================
  // PRETTIER CONFIGURATION
  // ====================
  "prettier": {
    "semi": true,
    "trailingComma": "es5",
    "singleQuote": true,
    "printWidth": 100,
    "tabWidth": 2,
    "useTabs": false,
    "arrowParens": "avoid",
    "endOfLine": "lf"
  },
  
  // ====================
  // JEST CONFIGURATION
  // ====================
  "jest": {
    "collectCoverageFrom": [
      "src/**/*.{js,jsx,ts,tsx}",
      "!src/**/*.d.ts",
      "!src/**/*.stories.{js,jsx,ts,tsx}",
      "!src/**/__tests__/**",
      "!src/setupTests.{js,ts}"
    ],
    "coverageThreshold": {
      "global": {
        "branches": 80,
        "functions": 80,
        "lines": 80,
        "statements": 80
      }
    },
    "coverageReporters": [
      "text",
      "lcov",
      "html"
    ]
  }
}
