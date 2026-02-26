{
  "name": "[[.ProjectName]]",
  "version": "1.0.0",
  "description": "[[.ProjectDescription]]",
  "main": "index.js",
  "scripts": {
    "start": "react-scripts start",
    "build": "react-scripts build",
    "test": "react-scripts test",
    "eject": "react-scripts eject",
    "lint": "eslint .",
    "lint:fix": "eslint . --fix"
  },
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-scripts": "5.0.1",
    "react-router-dom": "^6.14.0",
    "axios": "^1.5.0"
  },
  "devDependencies": {
    "@testing-library/react": "^13.4.0",
    "@testing-library/jest-dom": "^5.17.0",
    "@testing-library/user-event": "^14.4.0",
    "eslint": "^8.45.0",
    "prettier": "^3.0.0"
  },
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
  "templateNotes": {
    "dependencies": {
      "react": "Core React library used in all foundational templates",
      "react-dom": "React DOM renderer",
      "react-scripts": "Create React App build tool and scripts",
      "react-router-dom": "Routing library used in error-handling.tpl.js",
      "axios": "HTTP client used in http-client.tpl.js"
    },
    "devDependencies": {
      "@testing-library/react": "Testing library used in testing-utilities.tpl.js",
      "@testing-library/jest-dom": "Custom DOM matchers for Jest",
      "@testing-library/user-event": "User interaction simulation for testing",
      "eslint": "Code linting (optional)",
      "prettier": "Code formatting (optional)"
    },
    "note": "All React foundational templates are designed to work with these standard Create React App dependencies. They can be replaced with alternatives (Vite, Next.js, etc.) based on project requirements."
  }
}
