{
  "name": "[[.ProjectName]]",
  "version": "1.0.0",
  "description": "[[.ProjectDescription]]",
  "main": "index.js",
  "scripts": {
    "start": "node index.js",
    "dev": "nodemon index.js",
    "test": "jest",
    "test:watch": "jest --watch",
    "lint": "eslint .",
    "lint:fix": "eslint . --fix"
  },
  "dependencies": {
    "express": "^4.18.0",
    "cors": "^2.8.5",
    "helmet": "^7.0.0",
    "dotenv": "^16.3.0",
    "winston": "^3.10.0",
    "joi": "^17.9.0",
    "axios": "^1.5.0"
  },
  "devDependencies": {
    "jest": "^29.6.0",
    "supertest": "^6.3.0",
    "nodemon": "^3.0.0",
    "eslint": "^8.45.0",
    "prettier": "^3.0.0"
  },
  "jest": {
    "testEnvironment": "node",
    "collectCoverageFrom": [
      "**/*.js",
      "!node_modules/**",
      "!coverage/**"
    ]
  },
  "templateNotes": {
    "dependencies": {
      "express": "Web framework used in http-client.tpl.js and error-handling.tpl.js",
      "cors": "CORS middleware for HTTP examples",
      "helmet": "Security middleware for HTTP examples",
      "dotenv": "Environment variable loading for config-management.tpl.js",
      "winston": "Logging library used in logging-utilities.tpl.js",
      "joi": "Data validation library used in data-validation.tpl.js",
      "axios": "HTTP client used in http-client.tpl.js examples"
    },
    "devDependencies": {
      "jest": "Testing framework used in testing-utilities.tpl.js",
      "supertest": "HTTP assertion library for testing HTTP endpoints",
      "nodemon": "Auto-restart server during development",
      "eslint": "Code linting (optional)",
      "prettier": "Code formatting (optional)"
    },
    "note": "All Node.js foundational templates are designed to work with these common dependencies. They can be replaced with alternatives (standard library or other packages) based on project requirements."
  }
}
