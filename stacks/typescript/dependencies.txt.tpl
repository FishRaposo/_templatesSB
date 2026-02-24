// TypeScript Stack Dependencies Template
// TypeScript backend stack (Node.js with enhanced type safety)

{
  "name": "{{PROJECT_NAME}}",
  "version": "1.0.0",
  "description": "{{PROJECT_DESCRIPTION}}",
  "main": "dist/index.js",
  "scripts": {
    "dev": "nodemon --exec ts-node -r tsconfig-paths/register src/index.ts",
    "build": "tsc && tsc-alias",
    "start": "node -r tsconfig-paths/register dist/index.js",
    "test": "jest",
    "lint": "eslint src/**/*.ts",
    "type-check": "tsc --noEmit"
  },
  "dependencies": {
    // TypeScript Runtime
    "@tsconfig/node20": "^20.1.2",
    "tsconfig-paths": "^4.2.0",
    
    // Web Framework
    "express": "^4.18.2",
    "@types/express": "^4.17.21",
    "helmet": "^7.1.0",
    "cors": "^2.8.5",
    
    // Validation
    "zod": "^3.22.4",
    "class-validator": "^0.14.0",
    "class-transformer": "^0.5.1",
    
    // Database
    "@prisma/client": "^5.6.0",
    "prisma": "^5.6.0",
    
    // Utilities
    "dotenv": "^16.3.1",
    "dayjs": "^1.11.10"
  },
  "devDependencies": {
    "typescript": "^5.3.2",
    "ts-node": "^10.9.1",
    "nodemon": "^3.0.1",
    "jest": "^29.7.0",
    "@types/jest": "^29.5.8",
    "ts-jest": "^29.1.1",
    "eslint": "^8.52.0",
    "@typescript-eslint/eslint-plugin": "^6.9.1",
    "@typescript-eslint/parser": "^6.9.1",
    "tsc-alias": "^1.8.8"
  }
}
