// Next.js Stack Dependencies Template
// Complete package management for Next.js full-stack projects

{
  "name": "{{PROJECT_NAME}}",
  "version": "1.0.0",
  "private": true,
  "scripts": {
    "dev": "next dev",
    "build": "next build",
    "start": "next start",
    "lint": "next lint",
    "type-check": "tsc --noEmit",
    "test": "jest",
    "test:watch": "jest --watch",
    "test:ci": "jest --ci --coverage",
    "validate": "npm run type-check && npm run lint && npm run test:ci"
  },
  "dependencies": {
    "next": "^14.0.3",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "typescript": "^5.3.2",
    
    // Data Fetching
    "@tanstack/react-query": "^5.8.2",
    "@tanstack/react-query-next-experimental": "^5.8.2",
    
    // Styling
    "tailwindcss": "^3.3.5",
    "@tailwindcss/forms": "^0.5.7",
    "@tailwindcss/typography": "^0.5.10",
    "classnames": "^2.3.2",
    
    // UI Components
    "@headlessui/react": "^1.7.17",
    "@heroicons/react": "^2.0.18",
    "framer-motion": "^10.16.5",
    
    // Database
    "@prisma/client": "^5.6.0",
    "prisma": "^5.6.0",
    
    // Utilities
    "zod": "^3.22.4",
    "lodash": "^4.17.21",
    "dayjs": "^1.11.10"
  },
  "devDependencies": {
    "@types/node": "^20.8.0",
    "@types/react": "^18.2.34",
    "@types/react-dom": "^18.2.14",
    "autoprefixer": "^10.4.16",
    "postcss": "^8.4.31",
    "eslint": "^8.52.0",
    "eslint-config-next": "^14.0.3",
    "jest": "^29.7.0",
    "@testing-library/react": "^14.1.0",
    "@testing-library/jest-dom": "^6.1.4"
  }
}
