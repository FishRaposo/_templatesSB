<!--
File: PROJECT-STRUCTURE.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# {{PROJECT_NAME}} - React Project Structure

**Tier**: {{TIER}} | **Stack**: React

## ⚛️ Canonical React Project Structure

### **MVP Tier (Simple SPA)**
```
{{PROJECT_NAME}}/
├── src/
│   ├── App.tsx
│   ├── main.tsx
│   ├── components/
│   │   ├── Button.tsx
│   │   ├── Input.tsx
│   │   └── Layout.tsx
│   ├── features/
│   │   └── counter/
│   │       ├── Counter.tsx
│   │       └── Counter.css
│   └── hooks/
│       └── useCounter.ts
├── public/
│   └── index.html
├── package.json
├── vite.config.ts
├── tsconfig.json
└── README.md
```

### **CORE Tier (Production SPA)**
```
{{PROJECT_NAME}}/
├── src/
│   ├── main.tsx
│   ├── App.tsx
│   ├── components/
│   │   ├── ui/
│   │   │   ├── Button.tsx
│   │   │   ├── Input.tsx
│   │   │   ├── Modal.tsx
│   │   │   ├── Form.tsx
│   │   │   └── index.ts
│   │   ├── layout/
│   │   │   ├── Header.tsx
│   │   │   ├── Sidebar.tsx
│   │   │   ├── Footer.tsx
│   │   │   └── MainLayout.tsx
│   │   └── common/
│   │       ├── Loading.tsx
│   │       ├── ErrorBoundary.tsx
│   │       └── ProtectedRoute.tsx
│   ├── features/
│   │   ├── authentication/
│   │   │   ├── components/
│   │   │   │   ├── LoginForm.tsx
│   │   │   │   ├── RegisterForm.tsx
│   │   │   │   └── PasswordResetForm.tsx
│   │   │   ├── hooks/
│   │   │   │   ├── useAuth.ts
│   │   │   │   └── useAuthState.ts
│   │   │   ├── services/
│   │   │   │   └── authService.ts
│   │   │   └── types/
│   │   │       └── auth.ts
│   │   ├── dashboard/
│   │   │   ├── components/
│   │   │   │   ├── Dashboard.tsx
│   │   │   │   ├── StatsCard.tsx
│   │   │   │   └── RecentActivity.tsx
│   │   │   ├── hooks/
│   │   │   │   └── useDashboard.ts
│   │   │   └── services/
│   │   │       └── dashboardService.ts
│   │   └── [other_features]/
│   ├── hooks/
│   │   ├── useApi.ts
│   │   ├── useLocalStorage.ts
│   │   └── useDebounce.ts
│   ├── services/
│   │   ├── api.ts
│   │   ├── auth.ts
│   │   └── storage.ts
│   ├── lib/
│   │   ├── utils.ts
│   │   ├── constants.ts
│   │   └── validations.ts
│   ├── types/
│   │   ├── api.ts
│   │   ├── common.ts
│   │   └── index.ts
│   └── styles/
│       ├── globals.css
│       ├── components.css
│       └── variables.css
├── public/
│   ├── index.html
│   ├── favicon.ico
│   └── manifest.json
├── tests/
│   ├── __mocks__/
│   ├── setup.ts
│   ├── components/
│   ├── features/
│   └── utils/
├── .env.example
├── .gitignore
├── package.json
├── vite.config.ts
├── tsconfig.json
├── tailwind.config.js
└── README.md
```

### **FULL Tier (Enterprise SPA)**
```
{{PROJECT_NAME}}/
├── src/
│   ├── [CORE tier structure]
│   ├── admin/
│   │   ├── components/
│   │   ├── features/
│   │   └── routes/
│   ├── analytics/
│   │   ├── components/
│   │   ├── hooks/
│   │   └── services/
│   ├── monitoring/
│   │   ├── components/
│   │   ├── hooks/
│   │   └── services/
│   ├── internationalization/
│   │   ├── locales/
│   │   ├── hooks/
│   │   └── components/
│   └── performance/
│       ├── components/
│       ├── hooks/
│       └── utils/
├── tests/
│   ├── [CORE test structure]
│   ├── e2e/
│   ├── visual/
│   └── performance/
├── tools/
│   ├── build/
│   ├── deploy/
│   └── performance/
├── docs/
│   ├── components/
│   ├── features/
│   └── deployment/
└── [CORE tier files]
```

## 📁 Feature Structure Pattern

### **Feature Organization**
```typescript
// src/features/authentication/components/LoginForm.tsx
import React, { useState } from 'react';
import { useAuth } from '../hooks/useAuth';
import { LoginCredentials } from '../types/auth';

export const LoginForm: React.FC = () => {
  const [credentials, setCredentials] = useState<LoginCredentials>({
    email: '',
    password: '',
  });
  
  const { login, isLoading, error } = useAuth();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    await login(credentials);
  };

  return (
    <form onSubmit={handleSubmit} className="login-form">
      {/* Form JSX */}
    </form>
  );
};
```

### **Custom Hook Pattern**
```typescript
// src/features/authentication/hooks/useAuth.ts
import { useMutation, useQuery } from '@tanstack/react-query';
import { authService } from '../services/authService';
import { LoginCredentials, AuthUser } from '../types/auth';

export const useAuth = () => {
  const loginMutation = useMutation({
    mutationFn: authService.login,
    onSuccess: (user) => {
      // Store user data, update context, etc.
    },
    onError: (error) => {
      // Handle error
    },
  });

  const { data: user, isLoading } = useQuery({
    queryKey: ['auth', 'user'],
    queryFn: authService.getCurrentUser,
    staleTime: 5 * 60 * 1000, // 5 minutes
  });

  return {
    login: loginMutation.mutate,
    isLoading: loginMutation.isPending || isLoading,
    error: loginMutation.error,
    user,
    isAuthenticated: !!user,
  };
};
```

### **Service Layer Pattern**
```typescript
// src/features/authentication/services/authService.ts
import { api } from '../../services/api';
import { LoginCredentials, RegisterData, AuthUser } from '../types/auth';

export const authService = {
  async login(credentials: LoginCredentials): Promise<AuthUser> {
    const response = await api.post<AuthUser>('/auth/login', credentials);
    return response.data;
  },

  async register(data: RegisterData): Promise<AuthUser> {
    const response = await api.post<AuthUser>('/auth/register', data);
    return response.data;
  },

  async getCurrentUser(): Promise<AuthUser | null> {
    const response = await api.get<AuthUser>('/auth/me');
    return response.data;
  },

  async logout(): Promise<void> {
    await api.post('/auth/logout');
  },
};
```

## 🎯 Tier Mapping

| Tier | Features | Complexity | State Management | Testing |
|------|----------|------------|------------------|---------|
| **MVP** | Single feature, basic UI | Simple | Local state only | Component tests |
| **CORE** | Auth, routing, API integration | Modular | Context + TanStack Query | Unit + Integration |
| **FULL** | Admin, analytics, i18n | Enterprise | Advanced patterns | All tests + E2E |

## 📦 Package Organization

**Core Dependencies** (all tiers):
- `react` + `react-dom` - Core React
- `typescript` - Type system
- `vite` - Build tool
- `@types/react` + `@types/react-dom` - React types

**CORE Tier Additions**:
- `@tanstack/react-query` - Server state
- `react-router-dom` - Routing
- `axios` - HTTP client
- `tailwindcss` - Styling
- `@headlessui/react` - UI components
- `react-hook-form` - Forms
- `zod` - Validation

**FULL Tier Additions**:
- `@tanstack/react-table` - Data tables
- `react-i18next` - Internationalization
- `@sentry/react` - Error tracking
- `react-beautiful-dnd` - Drag & drop
- `recharts` - Charts
- `react-window` - Virtualization

## 🔧 Configuration Pattern

### **Vite Configuration**
```typescript
// vite.config.ts
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
      '@components': path.resolve(__dirname, './src/components'),
      '@features': path.resolve(__dirname, './src/features'),
      '@hooks': path.resolve(__dirname, './src/hooks'),
      '@services': path.resolve(__dirname, './src/services'),
      '@types': path.resolve(__dirname, './src/types'),
      '@utils': path.resolve(__dirname, './src/lib/utils'),
    },
  },
  server: {
    port: 3000,
    open: true,
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
});
```

### **TypeScript Configuration**
```json
// tsconfig.json
{
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true,
    "baseUrl": ".",
    "paths": {
      "@/*": ["./src/*"],
      "@components/*": ["./src/components/*"],
      "@features/*": ["./src/features/*"],
      "@hooks/*": ["./src/hooks/*"],
      "@services/*": ["./src/services/*"],
      "@types/*": ["./src/types/*"],
      "@utils/*": ["./src/lib/utils/*"]
    }
  },
  "include": ["src"],
  "references": [{ "path": "./tsconfig.node.json" }]
}
```

## 🧪 Testing Structure

### **Component Testing**
```typescript
// tests/components/Button.test.tsx
import { render, screen, fireEvent } from '@testing-library/react';
import { Button } from '@/components/ui/Button';

describe('Button', () => {
  it('renders with correct text', () => {
    render(<Button>Click me</Button>);
    expect(screen.getByRole('button', { name: 'Click me' })).toBeInTheDocument();
  });

  it('calls onClick when clicked', () => {
    const handleClick = jest.fn();
    render(<Button onClick={handleClick}>Click me</Button>);
    
    fireEvent.click(screen.getByRole('button'));
    expect(handleClick).toHaveBeenCalledTimes(1);
  });
});
```

### **Hook Testing**
```typescript
// tests/hooks/useCounter.test.ts
import { renderHook, act } from '@testing-library/react';
import { useCounter } from '@/hooks/useCounter';

describe('useCounter', () => {
  it('should initialize with default value', () => {
    const { result } = renderHook(() => useCounter());
    expect(result.current.count).toBe(0);
  });

  it('should increment count', () => {
    const { result } = renderHook(() => useCounter());
    
    act(() => {
      result.current.increment();
    });
    
    expect(result.current.count).toBe(1);
  });
});
```

---
*React Project Structure Template - Follow this pattern for consistent React applications*
