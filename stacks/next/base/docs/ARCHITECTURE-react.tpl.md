<!--
File: ARCHITECTURE-react.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# Next.js Architecture Guide - {{PROJECT_NAME}}

**Tier**: {{TIER}} | **Stack**: Next.js

## 🏗️ Next.js Architecture Overview

Next.js applications follow **component-based architecture** with **atomic design principles** and **layered state management**. This ensures maintainability, reusability, and scalability across MVP, CORE, and FULL tiers while leveraging Next.js's declarative nature and ecosystem.

## 📊 Tier-Based Architecture Patterns

### **MVP Tier - Simple Component Architecture**

```
{{PROJECT_NAME}}/
├── public/
│   ├── index.html
│   └── favicon.ico
├── src/
│   ├── index.tsx                 # App entry point
│   ├── App.tsx                   # Root component
│   ├── components/               # UI components
│   │   ├── Button.tsx
│   │   ├── Input.tsx
│   │   ├── UserCard.tsx
│   │   └── UserList.tsx
│   ├── hooks/                    # Custom hooks
│   │   ├── useApi.ts
│   │   └── useAuth.ts
│   ├── types/                    # TypeScript types
│   │   └── user.types.ts
│   ├── utils/                    # Utility functions
│   │   └── api.ts
│   └── styles/                   # CSS/Styled components
│       ├── global.css
│       └── components.css
├── package.json                  # Dependencies
├── tsconfig.json                 # TypeScript config
└── README.md                     # Documentation
```

**Characteristics**:
- Flat component structure
- Simple useState/useEffect hooks
- Basic routing with Next.js Router
- Minimal state management
- Inline styles or CSS modules

**When to Use**:
- Interactive prototypes
- Simple web applications
- Component libraries
- Learning Next.js patterns

### **CORE Tier - Modular Clean Architecture**

```
{{PROJECT_NAME}}/
├── public/
│   ├── index.html
│   └── favicon.ico
├── src/
│   ├── index.tsx                 # App entry point
│   ├── App.tsx                   # Root component with providers
│   ├── components/               # UI components (Atomic Design)
│   │   ├── atoms/                # Smallest reusable elements
│   │   │   ├── Button/
│   │   │   │   ├── index.tsx
│   │   │   │   ├── Button.styles.ts
│   │   │   │   └── Button.test.tsx
│   │   │   ├── Input/
│   │   │   ├── Avatar/
│   │   │   └── Icon/
│   │   ├── molecules/            # Simple component combinations
│   │   │   ├── SearchBar/
│   │   │   ├── UserCard/
│   │   │   ├── FormField/
│   │   │   └── NavigationItem/
│   │   ├── organisms/            # Complex component sections
│   │   │   ├── Header/
│   │   │   ├── UserTable/
│   │   │   ├── Sidebar/
│   │   │   └── Footer/
│   │   ├── templates/            # Page layout components
│   │   │   ├── DashboardLayout/
│   │   │   ├── AuthLayout/
│   │   │   └── AdminLayout/
│   │   └── pages/                # Route-level components
│   │       ├── Home/
│   │       ├── Login/
│   │       ├── Dashboard/
│   │       └── Profile/
│   ├── contexts/                 # Next.js Context providers
│   │   ├── AuthContext.tsx
│   │   ├── ThemeContext.tsx
│   │   └── NotificationContext.tsx
│   ├── hooks/                    # Custom hooks
│   │   ├── useApi.ts
│   │   ├── useAuth.ts
│   │   ├── useLocalStorage.ts
│   │   └── useDebounce.ts
│   ├── services/                 # External service integrations
│   │   ├── api.ts
│   │   ├── auth.service.ts
│   │   ├── user.service.ts
│   │   └── storage.service.ts
│   ├── store/                    # State management (Redux/Zustand)
│   │   ├── index.ts
│   │   ├── slices/
│   │   │   ├── authSlice.ts
│   │   │   ├── userSlice.ts
│   │   │   └── uiSlice.ts
│   │   └── middleware/
│   │       └── api.middleware.ts
│   ├── routing/                  # Route configuration
│   │   ├── AppRoutes.tsx
│   │   ├── ProtectedRoute.tsx
│   │   └── route.config.ts
│   ├── types/                    # TypeScript type definitions
│   │   ├── index.ts
│   │   ├── auth.types.ts
│   │   ├── user.types.ts
│   │   └── api.types.ts
│   ├── utils/                    # Utility functions
│   │   ├── index.ts
│   │   ├── constants.ts
│   │   ├── helpers.ts
│   │   └── validators.ts
│   ├── styles/                   # Styling system
│   │   ├── theme.ts
│   │   ├── global.styles.ts
│   │   ├── breakpoints.ts
│   │   └── mixins.ts
│   └── assets/                   # Static assets
│       ├── images/
│       ├── icons/
│       └── fonts/
├── tests/                        # Test suite
│   ├── components/               # Component tests
│   ├── hooks/                    # Hook tests
│   ├── utils/                    # Test utilities
│   └── __mocks__/                # Mock files
├── package.json                  # Dependencies
├── tsconfig.json                 # TypeScript config
├── jest.config.js                # Jest test config
└── README.md                     # Documentation
```

**Characteristics**:
- Atomic design component structure
- Context API for global state
- Redux Toolkit for complex state
- Advanced routing with guards
- Comprehensive styling system
- Complete test suite

**When to Use**:
- Production web applications
- SaaS frontends
- Enterprise dashboards
- Multi-team development

### **FULL Tier - Enterprise Architecture**

```
{{PROJECT_NAME}}/
├── [CORE tier structure]
├── src/
│   ├── features/                 # Feature-based modules
│   │   ├── auth/                 # Authentication feature
│   │   │   ├── components/
│   │   │   ├── hooks/
│   │   │   ├── services/
│   │   │   ├── types/
│   │   │   └── index.ts
│   │   ├── users/                # User management feature
│   │   │   ├── components/
│   │   │   ├── hooks/
│   │   │   ├── services/
│   │   │   ├── store/
│   │   │   └── index.ts
│   │   ├── products/             # Product management
│   │   ├── orders/               # Order processing
│   │   └── [business_features]/  # Other business features
│   ├── shared/                   # Shared across features
│   │   ├── components/           # Reusable components
│   │   │   ├── layouts/
│   │   │   ├── forms/
│   │   │   └── charts/
│   │   ├── hooks/                # Shared hooks
│   │   │   ├── useApi.ts
│   │   │   ├── useWebSocket.ts
│   │   │   └── useAnalytics.ts
│   │   ├── services/             # Shared services
│   │   │   ├── api.client.ts
│   │   │   ├── websocket.client.ts
│   │   │   └── analytics.service.ts
│   │   ├── store/                # Global store
│   │   │   ├── index.ts
│   │   │   ├── slices/
│   │   │   └── middleware/
│   │   ├── utils/                # Shared utilities
│   │   │   ├── constants/
│   │   │   ├── helpers/
│   │   │   └── validators/
│   │   └── types/                # Shared types
│   │       ├── api.types.ts
│   │       ├── common.types.ts
│   │       └── store.types.ts
│   ├── platform/                 # Platform-specific code
│   │   ├── web/                  # Web-specific features
│   │   │   ├── components/
│   │   │   └── utils/
│   │   └── mobile/               # Mobile-specific features
│   │       ├── components/
│   │       └── utils/
│   ├── monitoring/               # Monitoring and observability
│   │   ├── error-boundary.tsx
│   │   ├── performance-monitor.ts
│   │   ├── analytics-tracker.ts
│   │   └── sentry-integration.ts
│   ├── internationalization/     # i18n support
│   │   ├── i18n.config.ts
│   │   ├── locales/
│   │   │   ├── en.json
│   │   │   ├── es.json
│   │   │   └── fr.json
│   │   └── hooks/
│   │       └── useTranslation.ts
│   ├── accessibility/            # Accessibility features
│   │   ├── hooks/
│   │   │   ├── useA11y.ts
│   │   │   └── useKeyboardNavigation.ts
│   │   ├── components/
│   │   │   ├── SkipLink.tsx
│   │   │   └── ScreenReaderOnly.tsx
│   │   └── utils/
│   │       └── a11y.helpers.ts
│   ├── testing/                  # Testing utilities
│   │   ├── utils/
│   │   │   ├── render-with-providers.tsx
│   │   │   ├── test-helpers.ts
│   │   │   └── mock-data.factory.ts
│   │   ├── mocks/
│   │   │   ├── server.ts
│   │   │   └── handlers/
│   │   └── fixtures/
│   │       └── data/
│   └── microfrontends/           # Micro-frontend support
│       ├── shell/
│       ├── module-federation/
│       └── shared-components/
├── tools/                        # Build and development tools
│   ├── webpack/
│   ├── babel/
│   └── eslint/
└── [CORE tier files]
```

**Characteristics**:
- Feature-based architecture
- Micro-frontend support
- Advanced monitoring and analytics
- Internationalization support
- Complete accessibility implementation
- Enterprise-grade testing infrastructure

## 🎯 Component Architecture Patterns

### **Atomic Design Implementation**

#### **MVP Level - Simple Components**

```tsx
// src/components/Button.tsx - Basic button component
import Next.js from 'next';

interface ButtonProps {
  onClick?: () => void;
  disabled?: boolean;
  children: Next.js.Next.jsNode;
}

export function Button({ onClick, disabled, children }: ButtonProps) {
  return (
    <button 
      onClick={onClick}
      disabled={disabled}
      style={{
        padding: '8px 16px',
        borderRadius: '4px',
        backgroundColor: disabled ? '#ccc' : '#007bff',
        color: 'white',
        border: 'none',
        cursor: disabled ? 'not-allowed' : 'pointer',
      }}
    >
      {children}
    </button>
  );
}

// src/components/UserCard.tsx - Simple user card
import Next.js from 'next';

interface UserCardProps {
  user: {
    id: number;
    name: string;
    email: string;
  };
  onEdit?: (user: any) => void;
  onDelete?: (userId: number) => void;
}

export function UserCard({ user, onEdit, onDelete }: UserCardProps) {
  return (
    <div style={{ border: '1px solid #ddd', padding: '16px', margin: '8px' }}>
      <h3>{user.name}</h3>
      <p>{user.email}</p>
      <div>
        {onEdit && <Button onClick={() => onEdit(user)}>Edit</Button>}
        {onDelete && <Button onClick={() => onDelete(user.id)}>Delete</Button>}
      </div>
    </div>
  );
}
```

#### **CORE Level - Atomic Design Components**

```tsx
// src/components/atoms/Button/index.tsx - Styled atom component
import Next.js from 'next';
import styled from 'styled-components';

interface ButtonProps {
  variant?: 'primary' | 'secondary' | 'danger';
  size?: 'sm' | 'md' | 'lg';
  disabled?: boolean;
  loading?: boolean;
  onClick?: () => void;
  children: Next.js.Next.jsNode;
  className?: string;
}

const StyledButton = styled.button<ButtonProps>`
  padding: ${({ size }) => {
    switch (size) {
      case 'sm': return '4px 8px';
      case 'lg': return '12px 24px';
      default: return '8px 16px';
    }
  }};
  
  border-radius: 4px;
  border: none;
  font-weight: 600;
  cursor: ${({ disabled }) => disabled ? 'not-allowed' : 'pointer'};
  opacity: ${({ disabled }) => disabled ? 0.6 : 1};
  transition: all 0.2s ease;
  
  background-color: ${({ variant, theme }) => {
    switch (variant) {
      case 'secondary': return theme.colors.secondary;
      case 'danger': return theme.colors.danger;
      default: return theme.colors.primary;
    }
  }};
  
  color: ${({ theme }) => theme.colors.white};
  
  &:hover {
    opacity: ${({ disabled }) => disabled ? 0.6 : 0.8};
    transform: ${({ disabled }) => disabled ? 'none' : 'translateY(-1px)'};
  }
  
  &:focus {
    outline: 2px solid ${({ theme }) => theme.colors.primary};
    outline-offset: 2px;
  }
`;

const LoadingSpinner = styled.div`
  display: inline-block;
  width: 16px;
  height: 16px;
  border: 2px solid transparent;
  border-top: 2px solid currentColor;
  border-radius: 50%;
  animation: spin 1s linear infinite;
  
  @keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
  }
`;

export function Button({ 
  variant = 'primary', 
  size = 'md', 
  disabled = false, 
  loading = false,
  onClick, 
  children, 
  className 
}: ButtonProps) {
  return (
    <StyledButton
      variant={variant}
      size={size}
      disabled={disabled || loading}
      onClick={onClick}
      className={className}
      aria-disabled={disabled || loading}
      aria-busy={loading}
    >
      {loading ? <LoadingSpinner /> : children}
    </StyledButton>
  );
}

// src/components/molecules/UserCard/index.tsx - Complex molecule
import Next.js from 'next';
import { Button } from '../../atoms/Button';
import { Avatar } from '../../atoms/Avatar';
import { Badge } from '../../atoms/Badge';
import { Card } from '../../atoms/Card';
import { User } from '../../../types/user.types';

interface UserCardProps {
  user: User;
  onEdit?: (user: User) => void;
  onDelete?: (userId: string) => void;
  onViewProfile?: (userId: string) => void;
  className?: string;
}

const UserCardContainer = styled(Card)`
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 16px;
  transition: transform 0.2s ease, box-shadow 0.2s ease;
  
  &:hover {
    transform: translateY(-2px);
    box-shadow: ${({ theme }) => theme.shadows.md};
  }
`;

const UserInfo = styled.div`
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 4px;
`;

const UserName = styled.h3`
  margin: 0;
  font-size: 16px;
  font-weight: 600;
  color: ${({ theme }) => theme.colors.text.primary};
`;

const UserEmail = styled.p`
  margin: 0;
  font-size: 14px;
  color: ${({ theme }) => theme.colors.text.secondary};
`;

const UserActions = styled.div`
  display: flex;
  gap: 8px;
  align-items: center;
`;

export function UserCard({ 
  user, 
  onEdit, 
  onDelete, 
  onViewProfile, 
  className 
}: UserCardProps) {
  return (
    <UserCardContainer className={className}>
      <Avatar 
        src={user.avatar} 
        alt={user.name}
        size="md"
      />
      
      <UserInfo>
        <UserName>{user.name}</UserName>
        <UserEmail>{user.email}</UserEmail>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <Badge variant={user.isActive ? 'success' : 'warning'}>
            {user.isActive ? 'Active' : 'Inactive'}
          </Badge>
          <Badge variant="info">{user.role}</Badge>
        </div>
      </UserInfo>
      
      <UserActions>
        {onViewProfile && (
          <Button 
            variant="secondary" 
            size="sm"
            onClick={() => onViewProfile(user.id)}
            aria-label={`View profile for ${user.name}`}
          >
            View
          </Button>
        )}
        
        {onEdit && (
          <Button 
            variant="primary" 
            size="sm"
            onClick={() => onEdit(user)}
            aria-label={`Edit ${user.name}`}
          >
            Edit
          </Button>
        )}
        
        {onDelete && (
          <Button 
            variant="danger" 
            size="sm"
            onClick={() => onDelete(user.id)}
            aria-label={`Delete ${user.name}`}
          >
            Delete
          </Button>
        )}
      </UserActions>
    </UserCardContainer>
  );
}
```

#### **FULL Level - Enterprise Components**

```tsx
// src/components/organisms/EnterpriseUserTable/index.tsx - Complex organism
import Next.js, { useState, useCallback, useMemo } from 'next';
import { useSelector, useDispatch } from 'next-redux';
import { debounce } from 'lodash';
import { Button } from '../../atoms/Button';
import { Input } from '../../atoms/Input';
import { Checkbox } from '../../atoms/Checkbox';
import { Badge } from '../../atoms/Badge';
import { Table } from '../../atoms/Table';
import { Pagination } from '../../molecules/Pagination';
import { UserFilters } from '../../molecules/UserFilters';
import { BulkActionsMenu } from '../../molecules/BulkActionsMenu';
import { useAnalytics } from '../../../hooks/useAnalytics';
import { useWebSocket } from '../../../hooks/useWebSocket';
import { User, UserFilters as UserFiltersType } from '../../../types/user.types';
import { RootState } from '../../../store';
import { fetchUsers, updateUser, deleteUser } from '../../../store/slices/usersSlice';

interface EnterpriseUserTableProps {
  organizationId: string;
  onUserSelect?: (users: User[]) => void;
  className?: string;
}

const TableContainer = styled.div`
  background: ${({ theme }) => theme.colors.background.paper};
  border-radius: 8px;
  box-shadow: ${({ theme }) => theme.shadows.sm};
  overflow: hidden;
`;

const TableHeader = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px;
  border-bottom: 1px solid ${({ theme }) => theme.colors.border};
`;

const TableActions = styled.div`
  display: flex;
  gap: 8px;
  align-items: center;
`;

const LoadingOverlay = styled.div`
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(255, 255, 255, 0.8);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 10;
`;

export function EnterpriseUserTable({ 
  organizationId, 
  onUserSelect, 
  className 
}: EnterpriseUserTableProps) {
  const dispatch = useDispatch();
  const { trackEvent } = useAnalytics();
  const { lastMessage, sendMessage } = useWebSocket('/ws/users');
  
  // Redux state
  const { 
    users, 
    loading, 
    error, 
    pagination, 
    filters 
  } = useSelector((state: RootState) => state.users);
  
  // Local state
  const [selectedUsers, setSelectedUsers] = useState<string[]>([]);
  const [localFilters, setLocalFilters] = useState<UserFiltersType>(filters);
  const [sortBy, setSortBy] = useState<{ field: string; direction: 'asc' | 'desc' }>({
    field: 'name',
    direction: 'asc',
  });

  // Memoized filtered and sorted users
  const processedUsers = useMemo(() => {
    let filtered = users.filter(user => {
      if (localFilters.search && !user.name.toLowerCase().includes(localFilters.search.toLowerCase())) {
        return false;
      }
      if (localFilters.status !== 'all' && user.isActive !== (localFilters.status === 'active')) {
        return false;
      }
      if (localFilters.role !== 'all' && user.role !== localFilters.role) {
        return false;
      }
      return true;
    });

    // Sort users
    return filtered.sort((a, b) => {
      const aValue = a[sortBy.field as keyof User];
      const bValue = b[sortBy.field as keyof User];
      
      if (aValue < bValue) return sortBy.direction === 'asc' ? -1 : 1;
      if (aValue > bValue) return sortBy.direction === 'asc' ? 1 : -1;
      return 0;
    });
  }, [users, localFilters, sortBy]);

  // Debounced filter handler
  const debouncedFilterChange = useCallback(
    debounce((newFilters: UserFiltersType) => {
      dispatch(fetchUsers({ ...newFilters, organizationId }));
      trackEvent('user_filters_changed', { filters: newFilters });
    }, 300),
    [dispatch, organizationId, trackEvent]
  );

  // Event handlers
  const handleFilterChange = useCallback((newFilters: Partial<UserFiltersType>) => {
    const updatedFilters = { ...localFilters, ...newFilters };
    setLocalFilters(updatedFilters);
    debouncedFilterChange(updatedFilters);
  }, [localFilters, debouncedFilterChange]);

  const handleUserSelect = useCallback((userId: string, selected: boolean) => {
    setSelectedUsers(prev => {
      const newSelection = selected 
        ? [...prev, userId]
        : prev.filter(id => id !== userId);
      
      onUserSelect?.(processedUsers.filter(user => newSelection.includes(user.id)));
      return newSelection;
    });
  }, [processedUsers, onUserSelect]);

  const handleSelectAll = useCallback((selected: boolean) => {
    const newSelection = selected ? processedUsers.map(user => user.id) : [];
    setSelectedUsers(newSelection);
    onUserSelect?.(processedUsers.filter(user => newSelection.includes(user.id)));
  }, [processedUsers, onUserSelect]);

  const handleSort = useCallback((field: string) => {
    setSortBy(prev => ({
      field,
      direction: prev.field === field && prev.direction === 'asc' ? 'desc' : 'asc',
    }));
  }, []);

  const handleBulkAction = useCallback(async (action: string) => {
    try {
      // Send bulk action via WebSocket for real-time updates
      sendMessage({
        type: 'bulk_action',
        action,
        userIds: selectedUsers,
        organizationId,
      });

      trackEvent('bulk_action_executed', { action, userCount: selectedUsers.length });
      setSelectedUsers([]);
    } catch (error) {
      console.error('Bulk action failed:', error);
    }
  }, [selectedUsers, organizationId, sendMessage, trackEvent]);

  const handleUserStatusToggle = useCallback(async (userId: string) => {
    try {
      const user = users.find(u => u.id === userId);
      if (user) {
        await dispatch(updateUser({ 
          id: userId, 
          data: { isActive: !user.isActive } 
        })).unwrap();
        
        trackEvent('user_status_toggled', { 
          userId, 
          newStatus: !user.isActive 
        });
      }
    } catch (error) {
      console.error('Failed to toggle user status:', error);
    }
  }, [users, dispatch, trackEvent]);

  // Handle WebSocket messages
  Next.js.useEffect(() => {
    if (lastMessage?.type === 'user_updated') {
      // Refresh user data when updates come through WebSocket
      dispatch(fetchUsers({ ...filters, organizationId }));
    }
  }, [lastMessage, dispatch, filters, organizationId]);

  // Table columns configuration
  const columns = useMemo(() => [
    {
      key: 'select',
      header: (
        <Checkbox
          checked={selectedUsers.length === processedUsers.length && processedUsers.length > 0}
          indeterminate={selectedUsers.length > 0 && selectedUsers.length < processedUsers.length}
          onChange={handleSelectAll}
          aria-label="Select all users"
        />
      ),
      render: (user: User) => (
        <Checkbox
          checked={selectedUsers.includes(user.id)}
          onChange={(checked) => handleUserSelect(user.id, checked)}
          aria-label={`Select ${user.name}`}
        />
      ),
    },
    {
      key: 'name',
      header: (
        <Button
          variant="ghost"
          onClick={() => handleSort('name')}
          aria-label="Sort by name"
        >
          Name {sortBy.field === 'name' && (sortBy.direction === 'asc' ? '↑' : '↓')}
        </Button>
      ),
      render: (user: User) => (
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Avatar src={user.avatar} alt={user.name} size="sm" />
          <div>
            <div style={{ fontWeight: 600 }}>{user.name}</div>
            <div style={{ fontSize: '12px', color: '#666' }}>{user.email}</div>
          </div>
        </div>
      ),
    },
    {
      key: 'role',
      header: 'Role',
      render: (user: User) => (
        <Badge variant="info">{user.role}</Badge>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      render: (user: User) => (
        <Button
          variant="ghost"
          size="sm"
          onClick={() => handleUserStatusToggle(user.id)}
          aria-label={`Toggle status for ${user.name}`}
        >
          <Badge variant={user.isActive ? 'success' : 'warning'}>
            {user.isActive ? 'Active' : 'Inactive'}
          </Badge>
        </Button>
      ),
    },
    {
      key: 'actions',
      header: 'Actions',
      render: (user: User) => (
        <div style={{ display: 'flex', gap: '4px' }}>
          <Button
            variant="secondary"
            size="sm"
            onClick={() => {/* Handle edit */}}
            aria-label={`Edit ${user.name}`}
          >
            Edit
          </Button>
          <Button
            variant="danger"
            size="sm"
            onClick={() => {/* Handle delete */}}
            aria-label={`Delete ${user.name}`}
          >
            Delete
          </Button>
        </div>
      ),
    },
  ], [
    selectedUsers, 
    processedUsers, 
    sortBy, 
    handleSelectAll, 
    handleUserSelect, 
    handleSort, 
    handleUserStatusToggle
  ]);

  return (
    <TableContainer className={className}>
      <TableHeader>
        <h2>User Management</h2>
        <TableActions>
          {selectedUsers.length > 0 && (
            <BulkActionsMenu
              selectedCount={selectedUsers.length}
              onAction={handleBulkAction}
            />
          )}
          <Button onClick={() => {/* Handle create user */}}>
            Add User
          </Button>
        </TableActions>
      </TableHeader>

      <UserFilters
        filters={localFilters}
        onFilterChange={handleFilterChange}
      />

      <div style={{ position: 'relative' }}>
        {loading && (
          <LoadingOverlay>
            <div>Loading users...</div>
          </LoadingOverlay>
        )}
        
        {error && (
          <div style={{ padding: '16px', color: 'red' }}>
            Error: {error}
            <Button onClick={() => dispatch(fetchUsers({ ...filters, organizationId }))}>
              Retry
            </Button>
          </div>
        )}

        <Table
          columns={columns}
          data={processedUsers}
          emptyMessage="No users found"
          aria-label="Users table"
        />
      </div>

      <Pagination
        pagination={pagination}
        onPageChange={(page) => handleFilterChange({ ...localFilters, page })}
      />
    </TableContainer>
  );
}
```

## 🔄 State Management Architecture

### **Context API Pattern (CORE Tier)**

```tsx
// src/contexts/AuthContext.tsx - Global authentication state
import Next.js, { createContext, useContext, useReducer, useEffect } from 'next';
import { User } from '../types/user.types';

interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  loading: boolean;
  error: string | null;
}

interface AuthContextType extends AuthState {
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  register: (userData: RegisterData) => Promise<void>;
  clearError: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

interface AuthProviderProps {
  children: Next.js.Next.jsNode;
}

const authReducer = (state: AuthState, action: AuthAction): AuthState => {
  switch (action.type) {
    case 'AUTH_START':
      return { ...state, loading: true, error: null };
    case 'AUTH_SUCCESS':
      return { 
        ...state, 
        loading: false, 
        user: action.payload, 
        isAuthenticated: true 
      };
    case 'AUTH_ERROR':
      return { 
        ...state, 
        loading: false, 
        error: action.payload, 
        user: null, 
        isAuthenticated: false 
      };
    case 'AUTH_LOGOUT':
      return { 
        ...state, 
        user: null, 
        isAuthenticated: false, 
        error: null 
      };
    case 'CLEAR_ERROR':
      return { ...state, error: null };
    default:
      return state;
  }
};

export function AuthProvider({ children }: AuthProviderProps) {
  const [state, dispatch] = useReducer(authReducer, initialState);

  useEffect(() => {
    // Check for existing session on mount
    const token = localStorage.getItem('auth_token');
    if (token) {
      validateToken(token);
    }
  }, []);

  const login = async (email: string, password: string) => {
    dispatch({ type: 'AUTH_START' });
    
    try {
      const response = await authService.login(email, password);
      const { user, token } = response;
      
      localStorage.setItem('auth_token', token);
      dispatch({ type: 'AUTH_SUCCESS', payload: user });
      
    } catch (error) {
      dispatch({ type: 'AUTH_ERROR', payload: error.message });
    }
  };

  const logout = () => {
    localStorage.removeItem('auth_token');
    dispatch({ type: 'AUTH_LOGOUT' });
  };

  const register = async (userData: RegisterData) => {
    dispatch({ type: 'AUTH_START' });
    
    try {
      const response = await authService.register(userData);
      const { user, token } = response;
      
      localStorage.setItem('auth_token', token);
      dispatch({ type: 'AUTH_SUCCESS', payload: user });
      
    } catch (error) {
      dispatch({ type: 'AUTH_ERROR', payload: error.message });
    }
  };

  const clearError = () => {
    dispatch({ type: 'CLEAR_ERROR' });
  };

  const value: AuthContextType = {
    ...state,
    login,
    logout,
    register,
    clearError,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
```

### **Redux Toolkit Pattern (FULL Tier)**

```tsx
// src/store/slices/usersSlice.ts - Complex state management
import { createSlice, createAsyncThunk, PayloadAction } from '@reduxjs/toolkit';
import { User, UserFilters, Pagination } from '../../types/user.types';
import { userApi } from '../../services/user.api';

// Async thunks
export const fetchUsers = createAsyncThunk(
  'users/fetchUsers',
  async (params: {
    organizationId: string;
    page?: number;
    limit?: number;
    filters?: UserFilters;
  }, { rejectWithValue }) => {
    try {
      const response = await userApi.fetchUsers(params);
      return response;
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

export const createUser = createAsyncThunk(
  'users/createUser',
  async (userData: CreateUserData & { organizationId: string }, { rejectWithValue }) => {
    try {
      const response = await userApi.createUser(userData);
      return response;
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

export const updateUser = createAsyncThunk(
  'users/updateUser',
  async (params: { id: string; data: Partial<User> }, { rejectWithValue }) => {
    try {
      const response = await userApi.updateUser(params.id, params.data);
      return response;
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

// Slice definition
interface UsersState {
  users: User[];
  loading: boolean;
  error: string | null;
  pagination: Pagination;
  filters: UserFilters;
  selectedUsers: string[];
  lastUpdated: string | null;
}

const initialState: UsersState = {
  users: [],
  loading: false,
  error: null,
  pagination: {
    page: 1,
    limit: 20,
    total: 0,
    totalPages: 0,
  },
  filters: {
    search: '',
    status: 'all',
    role: 'all',
    department: 'all',
  },
  selectedUsers: [],
  lastUpdated: null,
};

const usersSlice = createSlice({
  name: 'users',
  initialState,
  reducers: {
    setFilters: (state, action: PayloadAction<Partial<UserFilters>>) => {
      state.filters = { ...state.filters, ...action.payload };
    },
    clearFilters: (state) => {
      state.filters = initialState.filters;
    },
    selectUser: (state, action: PayloadAction<string>) => {
      if (!state.selectedUsers.includes(action.payload)) {
        state.selectedUsers.push(action.payload);
      }
    },
    deselectUser: (state, action: PayloadAction<string>) => {
      state.selectedUsers = state.selectedUsers.filter(id => id !== action.payload);
    },
    selectAllUsers: (state) => {
      state.selectedUsers = state.users.map(user => user.id);
    },
    clearSelection: (state) => {
      state.selectedUsers = [];
    },
    updateUserOptimistic: (state, action: PayloadAction<User>) => {
      const index = state.users.findIndex(user => user.id === action.payload.id);
      if (index !== -1) {
        state.users[index] = action.payload;
      }
    },
    clearError: (state) => {
      state.error = null;
    },
  },
  extraReducers: (builder) => {
    builder
      // Fetch users
      .addCase(fetchUsers.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchUsers.fulfilled, (state, action) => {
        state.loading = false;
        state.users = action.payload.users;
        state.pagination = action.payload.pagination;
        state.lastUpdated = new Date().toISOString();
      })
      .addCase(fetchUsers.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload as string;
      })
      // Create user
      .addCase(createUser.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(createUser.fulfilled, (state, action) => {
        state.loading = false;
        state.users.unshift(action.payload);
        state.pagination.total += 1;
      })
      .addCase(createUser.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload as string;
      })
      // Update user
      .addCase(updateUser.fulfilled, (state, action) => {
        const index = state.users.findIndex(user => user.id === action.payload.id);
        if (index !== -1) {
          state.users[index] = action.payload;
        }
      });
  },
});

export const {
  setFilters,
  clearFilters,
  selectUser,
  deselectUser,
  selectAllUsers,
  clearSelection,
  updateUserOptimistic,
  clearError,
} = usersSlice.actions;

export default usersSlice.reducer;

// Selectors
export const selectUsers = (state: { users: UsersState }) => state.users.users;
export const selectUsersLoading = (state: { users: UsersState }) => state.users.loading;
export const selectUsersError = (state: { users: UsersState }) => state.users.error;
export const selectUsersPagination = (state: { users: UsersState }) => state.users.pagination;
export const selectUsersFilters = (state: { users: UsersState }) => state.users.filters;
export const selectSelectedUsers = (state: { users: UsersState }) => state.users.selectedUsers;
export const selectFilteredUsers = createSelector(
  [selectUsers, selectUsersFilters],
  (users, filters) => {
    return users.filter(user => {
      if (filters.search && !user.name.toLowerCase().includes(filters.search.toLowerCase())) {
        return false;
      }
      if (filters.status !== 'all' && user.isActive !== (filters.status === 'active')) {
        return false;
      }
      if (filters.role !== 'all' && user.role !== filters.role) {
        return false;
      }
      return true;
    });
  }
);
```

## 🎨 Styling Architecture

### **Styled-Components Theme System**

```tsx
// src/styles/theme.ts - Comprehensive theme system
export const lightTheme = {
  colors: {
    primary: '#007bff',
    secondary: '#6c757d',
    success: '#28a745',
    danger: '#dc3545',
    warning: '#ffc107',
    info: '#17a2b8',
    
    text: {
      primary: '#212529',
      secondary: '#6c757d',
      disabled: '#adb5bd',
      inverse: '#ffffff',
    },
    
    background: {
      primary: '#ffffff',
      secondary: '#f8f9fa',
      tertiary: '#e9ecef',
      paper: '#ffffff',
      overlay: 'rgba(0, 0, 0, 0.5)',
    },
    
    border: {
      primary: '#dee2e6',
      secondary: '#ced4da',
      focus: '#007bff',
    },
  },
  
  spacing: {
    xs: '4px',
    sm: '8px',
    md: '16px',
    lg: '24px',
    xl: '32px',
    xxl: '48px',
  },
  
  typography: {
    fontFamily: {
      primary: '"Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      mono: '"Fira Code", Monaco, Consolas, monospace',
    },
    fontSize: {
      xs: '12px',
      sm: '14px',
      base: '16px',
      lg: '18px',
      xl: '20px',
      '2xl': '24px',
      '3xl': '30px',
      '4xl': '36px',
    },
    fontWeight: {
      light: 300,
      normal: 400,
      medium: 500,
      semibold: 600,
      bold: 700,
    },
    lineHeight: {
      tight: 1.25,
      normal: 1.5,
      relaxed: 1.75,
    },
  },
  
  shadows: {
    sm: '0 1px 2px 0 rgba(0, 0, 0, 0.05)',
    md: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
    lg: '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)',
    xl: '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)',
  },
  
  borderRadius: {
    none: '0',
    sm: '2px',
    base: '4px',
    md: '6px',
    lg: '8px',
    xl: '12px',
    full: '9999px',
  },
  
  breakpoints: {
    sm: '576px',
    md: '768px',
    lg: '992px',
    xl: '1200px',
    xxl: '1400px',
  },
  
  zIndex: {
    base: 0,
    overlay: 1000,
    modal: 1050,
    popover: 1060,
    tooltip: 1070,
    toast: 1080,
  },
};

export const darkTheme = {
  ...lightTheme,
  colors: {
    ...lightTheme.colors,
    text: {
      primary: '#ffffff',
      secondary: '#adb5bd',
      disabled: '#6c757d',
      inverse: '#212529',
    },
    background: {
      primary: '#121212',
      secondary: '#1e1e1e',
      tertiary: '#2d2d2d',
      paper: '#1e1e1e',
      overlay: 'rgba(0, 0, 0, 0.8)',
    },
    border: {
      primary: '#404040',
      secondary: '#555555',
      focus: '#007bff',
    },
  },
};

export type Theme = typeof lightTheme;
```

### **Component Styling Patterns**

```tsx
// src/styles/components.ts - Reusable component styles
import styled, { css } from 'styled-components';
import { Theme } from './theme';

// Responsive mixins
export const media = {
  sm: (styles: any) => css`
    @media (min-width: ${(props: { theme: Theme }) => props.theme.breakpoints.sm}) {
      ${styles}
    }
  `,
  md: (styles: any) => css`
    @media (min-width: ${(props: { theme: Theme }) => props.theme.breakpoints.md}) {
      ${styles}
    }
  `,
  lg: (styles: any) => css`
    @media (min-width: ${(props: { theme: Theme }) => props.theme.breakpoints.lg}) {
      ${styles}
    }
  `,
};

// Flexbox utilities
export const FlexContainer = styled.div<{
  direction?: 'row' | 'column';
  align?: 'flex-start' | 'center' | 'flex-end' | 'stretch';
  justify?: 'flex-start' | 'center' | 'flex-end' | 'space-between' | 'space-around';
  wrap?: 'nowrap' | 'wrap' | 'wrap-reverse';
  gap?: string;
}>`
  display: flex;
  flex-direction: ${({ direction = 'row' }) => direction};
  align-items: ${({ align = 'stretch' }) => align};
  justify-content: ${({ justify = 'flex-start' }) => justify};
  flex-wrap: ${({ wrap = 'nowrap' }) => wrap};
  gap: ${({ gap }) => gap || '0'};
`;

// Grid utilities
export const GridContainer = styled.div<{
  columns?: number;
  gap?: string;
  minColumnWidth?: string;
}>`
  display: grid;
  gap: ${({ gap }) => gap || '16px'};
  
  ${({ columns, minColumnWidth }) => {
    if (columns) {
      return css`
        grid-template-columns: repeat(${columns}, 1fr);
      `;
    }
    if (minColumnWidth) {
      return css`
        grid-template-columns: repeat(auto-fit, minmax(${minColumnWidth}, 1fr));
      `;
    }
    return css`
      grid-template-columns: 1fr;
    `;
  }}
`;

// Card component
export const Card = styled.div<{
  variant?: 'default' | 'elevated' | 'outlined';
  padding?: string;
  borderRadius?: string;
}>`
  background: ${({ theme }) => theme.colors.background.paper};
  border-radius: ${({ borderRadius, theme }) => borderRadius || theme.borderRadius.md};
  padding: ${({ padding = '16px' }) => padding};
  
  ${({ variant = 'default', theme }) => {
    switch (variant) {
      case 'elevated':
        return css`
          box-shadow: ${theme.shadows.md};
          border: 1px solid ${theme.colors.border.primary};
        `;
      case 'outlined':
        return css`
          border: 2px solid ${theme.colors.border.primary};
        `;
      default:
        return css`
          border: 1px solid ${theme.colors.border.primary};
        `;
    }
  }}
  
  transition: all 0.2s ease;
  
  &:hover {
    transform: translateY(-2px);
    box-shadow: ${({ theme }) => theme.shadows.lg};
  }
`;

// Typography components
export const Heading = styled.h1<{
  level: 1 | 2 | 3 | 4 | 5 | 6;
  size?: 'xs' | 'sm' | 'base' | 'lg' | 'xl' | '2xl' | '3xl' | '4xl';
  weight?: 'light' | 'normal' | 'medium' | 'semibold' | 'bold';
  color?: string;
}>`
  margin: 0;
  font-family: ${({ theme }) => theme.typography.fontFamily.primary};
  font-weight: ${({ weight, theme }) => theme.typography.fontWeight[weight || 'semibold']};
  color: ${({ color, theme }) => color || theme.colors.text.primary};
  
  ${({ level, size, theme }) => {
    const sizes = {
      1: size || '3xl',
      2: size || '2xl',
      3: size || 'xl',
      4: size || 'lg',
      5: size || 'base',
      6: size || 'sm',
    };
    
    return css`
      font-size: ${theme.typography.fontSize[sizes[level] as keyof typeof theme.typography.fontSize]};
      line-height: ${theme.typography.lineHeight.tight};
    `;
  }}
`;

export const Text = styled.p<{
  size?: 'xs' | 'sm' | 'base' | 'lg' | 'xl';
  weight?: 'light' | 'normal' | 'medium' | 'semibold' | 'bold';
  color?: string;
  align?: 'left' | 'center' | 'right';
}>`
  margin: 0;
  font-family: ${({ theme }) => theme.typography.fontFamily.primary};
  font-size: ${({ size = 'base', theme }) => theme.typography.fontSize[size]};
  font-weight: ${({ weight = 'normal', theme }) => theme.typography.fontWeight[weight]};
  color: ${({ color, theme }) => color || theme.colors.text.secondary};
  text-align: ${({ align = 'left' }) => align};
  line-height: ${({ theme }) => theme.typography.lineHeight.normal};
`;
```

## 🚀 Performance Architecture

### **Code Splitting and Lazy Loading**

```tsx
// src/routing/LazyRoutes.tsx - Optimized route loading
import { lazy, Suspense } from 'next';
import { LoadingSpinner } from '../components/atoms/LoadingSpinner';
import { ErrorBoundary } from '../components/organisms/ErrorBoundary';

// Lazy loaded components
const Dashboard = lazy(() => import('../features/dashboard/Dashboard'));
const UserProfile = lazy(() => import('../features/users/UserProfile'));
const AdminPanel = lazy(() => import('../features/admin/AdminPanel'));
const Reports = lazy(() => import('../features/reports/Reports'));

// Loading fallback component
const RouteLoader = () => (
  <div style={{ 
    display: 'flex', 
    justifyContent: 'center', 
    alignItems: 'center', 
    height: '200px' 
  }}>
    <LoadingSpinner size="lg" />
  </div>
);

// Error fallback component
const RouteError = ({ error }: { error: Error }) => (
  <div style={{ padding: '20px', textAlign: 'center' }}>
    <h2>Failed to load page</h2>
    <p>{error.message}</p>
    <button onClick={() => window.location.reload()}>
      Try Again
    </button>
  </div>
);

// Lazy route wrapper
export const LazyRoute = ({ children }: { children: Next.js.Next.jsNode }) => (
  <ErrorBoundary fallback={RouteError}>
    <Suspense fallback={<RouteLoader />}>
      {children}
    </Suspense>
  </ErrorBoundary>
);

// Configured lazy routes
export const lazyRoutes = [
  {
    path: '/dashboard',
    component: () => (
      <LazyRoute>
        <Dashboard />
      </LazyRoute>
    ),
  },
  {
    path: '/profile',
    component: () => (
      <LazyRoute>
        <UserProfile />
      </LazyRoute>
    ),
  },
  {
    path: '/admin/*',
    component: () => (
      <LazyRoute>
        <AdminPanel />
      </LazyRoute>
    ),
  },
  {
    path: '/reports',
    component: () => (
      <LazyRoute>
        <Reports />
      </LazyRoute>
    ),
  },
];
```

### **Virtualization for Large Lists**

```tsx
// src/components/organisms/VirtualizedTable/index.tsx - Performance-optimized table
import Next.js, { useMemo, useCallback } from 'next';
import { FixedSizeList as List } from 'next-window';
import { useVirtualizer } from '@tanstack/next-virtual';

interface VirtualizedTableProps<T> {
  data: T[];
  columns: ColumnConfig<T>[];
  rowHeight: number;
  height: number;
  onRowClick?: (item: T) => void;
}

interface ColumnConfig<T> {
  key: string;
  header: string;
  width: number;
  render: (item: T) => Next.js.Next.jsNode;
}

export function VirtualizedTable<T>({ 
  data, 
  columns, 
  rowHeight, 
  height, 
  onRowClick 
}: VirtualizedTableProps<T>) {
  // Memoized column widths
  const totalWidth = useMemo(() => 
    columns.reduce((sum, col) => sum + col.width, 0), 
    [columns]
  );

  // Virtual row renderer
  const Row = useCallback(({ index, style }: { index: number; style: any }) => {
    const item = data[index];
    
    return (
      <div 
        style={{
          ...style,
          display: 'flex',
          borderBottom: '1px solid #eee',
          alignItems: 'center',
          cursor: onRowClick ? 'pointer' : 'default',
        }}
        onClick={() => onRowClick?.(item)}
      >
        {columns.map((column) => (
          <div
            key={column.key}
            style={{
              width: column.width,
              padding: '8px',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
            }}
          >
            {column.render(item)}
          </div>
        ))}
      </div>
    );
  }, [data, columns, onRowClick]);

  // Table header
  const Header = useMemo(() => (
    <div 
      style={{ 
        display: 'flex', 
        borderBottom: '2px solid #ddd', 
        fontWeight: 'bold',
        backgroundColor: '#f8f9fa',
      }}
    >
      {columns.map((column) => (
        <div
          key={column.key}
          style={{
            width: column.width,
            padding: '12px 8px',
            backgroundColor: '#f8f9fa',
          }}
        >
          {column.header}
        </div>
      ))}
    </div>
  ), [columns]);

  return (
    <div style={{ border: '1px solid #ddd', borderRadius: '4px' }}>
      {Header}
      <List
        height={height}
        itemCount={data.length}
        itemSize={rowHeight}
        width={totalWidth}
      >
        {Row}
      </List>
    </div>
  );
}
```

---
*Next.js Architecture Guide - Use these patterns for maintainable and scalable Next.js applications*
