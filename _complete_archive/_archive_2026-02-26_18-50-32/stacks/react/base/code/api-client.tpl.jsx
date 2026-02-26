/*
File: api-client.tpl.jsx
Purpose: TanStack Query (React Query) API client setup
Generated for: {{PROJECT_NAME}}
*/

import { QueryClient, QueryClientProvider, useQuery, useMutation, useQueryClient } from '@tanstack/react-query';

// Create a client
export const queryClient = new QueryClient({
    defaultOptions: {
        queries: {
            staleTime: 1000 * 60 * 5, // 5 minutes
            retry: 2,
            refetchOnWindowFocus: false,
        },
    },
});

// Base API configuration
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:3000/api';

async function apiRequest(endpoint, options = {}) {
    const token = localStorage.getItem('token');

    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        headers: {
            'Content-Type': 'application/json',
            ...(token && { Authorization: `Bearer ${token}` }),
            ...options.headers,
        },
        ...options,
    });

    if (!response.ok) {
        const error = await response.json().catch(() => ({}));
        throw new Error(error.message || 'API request failed');
    }

    return response.json();
}

// Query Keys Factory
export const queryKeys = {
    users: {
        all: ['users'],
        detail: (id) => ['users', id],
        list: (filters) => ['users', 'list', filters],
    },
    posts: {
        all: ['posts'],
        detail: (id) => ['posts', id],
    },
};

// Example Hooks
export function useUsers(filters = {}) {
    return useQuery({
        queryKey: queryKeys.users.list(filters),
        queryFn: () => apiRequest('/users', { params: filters }),
    });
}

export function useUser(id) {
    return useQuery({
        queryKey: queryKeys.users.detail(id),
        queryFn: () => apiRequest(`/users/${id}`),
        enabled: !!id,
    });
}

export function useCreateUser() {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: (userData) => apiRequest('/users', {
            method: 'POST',
            body: JSON.stringify(userData),
        }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: queryKeys.users.all });
        },
    });
}

// Provider wrapper
export function ApiProvider({ children }) {
    return (
        <QueryClientProvider client={queryClient}>
            {children}
        </QueryClientProvider>
    );
}
