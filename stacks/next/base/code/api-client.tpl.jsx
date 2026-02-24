/*
File: api-client.tpl.jsx
Purpose: TanStack Query API client for Next.js (App Router compatible)
Generated for: {{PROJECT_NAME}}
*/

'use client';

import { QueryClient, QueryClientProvider, useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';

// Create query client (hydration-safe for Next.js)
function makeQueryClient() {
    return new QueryClient({
        defaultOptions: {
            queries: {
                staleTime: 60 * 1000, // 1 minute
                refetchOnWindowFocus: false,
            },
        },
    });
}

let browserQueryClient;

function getQueryClient() {
    if (typeof window === 'undefined') {
        // Server: always make a new query client
        return makeQueryClient();
    } else {
        // Browser: reuse client
        if (!browserQueryClient) browserQueryClient = makeQueryClient();
        return browserQueryClient;
    }
}

// Provider for App Router
export function Providers({ children }) {
    const [queryClient] = useState(() => getQueryClient());

    return (
        <QueryClientProvider client={queryClient}>
            {children}
        </QueryClientProvider>
    );
}

// API Request Helper
const API_BASE = process.env.NEXT_PUBLIC_API_URL || '/api';

export async function api(endpoint, options = {}) {
    const res = await fetch(`${API_BASE}${endpoint}`, {
        headers: {
            'Content-Type': 'application/json',
            ...options.headers,
        },
        ...options,
    });

    if (!res.ok) {
        throw new Error(`API Error: ${res.status}`);
    }

    return res.json();
}

// Server Actions Integration Note:
// For mutations that modify server state, consider using Server Actions instead:
// 'use server';
// export async function createUser(formData) { ... }

// Query Keys
export const keys = {
    users: {
        all: ['users'],
        byId: (id) => ['users', id],
    },
};

// Example Hooks
export function useUsers() {
    return useQuery({
        queryKey: keys.users.all,
        queryFn: () => api('/users'),
    });
}

export function useCreateUser() {
    const qc = useQueryClient();
    return useMutation({
        mutationFn: (data) => api('/users', { method: 'POST', body: JSON.stringify(data) }),
        onSuccess: () => qc.invalidateQueries({ queryKey: keys.users.all }),
    });
}
