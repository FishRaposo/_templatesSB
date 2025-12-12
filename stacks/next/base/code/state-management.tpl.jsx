/*
File: state-management.tpl.jsx
Purpose: Global state management using Zustand (Next.js focus)
Generated for: {{PROJECT_NAME}}
*/

import { create } from 'zustand'

/**
 * NOTE: In Next.js App Router, global state providers (like Context or Zustand)
 * must be used in Client Components ('use client').
 * 
 * Server Components should fetch data directly.
 */

export const useAppStore = create((set) => ({
    count: 0,
    increment: () => set((state) => ({ count: state.count + 1 })),
    decrement: () => set((state) => ({ count: state.count - 1 })),
    reset: () => set({ count: 0 }),
}))

// Example of Safe Initialization in Next.js
/*
// providers.jsx
'use client';

export const GlobalStoreProvider = ({ children, initialCount }) => {
    const store = useRef(useAppStore).current
    
    // Optional: Hydrate from server props if needed (careful with hydration mismatch)
    if (!store.initialized) {
        useAppStore.setState({ count: initialCount })
        store.initialized = true
    }

    return children
}
*/
