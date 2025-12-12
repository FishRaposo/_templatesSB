/*
File: state-management.tpl.jsx
Purpose: Global state management using Zustand
Generated for: {{PROJECT_NAME}}
*/

import { create } from 'zustand'
import { persist } from 'zustand/middleware'

/**
 * Auth Store Example
 */
export const useAuthStore = create(
    persist(
        (set) => ({
            user: null,
            isAuthenticated: false,
            token: null,

            login: (userData, token) => set({
                user: userData,
                isAuthenticated: true,
                token
            }),

            logout: () => set({
                user: null,
                isAuthenticated: false,
                token: null
            }),
        }),
        {
            name: 'auth-storage', // unique name
            getStorage: () => localStorage, // (optional) by default, 'localStorage' is used
        }
    )
)

/**
 * UI Store Example (Ephemeral)
 */
export const useUIStore = create((set) => ({
    isSidebarOpen: false,
    toggleSidebar: () => set((state) => ({ isSidebarOpen: !state.isSidebarOpen })),
    closeSidebar: () => set({ isSidebarOpen: false }),
}))

// Example Usage in Component
/*
import { useAuthStore } from './state-management'

function UserProfile() {
  const user = useAuthStore((state) => state.user)
  const logout = useAuthStore((state) => state.logout)

  if (!user) return <div>Please login</div>

  return (
    <div>
      <h1>Welcome, {user.name}</h1>
      <button onClick={logout}>Logout</button>
    </div>
  )
}
*/
