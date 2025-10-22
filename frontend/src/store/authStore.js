import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import api from '../services/api'
import toast from 'react-hot-toast'

export const useAuthStore = create(
  persist(
    (set, get) => ({
      user: null,
      token: null,
      isAuthenticated: false,
      loading: false,
      error: null,

      login: async (username, password) => {
        set({ loading: true, error: null })
        
        try {
          const response = await api.post('/api/auth/login', {
            username,
            password
          })
          
          const { access_token, user } = response.data
          
          set({
            user,
            token: access_token,
            isAuthenticated: true,
            loading: false,
            error: null
          })
          
          toast.success(`Welcome back, ${user.username}!`)
          return { success: true }
          
        } catch (error) {
          const errorMessage = error.response?.data?.error || 'Login failed'
          set({
            user: null,
            token: null,
            isAuthenticated: false,
            loading: false,
            error: errorMessage
          })
          
          toast.error(errorMessage)
          return { success: false, error: errorMessage }
        }
      },

      logout: async () => {
        set({
          user: null,
          token: null,
          isAuthenticated: false,
          loading: false,
          error: null
        })
        
        toast.success('Logged out successfully')
      },

      checkAuth: async () => {
        const token = get().token
        if (!token) {
          return false
        }

        try {
          const response = await api.get('/api/auth/me')
          set({
            user: response.data,
            isAuthenticated: true,
            error: null
          })
          return true
        } catch (error) {
          set({
            user: null,
            token: null,
            isAuthenticated: false,
            error: null
          })
          return false
        }
      },

      clearError: () => {
        set({ error: null })
      },

      // Demo mode login (fallback)
      loginDemo: () => {
        const demoUser = {
          id: 1,
          username: 'demo_user',
          role: 'admin'
        }
        
        set({
          user: demoUser,
          token: 'demo-token',
          isAuthenticated: true,
          loading: false,
          error: null
        })
        
        toast.success('Logged in to demo mode')
        return { success: true }
      }
    }),
    {
      name: 'auth-storage',
      partialize: (state) => ({
        user: state.user,
        token: state.token,
        isAuthenticated: state.isAuthenticated
      })
    }
  )
)

// Initialize auth check on app load
if (typeof window !== 'undefined') {
  const store = useAuthStore.getState()
  if (store.token) {
    store.checkAuth()
  }
}