import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import api from '../services/api'
import toast from 'react-hot-toast'

const defaultUser = {
  username: import.meta.env.VITE_DEFAULT_USERNAME || 'Theo_Madzinga',
}

export const useAuthStore = create(
  persist(
    (set, get) => ({
      user: defaultUser,
      token: null,
      isAuthenticated: true,
      mfaRequired: false,
      mfaSessionId: null,

      login: async (username, password) => {
        set({
          user: { username },
          token: null,
          isAuthenticated: true,
          mfaRequired: false,
          mfaSessionId: null
        })
        return { success: true }
      },

      verifyMFA: async (code) => {
        set({
          mfaRequired: false,
          mfaSessionId: null
        })
        return { success: true }
      },

      register: async (username, password, email) => {
        try {
          await api.post('/api/auth/register', { username, password, email })
            return { success: true }
        } catch (error) {
          throw new Error(error.response?.data?.error || 'Registration failed')
        }
      },

      logout: async () => {
        toast.success('Signed out of the console')
        set({
          user: defaultUser,
          token: null,
          isAuthenticated: true,
          mfaRequired: false,
          mfaSessionId: null
        })
      },

      refreshToken: async () => {
        const token = get().token
        if (!token) {
          return null
        }
        return token
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
