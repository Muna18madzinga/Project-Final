import axios from 'axios'
import toast from 'react-hot-toast'

const isDev = import.meta.env.DEV
const API_BASE_URL = import.meta.env.VITE_API_URL || (isDev ? 'http://localhost:5000' : '')

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json'
  }
})

// Request interceptor to add auth token
api.interceptors.request.use(
  (config) => {
    const authData = localStorage.getItem('auth-storage')
    if (authData) {
      try {
        const { state } = JSON.parse(authData)
        if (state?.token) {
          config.headers.Authorization = `Bearer ${state.token}`
        }
      } catch (error) {
        console.error('Error parsing auth data:', error)
        // If auth data is corrupted, remove it
        localStorage.removeItem('auth-storage')
      }
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor for error handling
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config

    // Handle 401 Unauthorized
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true

      // Clear auth data and redirect to login
      localStorage.removeItem('auth-storage')
      
      // Don't redirect if we're already on login page or this is a login request
      if (!window.location.pathname.includes('/login') && !originalRequest.url?.includes('/api/auth/login')) {
        // Show error message
        toast.error('Session expired. Please log in again.')
        
        // Redirect to login after a short delay
        setTimeout(() => {
          window.location.href = '/'
        }, 1000)
      }
      
      return Promise.reject(error)
    }

    // Handle other errors
    if (error.code === 'ECONNABORTED') {
      toast.error('Request timed out. Please try again.')
    } else if (error.code === 'ERR_NETWORK') {
      toast.error('Network error. Please check your connection.')
    } else if (error.response?.data?.error) {
      // Don't show error toast for login failures or expected errors
      if (!originalRequest.url?.includes('/api/auth/login')) {
        toast.error(error.response.data.error)
      }
    } else if (error.message && !error.message.includes('Network Error')) {
      toast.error(error.message)
    }

    return Promise.reject(error)
  }
)

export default api