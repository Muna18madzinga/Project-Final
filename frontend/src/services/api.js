import axios from 'axios'
import toast from 'react-hot-toast'

const isDev = import.meta.env.DEV
const configuredBasePath = import.meta.env.VITE_APP_BASE_PATH || (isDev ? '/' : '/suite/status')
const appBasePath = configuredBasePath.endsWith('/')
  ? configuredBasePath
  : `${configuredBasePath}/`

const apiBaseURL = (() => {
  if (import.meta.env.VITE_API_URL) {
    return import.meta.env.VITE_API_URL
  }

  if (typeof window !== 'undefined') {
    // Relative paths so Vite proxy (dev) or Flask (prod) can handle /api routes
    return ''
  }

  return 'http://localhost:5000'
})()

const api = axios.create({
  baseURL: apiBaseURL,
  headers: {
    'Content-Type': 'application/json'
  },
  withCredentials: true
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

      try {
        // Try to refresh token
        const response = await api.post('/api/auth/refresh')
        const newToken = response.data.access_token

        // Update token in localStorage
        const authData = localStorage.getItem('auth-storage')
        if (authData) {
          const parsed = JSON.parse(authData)
          parsed.state.token = newToken
          localStorage.setItem('auth-storage', JSON.stringify(parsed))
        }

        // Retry original request
        originalRequest.headers.Authorization = `Bearer ${newToken}`
        return api(originalRequest)
      } catch (refreshError) {
        // Refresh failed, logout user
        localStorage.removeItem('auth-storage')
        window.location.href = `${appBasePath}login`
        return Promise.reject(refreshError)
      }
    }

    // Show error toast
    const errorMessage = error.response?.data?.error || 'An error occurred'
    toast.error(errorMessage)

    return Promise.reject(error)
  }
)

export default api
