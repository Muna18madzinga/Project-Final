import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import { Toaster } from 'react-hot-toast'
import { useAuthStore } from './store/authStore'

// Pages
import LoginPage from './pages/LoginPage'
import DashboardPage from './pages/DashboardPage'
import ThreatMonitorPage from './pages/ThreatMonitorPage'
import DevicesPage from './pages/DevicesPage'
import SecuritySettingsPage from './pages/SecuritySettingsPage'
import AdminPage from './pages/AdminPage'

// Layout
import DashboardLayout from './components/Layout/DashboardLayout'

// Protected Route Component
function ProtectedRoute({ children }) {
  const { isAuthenticated, token } = useAuthStore()
  
  if (!isAuthenticated || !token) {
    return <Navigate to="/login" replace />
  }
  
  return children
}

function App() {
  return (
    <Router>
      <div className="min-h-screen bg-gray-50">
        <Routes>
          {/* Public Routes */}
          <Route path="/login" element={<LoginPage />} />
          
          {/* Protected Routes */}
          <Route path="/" element={
            <ProtectedRoute>
              <DashboardLayout />
            </ProtectedRoute>
          }>
            <Route index element={<DashboardPage />} />
            <Route path="threats" element={<ThreatMonitorPage />} />
            <Route path="devices" element={<DevicesPage />} />
            <Route path="settings" element={<SecuritySettingsPage />} />
            <Route path="admin" element={<AdminPage />} />
          </Route>

          {/* 404 - Redirect to login */}
          <Route path="*" element={<Navigate to="/login" replace />} />
        </Routes>

        {/* Toast Notifications */}
        <Toaster
          position="top-right"
          toastOptions={{
            duration: 4000,
            style: {
              background: '#1f2937',
              color: '#ffffff',
              fontSize: '14px',
              borderRadius: '8px',
              padding: '12px 16px',
            },
            success: {
              duration: 3000,
              iconTheme: {
                primary: '#10b981',
                secondary: '#ffffff',
              },
            },
            error: {
              duration: 5000,
              iconTheme: {
                primary: '#ef4444',
                secondary: '#ffffff',
              },
            },
            loading: {
              iconTheme: {
                primary: '#3b82f6',
                secondary: '#ffffff',
              },
            },
          }}
        />
      </div>
    </Router>
  )
}

export default App