import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import { Toaster } from 'react-hot-toast'

// Pages
import DashboardPage from './pages/DashboardPage'
import ThreatMonitorPage from './pages/ThreatMonitorPage'
import DevicesPage from './pages/DevicesPage'
import SecuritySettingsPage from './pages/SecuritySettingsPage'
import AdminPage from './pages/AdminPage'

// Layout
import DashboardLayout from './components/Layout/DashboardLayout'

function App() {
  const routerBase =
    import.meta.env.VITE_APP_BASE_PATH || (import.meta.env.DEV ? '/' : '/suite/status')

  return (
    <Router basename={routerBase}>
      <div className="min-h-screen bg-gray-50">
        <Routes>
          <Route path="/" element={<DashboardLayout />}>
            <Route index element={<DashboardPage />} />
            <Route path="threats" element={<ThreatMonitorPage />} />
            <Route path="devices" element={<DevicesPage />} />
            <Route path="settings" element={<SecuritySettingsPage />} />
            <Route path="admin" element={<AdminPage />} />
          </Route>

          {/* 404 */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>

        {/* Toast Notifications */}
        <Toaster
          position="top-right"
          toastOptions={{
            duration: 4000,
            style: {
              background: '#363636',
              color: '#fff',
            },
            success: {
              duration: 3000,
              iconTheme: {
                primary: '#22c55e',
                secondary: '#fff',
              },
            },
            error: {
              duration: 5000,
              iconTheme: {
                primary: '#ef4444',
                secondary: '#fff',
              },
            },
          }}
        />
      </div>
    </Router>
  )
}

export default App
